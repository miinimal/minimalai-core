"""Minimal Witness W1 — the continuous record of agent tools (master prompt part C, block E1).

What is recorded. Every hour the witness service reads public sources and keeps one observation per new fact:
  manifest  a server entry of the official MCP Registry (registry.modelcontextprotocol.io, API v0.1) — the full `server`
            object as published, per version; digest = sha256 of its canonical JSON
  status    the registry status of a version (active / deprecated / deleted) when it changes
  package   the npm or PyPI artifact a registry entry points to — npm `dist.integrity` / `dist.shasum` / tarball,
            PyPI file names with their sha256 digests
  tools     the `tools/list` answer of a public streamable-http remote (name, description, inputSchema, annotations):
            tool descriptions are the main vector of a silent swap, so they are hashed and kept per change
  run       one summary per hourly run (what was read, what failed): the hour is recorded even when nothing moved,
            so the history has no silent gaps (quality gate C5: a missed record is an incident)
An observation is a canonical JSON record; its leaf is sha256(record). Each record names the leaf of the previous
observation of the same object and kind (`prev`), so the history of one tool is a hash chain of its own.

How it is fixed. Once an hour all new leaves are sealed into a batch: a Merkle root (notary.py: leaf = sha256(0x00||h),
node = sha256(0x01||l||r)), the previous batch head and the count go into the batch record; head = sha256(record).
The record is signed by the isolated signer (Ed25519, gateway key) and the head is anchored at once in OpenTimestamps
(Bitcoin), an RFC 3161 TSA and Sigstore Rekor; the daily anchor batch (anchors.py) adds the latest head to TON and EAS on
Base. Anyone can check a single observation without us: record -> leaf -> Merkle path -> root -> batch record -> head ->
any anchor (GET /v1/witness/proof?seq=N returns every piece).

Rules for sources (L5): only public data, the registry's own API (built for sub-registries that enrich it), npm and PyPI
JSON APIs, and remotes their authors published in the registry; one identified client, paced requests, no auth bypass,
no private address is ever called (SSRF guard). Records state facts ("the description changed"), never labels.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: MIT (open core).
"""
import hashlib
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

log = logging.getLogger("witness")
WITNESS_DB = os.environ.get("WITNESS_DB", "/data/witness.db")
MAIN_DB = os.environ.get("MINIMALAI_DB", "/data/minimalai.db")
REGISTRY = os.environ.get("WITNESS_REGISTRY", "https://registry.modelcontextprotocol.io")
REGISTRY_SOURCE = "registry.modelcontextprotocol.io"
NPM = os.environ.get("WITNESS_NPM", "https://registry.npmjs.org")
PYPI = os.environ.get("WITNESS_PYPI", "https://pypi.org")
UA = "MinimalWitness/1.0 (+https://minimalcult.org/witness; public-data recorder)"
REKOR_KEY = os.environ.get("WITNESS_REKOR_KEY", "/keys/witness_rekor.key")
RUN_BUDGET_S = int(os.environ.get("WITNESS_RUN_BUDGET_S", "2400"))     # crawl time per hourly run; the rest of the hour is idle
PROBES_PER_RUN = int(os.environ.get("WITNESS_PROBES_PER_RUN", "20000"))
PAGE_PAUSE_S = float(os.environ.get("WITNESS_PAGE_PAUSE_S", "0.2"))
PROBE_EVERY_S = 86400
WORKERS = int(os.environ.get("WITNESS_WORKERS", "8"))
MAX_BODY = 4 * 1024 * 1024
PROTOCOL = "2025-06-18"

SCHEMA = """
CREATE TABLE IF NOT EXISTS w_obs(seq INTEGER PRIMARY KEY AUTOINCREMENT, object TEXT, kind TEXT, version TEXT, observed_at INTEGER,
    digest TEXT, prev TEXT, record TEXT, leaf TEXT, body BLOB, batch_id TEXT, UNIQUE(object, kind, version, digest));
CREATE INDEX IF NOT EXISTS w_obs_obj ON w_obs(object, kind, seq);
CREATE INDEX IF NOT EXISTS w_obs_batch ON w_obs(batch_id);
CREATE INDEX IF NOT EXISTS w_obs_kind ON w_obs(kind, seq);
CREATE TABLE IF NOT EXISTS w_objects(id TEXT PRIMARY KEY, kind TEXT, name TEXT, title TEXT, description TEXT, source TEXT, first_seen INTEGER,
    last_seen INTEGER, latest TEXT, versions INTEGER DEFAULT 0, changes INTEGER DEFAULT 0, last_change INTEGER, status TEXT, repo TEXT, links TEXT);
CREATE INDEX IF NOT EXISTS w_objects_change ON w_objects(last_change);
CREATE TABLE IF NOT EXISTS w_batches(seq INTEGER PRIMARY KEY, id TEXT UNIQUE, ts INTEGER, n INTEGER, first_seq INTEGER, last_seq INTEGER,
    root TEXT, prev_head TEXT, head TEXT, record TEXT, sig TEXT);
CREATE TABLE IF NOT EXISTS w_proofs(batch_id TEXT, kind TEXT, ts INTEGER, status TEXT, proof TEXT, meta TEXT, error TEXT, PRIMARY KEY(batch_id, kind));
CREATE TABLE IF NOT EXISTS w_queue(registry TEXT, identifier TEXT, version TEXT, mcp TEXT, added INTEGER, tries INTEGER DEFAULT 0, error TEXT, latest INTEGER DEFAULT 0,
    live INTEGER DEFAULT 0, PRIMARY KEY(registry, identifier, version));
CREATE TABLE IF NOT EXISTS w_probe(endpoint TEXT PRIMARY KEY, object TEXT, version TEXT, next_at INTEGER, fails INTEGER DEFAULT 0, last_ok INTEGER, error TEXT);
CREATE TABLE IF NOT EXISTS w_state(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS w_count(key TEXT PRIMARY KEY, n INTEGER);
CREATE TABLE IF NOT EXISTS w_changes(seq INTEGER PRIMARY KEY, object TEXT, ts INTEGER, what TEXT);
CREATE TABLE IF NOT EXISTS w_capacity(ts INTEGER PRIMARY KEY, sample TEXT);
"""
# counters and the change list are kept as facts are written: the public pages never scan the observation table
CHANGE_KINDS = ("manifest", "package", "tools", "status")
STOP = {"now": False}       # set by SIGTERM: finish the current call, record the run, seal, anchor, exit


def go(deadline):
    return not STOP["now"] and time.time() < deadline


# ---------------------------------------------------------------- storage and hashing
def connect(path=None):
    c = sqlite3.connect(path or WITNESS_DB, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass
    c.executescript(SCHEMA)
    _migrate(c)
    return c


def rec_id(object_id):
    """Public record id (official names, 04.11): rec_ + 24 hex of sha256 of the internal object id; stable forever."""
    return "rec_" + hashlib.sha256(object_id.encode()).hexdigest()[:24]


def ver_id(leaf):
    """Public version id: ver_ + the first 24 hex of the observation leaf (content-derived, unique per fact)."""
    return "ver_" + leaf[:24]


def _bump(c, key, n=1):
    c.execute("INSERT INTO w_count(key, n) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET n=n+excluded.n", (key, n))


def _migrate(c):
    """One-time: counters and the change list for a record written before they existed; the leaf index for proofs."""
    c.execute("CREATE INDEX IF NOT EXISTS w_obs_leaf ON w_obs(leaf)")
    if "rec_id" not in [r[1] for r in c.execute("PRAGMA table_info(w_objects)")]:
        c.execute("ALTER TABLE w_objects ADD COLUMN rec_id TEXT")
    if c.execute("SELECT 1 FROM w_objects WHERE rec_id IS NULL LIMIT 1").fetchone():
        c.executemany("UPDATE w_objects SET rec_id=? WHERE id=?", [(rec_id(r[0]), r[0]) for r in c.execute("SELECT id FROM w_objects WHERE rec_id IS NULL").fetchall()])
        c.commit()
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS w_objects_rec ON w_objects(rec_id)")
    if "live" not in [r[1] for r in c.execute("PRAGMA table_info(w_queue)")]:
        c.execute("ALTER TABLE w_queue ADD COLUMN live INTEGER DEFAULT 0")
    if state(c, "fix_backlog_changes_v1") is None and not c.execute("SELECT 1 FROM w_count LIMIT 1").fetchone():
        set_state(c, "fix_backlog_changes_v1", 0)      # a new record: counted correctly from the start
    elif state(c, "fix_backlog_changes_v1") is None:
        # 2026-11-04: package versions drained from the backlog queue in later hours were counted as changes; they are
        # history, not news. Drop them from the change list and the counters (facts and their chain stay as recorded).
        bad = c.execute("SELECT count(*) FROM w_changes WHERE object LIKE 'npm:%' OR object LIKE 'pypi:%'").fetchone()[0]
        c.execute("DELETE FROM w_changes WHERE object LIKE 'npm:%' OR object LIKE 'pypi:%'")
        c.execute("UPDATE w_objects SET changes=0, last_change=NULL WHERE kind IN ('npm','pypi')")
        c.execute("UPDATE w_count SET n=max(0, n-?) WHERE key='changes'", (bad,))
        set_state(c, "fix_backlog_changes_v1", bad)
        c.commit()
    if c.execute("SELECT 1 FROM w_count LIMIT 1").fetchone() or not c.execute("SELECT 1 FROM w_obs LIMIT 1").fetchone():
        return
    for r in c.execute("SELECT kind, count(*) n FROM w_obs GROUP BY kind").fetchall():
        _bump(c, "obs:" + r["kind"], r["n"])
    for r in c.execute("SELECT kind, count(*) n FROM w_objects GROUP BY kind").fetchall():
        _bump(c, "objects:" + r["kind"], r["n"])
    _bump(c, "changes", c.execute("SELECT coalesce(sum(changes), 0) FROM w_objects").fetchone()[0])
    first = c.execute("SELECT min(observed_at) FROM w_obs").fetchone()[0]
    if first and state(c, "first_observed") is None:
        set_state(c, "first_observed", first)
    for o in c.execute("SELECT id, last_change FROM w_objects WHERE last_change IS NOT NULL").fetchall():
        r = c.execute("SELECT * FROM w_obs WHERE object=? AND observed_at=? AND prev IS NOT NULL ORDER BY seq DESC LIMIT 1", (o["id"], o["last_change"])).fetchone()
        if r:
            p = c.execute("SELECT version FROM w_obs WHERE leaf=?", (r["prev"],)).fetchone()
            c.execute("INSERT OR IGNORE INTO w_changes(seq, object, ts, what) VALUES(?,?,?,?)", (r["seq"], r["object"], r["observed_at"], _what(r["kind"], r["version"], p and p["version"], None)))
    c.commit()


def _what(kind, version, prev_version, payload):
    if kind == "status":
        return f"registry status: {(payload or {}).get('status')}"
    if kind == "tools":                       # the main swap vector: never hidden behind a version bump
        return "tool descriptions changed" + (f" (with version {version})" if prev_version is not None and prev_version != version else "")
    if prev_version is not None and prev_version != version:
        return f"new version {version}"
    if kind == "tools":
        return "tool descriptions changed"
    return f"{kind} of {version} changed"


def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha(obj):
    return hashlib.sha256(obj if isinstance(obj, (bytes, bytearray)) else canon(obj)).hexdigest()


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def state(c, key, default=None):
    r = c.execute("SELECT value FROM w_state WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_state(c, key, value):
    c.execute("INSERT OR REPLACE INTO w_state(key, value) VALUES(?,?)", (key, None if value is None else str(value)))


def body_of(row):
    return json.loads(zlib.decompress(row["body"])) if row["body"] else None


def observe(c, obj, kind, version, payload, now, source, meta=None, info=None, news=True):
    """Record one fact if it is new. Returns the seq of the new observation, or None when this exact fact is already recorded."""
    digest = sha(payload)
    if c.execute("SELECT 1 FROM w_obs WHERE object=? AND kind=? AND version=? AND digest=?", (obj, kind, version, digest)).fetchone():
        c.execute("UPDATE w_objects SET last_seen=? WHERE id=?", (now, obj))
        return None
    last = c.execute("SELECT leaf, digest, observed_at, version FROM w_obs WHERE object=? AND kind=? ORDER BY seq DESC LIMIT 1", (obj, kind)).fetchone()
    rec = {"v": 1, "object": obj, "kind": kind, "version": version, "source": source, "observed_at": iso(now), "digest": digest,
           "prev": last["leaf"] if last else None}
    if meta:
        rec["meta"] = meta
    leaf = sha(rec)
    cur = c.execute("INSERT INTO w_obs(object, kind, version, observed_at, digest, prev, record, leaf, body) VALUES(?,?,?,?,?,?,?,?,?)",
                    (obj, kind, version, now, digest, rec["prev"], canon(rec).decode(), leaf, zlib.compress(canon(payload), 6)))
    info = info or {}
    o = c.execute("SELECT id FROM w_objects WHERE id=?", (obj,)).fetchone()
    # a change is something that moved after we had already seen the object: versions read together in one backfill are history, not news
    # news=False: the fact comes from the backlog (first registry pass, package queue filled by it), not from the source moving
    changed = news and last is not None and kind in CHANGE_KINDS and last["digest"] != digest and last["observed_at"] < now
    _bump(c, "obs:" + kind)
    if state(c, "first_observed") is None:
        set_state(c, "first_observed", now)
    if changed:
        _bump(c, "changes")
        c.execute("INSERT INTO w_changes(seq, object, ts, what) VALUES(?,?,?,?)", (cur.lastrowid, obj, now, _what(kind, version, last["version"], payload)))
    if not o:
        _bump(c, "objects:" + obj.split(":", 1)[0])
        c.execute("INSERT INTO w_objects(id, kind, name, title, description, source, first_seen, last_seen, latest, versions, changes, last_change, status, repo, links, rec_id) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (obj, obj.split(":", 1)[0], obj.split(":", 1)[1], info.get("title"), info.get("description"), source, now, now, info.get("latest"),
                   1 if kind in ("manifest", "package") else 0, 0, None, info.get("status"), info.get("repo"), json.dumps(info.get("links") or {}), rec_id(obj)))
    else:
        sets, args = ["last_seen=?"], [now]
        for k in ("title", "description", "latest", "status", "repo"):
            if info.get(k) is not None:
                sets.append(f"{k}=?"); args.append(info[k])
        if kind in ("manifest", "package"):
            sets.append("versions=(SELECT count(DISTINCT version) FROM w_obs WHERE object=? AND kind=?)"); args += [obj, kind]
        if changed:
            sets.append("changes=changes+1"); sets.append("last_change=?"); args.append(now)
        c.execute(f"UPDATE w_objects SET {', '.join(sets)} WHERE id=?", (*args, obj))
    return cur.lastrowid


# ---------------------------------------------------------------- HTTP (public sources only)
class Blocked(Exception):
    pass


def public_host(host):
    """SSRF guard: every address the name resolves to must be a public unicast address."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise Blocked(f"dns: {e}")
    for inf in infos:
        ip = ipaddress.ip_address(inf[4][0].split("%")[0])
        if not ip.is_global or ip.is_multicast:
            raise Blocked(f"non-public address {ip}")
    return True


def fetch(url, data=None, headers=None, timeout=20, method=None, guard=False):
    """Returns (status, headers, body bytes). Bodies are capped; redirects are not followed for guarded (third-party) calls."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https":
        raise Blocked("https only")
    if guard:
        public_host(u.hostname or "")
    h = {"User-Agent": UA, "Accept": "application/json"}
    h.update(headers or {})
    rq = urllib.request.Request(url, data=data, headers=h, method=method or ("POST" if data is not None else "GET"))
    opener = urllib.request.build_opener(_NoRedirect) if guard else urllib.request.build_opener()
    try:
        with opener.open(rq, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(MAX_BODY + 1)[:MAX_BODY]
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read(65536) if e.fp else b"")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def get_json(url, timeout=30):
    st, _h, b = fetch(url, timeout=timeout)
    if st != 200:
        raise RuntimeError(f"{st} {url}")
    return json.loads(b)


# ---------------------------------------------------------------- source 1: the official MCP Registry
def _registry_info(entry):
    s = entry.get("server") or {}
    off = (entry.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
    return s, off


def ingest_entry(c, entry, now, live=False):
    """One registry entry (one server version) -> manifest / status observations, package queue, remote probe queue."""
    s, off = _registry_info(entry)
    name, ver = s.get("name"), str(s.get("version") or "")
    if not name or not ver:
        return 0
    obj = "mcp:" + name
    info = {"title": s.get("title"), "description": (s.get("description") or "")[:500], "repo": (s.get("repository") or {}).get("url"),
            "status": off.get("status"), "links": {"website": s.get("websiteUrl")}}
    if off.get("isLatest"):
        info["latest"] = ver
    meta = {k: off[k] for k in ("publishedAt", "updatedAt") if off.get(k)}
    n = 0
    if observe(c, obj, "manifest", ver, s, now, REGISTRY_SOURCE, meta=meta or None, info=info, news=live):
        n += 1
    st = off.get("status") or "active"
    prev = c.execute("SELECT body FROM w_obs WHERE object=? AND kind='status' AND version=? ORDER BY seq DESC LIMIT 1", (obj, ver)).fetchone()
    prev_st = json.loads(zlib.decompress(prev["body"]))["status"] if prev else ("active" if st == "active" else None)
    if st != prev_st and observe(c, obj, "status", ver, {"status": st, "changedAt": off.get("statusChangedAt")}, now, REGISTRY_SOURCE, info={"status": st}, news=live):
        n += 1
    for p in s.get("packages") or []:
        reg, ident, pv = (p.get("registryType") or "").lower(), p.get("identifier"), str(p.get("version") or "")
        if reg in ("npm", "pypi") and ident and pv and pv != "latest":
            c.execute("INSERT INTO w_queue(registry, identifier, version, mcp, added, latest, live) VALUES(?,?,?,?,?,?,?) "
                      "ON CONFLICT(registry, identifier, version) DO UPDATE SET latest=max(latest, excluded.latest)", (reg, ident, pv, name, now, 1 if off.get("isLatest") else 0, 1 if live else 0))
    if off.get("isLatest") and st == "active":
        for r in s.get("remotes") or []:
            url = r.get("url") or ""
            if r.get("type") == "streamable-http" and url.startswith("https://") and "{" not in url and len(url) < 400:
                c.execute("INSERT INTO w_probe(endpoint, object, version, next_at) VALUES(?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET object=excluded.object, version=excluded.version",
                          (url, obj, ver, now))
    return n


def crawl_registry(c, now, deadline, get=None, pause=None):
    """Full pass first (resumable through a stored cursor), then incremental passes with updated_since. Returns a summary."""
    get = get or get_json
    pause = PAGE_PAUSE_S if pause is None else pause
    since = state(c, "registry_since")            # set after the first complete pass
    cursor = state(c, "registry_cursor")
    started = state(c, "registry_pass_started") or str(now)
    set_state(c, "registry_pass_started", started)
    pages = entries = new = 0
    complete = False
    while go(deadline):
        q = {"limit": "100"}
        if cursor:
            q["cursor"] = cursor
        if since:
            q["updated_since"] = iso(int(since))
        d = get(f"{REGISTRY}/v0.1/servers?" + urllib.parse.urlencode(q))
        for e in d.get("servers") or []:
            entries += 1
            new += ingest_entry(c, e, now, live=bool(since))
        pages += 1
        cursor = (d.get("metadata") or {}).get("nextCursor")
        set_state(c, "registry_cursor", cursor)
        c.commit()
        if not cursor:
            complete = True
            break
        if pause:
            time.sleep(pause)
    if complete:
        set_state(c, "registry_since", int(started) - 900)      # 15 min overlap: an entry updated during the pass is read again
        set_state(c, "registry_pass_started", None)
        set_state(c, "registry_cursor", None)
        if not since:
            set_state(c, "registry_full_pass_at", now)
        c.commit()
    return {"pages": pages, "entries": entries, "new": new, "pass": "incremental" if since else "full", "complete": complete}


# ---------------------------------------------------------------- source 2: npm and PyPI artifacts the registry points to
def package_fact(registry, ident, version, get=None):
    get = get or get_json
    if registry == "npm":
        d = get(f"{NPM}/{urllib.parse.quote(ident, safe='@')}/{urllib.parse.quote(version)}")
        dist = d.get("dist") or {}
        return {"registry": "npm", "name": ident, "version": version, "integrity": dist.get("integrity"), "shasum": dist.get("shasum"),
                "tarball": dist.get("tarball")}
    d = get(f"{PYPI}/pypi/{urllib.parse.quote(ident)}/{urllib.parse.quote(version)}/json")
    files = sorted(({"filename": u.get("filename"), "sha256": (u.get("digests") or {}).get("sha256")} for u in d.get("urls") or []), key=lambda x: x["filename"] or "")
    return {"registry": "pypi", "name": ident, "version": version, "files": files}


def _parallel(fn, items):
    """Network calls in a few threads (I/O only); results come back in order for the single writer."""
    from concurrent.futures import ThreadPoolExecutor

    def safe(x):
        try:
            return x, fn(x), None
        except Exception as e:  # noqa: BLE001
            return x, None, e
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        return list(ex.map(safe, items))


def crawl_packages(c, now, deadline, get=None, limit=100000):
    done = new = failed = 0
    while go(deadline) and done + failed < limit:
        rows = c.execute("SELECT * FROM w_queue WHERE tries < 3 AND (added < ? OR tries = 0) ORDER BY latest DESC, tries, added LIMIT ?",
                         (now, min(WORKERS * 8, limit - done - failed))).fetchall()
        if not rows:
            break
        n0 = done + failed
        done, new, failed = _write_packages(c, now, _parallel(lambda q: package_fact(q["registry"], q["identifier"], q["version"], get), rows), done, new, failed)
        if done + failed == n0:
            break
    c.commit()
    return {"done": done, "new": new, "failed": failed, "queued": c.execute("SELECT count(*) FROM w_queue WHERE tries < 3").fetchone()[0]}


def _write_packages(c, now, results, done, new, failed):
    for q, fact, err in results:
        try:
            if err:
                raise err
            if observe(c, f"{q['registry']}:{q['identifier']}", "package", q["version"], fact, now, {"npm": "registry.npmjs.org", "pypi": "pypi.org"}[q["registry"]],
                       meta={"mcp": q["mcp"]}, info={"latest": q["version"], "links": {"mcp": q["mcp"]}}, news=bool(q["live"])):
                new += 1
            c.execute("DELETE FROM w_queue WHERE registry=? AND identifier=? AND version=?", (q["registry"], q["identifier"], q["version"]))
            done += 1
        except Exception as e:  # noqa: BLE001  a missing or unpublished version: tried three times, then left with its error
            c.execute("UPDATE w_queue SET tries=tries+1, error=? WHERE registry=? AND identifier=? AND version=?", (str(e)[:200], q["registry"], q["identifier"], q["version"]))
            c.execute("UPDATE w_queue SET added=? WHERE registry=? AND identifier=? AND version=?", (now, q["registry"], q["identifier"], q["version"]))
            failed += 1
    c.commit()
    return done, new, failed


# ---------------------------------------------------------------- source 3: tool descriptions of public remotes
def _rpc_body(raw, ctype):
    """A JSON-RPC answer from a JSON body or from the first `data:` event of an SSE stream that carries a result or error."""
    text = raw.decode("utf-8", "replace")
    if "text/event-stream" in (ctype or ""):
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    m = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if isinstance(m, dict) and ("result" in m or "error" in m):
                    return m
        raise RuntimeError("no JSON-RPC answer in the event stream")
    return json.loads(text)


def normalize_tools(tools):
    keep = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
    return sorted(({k: t[k] for k in keep if k in t} for t in tools if isinstance(t, dict)), key=lambda t: str(t.get("name")))


def list_tools(url, post=None, timeout=10):
    """MCP streamable HTTP: initialize -> notifications/initialized -> tools/list (paged). Returns the normalized tool list."""
    post = post or (lambda u, body, h: fetch(u, data=body, headers=h, timeout=timeout, guard=True))
    base = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "minimal-witness", "version": "1.0"}}}
    st, h, raw = post(url, json.dumps(init).encode(), base)
    if st in (401, 403):
        raise PermissionError(f"auth required ({st})")
    if st != 200:
        raise RuntimeError(f"initialize {st}")
    hl = {k.lower(): v for k, v in h.items()}
    ans = _rpc_body(raw, hl.get("content-type"))
    if "error" in ans:
        raise RuntimeError(f"initialize error {str(ans['error'])[:80]}")
    hdr = dict(base)
    if hl.get("mcp-session-id"):
        hdr["Mcp-Session-Id"] = hl["mcp-session-id"]
    hdr["MCP-Protocol-Version"] = (ans.get("result") or {}).get("protocolVersion") or PROTOCOL
    post(url, json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode(), hdr)
    tools, cursor = [], None
    for i in range(10):
        msg = {"jsonrpc": "2.0", "id": 2 + i, "method": "tools/list", "params": ({"cursor": cursor} if cursor else {})}
        st, h2, raw = post(url, json.dumps(msg).encode(), hdr)
        if st in (401, 403):
            raise PermissionError(f"auth required ({st})")
        if st != 200:
            raise RuntimeError(f"tools/list {st}")
        ans = _rpc_body(raw, {k.lower(): v for k, v in h2.items()}.get("content-type"))
        if "error" in ans:
            raise RuntimeError(f"tools/list error {str(ans['error'])[:80]}")
        res = ans.get("result") or {}
        tools += res.get("tools") or []
        cursor = res.get("nextCursor")
        if not cursor:
            break
    return normalize_tools(tools)


def probe_remotes(c, now, deadline, post=None, limit=None):
    ok = new = auth = failed = 0
    limit = limit or PROBES_PER_RUN
    while go(deadline) and ok + auth + failed < limit:
        rows = c.execute("SELECT * FROM w_probe WHERE next_at <= ? ORDER BY next_at LIMIT ?", (now, min(WORKERS * 4, limit - ok - auth - failed))).fetchall()
        if not rows:
            break
        for p, tools, err in _parallel(lambda p: list_tools(p["endpoint"], post), rows):
            ok, new, auth, failed = _write_probe(c, now, p, tools, err, ok, new, auth, failed)
        c.commit()
    return {"ok": ok, "new": new, "auth_required": auth, "failed": failed, "due": c.execute("SELECT count(*) FROM w_probe WHERE next_at <= ?", (now,)).fetchone()[0]}


def _write_probe(c, now, p, tools, err, ok, new, auth, failed):
    try:
        if err:
            raise err
        if observe(c, p["object"], "tools", p["version"], tools, now, "remote:" + urllib.parse.urlsplit(p["endpoint"]).hostname,
                   meta={"endpoint": p["endpoint"], "count": len(tools)}):
            new += 1
        c.execute("UPDATE w_probe SET next_at=?, fails=0, last_ok=?, error=NULL WHERE endpoint=?", (now + PROBE_EVERY_S, now, p["endpoint"]))
        ok += 1
    except PermissionError as e:   # a private server: not ours to read; look again in a week
        c.execute("UPDATE w_probe SET next_at=?, error=? WHERE endpoint=?", (now + 7 * 86400, str(e)[:200], p["endpoint"]))
        auth += 1
    except Exception as e:  # noqa: BLE001
        f = (p["fails"] or 0) + 1
        c.execute("UPDATE w_probe SET next_at=?, fails=?, error=? WHERE endpoint=?", (now + min(7 * 86400, 3600 * 2 ** f), f, f"{type(e).__name__}: {str(e)[:160]}", p["endpoint"]))
        failed += 1
    return ok, new, auth, failed


# ---------------------------------------------------------------- the hourly seal
def merkle_root(leaves):
    import notary
    return notary.merkle_root(leaves) if leaves else sha(b"")


def seal(c, now, sign=None):
    """All unsealed observations -> one batch: Merkle root, chained to the previous head, signed. Returns the batch or None."""
    rows = c.execute("SELECT seq, leaf FROM w_obs WHERE batch_id IS NULL ORDER BY seq").fetchall()
    if not rows:
        return None
    last = c.execute("SELECT seq, head FROM w_batches ORDER BY seq DESC LIMIT 1").fetchone()
    n = (last["seq"] + 1) if last else 1
    rec = {"v": 1, "id": f"wb_{n}", "sealed_at": iso(now), "n": len(rows), "first_seq": rows[0]["seq"], "last_seq": rows[-1]["seq"],
           "merkle_root": merkle_root([r["leaf"] for r in rows]), "prev_head": last["head"] if last else None,
           "leaf_rule": "leaf = sha256(canonical observation record); Merkle as notary.py (0x00 leaf, 0x01 node, odd node carried up)"}
    head = sha(rec)
    sig = None
    try:
        sig = json.dumps((sign or _sign)({"type": "witness_batch", "head": head, "record": rec}))
    except Exception as e:  # noqa: BLE001  the signer is down: the batch is sealed and anchored, the signature is added later
        log.warning("witness: sign %s later: %s", rec["id"], e)
    c.execute("INSERT INTO w_batches(seq, id, ts, n, first_seq, last_seq, root, prev_head, head, record, sig) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
              (n, rec["id"], now, rec["n"], rec["first_seq"], rec["last_seq"], rec["merkle_root"], rec["prev_head"], head, canon(rec).decode(), sig))
    c.execute("UPDATE w_obs SET batch_id=? WHERE batch_id IS NULL AND seq<=?", (rec["id"], rows[-1]["seq"]))
    c.commit()
    return {"id": rec["id"], "head": head, "n": rec["n"], "record": rec, "signed": bool(sig)}


def _sign(payload):
    import receipts
    return receipts.sign(payload)


def sign_pending(c, sign=None):
    n = 0
    for b in c.execute("SELECT id, head, record FROM w_batches WHERE sig IS NULL ORDER BY seq LIMIT 50").fetchall():
        try:
            sig = (sign or _sign)({"type": "witness_batch", "head": b["head"], "record": json.loads(b["record"])})
            c.execute("UPDATE w_batches SET sig=? WHERE id=?", (json.dumps(sig), b["id"]))
            n += 1
        except Exception:  # noqa: BLE001
            break
    c.commit()
    return n


def default_adapters():
    import anchors
    return {"opentimestamps": lambda h: anchors.ots_submit(h),
            "rfc3161": lambda h: anchors.tsa_stamp(h),
            "rekor": lambda h: anchors.rekor_upload(h, key=anchors.rekor_key(path=REKOR_KEY))}


def anchor_batches(c, now, adapters=None, upgrade=None, limit=6):
    """Every batch head without a proof of each kind (or with a failed one) is submitted; pending OpenTimestamps proofs are upgraded."""
    ad = adapters if adapters is not None else default_adapters()
    out = {}
    for kind, fn in ad.items():
        rows = c.execute("SELECT b.id, b.head FROM w_batches b LEFT JOIN w_proofs p ON p.batch_id=b.id AND p.kind=? "
                         "WHERE p.batch_id IS NULL OR p.status='failed' ORDER BY b.seq DESC LIMIT ?", (kind, limit)).fetchall()
        for b in rows:
            try:
                status, proof, meta = fn(b["head"])
                c.execute("INSERT OR REPLACE INTO w_proofs VALUES(?,?,?,?,?,?,NULL)", (b["id"], kind, now, status, proof, json.dumps(meta, default=str)))
                out[f"{b['id']}:{kind}"] = status
            except Exception as e:  # noqa: BLE001
                c.execute("INSERT OR REPLACE INTO w_proofs VALUES(?,?,?,?,?,?,?)", (b["id"], kind, now, "failed", "", "{}", f"{type(e).__name__}: {str(e)[:250]}"))
                out[f"{b['id']}:{kind}"] = "failed"
        c.commit()
    if upgrade is None:
        import anchors
        upgrade = anchors.ots_upgrade
    for r in c.execute("SELECT batch_id, proof FROM w_proofs WHERE kind='opentimestamps' AND status='pending' AND ts < ? ORDER BY ts LIMIT 24", (now - 3 * 3600,)).fetchall():
        try:
            status, proof, meta = upgrade(r["proof"])
            if status == "attested":
                c.execute("UPDATE w_proofs SET status=?, proof=?, meta=?, ts=? WHERE batch_id=? AND kind='opentimestamps'", (status, proof, json.dumps(meta), now, r["batch_id"]))
                out[f"{r['batch_id']}:ots_upgrade"] = "attested"
        except Exception:  # noqa: BLE001  not in a Bitcoin block yet
            pass
    c.commit()
    return out


def publish_head(batch, main_db=None):
    """The latest head goes into the main database, where the daily anchor batch (anchors.heads) takes it to TON and EAS."""
    m = sqlite3.connect(main_db or MAIN_DB, timeout=30)
    try:
        m.execute("CREATE TABLE IF NOT EXISTS witness_heads(seq INTEGER PRIMARY KEY AUTOINCREMENT, batch_id TEXT UNIQUE, head TEXT, ts INTEGER)")
        m.execute("INSERT OR IGNORE INTO witness_heads(batch_id, head, ts) VALUES(?,?,?)", (batch["id"], batch["head"], int(time.time())))
        m.commit()
    finally:
        m.close()


# ---------------------------------------------------------------- ATT: attestations of other logs and services
def _main(main_db=None):
    m = sqlite3.connect(main_db or MAIN_DB, timeout=30)
    m.row_factory = sqlite3.Row
    import attest
    attest.migrate(m)
    return m


def _record_att(c, obj, kind, version, env, ts, source, att_id):
    seq = observe(c, obj, kind, version, env, ts, source, meta={"record_type": env["record_type"], "attestation": att_id},
                  info={"title": env.get("subject")}, news=False)
    if seq is None:   # the same envelope was recorded before (a retry): point at that observation
        r = c.execute("SELECT seq FROM w_obs WHERE object=? AND kind=? AND version=? AND digest=?", (obj, kind, version, sha(env))).fetchone()
        seq = r["seq"] if r else None
    return seq


def drain_attestations(c, now, main_db=None, limit=5000):
    """Writers' attestations accepted by the gateway (status received) become observations of this record, so the next seal
    and its anchors cover them. Quarantined ones older than 7 days are dropped (rejected)."""
    m = _main(main_db)
    n = 0
    try:
        m.execute("UPDATE attestations SET status='rejected' WHERE status='quarantined' AND created<?", (now - 7 * 86400,))
        rows = m.execute("SELECT * FROM attestations WHERE status='received' ORDER BY created LIMIT ?", (limit,)).fetchall()
        for r in rows:
            env = json.loads(r["envelope"])
            seq = _record_att(c, r["w_object"], r["payload_type"], r["w_version"], env, r["created"], r["writer"], r["id"])
            c.commit()
            m.execute("UPDATE attestations SET status='recorded', w_seq=? WHERE id=? AND status='received'", (seq, r["id"]))
            m.commit()
            n += 1
    finally:
        m.close()
    return {"recorded": n}


def read_logs(c, now, get=None, main_db=None, logs=None):
    """Read mode: the signed head of every configured public log, verified with its pinned key and recorded as an observation;
    consistency with the previous head is checked where the log serves proofs."""
    import att_logs
    import attest
    import attest_formats as AF
    get = get or (lambda u: fetch(u, guard=True, timeout=20))
    out = {}
    m = _main(main_db)
    try:
        for lg in (logs if logs is not None else att_logs.LOGS):
            try:
                st, _h, body = get(lg["head_url"])
                if st != 200:
                    raise RuntimeError(f"head {st}")
                tree_id = None
                if lg["format"] == "rekor_v1":
                    d = json.loads(body)
                    note, tree_id = d["signedTreeHead"], str(d.get("treeID") or "")
                else:
                    note = body.decode("utf-8")
                head = AF.verify_note(note, lg["key"])
                cons = {"status": "not_available"}
                prev = state(c, "att_head:" + lg["id"])
                prev = json.loads(prev) if prev else None
                if prev and prev["origin"] == head["origin"] and prev["tree_size"] < head["tree_size"] and lg.get("proof_url") and tree_id:
                    st2, _h2, pb = get(lg["proof_url"].format(first=prev["tree_size"], second=head["tree_size"], tree_id=tree_id))
                    proof = json.loads(pb) if st2 == 200 else None
                    if proof is not None and AF.verify_consistency(prev["tree_size"], head["tree_size"], prev["root_hash"], head["root_hash"], proof.get("hashes") or []):
                        cons = {"status": "verified", "from_tree_size": prev["tree_size"], "from_root_hash": prev["root_hash"], "proof": proof.get("hashes") or []}
                    elif proof is not None:
                        # a private notice first, with a right of reply; nothing about it enters the public record now
                        cons = {"status": "diverged", "proof": proof}
                    else:
                        cons = {"status": "proof_unavailable"}
                elif prev and prev["origin"] != head["origin"]:
                    cons = {"status": "new_origin", "previous_origin": prev["origin"]}
                elif prev and prev["tree_size"] == head["tree_size"]:
                    cons = {"status": "same_head"} if prev["root_hash"] == head["root_hash"] else {"status": "diverged", "proof": None}
                elif prev and prev["tree_size"] > head["tree_size"]:
                    cons = {"status": "diverged", "proof": None}   # a log never shrinks
                if cons["status"] == "diverged":
                    # a private notice first, with a 72-hour right of reply; this head stays out of the public record for now
                    m.execute("INSERT INTO att_divergences(ts, log, from_size, to_size, detail, publish_after) VALUES(?,?,?,?,?,?)",
                              (now, lg["id"], prev["tree_size"], head["tree_size"],
                               json.dumps({"from": prev, "to": head, "note": note, "proof": cons["proof"]}, default=str)[:20000], now + 72 * 3600))
                    m.commit()
                    out[lg["id"]] = {"tree_size": head["tree_size"], "consistency": "held: private notice"}
                    continue
                aid = f"att_obs_{hashlib.sha256((lg['id'] + head['origin'] + str(head['tree_size'])).encode()).hexdigest()[:16]}"
                env = {"v": 1, "type": "attestation", "id": aid, "record_type": "observation", "writer": "minimalcult", "writer_identity": "minimalcult.org",
                       "subject": head["origin"], "payload_type": "checkpoint", "payload_sha256": AF.sha256_hex(note.encode("utf-8")), "payload": note,
                       "verified": {"check": "signed_note", "origin": head["origin"], "tree_size": head["tree_size"], "root_hash": head["root_hash"],
                                    "log_key": lg["key"], "log_key_id": head["key_id"], "log_key_source": "pinned (att_logs.py)"},
                       "consistency": cons, "log": lg["id"], "fields": None, "received_at": iso(now)}
                obj = attest.subject_key(lg["id"])
                seq = _record_att(c, obj, "checkpoint", str(head["tree_size"]), env, now, "minimalcult.org", aid)
                c.commit()
                m.execute("INSERT OR IGNORE INTO attestations(id, created, writer, client_operation_id, subject, payload_type, payload_sha256, status, envelope, "
                          "w_object, w_version, w_seq) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                          (aid, now, "minimalcult", None, head["origin"], "checkpoint", env["payload_sha256"], "recorded", json.dumps(env, sort_keys=True), obj,
                           str(head["tree_size"]), seq))
                m.commit()
                set_state(c, "att_head:" + lg["id"], json.dumps({"origin": head["origin"], "tree_size": head["tree_size"], "root_hash": head["root_hash"]}))
                c.commit()
                out[lg["id"]] = {"tree_size": head["tree_size"], "consistency": cons["status"]}
            except Exception as e:  # noqa: BLE001  one log failing never stops the others or the record
                out[lg["id"]] = {"error": f"{type(e).__name__}: {str(e)[:160]}"}
    finally:
        m.close()
    return out


# ---------------------------------------------------------------- CAP-1: capacity, measured every hour (read only)
DATA_DIR = os.environ.get("WITNESS_DATA_DIR", os.path.dirname(os.path.abspath(WITNESS_DB)) or ".")


def _size(path):
    return sum(os.path.getsize(path + ext) for ext in ("", "-wal", "-shm") if os.path.exists(path + ext))


def _meminfo():
    out = {}
    try:
        for line in open("/proc/meminfo"):
            k, v = line.split(":", 1)
            out[k] = int(v.split()[0]) * 1024
    except (OSError, ValueError):
        pass
    return out


def _cgroup_mem():
    for p in ("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.usage_in_bytes"):
        try:
            return int(open(p).read().strip())
        except (OSError, ValueError):
            continue
    return None


def capacity_sample(c, now, cycle_s=None):
    """One hourly reading: sizes and growth inputs, host disk and memory, load, this service's memory, cycle time, coverage."""
    db_path = c.execute("PRAGMA database_list").fetchone()[2] or WITNESS_DB
    data_dir = os.environ.get("WITNESS_DATA_DIR") or os.path.dirname(os.path.abspath(db_path))
    st = os.statvfs(data_dir)
    mem = _meminfo()
    data_bytes = 0
    for f in os.listdir(data_dir):
        fp = os.path.join(data_dir, f)
        if os.path.isfile(fp):
            data_bytes += os.path.getsize(fp)
    backup = {}
    try:
        backup = json.load(open(os.path.join(data_dir, "backup_last.json")))
    except (OSError, ValueError):
        pass
    try:
        load1 = float(open("/proc/loadavg").read().split()[0])
    except (OSError, ValueError, IndexError):
        load1 = None
    n = {r["key"]: r["n"] for r in c.execute("SELECT key, n FROM w_count").fetchall()}
    smp = {"ts": now, "cycle_s": cycle_s, "witness_db_bytes": _size(db_path), "data_dir_bytes": data_bytes,
           "backup_archive_bytes": backup.get("bytes"), "backups_kept": backup.get("kept"),
           "disk_total": st.f_blocks * st.f_frsize, "disk_free": st.f_bavail * st.f_frsize,
           "mem_total": mem.get("MemTotal"), "mem_available": mem.get("MemAvailable"), "swap_free": mem.get("SwapFree"),
           "load1": load1, "cpus": os.cpu_count(), "service_mem": _cgroup_mem(),
           "objects": {k.split(":", 1)[1]: v for k, v in n.items() if k.startswith("objects:")},
           "observations": {k.split(":", 1)[1]: v for k, v in n.items() if k.startswith("obs:")},
           "queue_packages": c.execute("SELECT count(*) FROM w_queue WHERE tries < 3").fetchone()[0],
           "probes_due": c.execute("SELECT count(*) FROM w_probe WHERE next_at <= ?", (now,)).fetchone()[0],
           "probe_endpoints": c.execute("SELECT count(*) FROM w_probe").fetchone()[0]}
    c.execute("INSERT OR REPLACE INTO w_capacity(ts, sample) VALUES(?,?)", (now, json.dumps(smp)))
    c.commit()
    return smp


def capacity_forecast(c, scale=(1, 5)):
    """Growth per day from the samples (first vs last, at least 6 h apart) -> days of headroom per resource, at the current
    coverage and at x5. Disk counts the record, the rest of /data and the backup archives (kept copies of the record)."""
    rows = [json.loads(r["sample"]) for r in c.execute("SELECT sample FROM w_capacity ORDER BY ts").fetchall()]
    if len(rows) < 2 or rows[-1]["ts"] - rows[0]["ts"] < 6 * 3600:
        return {"status": "collecting", "samples": len(rows), "hours": round((rows[-1]["ts"] - rows[0]["ts"]) / 3600, 1) if rows else 0}
    a, b = rows[0], rows[-1]
    days = (b["ts"] - a["ts"]) / 86400
    db_day = max(0, (b["witness_db_bytes"] - a["witness_db_bytes"]) / days)
    data_day = max(0, (b["data_dir_bytes"] - a["data_dir_bytes"]) / days)
    kept = b.get("backups_kept") or 0
    archive_ratio = (b["backup_archive_bytes"] / b["data_dir_bytes"]) if b.get("backup_archive_bytes") and b["data_dir_bytes"] else 0.5
    disk_day = data_day * (1 + archive_ratio * kept)            # every kept archive grows with the data it copies
    used = b["disk_total"] - b["disk_free"]
    out = {"status": "forecast", "samples": len(rows), "hours": round(days * 24, 1), "witness_db_gb": round(b["witness_db_bytes"] / 1e9, 2),
           "witness_db_growth_mb_day": round(db_day / 1e6, 1), "disk_growth_mb_day": round(disk_day / 1e6, 1),
           "disk_used_pct": round(100 * used / b["disk_total"], 1),
           "mem_used_pct": round(100 * (1 - (b["mem_available"] or 0) / b["mem_total"]), 1) if b.get("mem_total") else None,
           "cycle_max_s": max((r.get("cycle_s") or 0) for r in rows), "by_scale": {}}
    for k in scale:
        g = disk_day * k
        to70 = (0.7 * b["disk_total"] - used) / g if g else None
        out["by_scale"][f"x{k}"] = {"disk_growth_mb_day": round(g / 1e6, 1),
                                    "days_to_disk_70pct": None if to70 is None else max(0, round(to70)),
                                    "disk_at_30_90_365_days_pct": [round(100 * (used + g * d) / b["disk_total"], 1) for d in (30, 90, 365)],
                                    "cycle_s_estimate": round(out["cycle_max_s"] * k)}
    first = []
    x5 = out["by_scale"].get("x5") or {}
    if x5.get("cycle_s_estimate", 0) > 3000:
        first.append("hourly cycle time at x5 coverage (crawl would no longer fit the hour)")
    if x5.get("days_to_disk_70pct") is not None and x5["days_to_disk_70pct"] < 365:
        first.append(f"disk at x5 coverage in {x5['days_to_disk_70pct']} days")
    if out["mem_used_pct"] and out["mem_used_pct"] > 60:
        first.append("host memory (2 GB shared by all services)")
    out["first_limit"] = first or ["none within a year at x5"]
    d1 = out["by_scale"]["x1"]["days_to_disk_70pct"]
    out["move_needed"] = d1 is not None and d1 < 30          # CAP-2 trigger: less than 30 days of headroom
    return out


def run_once(c, now=None, budget=None, get=None, post=None, adapters=None, upgrade=None, sign=None, main_db=None, logs_get=None):
    """One hourly run: read the sources within the time budget, record the run itself, seal, anchor, publish the head."""
    now = now or int(time.time())
    deadline = time.time() + (RUN_BUDGET_S if budget is None else budget)
    summary = {"started_at": iso(now)}
    for name, fn in (("registry", lambda: crawl_registry(c, now, deadline, get)),
                     ("packages", lambda: crawl_packages(c, now, deadline, get)),
                     ("remotes", lambda: probe_remotes(c, now, deadline, post)),
                     ("logs", lambda: read_logs(c, now, get=logs_get, main_db=main_db) if (logs_get or get is None) else {"skipped": "sources injected"}),
                     ("attestations", lambda: drain_attestations(c, int(time.time()), main_db))):
        try:
            summary[name] = fn()
        except Exception as e:  # noqa: BLE001  one failing source never stops the record of the others
            summary[name] = {"error": f"{type(e).__name__}: {str(e)[:200]}"}
            c.commit()
    summary["finished_at"] = iso(int(time.time()))
    try:
        capacity_sample(c, now, cycle_s=round(time.time() - (deadline - (RUN_BUDGET_S if budget is None else budget)), 1))
    except Exception as e:  # noqa: BLE001  a measurement never stops the record
        summary["capacity"] = f"failed: {e}"
    if STOP["now"]:
        summary["stopped_early"] = True
    observe(c, "witness:crawler", "run", summary["started_at"], summary, now, "minimalcult.org/witness")
    c.commit()
    return _finish(c, now, summary, sign=sign, adapters=adapters, upgrade=upgrade, main_db=main_db)


def recover(c, now=None, **kw):
    """At start: facts written by a run that was stopped before its seal are sealed at once (with a run record saying so),
    so a restart never leaves an hour without a seal."""
    if not c.execute("SELECT 1 FROM w_obs WHERE batch_id IS NULL LIMIT 1").fetchone():
        return None
    now = now or int(time.time())
    observe(c, "witness:crawler", "run", iso(now) + "/recovered", {"recovered": True, "note": "facts of an interrupted run, sealed at restart",
                                                                   "unsealed": c.execute("SELECT count(*) FROM w_obs WHERE batch_id IS NULL").fetchone()[0]},
            now, "minimalcult.org/witness")
    c.commit()
    return _finish(c, now, {"recovered": True}, **kw)


def _finish(c, now, summary, sign=None, adapters=None, upgrade=None, main_db=None):
    b = seal(c, now, sign)
    sign_pending(c, sign)
    summary["batch"] = b and {k: b[k] for k in ("id", "head", "n", "signed")}
    try:
        summary["anchors"] = anchor_batches(c, now, adapters, upgrade)
    except Exception as e:  # noqa: BLE001
        summary["anchors"] = {"error": str(e)[:200]}
    if b:
        try:
            publish_head(b, main_db)
        except Exception as e:  # noqa: BLE001
            summary["head_published"] = f"failed: {e}"
    return summary


def dispatch_loop(every=60):
    """MON: delivery runs beside the crawl, once a minute — events for a sealed hour go out within a minute of the seal,
    and retries keep their schedule even while a long crawl runs or after a restart."""
    import monitors
    while not STOP["now"]:
        try:
            c = connect()
            d = monitors.dispatch(MAIN_DB, c)
            c.close()
            if d["events"] or d["delivered"] or d["failed"]:
                log.info("monitors: %s", d)
        except Exception as e:  # noqa: BLE001
            log.warning("monitors: %s", e)
        for _ in range(every // 2):
            if STOP["now"]:
                break
            time.sleep(2)


def main():
    import signal
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    signal.signal(signal.SIGTERM, lambda *_: STOP.update(now=True))
    try:
        os.nice(int(os.environ.get("WITNESS_NICE", "10")))   # CAP-1: one shared vCPU; the site, bots and signer come first
    except OSError:
        pass
    import threading
    threading.Thread(target=dispatch_loop, name="monitors", daemon=True).start()
    try:
        c = connect()
        r = recover(c)
        c.close()
        if r:
            log.info("witness recovered: %s", json.dumps(r, default=str)[:800])
    except Exception as e:  # noqa: BLE001
        log.exception("witness recover failed: %s", e)
    while not STOP["now"]:
        start = time.time()
        try:
            c = connect()
            s = run_once(c)
            c.close()
            log.info("witness run: %s", json.dumps(s, default=str)[:1500])
        except Exception as e:  # noqa: BLE001
            log.exception("witness run failed: %s", e)
        while not STOP["now"] and time.time() - start < 3600:
            time.sleep(2)
    log.info("witness: stopped after sealing")


def sensors(now, path=None, data_dir=None):
    """CAP-1 alarms for nerves.sensors (importance 8 wakes the owner): disk or memory at 70%, an hour without a seal,
    an anchor that failed on a sealed batch. Reads the record without writing. WITNESS_SENSORS=0 turns them off (tests of
    other sensors must not depend on the disk and memory of the machine they run on)."""
    out = []
    if os.environ.get("WITNESS_SENSORS", "1") != "1":
        return out
    try:
        st = os.statvfs(data_dir or DATA_DIR)
        used = 1 - st.f_bavail / st.f_blocks
        if used >= 0.70:
            out.append(("witness_disk", 8, f"диск сервера занят на {used:.0%} — запись свидетеля упрётся; план переезда CAP-2 в docs/ops/CAPACITY.md", "/witness"))
    except OSError:
        pass
    mem = _meminfo()
    if mem.get("MemTotal") and mem.get("MemAvailable") is not None:
        mu = 1 - mem["MemAvailable"] / mem["MemTotal"]
        if mu >= 0.70:
            out.append(("witness_memory", 8, f"память сервера занята на {mu:.0%}", "/status"))
    c = open_ro(path)
    if c is None:
        return out
    try:
        if not c.execute("SELECT 1 FROM sqlite_master WHERE name='w_batches'").fetchone():
            return out
        last = c.execute("SELECT id, ts FROM w_batches ORDER BY seq DESC LIMIT 1").fetchone()
        first_obs = c.execute("SELECT value FROM w_state WHERE key='first_observed'").fetchone()
        started = int(first_obs[0]) if first_obs and first_obs[0] else None
        if (last and now - last["ts"] > 75 * 60) or (not last and started and now - started > 75 * 60):
            ago = int((now - (last["ts"] if last else started)) / 60)
            out.append(("witness_seal_missed", 8, f"свидетель не запечатал час: последняя печать {ago} мин назад", "/witness"))
        for b in c.execute("SELECT id, ts FROM w_batches WHERE ts < ? ORDER BY seq DESC LIMIT 3", (now - 600,)).fetchall():
            bad = [r[0] for r in c.execute("SELECT kind FROM w_proofs WHERE batch_id=? AND status='failed'", (b["id"],)).fetchall()]
            if bad:
                out.append(("witness_anchor_failed", 8, f"якорь не лёг для пачки {b['id']}: {', '.join(bad)} (повтор идёт каждый час)", "/v1/witness/batches"))
                break
    finally:
        c.close()
    return out


# ---------------------------------------------------------------- reading (gateway: API and pages)
def flatten(obj, prefix=""):
    out = {}
    if isinstance(obj, dict):
        for k in sorted(obj):
            out.update(flatten(obj[k], f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        if not obj:
            out[prefix] = []
        for i, v in enumerate(obj):
            out.update(flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = obj
    return out


def diff(a, b):
    """Field-level difference between two recorded bodies: added, removed, changed paths with old and new values."""
    fa, fb = flatten(a or {}), flatten(b or {})
    out = []
    for k in sorted(set(fa) | set(fb)):
        if k not in fa:
            out.append({"path": k, "op": "added", "new": fb[k]})
        elif k not in fb:
            out.append({"path": k, "op": "removed", "old": fa[k]})
        elif fa[k] != fb[k]:
            out.append({"path": k, "op": "changed", "old": fa[k], "new": fb[k]})
    return out


def tool_diff(a, b):
    """For tool lists: which tools appeared, disappeared, or changed their description or schema (by tool name)."""
    ia = {t.get("name"): t for t in a or []}
    ib = {t.get("name"): t for t in b or []}
    out = []
    for n in sorted(set(ia) | set(ib), key=str):
        if n not in ia:
            out.append({"tool": n, "op": "added"})
        elif n not in ib:
            out.append({"tool": n, "op": "removed"})
        else:
            for f in ("description", "inputSchema", "outputSchema", "annotations", "title"):
                if ia[n].get(f) != ib[n].get(f):
                    out.append({"tool": n, "op": "changed", "field": f, "old": ia[n].get(f), "new": ib[n].get(f)})
    return out


def open_ro(path=None):
    p = path or WITNESS_DB
    if not os.path.exists(p):
        return None
    c = sqlite3.connect(p, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def obs_view(r, with_body=False):
    rec = json.loads(r["record"])
    out = {"seq": r["seq"], "object": r["object"], "kind": r["kind"], "version": r["version"], "observed_at": rec["observed_at"], "digest": r["digest"],
           "prev": r["prev"], "leaf": r["leaf"], "batch": r["batch_id"], "meta": rec.get("meta")}
    if with_body:
        out["body"] = body_of(r)
    return out


def stats(c):
    """From the counters kept at write time (constant time); a record without counters is counted the slow way."""
    if c.execute("SELECT 1 FROM sqlite_master WHERE name='w_count'").fetchone() and c.execute("SELECT 1 FROM w_count LIMIT 1").fetchone():
        n = {r["key"]: r["n"] for r in c.execute("SELECT key, n FROM w_count").fetchall()}
        first = state(c, "first_observed")
        last_b = c.execute("SELECT id, ts, head, n FROM w_batches ORDER BY seq DESC LIMIT 1").fetchone()
        return {"objects": n.get("objects:mcp", 0) + n.get("objects:npm", 0) + n.get("objects:pypi", 0),
                "mcp_servers": n.get("objects:mcp", 0), "packages": n.get("objects:npm", 0) + n.get("objects:pypi", 0),
                "observations": sum(v for k, v in n.items() if k.startswith("obs:") and k != "obs:run"),
                "tool_lists": n.get("obs:tools", 0), "changes": n.get("changes", 0),
                "batches": c.execute("SELECT count(*) FROM w_batches").fetchone()[0],
                "recording_since": iso(int(first)) if first else None, "hours_recorded": c.execute("SELECT count(*) FROM w_batches").fetchone()[0],
                "last_batch": dict(last_b) if last_b else None, "registry_full_pass": state(c, "registry_full_pass_at") is not None}
    q = lambda sql, *a: c.execute(sql, a).fetchone()[0]
    first = q("SELECT min(observed_at) FROM w_obs")
    last_b = c.execute("SELECT id, ts, head, n FROM w_batches ORDER BY seq DESC LIMIT 1").fetchone()
    return {"objects": q("SELECT count(*) FROM w_objects WHERE kind!='witness'"),
            "mcp_servers": q("SELECT count(*) FROM w_objects WHERE kind='mcp'"),
            "packages": q("SELECT count(*) FROM w_objects WHERE kind IN ('npm','pypi')"),
            "observations": q("SELECT count(*) FROM w_obs WHERE kind!='run'"),
            "tool_lists": q("SELECT count(*) FROM w_obs WHERE kind='tools'"),
            "changes": q("SELECT coalesce(sum(changes),0) FROM w_objects"),
            "batches": q("SELECT count(*) FROM w_batches"),
            "recording_since": iso(first) if first else None,
            "hours_recorded": q("SELECT count(*) FROM w_obs WHERE kind='run'"),
            "last_batch": dict(last_b) if last_b else None,
            "registry_full_pass": bool(q("SELECT count(*) FROM w_state WHERE key='registry_full_pass_at'"))}


def history(c, obj, limit=200):
    o = c.execute("SELECT * FROM w_objects WHERE id=?", (obj,)).fetchone()
    if not o:
        return None
    rows = c.execute("SELECT * FROM w_obs WHERE object=? ORDER BY seq DESC LIMIT ?", (obj, limit)).fetchall()
    od = dict(o)
    od["links"] = json.loads(od.get("links") or "{}")
    for k in ("first_seen", "last_seen", "last_change"):
        od[k] = iso(od[k]) if od.get(k) else None
    related = [dict(r) for r in c.execute("SELECT id, latest, versions, changes FROM w_objects WHERE links LIKE ? AND id!=? LIMIT 20",
                                          (f'%"mcp": "{obj[4:]}"%', obj)).fetchall()] if obj.startswith("mcp:") else []
    return {"object": od, "observations": [obs_view(r) for r in rows], "packages": related}


def obs_diff(c, seq, against=None):
    """The observation `seq` against `against` (default: the previous observation of the same object and kind)."""
    r = c.execute("SELECT * FROM w_obs WHERE seq=?", (seq,)).fetchone()
    if not r:
        return None
    if against:
        p = c.execute("SELECT * FROM w_obs WHERE seq=? AND object=? AND kind=?", (against, r["object"], r["kind"])).fetchone()
    else:
        p = c.execute("SELECT * FROM w_obs WHERE object=? AND kind=? AND seq<? ORDER BY seq DESC LIMIT 1", (r["object"], r["kind"], seq)).fetchone()
    a, b = (body_of(p) if p else None), body_of(r)
    d = tool_diff(a, b) if r["kind"] == "tools" else diff(a, b)
    return {"object": r["object"], "kind": r["kind"], "from": obs_view(p) if p else None, "to": obs_view(r), "changes": d}


def proof(c, seq):
    import notary
    r = c.execute("SELECT * FROM w_obs WHERE seq=?", (seq,)).fetchone()
    if not r:
        return None
    out = {"observation": json.loads(r["record"]), "leaf": r["leaf"], "body_sha256": r["digest"], "batch": None}
    if r["batch_id"]:
        b = c.execute("SELECT * FROM w_batches WHERE id=?", (r["batch_id"],)).fetchone()
        leaves = [x["leaf"] for x in c.execute("SELECT leaf FROM w_obs WHERE batch_id=? ORDER BY seq", (b["id"],)).fetchall()]
        out["merkle_path"] = notary.merkle_proof(leaves, leaves.index(r["leaf"]))
        out["batch"] = {"record": json.loads(b["record"]), "head": b["head"], "signature": json.loads(b["sig"]) if b["sig"] else None,
                        "anchors": anchors_of(c, b["id"])}
    out["how_to_verify"] = [
        "leaf = sha256(canonical JSON of `observation`: keys sorted, no spaces, UTF-8) — equals `leaf`",
        "body_sha256 = sha256(canonical JSON of the recorded body) — GET /v1/witness/observation?seq=N&body=1",
        "fold `merkle_path` from sha256(0x00||leaf): sibling on side L -> sha256(0x01||sibling||acc), side R -> sha256(0x01||acc||sibling); result = batch.record.merkle_root",
        "head = sha256(canonical JSON of batch.record) — equals batch.head; batch.signature is the hybrid gateway signature: Ed25519 over the record "
        "without 'sig', ML-DSA-65 (FIPS 204) in `pq` over the record without 'sig' and 'pq' (keys: /.well-known/minimalai.json)",
        "each anchor fixes the 32 head bytes: OpenTimestamps (`ots verify`), RFC 3161 (`openssl ts -verify`), Sigstore Rekor (entry hash = sha256 of the head bytes); the daily batch at /v1/anchors adds TON and EAS"]
    return out


# ---------------------------------------------------------------- Point-in-Time (PIT): the record as it stood at a moment
STATE_KINDS = ("manifest", "status", "package", "tools")


def parse_time(v):
    """RFC 3339 (2026-11-04T21:00:00Z, offsets allowed) or unix seconds -> int seconds; ValueError otherwise."""
    import datetime
    v = str(v).strip()
    if v.isdigit():
        return int(v)
    d = datetime.datetime.fromisoformat(v.replace("Z", "+00:00"))
    if d.tzinfo is None:
        raise ValueError("as_of needs a time zone (use Z for UTC)")
    return int(d.timestamp())


def state_at(c, obj, as_of):
    """What the record held about `obj` at `as_of`: the latest fact of each kind observed at or before it, the versions known,
    and which of those facts were already sealed by then. None when the object was first observed after `as_of`."""
    first = c.execute("SELECT min(observed_at) FROM w_obs WHERE object=?", (obj,)).fetchone()[0]
    if first is None or first > as_of:
        return {"on_record": False, "first_observed_at": iso(first) if first else None}
    facts = {}
    for k in STATE_KINDS:
        r = c.execute("SELECT * FROM w_obs WHERE object=? AND kind=? AND observed_at<=? ORDER BY seq DESC LIMIT 1", (obj, k, as_of)).fetchone()
        if r:
            facts[k] = r
    versions = [r[0] for r in c.execute("SELECT DISTINCT version FROM w_obs WHERE object=? AND kind IN ('manifest','package') AND observed_at<=? ORDER BY seq",
                                        (obj, as_of)).fetchall()]
    sealed_upto = c.execute("SELECT max(ts) FROM w_batches WHERE ts<=?", (as_of,)).fetchone()[0]
    return {"on_record": True, "first_observed_at": iso(first), "facts": facts, "versions": versions,
            "latest_version": facts["manifest"]["version"] if "manifest" in facts else (facts["package"]["version"] if "package" in facts else None),
            "registry_status": (body_of(facts["status"]) or {}).get("status") if "status" in facts else ("active" if "manifest" in facts else None),
            "last_seal_before": iso(sealed_upto) if sealed_upto else None}


def fact_proof(c, r, cache=None):
    """Everything needed to check one fact without us: the observation, its leaf, the Merkle path, the batch record, its head,
    signature and anchors. A fact not sealed yet has no batch (sealed within the hour). `cache` keeps a batch's leaves
    between facts of one statement (the first batch holds the whole backfill)."""
    import notary
    out = {"observation": json.loads(r["record"]), "leaf": r["leaf"], "batch": None}
    if r["batch_id"]:
        b = c.execute("SELECT * FROM w_batches WHERE id=?", (r["batch_id"],)).fetchone()
        cache = {} if cache is None else cache
        if b["id"] not in cache:
            cache[b["id"]] = [x["leaf"] for x in c.execute("SELECT leaf FROM w_obs WHERE batch_id=? ORDER BY seq", (b["id"],)).fetchall()]
        leaves = cache[b["id"]]
        out["merkle_path"] = notary.merkle_proof(leaves, leaves.index(r["leaf"]))
        out["batch"] = {"id": b["id"], "record": json.loads(b["record"]), "head": b["head"], "signature": json.loads(b["sig"]) if b["sig"] else None,
                        "anchors": anchors_of(c, b["id"])}
    return out


def anchors_of(c, batch_id):
    return {p["kind"]: {"status": p["status"], **json.loads(p["meta"] or "{}"), "error": p["error"], "proof_url": f"/v1/witness/anchor/{batch_id}/{p['kind']}"}
            for p in c.execute("SELECT kind, status, meta, error FROM w_proofs WHERE batch_id=?", (batch_id,)).fetchall()}


def search(c, name=None, q=None, kind=None, order="change", limit=50, offset=0):
    where, args = ["kind!='witness'"], []
    if name:
        where.append("id IN (?,?,?,?) OR name=?"); args += [name, "mcp:" + name, "npm:" + name, "pypi:" + name, name]
    if q:
        where.append("(name LIKE ? OR title LIKE ? OR description LIKE ?)"); args += [f"%{q}%"] * 3
    if kind:
        where.append("kind=?"); args.append(kind)
    ob = {"change": "coalesce(last_change, 0) DESC, first_seen DESC", "new": "first_seen DESC", "name": "name"}.get(order, "name")
    rows = c.execute(f"SELECT * FROM w_objects WHERE {' AND '.join('(' + w + ')' for w in where)} ORDER BY {ob} LIMIT ? OFFSET ?", (*args, limit, offset)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d.pop("links", None)
        for k in ("first_seen", "last_seen", "last_change"):
            d[k] = iso(d[k]) if d.get(k) else None
        out.append(d)
    return out


def recent_changes(c, limit=20):
    if c.execute("SELECT 1 FROM sqlite_master WHERE name='w_changes'").fetchone():
        out = []
        for ch in c.execute("SELECT * FROM w_changes ORDER BY seq DESC LIMIT ?", (limit,)).fetchall():
            r = c.execute("SELECT * FROM w_obs WHERE seq=?", (ch["seq"],)).fetchone()
            if r:
                out.append({**obs_view(r), "what": ch["what"]})
        return out
    rows = c.execute("SELECT * FROM w_obs WHERE prev IS NOT NULL AND kind IN ('manifest','package','tools','status') ORDER BY seq DESC LIMIT ?", (limit * 3,)).fetchall()
    out = []
    for r in rows:
        p = c.execute("SELECT digest, version, observed_at FROM w_obs WHERE leaf=?", (r["prev"],)).fetchone()
        if not p or p["observed_at"] >= r["observed_at"]:
            continue                       # read in the same backfill run: history, not a change
        if r["kind"] != "status" and p and p["version"] != r["version"]:
            what = f"new version {r['version']}"
        elif r["kind"] == "tools":
            what = "tool descriptions changed"
        elif r["kind"] == "status":
            what = f"registry status: {(body_of(r) or {}).get('status')}"
        else:
            what = f"{r['kind']} of {r['version']} changed"
        out.append({**obs_view(r), "what": what})
        if len(out) >= limit:
            break
    return out


if __name__ == "__main__":
    main()
