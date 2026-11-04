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
    PRIMARY KEY(registry, identifier, version));
CREATE TABLE IF NOT EXISTS w_probe(endpoint TEXT PRIMARY KEY, object TEXT, version TEXT, next_at INTEGER, fails INTEGER DEFAULT 0, last_ok INTEGER, error TEXT);
CREATE TABLE IF NOT EXISTS w_state(key TEXT PRIMARY KEY, value TEXT);
"""


# ---------------------------------------------------------------- storage and hashing
def connect(path=None):
    c = sqlite3.connect(path or WITNESS_DB, timeout=30)
    c.row_factory = sqlite3.Row
    try:
        c.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass
    c.executescript(SCHEMA)
    return c


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


def observe(c, obj, kind, version, payload, now, source, meta=None, info=None):
    """Record one fact if it is new. Returns the seq of the new observation, or None when this exact fact is already recorded."""
    digest = sha(payload)
    if c.execute("SELECT 1 FROM w_obs WHERE object=? AND kind=? AND version=? AND digest=?", (obj, kind, version, digest)).fetchone():
        c.execute("UPDATE w_objects SET last_seen=? WHERE id=?", (now, obj))
        return None
    last = c.execute("SELECT leaf, digest, observed_at FROM w_obs WHERE object=? AND kind=? ORDER BY seq DESC LIMIT 1", (obj, kind)).fetchone()
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
    changed = last is not None and kind in ("manifest", "package", "tools") and last["digest"] != digest and last["observed_at"] < now
    if not o:
        c.execute("INSERT INTO w_objects(id, kind, name, title, description, source, first_seen, last_seen, latest, versions, changes, last_change, status, repo, links) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (obj, obj.split(":", 1)[0], obj.split(":", 1)[1], info.get("title"), info.get("description"), source, now, now, info.get("latest"),
                   1 if kind in ("manifest", "package") else 0, 0, None, info.get("status"), info.get("repo"), json.dumps(info.get("links") or {})))
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


def ingest_entry(c, entry, now):
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
    if observe(c, obj, "manifest", ver, s, now, REGISTRY_SOURCE, meta=meta or None, info=info):
        n += 1
    st = off.get("status") or "active"
    prev = c.execute("SELECT body FROM w_obs WHERE object=? AND kind='status' AND version=? ORDER BY seq DESC LIMIT 1", (obj, ver)).fetchone()
    prev_st = json.loads(zlib.decompress(prev["body"]))["status"] if prev else ("active" if st == "active" else None)
    if st != prev_st and observe(c, obj, "status", ver, {"status": st, "changedAt": off.get("statusChangedAt")}, now, REGISTRY_SOURCE, info={"status": st}):
        n += 1
    for p in s.get("packages") or []:
        reg, ident, pv = (p.get("registryType") or "").lower(), p.get("identifier"), str(p.get("version") or "")
        if reg in ("npm", "pypi") and ident and pv and pv != "latest":
            c.execute("INSERT INTO w_queue(registry, identifier, version, mcp, added, latest) VALUES(?,?,?,?,?,?) "
                      "ON CONFLICT(registry, identifier, version) DO UPDATE SET latest=max(latest, excluded.latest)", (reg, ident, pv, name, now, 1 if off.get("isLatest") else 0))
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
    while time.time() < deadline:
        q = {"limit": "100"}
        if cursor:
            q["cursor"] = cursor
        if since:
            q["updated_since"] = iso(int(since))
        d = get(f"{REGISTRY}/v0.1/servers?" + urllib.parse.urlencode(q))
        for e in d.get("servers") or []:
            entries += 1
            new += ingest_entry(c, e, now)
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
    while time.time() < deadline and done + failed < limit:
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
                       meta={"mcp": q["mcp"]}, info={"latest": q["version"], "links": {"mcp": q["mcp"]}}):
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
    while time.time() < deadline and ok + auth + failed < limit:
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


def run_once(c, now=None, budget=None, get=None, post=None, adapters=None, upgrade=None, sign=None, main_db=None):
    """One hourly run: read the sources within the time budget, record the run itself, seal, anchor, publish the head."""
    now = now or int(time.time())
    deadline = time.time() + (RUN_BUDGET_S if budget is None else budget)
    summary = {"started_at": iso(now)}
    for name, fn in (("registry", lambda: crawl_registry(c, now, deadline, get)),
                     ("packages", lambda: crawl_packages(c, now, deadline, get)),
                     ("remotes", lambda: probe_remotes(c, now, deadline, post))):
        try:
            summary[name] = fn()
        except Exception as e:  # noqa: BLE001  one failing source never stops the record of the others
            summary[name] = {"error": f"{type(e).__name__}: {str(e)[:200]}"}
            c.commit()
    summary["finished_at"] = iso(int(time.time()))
    observe(c, "witness:crawler", "run", summary["started_at"], summary, now, "minimalcult.org/witness")
    c.commit()
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


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    while True:
        start = time.time()
        try:
            c = connect()
            s = run_once(c)
            c.close()
            log.info("witness run: %s", json.dumps(s, default=str)[:1500])
        except Exception as e:  # noqa: BLE001
            log.exception("witness run failed: %s", e)
        time.sleep(max(60, 3600 - (time.time() - start)))


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
        "head = sha256(canonical JSON of batch.record) — equals batch.head; batch.signature is an Ed25519 signature of the gateway key (GET /v1/attestation)",
        "each anchor fixes the 32 head bytes: OpenTimestamps (`ots verify`), RFC 3161 (`openssl ts -verify`), Sigstore Rekor (entry hash = sha256 of the head bytes); the daily batch at /v1/anchors adds TON and EAS"]
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
    rows = c.execute("SELECT * FROM w_obs WHERE prev IS NOT NULL AND kind IN ('manifest','package','tools','status') ORDER BY seq DESC LIMIT ?", (limit * 3,)).fetchall()
    out = []
    for r in rows:
        p = c.execute("SELECT digest, version, observed_at FROM w_obs WHERE leaf=?", (r["prev"],)).fetchone()
        if not p or p["observed_at"] >= r["observed_at"]:
            continue                       # read in the same backfill run: history, not a change
        if r["kind"] != "status" and p and p["version"] != r["version"]:
            what = f"new version {r['version']}"
        elif r["kind"] == "tools":
            what = "tool list changed"
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
