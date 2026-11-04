"""Witness Check (block W2 of the master prompt, products C3): "is this clean?" before an agent installs a tool, pays an
address or calls a model — one call, a signed answer made of facts from the witness record, with links to the history and
the anchored proofs.

  GET  /v1/check?type=<type>&target=<target>[&version=&sha256=&integrity=]
  POST /v1/check  {"type": ..., "target": ..., "version": ..., "sha256": ..., "integrity": ...}

Types:
  mcp_tool      target = MCP Registry name (io.github.owner/server) or mcp:<name>. Facts: witnessed since, versions, registry
                status, changes of the last 30 days (versions, manifest, tool descriptions of the public endpoint), the
                hashes of the packages behind the latest version.
  package       target = npm:<name> or pypi:<name>, optional version and the hash the agent is about to install (`sha256`
                for a PyPI file, `integrity` or `shasum` for npm). A hash that differs from the one we recorded for that
                version is a red fact (`hash_mismatch`), with both values and the observation that recorded ours.
  url           target = https URL of an MCP remote. Facts: which witnessed server published it, its tool list history.
  ton_address   target = TON address. Facts: OFAC SDN list match (the list's date), nothing else is claimed.
  model_endpoint  planned (Witness Certificate, block W5): answers 400 with the plan.

The answer is a signed record (RECEIPTS v2, kind `witness_check`, hybrid Ed25519 + ML-DSA-65), chained like verdicts and
queued for the daily TON notary record. `status` is a fact class, never a judgement of intent:
  witnessed          known to the record, nothing moved in the last 30 days
  changed_recently   known, and something moved in the last 30 days (listed in `changes`)
  hash_mismatch      the hash you gave differs from the hash we recorded for that version
  not_witnessed      not in the record (yet): no history is not a verdict
  sanctions_listed / not_listed   (ton_address)
Price: the first FREE_PER_DAY checks per key (or per address without a key) each day are free; then CHECK_PRICE_NANO from
the key balance, or GRAM-402 without a key (the payment above the price stays as credit for more checks). Test price,
announced as such. x402 USDC on Base: block G2.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: MIT (open core).
"""
import json
import os
import re
import time
import urllib.parse
import uuid

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

import receipts
import witness as W

FREE_PER_DAY = int(os.environ.get("CHECK_FREE_PER_DAY", "100"))
CHECK_PRICE_NANO = int(os.environ.get("CHECK_PRICE_NANO", "5000000"))      # 0.005 GRAM, test price
PER_ID_DAY = int(os.environ.get("CHECK_PER_ID_DAY", "20000"))
RECENT_S = 30 * 86400
TYPES = ("mcp_tool", "package", "url", "ton_address", "model_endpoint")
BASE = "https://ai.minimalcult.org"
SCHEMA = """
CREATE TABLE IF NOT EXISTS witness_checks(id TEXT PRIMARY KEY, seq INTEGER, ts INTEGER, payer TEXT, type TEXT, target TEXT, status TEXT,
    charged_nano INTEGER, sha256 TEXT, body TEXT);
CREATE INDEX IF NOT EXISTS witness_checks_payer ON witness_checks(payer, ts);
CREATE INDEX IF NOT EXISTS witness_checks_seq ON witness_checks(seq);
"""
NAME = re.compile(r"^[A-Za-z0-9@._/:+~-]{1,300}$")


def _href(oid):
    return f"{BASE}/witness/tool/" + urllib.parse.quote(oid, safe=":@/")


def _obs_ref(r):
    return {"seq": r["seq"], "kind": r["kind"], "version": r["version"], "observed_at": W.iso(r["observed_at"]), "digest": r["digest"],
            "leaf": r["leaf"], "batch": r["batch_id"], "proof": f"{BASE}/v1/witness/proof?seq={r['seq']}"}


def _object_facts(c, oid, now):
    o = c.execute("SELECT * FROM w_objects WHERE id=?", (oid,)).fetchone()
    if not o:
        return None
    facts = {"object": oid, "witnessed_since": W.iso(o["first_seen"]), "last_seen": W.iso(o["last_seen"]), "versions": o["versions"],
             "latest": o["latest"], "registry_status": o["status"], "history": _href(oid)}
    ch = c.execute("SELECT c.seq, c.ts, c.what, o.kind FROM w_changes c JOIN w_obs o ON o.seq=c.seq WHERE c.object=? AND c.ts>? ORDER BY c.seq DESC LIMIT 20",
                   (oid, now - RECENT_S)).fetchall()
    changes = [{"what": r["what"], "kind": r["kind"], "at": W.iso(r["ts"]), "diff": f"{BASE}/v1/witness/diff?seq={r['seq']}"} for r in ch]
    return o, facts, changes


def check_mcp_tool(c, target, now):
    name = target[4:] if target.startswith("mcp:") else target
    got = _object_facts(c, "mcp:" + name, now)
    if not got:
        return "not_witnessed", {"object": "mcp:" + name}, [], [{"code": "not_in_record", "severity": "info",
                                                                   "fact": "this name is not in the witness record; the record follows the official MCP Registry"}]
    o, facts, changes = got
    flags = []
    if o["status"] and o["status"] != "active":
        flags.append({"code": f"registry_{o['status']}", "severity": "warn", "fact": f"the official MCP Registry marks this server {o['status']}"})
    tools = c.execute("SELECT * FROM w_obs WHERE object=? AND kind='tools' ORDER BY seq DESC LIMIT 1", ("mcp:" + name,)).fetchone()
    if tools:
        facts["tool_descriptions"] = {**_obs_ref(tools), "count": (json.loads(tools["record"]).get("meta") or {}).get("count")}
    else:
        facts["tool_descriptions"] = None
        flags.append({"code": "tools_not_read", "severity": "info", "fact": "no public tool list recorded (no public endpoint, auth required, or not read yet)"})
    man = c.execute("SELECT * FROM w_obs WHERE object=? AND kind='manifest' ORDER BY seq DESC LIMIT 1", ("mcp:" + name,)).fetchone()
    if man:
        facts["registry_entry"] = _obs_ref(man)
        pk = []
        for p in (W.body_of(man) or {}).get("packages") or []:
            reg, ident, ver = (p.get("registryType") or "").lower(), p.get("identifier"), str(p.get("version") or "")
            if reg in ("npm", "pypi") and ident:
                r = c.execute("SELECT * FROM w_obs WHERE object=? AND kind='package' AND version=? ORDER BY seq DESC LIMIT 1", (f"{reg}:{ident}", ver)).fetchone()
                pk.append({"package": f"{reg}:{ident}", "version": ver, "recorded": _obs_ref(r) if r else None,
                           "hashes": _hashes(W.body_of(r)) if r else None})
        facts["packages"] = pk
    if any(x["kind"] == "tools" for x in changes):
        flags.append({"code": "tool_descriptions_changed", "severity": "warn",
                      "fact": "the tool descriptions served by the public endpoint changed in the last 30 days; read the diff before trusting them"})
    status = "changed_recently" if changes else "witnessed"
    return status, facts, changes, flags


def _hashes(body):
    if not body:
        return None
    if body.get("registry") == "npm":
        return {"integrity": body.get("integrity"), "shasum": body.get("shasum")}
    return {"files": body.get("files")}


def check_package(c, target, now, version=None, sha256=None, integrity=None, shasum=None):
    if not (target.startswith("npm:") or target.startswith("pypi:")):
        raise HTTPException(400, "package: target is npm:<name> or pypi:<name>")
    got = _object_facts(c, target, now)
    if not got:
        return "not_witnessed", {"object": target}, [], [{"code": "not_in_record", "severity": "info",
                                                          "fact": "the record holds the npm and PyPI packages that MCP Registry entries point to; this one is not among them (yet)"}]
    o, facts, changes = got
    ver = version or o["latest"]
    r = c.execute("SELECT * FROM w_obs WHERE object=? AND kind='package' AND version=? ORDER BY seq DESC LIMIT 1", (target, ver)).fetchone()
    flags, status = [], ("changed_recently" if changes else "witnessed")
    if not r:
        facts["version"] = ver
        flags.append({"code": "version_not_recorded", "severity": "info", "fact": f"version {ver} of this package is not in the record"})
        return status, facts, changes, flags
    body = W.body_of(r)
    facts.update(version=ver, recorded=_obs_ref(r), hashes=_hashes(body))
    given = {k: v for k, v in (("sha256", sha256), ("integrity", integrity), ("shasum", shasum)) if v}
    if given:
        known = set()
        if body.get("registry") == "npm":
            known |= {body.get("integrity"), body.get("shasum")}
        else:
            known |= {f.get("sha256") for f in body.get("files") or []}
        known.discard(None)
        match = [k for k, v in given.items() if v.strip().lower() in {x.lower() for x in known}]
        facts["your_hash"] = {**given, "matches_record": bool(match)}
        if not match:
            status = "hash_mismatch"
            flags.append({"code": "hash_mismatch", "severity": "red",
                          "fact": f"the hash you are about to install differs from every hash recorded for {target} {ver}; do not install as is"})
    return status, facts, changes, flags


def check_url(c, target, now):
    u = urllib.parse.urlsplit(target)
    if u.scheme != "https" or not u.hostname:
        raise HTTPException(400, "url: an https URL")
    p = c.execute("SELECT * FROM w_probe WHERE endpoint=?", (target,)).fetchone()
    if not p:
        return "not_witnessed", {"url": target}, [], [{"code": "not_in_record", "severity": "info",
                                                       "fact": "no witnessed MCP server published this endpoint in the official registry"}]
    status, facts, changes, flags = check_mcp_tool(c, p["object"], now)
    facts.update(url=target, published_by=p["object"], endpoint_last_read=W.iso(p["last_ok"]) if p["last_ok"] else None,
                 endpoint_note=p["error"])
    return status, facts, changes, flags


def check_ton_address(target):
    import sanctions
    st = sanctions.status()
    facts = {"address": target, "list": "OFAC SDN (digital currency addresses)", "list_fetched_at": st.get("fetched_at"), "list_ok": st.get("ok")}
    if not st.get("ok"):
        return "unverifiable", facts, [], [{"code": "list_unavailable", "severity": "warn", "fact": "the sanctions list is missing or stale right now"}]
    try:
        sanctions.check(target)
    except sanctions.Blocked:
        return "sanctions_listed", facts, [], [{"code": "sanctions_listed", "severity": "red", "fact": "the address is on the OFAC SDN list"}]
    return "not_listed", facts, [], []


def run(c_w, claim, now):
    t, target = claim["type"], claim["target"]
    if t == "model_endpoint":
        raise HTTPException(400, "model_endpoint: planned (Witness Certificate, model identity index); not checked yet")
    if t == "ton_address":
        return check_ton_address(target)
    if c_w is None:
        return "unverifiable", {"note": "the witness record is starting"}, [], []
    if t == "mcp_tool":
        return check_mcp_tool(c_w, target, now)
    if t == "package":
        return check_package(c_w, target, now, claim.get("version"), claim.get("sha256"), claim.get("integrity"), claim.get("shasum"))
    return check_url(c_w, target, now)


def clean(b):
    if not isinstance(b, dict) or b.get("type") not in TYPES:
        raise HTTPException(400, f"check: {{type: {'|'.join(TYPES)}, target: ...}}")
    target = str(b.get("target") or "").strip()
    if not target or len(target) > 400 or (b["type"] != "url" and not NAME.match(target)):
        raise HTTPException(400, "target: a name, package, https URL or address (400 chars at most)")
    out = {"type": b["type"], "target": target}
    for k in ("version", "sha256", "integrity", "shasum"):
        v = b.get(k)
        if v:
            out[k] = str(v).strip()[:200]
    return out


def record(c, claim, status, facts, changes, flags, payer, charged, head, now):
    c.executescript(SCHEMA)
    prev = c.execute("SELECT sha256 FROM witness_checks ORDER BY seq DESC LIMIT 1").fetchone()
    seq = (c.execute("SELECT max(seq) FROM witness_checks").fetchone()[0] or 0) + 1
    cid = "wc_" + uuid.uuid4().hex[:16]
    observed = ["the witness record at the time of the check", "the hashes and changes listed in `facts` and `changes`"]
    rec = receipts.sign({"v": 2, "kind": "witness_check", "issuer": "MINIMALCULT Witness", "ts": now, "check_id": cid, "type": claim["type"],
                         "target": claim["target"], "query": claim, "status": status, "flags": flags, "facts": facts, "changes": changes,
                         "record_head": head, "client": receipts.pseudonym(payer), "price_nano": charged,
                         "prev_sha256": prev[0] if prev else None,
                         **receipts.delivery("executed", observed=observed,
                                             assumed=["no history is not a verdict; a fact class is not a judgement of intent",
                                                      "the record describes what the public sources served when we read them"])})
    c.execute("INSERT INTO witness_checks(id, seq, ts, payer, type, target, status, charged_nano, sha256, body) VALUES(?,?,?,?,?,?,?,?,?,?)",
              (cid, seq, now, payer, claim["type"], claim["target"][:400], status, charged, receipts.sha256(rec), json.dumps(rec, ensure_ascii=False, sort_keys=True)))
    try:
        import notary
        notary.queue_answer(c, receipts.receipt_id(rec))
    except Exception:  # noqa: BLE001
        pass
    return rec


def setup(app, db, get_key, pay_gate, client_ip, h):
    with db() as c:
        c.executescript(SCHEMA)

    async def handle(request, b):
        auth = request.headers.get("authorization")
        claim = clean(b)
        now = int(time.time())
        key, settlement = None, None
        if auth:
            key = get_key(auth)
            payer = "key:" + key["key_hash"]
        elif request.headers.get("x-payment"):
            gate = await pay_gate(request, b, "/v1/check", CHECK_PRICE_NANO)
            if isinstance(gate, JSONResponse):
                return gate
            key, settlement = gate
            payer = "key:" + key["key_hash"]
        else:
            payer = "ip:" + h("ip:" + client_ip(request))
        with db() as c:
            c.executescript(SCHEMA)
            used = c.execute("SELECT count(*) FROM witness_checks WHERE payer=? AND ts>? AND status!='unverifiable'", (payer, now - 86400)).fetchone()[0]
        if used >= PER_ID_DAY:
            raise HTTPException(429, f"up to {PER_ID_DAY} checks a day per key; volume and commercial use: {BASE}/witness", headers={"Retry-After": "3600"})
        paid = bool(b.get("pay")) or settlement is not None      # a buyer can ask for a paid check (catalogues, its own books)
        free_left = 0 if paid else max(0, FREE_PER_DAY - used)
        if not free_left and key is None:
            return await pay_gate(request, b, "/v1/check", CHECK_PRICE_NANO)   # over the free threshold without a key: GRAM-402
        cw = W.open_ro()
        try:
            status, facts, changes, flags = run(cw, claim, now)
            head = None
            if cw is not None:
                lb = cw.execute("SELECT id, head, ts FROM w_batches ORDER BY seq DESC LIMIT 1").fetchone()
                head = {"batch": lb["id"], "head": lb["head"], "sealed_at": W.iso(lb["ts"])} if lb else None
        finally:
            if cw is not None:
                cw.close()
        charge = 0
        with db() as c:
            if not free_left and status != "unverifiable":
                import starter
                starter.spend(c, key["key_hash"], CHECK_PRICE_NANO, "witness_check")
                charge = CHECK_PRICE_NANO
            rec = record(c, claim, status, facts, changes, flags, payer, charge, head, now)
            left = c.execute("SELECT balance_nano FROM keys WHERE key_hash=?", (key["key_hash"],)).fetchone()[0] if key else None
        out = {"status": status, "flags": flags, "check": rec, "charged_nano": charge, "free_checks_left_today": max(0, free_left - 1),
               "lookup": f"{BASE}/v1/check/{rec['check_id']}"}
        if left is not None:
            out["balance_left_nano"] = left
        if settlement:
            out["payment"] = {"transaction": settlement["tx_hash"], "payer": settlement["payer"], "paid_nano": settlement["paid_nano"],
                              "api_key": settlement["api_key"], "note": "api_key is shown once; the payment above the price is credit for more checks"}
        return out

    @app.get("/v1/check")
    async def check_get(request: Request, type: str = "", target: str = "", version: str = "", sha256: str = "", integrity: str = "", shasum: str = "", pay: int = 0):
        """Witness Check. Without parameters: what it does, the price, the free threshold."""
        if not type:
            return {"what": "Witness Check: is this tool, package, endpoint or address clean? A signed answer of facts from the anchored witness record",
                    "types": {"mcp_tool": "target=io.github.owner/server", "package": "target=npm:<name>|pypi:<name>, version=, sha256=|integrity=|shasum=",
                              "url": "target=https://<MCP remote>", "ton_address": "target=<address>", "model_endpoint": "planned (Witness Certificate)"},
                    "statuses": ["witnessed", "changed_recently", "hash_mismatch", "not_witnessed", "sanctions_listed", "not_listed", "unverifiable"],
                    "free_per_day": FREE_PER_DAY, "price_nano": CHECK_PRICE_NANO,
                    "price_note": "test price, announced as such; the first checks of each day are free per key, or per address without a key",
                    "pay": "Bearer key (balance), or GRAM-402: over the free threshold a call without a key answers 402 -> pay -> repeat with X-PAYMENT; "
                           "pay=1 (or \"pay\": true) asks for a paid check even within the free threshold",
                    "example": f"{BASE}/v1/check?type=mcp_tool&target=io.github.github/github-mcp-server", "docs": f"{BASE}/witness"}
        return await handle(request, {"type": type, "target": target, "version": version, "sha256": sha256, "integrity": integrity, "shasum": shasum, "pay": pay})

    @app.post("/v1/check")
    async def check_post(request: Request):
        try:
            b = await request.json()
        except ValueError:
            b = {}
        return await handle(request, b)

    @app.get("/v1/check/{cid}")
    def one(cid: str):
        with db() as c:
            c.executescript(SCHEMA)
            r = c.execute("SELECT body FROM witness_checks WHERE id=?", (cid[:40],)).fetchone()
        if not r:
            raise HTTPException(404, "no such check")
        return json.loads(r["body"])
