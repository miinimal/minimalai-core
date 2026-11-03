"""Multi-anchoring (block H2-3, staff direction 2): the heads of our chains are fixed not only in TON but in independent
systems run by other people, so forging a record would mean breaking several networks at once — and our hash lives in
their ecosystems.

Once a day the anchor service builds one batch: a Merkle root over the current heads (task receipts, notary, verdicts,
the last TON anchor) and submits that single 32-byte root to every adapter that is configured. Costs: OpenTimestamps and a
public RFC 3161 TSA are free; EAS on Base costs one attestation's gas (the project's own EVM key, Base Sepolia first).
Each anchor is stored with its proof bytes and a recipe anyone can follow to check it without us:

  opentimestamps  calendar servers (a/b.pool, alice/bob.btc) return a pending attestation; it upgrades to a Bitcoin block
                  attestation within hours. Verify: `ots verify batch.ots` (opentimestamps-client) against the root bytes.
  rfc3161         a TimeStampReq over the root to FreeTSA (https://freetsa.org/tsr); the answer is a signed TimeStampToken.
                  Verify: `openssl ts -verify -digest <root> -in batch.tsr -CAfile cacert.pem` with the TSA's published CA.
  eas             Ethereum Attestation Service on Base (predeploys 0x4200…0020 schema registry, 0x4200…0021 EAS); schema
                  `bytes32 root,string source`; attestation UID in the batch. Verify: base.easscan.org/attestation/view/<uid>.
  ton             the existing daily anchor of the notary head (gateway/anchor.py).
Sigstore Rekor is listed in the staff direction; its hashedrekord type cannot take an Ed25519 signature over a bare hash,
so it waits for a source check of the `rekord` type (not pretended here).
Facts to confirm at the source on the first live run (printed by the rollout): calendar URLs answer, FreeTSA answers a
TimeStampResp with status 0, `eth_getCode` of the EAS predeploys is non-empty on Base Sepolia.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: MIT (open core).
"""
import base64
import hashlib
import json
import logging
import os
import time
import urllib.request

log = logging.getLogger("anchors")
CALENDARS = [u for u in os.environ.get("OTS_CALENDARS", "https://a.pool.opentimestamps.org,https://b.pool.opentimestamps.org,https://alice.btc.calendar.opentimestamps.org").split(",") if u]
TSA_URL = os.environ.get("TSA_URL", "https://freetsa.org/tsr")
TSA_CA_URL = os.environ.get("TSA_CA_URL", "https://freetsa.org/files/cacert.pem")
EAS = {84532: {"eas": "0x4200000000000000000000000000000000000021", "registry": "0x4200000000000000000000000000000000000020", "scan": "https://base-sepolia.easscan.org/attestation/view/"},
       8453: {"eas": "0x4200000000000000000000000000000000000021", "registry": "0x4200000000000000000000000000000000000020", "scan": "https://base.easscan.org/attestation/view/"}}
EAS_SCHEMA = "bytes32 root,string source"
DB_PATH = os.environ.get("MINIMALAI_DB", "/data/minimalai.db")
DATA_DIR = os.path.dirname(DB_PATH) or "."
SCHEMA = """
CREATE TABLE IF NOT EXISTS anchor_batches(id TEXT PRIMARY KEY, ts INTEGER, root TEXT, leaves TEXT);
CREATE TABLE IF NOT EXISTS anchor_proofs(batch_id TEXT, kind TEXT, ts INTEGER, status TEXT, proof TEXT, meta TEXT, error TEXT, PRIMARY KEY(batch_id, kind));
"""


# ---------------------------------------------------------------- the batch
def heads(c):
    """Current heads of the public chains: what the batch fixes."""
    q = lambda sql: (c.execute(sql).fetchone() or [None])[0]
    out = []
    for name, sql in (("task_receipts", "SELECT sha256 FROM task_receipts ORDER BY seq DESC LIMIT 1"),
                      ("notary", "SELECT sha256 FROM notary ORDER BY seq DESC LIMIT 1"),
                      ("verdicts", "SELECT sha256 FROM verdicts ORDER BY seq DESC LIMIT 1"),
                      ("disputes", "SELECT sha256 FROM disputes ORDER BY seq DESC LIMIT 1"),
                      ("ton_anchor", "SELECT tx FROM anchors ORDER BY id DESC LIMIT 1")):
        try:
            v = q(sql)
        except Exception:  # noqa: BLE001  a table that does not exist in this build
            v = None
        if v:
            out.append((name, str(v)))
    return out


def root_of(leaves):
    import notary
    hs = [hashlib.sha256(f"{k}:{v}".encode()).hexdigest() for k, v in leaves]
    return notary.merkle_root(hs) if hs else hashlib.sha256(b"").hexdigest()


def new_batch(c, now=None):
    c.executescript(SCHEMA)
    now = now or int(time.time())
    leaves = heads(c)
    root = root_of(leaves)
    last = c.execute("SELECT id, root FROM anchor_batches ORDER BY ts DESC LIMIT 1").fetchone()
    if last and last["root"] == root:
        return None                                   # nothing moved since the last batch: no new anchors
    bid = "ab_" + hashlib.sha256(f"{root}{now}".encode()).hexdigest()[:12]
    c.execute("INSERT INTO anchor_batches(id, ts, root, leaves) VALUES(?,?,?,?)", (bid, now, root, json.dumps(leaves)))
    return {"id": bid, "ts": now, "root": root, "leaves": leaves}


# ---------------------------------------------------------------- adapters: each returns (status, proof_b64, meta) or raises
def ots_submit(root_hex, calendars=None, timeout=20):
    from opentimestamps.calendar import RemoteCalendar
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    digest = bytes.fromhex(root_hex)
    dtf = DetachedTimestampFile(OpSHA256(), Timestamp(digest))
    ok, errs = [], {}
    for url in (calendars or CALENDARS):
        try:
            dtf.timestamp.merge(RemoteCalendar(url).submit(digest, timeout=timeout))
            ok.append(url)
        except Exception as e:  # noqa: BLE001
            errs[url] = f"{type(e).__name__}: {str(e)[:80]}"
    if not ok:
        raise RuntimeError("no calendar answered: " + json.dumps(errs))
    ctx = BytesSerializationContext(); dtf.serialize(ctx)
    return "pending", base64.b64encode(ctx.getbytes()).decode(), {"calendars": ok, "errors": errs,
                                                                   "verify": "ots verify <file>.ots  (the .ots file is `proof`, base64; upgrades to a Bitcoin attestation within hours)"}


def ots_upgrade(proof_b64, timeout=20):
    """Ask the calendars for the Bitcoin attestation of a pending proof; returns (status, proof_b64, meta)."""
    from opentimestamps.calendar import RemoteCalendar
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile
    dtf = DetachedTimestampFile.deserialize(BytesDeserializationContext(base64.b64decode(proof_b64)))

    def directly_verified(stamp):          # the leaves that carry attestations (same walk as the reference client)
        if stamp.attestations:
            yield stamp
        else:
            for sub in stamp.ops.values():
                yield from directly_verified(sub)
    upgraded = False
    for sub_stamp in list(directly_verified(dtf.timestamp)):
        for att in list(sub_stamp.attestations):
            if isinstance(att, PendingAttestation):
                try:
                    better = RemoteCalendar(att.uri).get_timestamp(sub_stamp.msg, timeout=timeout)
                    sub_stamp.merge(better); upgraded = True
                except Exception:  # noqa: BLE001  not ready yet
                    pass
    blocks = [a.height for _m, a in dtf.timestamp.all_attestations() if isinstance(a, BitcoinBlockHeaderAttestation)]
    ctx = BytesSerializationContext(); dtf.serialize(ctx)
    status = "attested" if blocks else "pending"
    return status, base64.b64encode(ctx.getbytes()).decode(), {"bitcoin_blocks": blocks, "upgraded_now": upgraded,
                                                               "verify": "ots verify <file>.ots" + (f"  (Bitcoin block {blocks[0]})" if blocks else "")}


def tsa_stamp(root_hex, url=None, timeout=20, post=None):
    import rfc3161_client as R
    req = R.TimestampRequestBuilder().data(bytes.fromhex(root_hex)).hash_algorithm(R.HashAlgorithm.SHA256).nonce(nonce=True).cert_request(cert_request=True).build()
    imprint = hashlib.sha256(bytes.fromhex(root_hex)).hexdigest()      # the TSA stamps sha256(root bytes)
    body = req.as_bytes()
    if post:
        raw = post(url or TSA_URL, body)
    else:
        rq = urllib.request.Request(url or TSA_URL, data=body, method="POST", headers={"Content-Type": "application/timestamp-query", "User-Agent": "minimalai-anchors/1"})
        with urllib.request.urlopen(rq, timeout=timeout) as r:
            raw = r.read()
    resp = R.decode_timestamp_response(raw)
    if int(resp.status) != 0:
        raise RuntimeError(f"TSA status {resp.status}: {resp.status_string}")
    info = resp.tst_info
    return "attested", base64.b64encode(raw).decode(), {"tsa": url or TSA_URL, "gen_time": info.gen_time.isoformat(), "serial": str(info.serial_number),
                                                         "policy": str(info.policy), "imprint_sha256": imprint,
                                                         "verify": f"openssl ts -verify -digest {imprint} -sha256 -in <file>.tsr -CAfile cacert.pem  (imprint = sha256 of the 32 root bytes; CA: {TSA_CA_URL})"}


def eas_attest(root_hex, acct, chain=84532, rpc=None, dry=False):
    """One EAS attestation of the root on Base (Sepolia first). Registers the schema once (uid kept next to the database)."""
    import erc8004 as E
    r = rpc or E.rpc
    cfg = EAS[chain]
    code = r("eth_getCode", [cfg["eas"], "latest"])
    if not code or code == "0x":
        raise RuntimeError(f"no contract at {cfg['eas']} on chain {chain}: EAS address unconfirmed")
    schema_file = os.path.join(DATA_DIR, f"eas_schema_{chain}.txt")
    uid = open(schema_file).read().strip() if os.path.exists(schema_file) else ""
    if not uid:
        data = E.encode_call("register(string,address,bool)", ["string", "address", "bool"], [EAS_SCHEMA, "0x" + "0" * 40, False])
        res = E.send(cfg["registry"], data, acct, chain, r, dry)
        if dry:
            return "dry", "", {"would": "register schema then attest", **res}
        if res.get("status") != 1:
            raise RuntimeError(f"schema registration failed: {res}")
        # Registered(bytes32 indexed uid, address indexed registerer, SchemaRecord schema): topic1 = uid
        for lg in res.get("logs", []):
            if len(lg.get("topics", [])) >= 2:
                uid = lg["topics"][1]
        if not uid:
            raise RuntimeError("schema registered but no uid in the logs")
        open(schema_file, "w").write(uid)
    from eth_abi import encode
    payload = encode(["bytes32", "string"], [bytes.fromhex(root_hex), "MINIMAL AI anchor batch: merkle root of the public chain heads (ai.minimalcult.org/v1/anchors)"])
    req_tuple = (bytes.fromhex(uid[2:].rjust(64, "0")), ("0x" + "0" * 40, 0, False, b"\0" * 32, payload, 0))
    data = "0x" + (E.selector("attest((bytes32,(address,uint64,bool,bytes32,bytes,uint256)))") +
                   encode(["(bytes32,(address,uint64,bool,bytes32,bytes,uint256))"], [req_tuple])).hex()
    res = E.send(cfg["eas"], data, acct, chain, r, dry)
    if dry:
        return "dry", "", {"would": "attest", "schema": uid, **res}
    if res.get("status") != 1:
        raise RuntimeError(f"attest failed: {res}")
    att_uid = None
    for lg in res.get("logs", []):          # Attested(address indexed recipient, address indexed attester, bytes32 uid, bytes32 indexed schemaUID): uid in data
        if lg.get("address", "").lower() == cfg["eas"].lower() and lg.get("data") and len(lg["data"]) >= 66:
            att_uid = "0x" + lg["data"][2:66]
    return "attested", att_uid or "", {"chain": chain, "schema": uid, "tx": res["tx"], "attestation": att_uid,
                                        "verify": (cfg["scan"] + att_uid) if att_uid else f"transaction {res['tx']}"}


# ---------------------------------------------------------------- the daily run (anchor service)
def run(c, acct=None, now=None, adapters=None, eas_chain=84532, rpc=None, log_fn=None):
    """New batch (when a head moved) -> every adapter; then try to upgrade pending OpenTimestamps proofs. Returns a summary."""
    now = now or int(time.time())
    c.executescript(SCHEMA)
    say = log_fn or log.info
    out = {"batch": None, "anchors": {}, "upgraded": 0}
    b = new_batch(c, now)
    if b:
        out["batch"] = b["id"]
        say(f"anchors: batch {b['id']} root {b['root'][:16]}… over {len(b['leaves'])} heads")
        ad = adapters or {"opentimestamps": lambda root: ots_submit(root), "rfc3161": lambda root: tsa_stamp(root)}
        if acct is not None and "eas" not in (adapters or {}):
            ad["eas"] = lambda root: eas_attest(root, acct, eas_chain, rpc)
        for kind, fn in ad.items():
            try:
                status, proof, meta = fn(b["root"])
                c.execute("INSERT OR REPLACE INTO anchor_proofs(batch_id, kind, ts, status, proof, meta, error) VALUES(?,?,?,?,?,?,NULL)",
                          (b["id"], kind, now, status, proof, json.dumps(meta, default=str)))
                out["anchors"][kind] = status
            except Exception as e:  # noqa: BLE001
                c.execute("INSERT OR REPLACE INTO anchor_proofs(batch_id, kind, ts, status, proof, meta, error) VALUES(?,?,?,?,?,?,?)",
                          (b["id"], kind, now, "failed", "", "{}", str(e)[:300]))
                out["anchors"][kind] = "failed: " + str(e)[:80]
        c.commit()
    # pending OpenTimestamps proofs of earlier batches: ask for the Bitcoin attestation
    up = (adapters or {}).get("ots_upgrade", ots_upgrade)
    for row in c.execute("SELECT batch_id, proof FROM anchor_proofs WHERE kind='opentimestamps' AND status='pending' ORDER BY ts LIMIT 10").fetchall():
        try:
            status, proof, meta = up(row["proof"])
            if status == "attested":
                c.execute("UPDATE anchor_proofs SET status=?, proof=?, meta=?, ts=? WHERE batch_id=? AND kind='opentimestamps'",
                          (status, proof, json.dumps(meta), now, row["batch_id"]))
                out["upgraded"] += 1
        except Exception as e:  # noqa: BLE001
            say(f"anchors: upgrade {row['batch_id']}: {e}")
    c.commit()
    return out


def view(c, limit=20):
    c.executescript(SCHEMA)
    rows = c.execute("SELECT * FROM anchor_batches ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for b in rows:
        proofs = {}
        for p in c.execute("SELECT kind, ts, status, meta, error, length(proof) n FROM anchor_proofs WHERE batch_id=?", (b["id"],)).fetchall():
            proofs[p["kind"]] = {"status": p["status"], "ts": p["ts"], **json.loads(p["meta"] or "{}"), "proof_bytes": p["n"] or 0, "error": p["error"],
                                 "proof_url": f"/v1/anchors/{b['id']}/{p['kind']}"}
        out.append({"id": b["id"], "ts": b["ts"], "root": b["root"], "leaves": json.loads(b["leaves"]), "anchors": proofs})
    return out


def setup(app, db):
    from fastapi import HTTPException
    from fastapi.responses import Response
    with db() as c:
        c.executescript(SCHEMA)

    @app.get("/v1/anchors")
    def anchors(limit: int = 20):
        """Every daily batch: the Merkle root over the chain heads and its independent anchors with verification recipes."""
        with db() as c:
            items = view(c, min(limit, 200))
        return {"items": items, "how": {"root": "sha256 Merkle root (notary.py: leaf = sha256(0x00||h), node = sha256(0x01||l||r)) over sha256('<name>:<head>') per head",
                                        "opentimestamps": "download the proof, `ots verify` it against the 32 root bytes; pending until a Bitcoin block includes it",
                                        "rfc3161": "download the proof (.tsr), `openssl ts -verify -digest <sha256 of the root bytes> -sha256 -in proof.tsr -CAfile cacert.pem` with the TSA's CA",
                                        "eas": "open the attestation on EAS scan: the `root` field equals the batch root",
                                        "ton": "the notary head is written to TON daily (GET /v1/notary/chain → ton_anchor)"},
                "principle": "forging a record would mean breaking several networks at once; our hash lives in other people's ecosystems"}

    @app.get("/v1/anchors/{bid}/{kind}")
    def proof(bid: str, kind: str):
        with db() as c:
            r = c.execute("SELECT proof, status FROM anchor_proofs WHERE batch_id=? AND kind=?", (bid[:24], kind[:24])).fetchone()
        if not r or not r["proof"]:
            raise HTTPException(404, "no such proof")
        raw = base64.b64decode(r["proof"]) if kind in ("opentimestamps", "rfc3161") else r["proof"].encode()
        ext = {"opentimestamps": "ots", "rfc3161": "tsr"}.get(kind, "txt")
        return Response(raw, media_type="application/octet-stream", headers={"Content-Disposition": f'attachment; filename="{bid}.{ext}"', "X-Anchor-Status": r["status"]})
