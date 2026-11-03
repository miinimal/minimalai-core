"""VERIFY (block H2-1, staff direction 2): a paid check of an agent's claim, answered with a signed verdict.

Agents cannot prove that something really happened ("the task ran" but nothing was delivered; a confirmation that only
proves a start; server time anyone can fake). Here an agent sends a claim, we check it against the world — the TON chain,
the live resource, the public channel, our own signature — and sign a verdict: `true`, `false` or `unverifiable`, with the
evidence we saw, the method, the time of the check, and the same delivery/distrust blocks every v2 record carries. Verdicts
are chained and queued for the daily notary record, so the time of the check is anchored in TON next day.

Claim types (the `type` field) and what counts:
  ton_transfer   {"tx": "<hash>"} or {"to": "<address>", "amount_nano": N, "comment": "...", "after_ts": T} — the transfer
                 exists on chain and matches (toncenter API v3, same client as GRAM-402); the account's last 300 transactions
  http_delivered {"url": "https://...", "expect": {"status": 200, "sha256": "...", "contains": "..."}} — the resource is there
                 now and matches (public https hosts only, 64 KB, no redirects; a network failure is `unverifiable`)
  message_sent   {"channel": "name", "message_id": N, "contains": "..."} — the message is visible on the public t.me/s page
                 (private chats are `unverifiable`: we do not join chats)
  receipt        {"record": {...}} — a MINIMAL AI record (receipt, verdict, passport, ack) carries a valid signature by the
                 pinned gateway key (`true`), a wrong one (`false`); other issuers are `unverifiable`
Price: a test price, announced as such, below the market (Tsuki and PaidCheck ask about 1 USDC per check — staff note
2026-11-03; to be confirmed at the source before any public comparison): 0.02 GRAM through GRAM-402 or a key balance.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: MIT (open core).
"""
import hashlib
import json
import os
import re
import time
import uuid

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

import receipts

PRICE_NANO = int(os.environ.get("VERIFY_PRICE_NANO", "20000000"))   # 0.02 GRAM, test price
PER_KEY_DAY = int(os.environ.get("VERIFY_PER_KEY_DAY", "200"))
TYPES = ("ton_transfer", "http_delivered", "message_sent", "receipt")
SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts(id TEXT PRIMARY KEY, seq INTEGER, ts INTEGER, key_hash TEXT, type TEXT, result TEXT, claim_sha256 TEXT,
    sha256 TEXT, body TEXT);
CREATE INDEX IF NOT EXISTS verdicts_seq ON verdicts(seq);
"""
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def claim_hash(claim):
    return receipts.sha256(claim)


# ---------------------------------------------------------------- checks: each returns (result, evidence, observed, assumed)
async def check_ton_transfer(claim, fetch_txs):
    tx = str(claim.get("tx") or "").strip()
    to = str(claim.get("to") or "").strip()
    want_amount = int(claim.get("amount_nano") or 0)
    want_comment = str(claim.get("comment") or "")
    after = int(claim.get("after_ts") or 0)
    if not tx and not to:
        raise HTTPException(400, "ton_transfer: give tx (hash) or to (address) with amount_nano/comment/after_ts")
    account = to or str(claim.get("account") or "")
    if tx and not account:
        raise HTTPException(400, "ton_transfer: with tx also give the account (to) whose transactions hold it")
    try:
        txs = await fetch_txs(account)
    except Exception as e:  # noqa: BLE001
        return "unverifiable", {"reason": f"chain API unavailable: {type(e).__name__}"}, [], ["the transfer may exist; the chain could not be read now"]
    for t in txs:
        im = t.get("in_msg") or {}
        if not im.get("source"):
            continue
        h = str(t.get("hash") or "")
        if tx and h not in (tx, tx.replace("-", "+").replace("_", "/")):
            continue
        value = int(im.get("value") or 0)
        comment = ((im.get("message_content") or {}).get("decoded") or {}).get("comment", "")
        utime = int(t.get("now") or t.get("utime") or 0)
        desc = t.get("description") or {}
        ok_exec = not desc.get("aborted") and (desc.get("compute_ph") or {}).get("success") is not False
        ev = {"tx": h, "from": im.get("source"), "to": im.get("destination"), "value_nano": value, "comment": comment, "utime": utime, "executed": ok_exec}
        if not tx:
            if want_amount and value < want_amount:
                continue
            if want_comment and comment.strip() != want_comment.strip():
                continue
            if after and utime < after:
                continue
        if not ok_exec:
            return "false", ev, ["a matching message exists but its transaction aborted"], []
        if tx and want_amount and value < want_amount:
            return "false", ev, ["the transaction exists; its value is below the claimed amount"], []
        return "true", ev, ["the transfer is on chain with this value, sender, comment and time"], ["the sender is who the agent says it is"]
    return "false", {"searched": len(txs), "account": account}, [f"no matching incoming transfer among the last {len(txs)} transactions of the account"], \
        ["a transfer older than those transactions would not be seen"] if len(txs) >= 300 else []


async def check_http_delivered(claim, client=None):
    url = str(claim.get("url") or "")
    exp = claim.get("expect") or {}
    import bazaar
    _h, err = await bazaar.check_url_async(url)
    if err:
        raise HTTPException(400, f"url: {err}")
    own = client is None
    client = client or httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False)
    try:
        r = await client.get(url, headers={"User-Agent": "minimalai-verify/1 (+https://ai.minimalcult.org/docs/verify)"})
        body = r.content[:65536]
    except Exception as e:  # noqa: BLE001
        return "unverifiable", {"reason": f"unreachable: {type(e).__name__}"}, [], ["the resource may exist; it could not be fetched now"]
    finally:
        if own:
            await client.aclose()
    ev = {"status": r.status_code, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body), "truncated": len(r.content) > 65536,
          "content_type": r.headers.get("content-type", "")}
    want_status = int(exp.get("status") or 200)
    if r.status_code != want_status:
        return "false", ev, [f"the resource answered {r.status_code}, not {want_status}"], []
    if exp.get("sha256") and ev["sha256"] != str(exp["sha256"]).lower():
        return ("unverifiable" if ev["truncated"] else "false"), ev, ["the first 64 KB hash differently from the claim"], \
            (["the body is longer than 64 KB; only the first 64 KB were hashed"] if ev["truncated"] else [])
    if exp.get("contains") and str(exp["contains"]).encode() not in body:
        return "false", ev, ["the claimed text is not in the first 64 KB of the body"], []
    return "true", ev, [f"the resource answered {r.status_code} now" + (" with the claimed hash" if exp.get("sha256") else "") + (" and the claimed text" if exp.get("contains") else "")], \
        ["the resource looked the same at the time the agent claims; we saw it now"]


async def check_message_sent(claim, client=None):
    chan = str(claim.get("channel") or "").lstrip("@").strip()
    try:
        mid = int(claim.get("message_id") or 0)
    except (TypeError, ValueError):
        mid = 0
    if not re.fullmatch(r"[A-Za-z0-9_]{4,64}", chan) or mid <= 0:
        raise HTTPException(400, "message_sent: channel (public username) and message_id (integer) are required")
    url = f"https://t.me/s/{chan}/{mid}"
    own = client is None
    client = client or httpx.AsyncClient(timeout=10, follow_redirects=True, trust_env=False)
    try:
        r = await client.get(url, headers={"User-Agent": "minimalai-verify/1"})
        html = r.text[:400_000]
    except Exception as e:  # noqa: BLE001
        return "unverifiable", {"reason": f"t.me unreachable: {type(e).__name__}"}, [], []
    finally:
        if own:
            await client.aclose()
    marker = f'data-post="{chan}/{mid}"'
    if r.status_code != 200 or "tgme_widget_message" not in html:
        return "unverifiable", {"status": r.status_code, "url": url}, [], ["the channel is private or has no public preview; we do not join chats"]
    if marker not in html:
        return "false", {"url": url}, [f"the public preview of @{chan} shows no message {mid}"], ["a deleted message disappears from the preview"]
    seg = html[html.index(marker):]
    text_ok = True
    if claim.get("contains"):
        text_ok = str(claim["contains"]) in seg[:20000]
    ev = {"url": url, "found": True, "contains": text_ok if claim.get("contains") else None}
    if not text_ok:
        return "false", ev, [f"message {mid} exists but does not contain the claimed text"], []
    return "true", ev, [f"message {mid} is visible on the public preview of @{chan}" + (" with the claimed text" if claim.get("contains") else "")], \
        ["the message was posted when the agent says; the preview shows it now"]


def check_receipt(claim):
    rec = claim.get("record")
    if not isinstance(rec, dict) or "sig" not in rec:
        raise HTTPException(400, "receipt: give the signed record as `record`")
    gk = str(rec.get("gateway_key") or "")
    if gk.lower() != receipts.public_key_hex().lower():
        return "unverifiable", {"gateway_key": gk[:16] + "…"}, [], ["the record names another issuer; only MINIMAL AI records are checked here"]
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(gk)).verify(base64.b64decode(rec["sig"]), receipts.canon({k: v for k, v in rec.items() if k != "sig"}))
    except Exception:  # noqa: BLE001
        return "false", {"receipt_id": receipts.receipt_id(rec)}, ["the signature does not match the record"], []
    return "true", {"receipt_id": receipts.receipt_id(rec), "kind": rec.get("kind", "answer"), "ts": rec.get("ts")}, \
        ["the signature is valid for the pinned gateway key"], ["what the record claims is as true as the issuer (see its own distrust block)"]


async def run_check(claim, fetch_txs=None, client=None):
    t = claim.get("type")
    if t == "ton_transfer":
        import pay402
        return await check_ton_transfer(claim, fetch_txs or (lambda acct: pay402.fetch_incoming(account=acct)))
    if t == "http_delivered":
        return await check_http_delivered(claim, client)
    if t == "message_sent":
        return await check_message_sent(claim, client)
    if t == "receipt":
        return check_receipt(claim)
    raise HTTPException(400, f"type must be one of {TYPES}")


def clean_claim(b):
    if not isinstance(b, dict) or b.get("type") not in TYPES:
        raise HTTPException(400, f"claim: {{type: {'|'.join(TYPES)}, ...}}")
    claim = {k: v for k, v in b.items() if k in ("type", "tx", "to", "account", "amount_nano", "comment", "after_ts", "url", "expect", "channel", "message_id", "contains", "record", "note")}
    if len(json.dumps(claim, ensure_ascii=False)) > 16000:
        raise HTTPException(400, "claim too large (16 KB)")
    return claim


def make_verdict(c, claim, result, evidence, observed, assumed, kh, price_nano, now=None):
    now = now or int(time.time())
    c.executescript(SCHEMA)
    prev = c.execute("SELECT sha256 FROM verdicts ORDER BY seq DESC LIMIT 1").fetchone()
    seq = (c.execute("SELECT max(seq) FROM verdicts").fetchone()[0] or 0) + 1
    vid = "v_" + uuid.uuid4().hex[:16]
    rec = receipts.sign({"v": 2, "kind": "verdict", "issuer": "MINIMALAI", "ts": now, "verdict_id": vid, "type": claim["type"],
                         "claim_sha256": claim_hash(claim), "claim": claim, "result": result, "evidence": evidence,
                         "method": {"ton_transfer": "toncenter API v3, incoming transactions of the account", "http_delivered": "one GET now, public https hosts, first 64 KB",
                                    "message_sent": "public preview t.me/s/<channel>/<id>", "receipt": "Ed25519 over the canonical record"}[claim["type"]],
                         "client": receipts.pseudonym("key:" + kh), "price_nano": price_nano, "prev_sha256": prev[0] if prev else None,
                         **receipts.delivery("executed", observed=observed, assumed=assumed + ["the check describes the moment it ran, not the moment the agent claims"],
                                             ack="POST /v1/receipts/{receipt_id}/ack")})
    c.execute("INSERT INTO verdicts(id,seq,ts,key_hash,type,result,claim_sha256,sha256,body) VALUES(?,?,?,?,?,?,?,?,?)",
              (vid, seq, now, kh, claim["type"], result, rec["claim_sha256"], receipts.sha256(rec), json.dumps(rec, ensure_ascii=False, sort_keys=True)))
    try:
        import notary
        notary.queue_answer(c, receipts.receipt_id(rec))   # anchored in TON with the next daily notary record
    except Exception:  # noqa: BLE001
        pass
    return rec


def setup(app, db, get_key, pay_gate):
    with db() as c:
        c.executescript(SCHEMA)

    @app.post("/v1/verify")
    async def verify(request: Request):
        """Paid: Bearer key (balance) or GRAM-402 (402 → transfer → X-PAYMENT). Body = the claim. Answer = the signed verdict."""
        try:
            b = await request.json()
        except ValueError:
            b = {}
        auth = request.headers.get("authorization")
        if not auth and not request.headers.get("x-payment"):
            return await pay_gate(request, b, "/v1/verify", PRICE_NANO)
        claim = clean_claim(b)
        settlement = None
        if auth:
            key = get_key(auth)
        else:
            gate = await pay_gate(request, b, "/v1/verify", PRICE_NANO)
            if isinstance(gate, JSONResponse):
                return gate
            key, settlement = gate
        kh, now = key["key_hash"], int(time.time())
        with db() as c:
            if c.execute("SELECT count(*) FROM verdicts WHERE key_hash=? AND ts>?", (kh, now - 86400)).fetchone()[0] >= PER_KEY_DAY:
                raise HTTPException(429, f"up to {PER_KEY_DAY} checks a day per key", headers={"Retry-After": "3600"})
        result, evidence, observed, assumed = await run_check(claim, getattr(app.state, "verify_fetch_txs", None), getattr(app.state, "verify_client", None))
        import starter
        with db() as c:
            charge = PRICE_NANO if result != "unverifiable" else 0           # nothing checked, nothing charged
            if charge:
                starter.spend(c, kh, charge, "verify")
            rec = make_verdict(c, claim, result, evidence, observed, assumed, kh, charge, now)
            left = c.execute("SELECT balance_nano FROM keys WHERE key_hash=?", (kh,)).fetchone()[0]
        out = {"verdict": rec, "result": result, "charged_nano": charge, "balance_left_nano": left,
               "anchoring": "the verdict is in the notary queue; the chain head is written to TON once a day (GET /v1/notary/chain)",
               "lookup": f"GET /v1/verify/{rec['verdict_id']}"}
        if settlement:
            out["payment"] = {"transaction": settlement["tx_hash"], "payer": settlement["payer"], "paid_nano": settlement["paid_nano"],
                              "api_key": settlement["api_key"], "note": "api_key is shown once; the rest of the payment is credit for more checks"}
        return out

    @app.get("/v1/verify")
    def about():
        return {"what": "a paid check of a claim, answered with a signed verdict: true, false or unverifiable, with evidence and the time of the check",
                "types": {"ton_transfer": "{tx, to} or {to, amount_nano, comment, after_ts}", "http_delivered": "{url, expect{status, sha256, contains}}",
                          "message_sent": "{channel, message_id, contains}", "receipt": "{record}"},
                "price_nano": PRICE_NANO, "price_note": "test price, announced as such; nothing is charged for an unverifiable outcome",
                "pay": "Bearer key, or GRAM-402: POST without a key -> 402 invoice -> pay -> repeat with X-PAYMENT",
                "verdict": "RECEIPTS v2 record (kind verdict) with delivery and distrust blocks; anchored in TON with the daily notary record",
                "chain": "GET /v1/verify/chain", "docs": "https://ai.minimalcult.org/docs/verify"}

    @app.get("/v1/verify/chain")
    def chain(limit: int = 50):
        with db() as c:
            rows = c.execute("SELECT id, seq, ts, type, result, sha256 FROM verdicts ORDER BY seq DESC LIMIT ?", (min(limit, 500),)).fetchall()
            n = c.execute("SELECT count(*) FROM verdicts").fetchone()[0]
            by = {r["result"]: r["n"] for r in c.execute("SELECT result, count(*) n FROM verdicts GROUP BY result")}
        return {"count": n, "by_result": by, "head": rows[0]["sha256"] if rows else None, "items": [dict(r) for r in rows], "gateway_key": receipts.public_key_hex()}

    @app.get("/v1/verify/{vid}")
    def one(vid: str):
        with db() as c:
            r = c.execute("SELECT body FROM verdicts WHERE id=?", (vid[:32],)).fetchone()
        if not r:
            raise HTTPException(404, "no such verdict")
        return json.loads(r["body"])
