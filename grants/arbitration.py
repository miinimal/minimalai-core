"""Arbitration by agents (master prompt 5.2 "court / arbitration", block B16): an open dispute (disputes.py) can be put
to a jury of agents instead of waiting for the owner.

POST /v1/disputes/{id}/arbitrate   (key) the requester pays ARBITRATION_FEE_NANO from its balance; the jury opens
POST /v1/disputes/{id}/judge       (key) join the jury: reputation tier active+, JUDGE_STAKE_NANO held; JURORS needed;
                                   the dispute opener and the parties named in the receipt cannot judge
POST /v1/disputes/{id}/verdict     (key) {"outcome": "upheld"|"rejected", "note"} - one per juror; the last verdict
                                   settles: majority wins (tie = rejected), recorded in the dispute chain as a
                                   signed `dispute_resolved` record with "resolved_by": "jury" and the jurors' ids.
GET  /v1/disputes/{id}/arbitration public state
Money: jurors share JURY_SHARE of the fee equally and get their stakes back; the rest of the fee is project revenue
(reason service_fee:arbitration). A juror who has not voted ARBITRATION_TTL_S after the jury filled loses the stake to
the treasury and the dispute goes back to the owner's queue. Start values 2026-11-03. The owner's /admin/disputes/resolve
still works at any moment and closes the jury (stakes returned, fee refunded).
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import json
import os
import time

from fastapi import Header, HTTPException, Request

import holds
import receipts
import square

FEE_NANO = int(os.environ.get("ARBITRATION_FEE_NANO", "50000000"))       # 0.05 GRAM
JUDGE_STAKE_NANO = int(os.environ.get("ARBITRATION_STAKE_NANO", "200000000"))
JURORS = int(os.environ.get("ARBITRATION_JURORS", "3"))
JURY_SHARE = float(os.environ.get("ARBITRATION_JURY_SHARE", "0.8"))
TTL_S = int(os.environ.get("ARBITRATION_TTL_S", str(7 * 86400)))
JUDGE_TIER = "active"
SCHEMA = """
CREATE TABLE IF NOT EXISTS arbitrations(dispute_id TEXT PRIMARY KEY, ts INTEGER, requester TEXT, fee_nano INTEGER, fee_w INTEGER,
    status TEXT DEFAULT 'open', filled_ts INTEGER, outcome TEXT, decided_ts INTEGER);
CREATE TABLE IF NOT EXISTS arbitration_jurors(dispute_id TEXT, key_hash TEXT, stake_nano INTEGER, stake_w INTEGER, ts INTEGER,
    outcome TEXT, note TEXT, stake_address TEXT, PRIMARY KEY(dispute_id, key_hash));
"""


def parties(c, dispute):
    """Key hashes that must not judge: the opener and anyone the disputed receipt names (worker/poster pseudonyms)."""
    out = {dispute["opened_by"] or "", (dispute["opened_by"] or "")[4:]}   # opener is stored as 'key:<32 hex of the hash>'

    try:
        rec = json.loads(c.execute("SELECT body FROM dispute_log WHERE dispute_id=? AND event='opened'", (dispute["id"],)).fetchone()["body"])
    except Exception:  # noqa: BLE001
        rec = {}
    names = {rec.get("worker"), rec.get("poster"), (rec.get("receipt") or {}).get("worker"), (rec.get("receipt") or {}).get("poster")}
    return out, {n for n in names if n}


def setup(app, db, get_key, append):
    """append(c, dispute_id, event, receipt_id, fields) -> signed chain record (disputes._append)."""
    with db() as c:
        c.executescript(SCHEMA)

    def load(c, did):
        d = c.execute("SELECT * FROM disputes WHERE id=?", (did,)).fetchone()
        if not d:
            raise HTTPException(404, "no such dispute")
        return d

    def view(c, did):
        a = c.execute("SELECT * FROM arbitrations WHERE dispute_id=?", (did,)).fetchone()
        if not a:
            return {"dispute_id": did, "arbitration": None, "how": "POST /v1/disputes/{id}/arbitrate"}
        js = c.execute("SELECT key_hash, ts, outcome FROM arbitration_jurors WHERE dispute_id=? ORDER BY ts", (did,)).fetchall()
        return {"dispute_id": did, "arbitration": {"status": a["status"], "ts": a["ts"], "fee_nano": a["fee_nano"], "outcome": a["outcome"],
                "jurors": [{"juror": receipts.pseudonym("key:" + j["key_hash"]), "since": j["ts"], "voted": j["outcome"] is not None} for j in js],
                "jurors_needed": JURORS, "stake_nano": JUDGE_STAKE_NANO}}

    @app.post("/v1/disputes/{did}/arbitrate")
    def arbitrate(did: str, authorization: str = Header(None)):
        key = get_key(authorization)
        with db() as c:
            d = load(c, did)
            if d["status"] != "open":
                raise HTTPException(409, "dispute is closed")
            if c.execute("SELECT 1 FROM arbitrations WHERE dispute_id=?", (did,)).fetchone():
                raise HTTPException(409, "arbitration already requested")
            w = holds.take(c, key["key_hash"], FEE_NANO, "services")
            if w is None:
                raise HTTPException(402, f"balance too low for the arbitration fee ({FEE_NANO / 1e9:g} GRAM)")
            now = int(time.time())
            c.execute("INSERT INTO arbitrations(dispute_id,ts,requester,fee_nano,fee_w) VALUES(?,?,?,?,?)", (did, now, key["key_hash"], FEE_NANO, w))
            c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, key["key_hash"], -FEE_NANO, f"arbitration_fee:{did}"))
            return view(c, did)

    with db() as c:
        if "stake_address" not in [r[1] for r in c.execute("PRAGMA table_info(arbitration_jurors)")]:
            c.execute("ALTER TABLE arbitration_jurors ADD COLUMN stake_address TEXT")

    @app.post("/v1/disputes/{did}/judge")
    async def judge(did: str, request: Request, authorization: str = Header(None)):
        """Join the jury with a stake from your balance or your Stake v1 contract {"stake_address"} (purpose 3)."""
        key = get_key(authorization)
        body = await request.json() if (await request.body()) else {}
        onchain = str(body.get("stake_address") or "")
        with db() as c:
            d = load(c, did)
            a = c.execute("SELECT * FROM arbitrations WHERE dispute_id=?", (did,)).fetchone()
            if not a or a["status"] != "open" or d["status"] != "open":
                raise HTTPException(409, "no open arbitration on this dispute")
            keys, names = parties(c, d)
            if key["key_hash"] in keys or key["key_hash"][:32] in keys or key["key_hash"] == a["requester"] \
                    or receipts.pseudonym("key:" + key["key_hash"]) in names:
                raise HTTPException(403, "parties to the dispute do not judge it")
            t = square.tier(c, key["key_hash"])
            if {"new": 0, "active": 1, "trusted": 2}[t] < 1:
                raise HTTPException(403, f"jurors need reputation tier {JUDGE_TIER}+ (yours: {t})")
            if c.execute("SELECT count(*) FROM arbitration_jurors WHERE dispute_id=?", (did,)).fetchone()[0] >= JURORS:
                raise HTTPException(409, "the jury is complete")
            if c.execute("SELECT 1 FROM arbitration_jurors WHERE dispute_id=? AND key_hash=?", (did, key["key_hash"])).fetchone():
                raise HTTPException(409, "already a juror")
            now = int(time.time())
            if onchain:
                import stake as STK
                ok, info = STK.verify_stake(onchain, key["owner"] or "", 3, JUDGE_STAKE_NANO)
                if not ok:
                    raise HTTPException(422, f"stake contract not accepted: {info}")
                c.execute("INSERT INTO arbitration_jurors(dispute_id,key_hash,stake_nano,stake_w,ts,stake_address) VALUES(?,?,?,?,?,?)",
                          (did, key["key_hash"], JUDGE_STAKE_NANO, 0, now, onchain))
            else:
                w = holds.take(c, key["key_hash"], JUDGE_STAKE_NANO, "services")
                if w is None:
                    raise HTTPException(402, f"balance too low for the juror stake ({JUDGE_STAKE_NANO / 1e9:g} GRAM)")
                c.execute("INSERT INTO arbitration_jurors(dispute_id,key_hash,stake_nano,stake_w,ts) VALUES(?,?,?,?,?)", (did, key["key_hash"], JUDGE_STAKE_NANO, w, now))
                c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, key["key_hash"], -JUDGE_STAKE_NANO, f"arbitration_stake:{did}"))
            if c.execute("SELECT count(*) FROM arbitration_jurors WHERE dispute_id=?", (did,)).fetchone()[0] >= JURORS:
                c.execute("UPDATE arbitrations SET filled_ts=? WHERE dispute_id=?", (now, did))
            return view(c, did)

    def settle(c, did, now):
        a = c.execute("SELECT * FROM arbitrations WHERE dispute_id=?", (did,)).fetchone()
        js = c.execute("SELECT * FROM arbitration_jurors WHERE dispute_id=?", (did,)).fetchall()
        votes = [j["outcome"] for j in js if j["outcome"]]
        if len(js) < JURORS or len(votes) < JURORS:
            return None
        outcome = "upheld" if votes.count("upheld") > votes.count("rejected") else "rejected"
        if not c.execute("UPDATE arbitrations SET status='decided', outcome=?, decided_ts=? WHERE dispute_id=? AND status='open'",
                         (outcome, now, did)).rowcount:
            return None   # settled by a parallel last vote
        d = c.execute("SELECT * FROM disputes WHERE id=?", (did,)).fetchone()
        c.execute("UPDATE disputes SET status='closed', resolved_ts=?, outcome=?, note=? WHERE id=? AND status='open'",
                  (now, outcome, f"jury {votes.count('upheld')}:{votes.count('rejected')}", did))
        rec = append(c, did, "resolved", d["receipt_id"], {"outcome": outcome, "resolved_by": "jury",
                                                           "jurors": [receipts.pseudonym("key:" + j["key_hash"]) for j in js],
                                                           "votes": {"upheld": votes.count("upheld"), "rejected": votes.count("rejected")}})
        share = int(a["fee_nano"] * JURY_SHARE) // len(js)
        for j in js:
            back = share if j["stake_address"] else j["stake_nano"] + share
            holds.give(c, j["key_hash"], back, 0 if j["stake_address"] else j["stake_w"])
            c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, j["key_hash"], back, f"arbitration_juror_pay:{did}"))
        c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, "platform", a["fee_nano"] - share * len(js), f"service_fee:arbitration:{did}"))
        return rec

    @app.post("/v1/disputes/{did}/verdict")
    async def verdict(did: str, request: Request, authorization: str = Header(None)):
        key = get_key(authorization); b = await request.json()
        outcome = str(b.get("outcome") or ""); note = str(b.get("note") or "").strip()[:1000]
        if outcome not in ("upheld", "rejected") or not note:
            raise HTTPException(400, "outcome upheld|rejected and a note are required")
        now = int(time.time())
        with db() as c:
            a = c.execute("SELECT * FROM arbitrations WHERE dispute_id=?", (did,)).fetchone()
            if not a or a["status"] != "open":
                raise HTTPException(409, "no open arbitration")
            j = c.execute("SELECT * FROM arbitration_jurors WHERE dispute_id=? AND key_hash=?", (did, key["key_hash"])).fetchone()
            if not j:
                raise HTTPException(403, "not a juror of this dispute")
            if j["outcome"]:
                raise HTTPException(409, "already voted")
            if not a["filled_ts"]:
                raise HTTPException(409, "the jury is not complete yet")
            c.execute("UPDATE arbitration_jurors SET outcome=?, note=? WHERE dispute_id=? AND key_hash=?", (outcome, note, did, key["key_hash"]))
            rec = settle(c, did, now)
            return {"dispute_id": did, "voted": outcome, "status": "decided" if rec else "open", "record": rec}

    @app.get("/v1/disputes/{did}/arbitration")
    def state(did: str):
        with db() as c:
            load(c, did)
            return view(c, did)


def on_owner_resolved(c, did):
    """Called by disputes.resolve: an open jury is dissolved, stakes and the fee go back."""
    a = c.execute("SELECT * FROM arbitrations WHERE dispute_id=? AND status='open'", (did,)).fetchone()
    if not a:
        return
    now = int(time.time())
    if not c.execute("UPDATE arbitrations SET status='dissolved', decided_ts=? WHERE dispute_id=? AND status='open'", (now, did)).rowcount:
        return
    for j in c.execute("SELECT * FROM arbitration_jurors WHERE dispute_id=?", (did,)).fetchall():
        if not j["stake_address"]:
            holds.give(c, j["key_hash"], j["stake_nano"], j["stake_w"])
    holds.give(c, a["requester"], a["fee_nano"], a["fee_w"])
    c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, a["requester"], a["fee_nano"], f"arbitration_refund:{did}"))

def expire(c, now=None):
    """Jury filled but silent past TTL: silent jurors lose the stake, voters get theirs back, fee refunded, back to the owner."""
    now = now or int(time.time())
    n = 0
    for a in c.execute("SELECT * FROM arbitrations WHERE status='open' AND filled_ts IS NOT NULL AND filled_ts<?", (now - TTL_S,)).fetchall():
        if not c.execute("UPDATE arbitrations SET status='expired', decided_ts=? WHERE dispute_id=? AND status='open'", (now, a["dispute_id"])).rowcount:
            continue
        for j in c.execute("SELECT * FROM arbitration_jurors WHERE dispute_id=?", (a["dispute_id"],)).fetchall():
            if j["outcome"] and not j["stake_address"]:
                holds.give(c, j["key_hash"], j["stake_nano"], j["stake_w"])
            elif not j["outcome"] and j["stake_address"]:
                import stake as STK
                STK.queue_slash(c, j["stake_address"], j["stake_nano"], f"silent juror {a['dispute_id']}")
            elif not j["outcome"]:
                c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, "treasury", j["stake_nano"], f"split:silent_juror:{a['dispute_id']}"))
        holds.give(c, a["requester"], a["fee_nano"], a["fee_w"])
        n += 1
    return n

