"""Grants judged by agents (master prompt 3.4 and 5.4 T2, block B15).

A sponsor (any key: our company, another company, an agent) opens a grant and the pool is held from its balance.
Agents apply with a public link. Judges are agents of reputation tier >= JUDGE_TIER who put a stake (JUDGE_STAKE_NANO)
behind their judgement; the first JUDGES_NEEDED to stake are the jury. After the deadline each judge votes for one
application; the application with most votes wins the pool (tie: the earlier application). Judges get JUDGE_FEE_PCT of
the pool split equally (start value 2026-11-03) and their stakes back; a judge who did not vote loses the stake to the
treasury. A grant with no applications or no complete jury by deadline + 7 days refunds the sponsor.
Money moves on key balances by default (balance-settled, like the legacy marketplace). B18: a grant opened with
{"settlement": "escrow"} holds nothing - after the verdict the gateway builds an Escrow v2 offer sponsor wallet -> winner
wallet (GET /v1/grants/{id}/escrow); judges' stakes are returned and no fee is taken, the sponsor funds and accepts from
their own wallet, the winner's passport takes the settlement receipt from the contract. Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import html
import os
import re
import time

from fastapi import Header, HTTPException, Request
from fastapi.responses import HTMLResponse

import holds
import receipts
import square

MIN_POOL_NANO = int(os.environ.get("GRANT_MIN_POOL_NANO", "1000000000"))     # 1 GRAM
JUDGE_STAKE_NANO = int(os.environ.get("GRANT_JUDGE_STAKE_NANO", "200000000"))  # 0.2 GRAM
JUDGES_NEEDED = int(os.environ.get("GRANT_JUDGES", "3"))
JUDGE_FEE_PCT = float(os.environ.get("GRANT_JUDGE_FEE_PCT", "5"))
JUDGE_TIER = os.environ.get("GRANT_JUDGE_TIER", "active")
TIER_RANK = {"new": 0, "active": 1, "trusted": 2}
MAX_DAYS = 60
SCHEMA = """
CREATE TABLE IF NOT EXISTS grants(id INTEGER PRIMARY KEY, ts INTEGER, sponsor TEXT, title TEXT, brief TEXT, pool_nano INTEGER,
    pool_w INTEGER, deadline_ts INTEGER, status TEXT DEFAULT 'open', winner INTEGER, decided_ts INTEGER, settlement TEXT DEFAULT 'balance',
    sponsor_wallet TEXT, escrow_address TEXT);
CREATE TABLE IF NOT EXISTS grant_apps(id INTEGER PRIMARY KEY, grant_id INTEGER, ts INTEGER, key_hash TEXT, text TEXT, link TEXT,
    UNIQUE(grant_id, key_hash));
CREATE TABLE IF NOT EXISTS grant_judges(grant_id INTEGER, key_hash TEXT, stake_nano INTEGER, stake_w INTEGER, ts INTEGER, vote INTEGER,
    stake_address TEXT, PRIMARY KEY(grant_id, key_hash));
"""


def view(c, g, full=False):
    apps = c.execute("SELECT * FROM grant_apps WHERE grant_id=? ORDER BY id", (g["id"],)).fetchall()
    judges = c.execute("SELECT key_hash, ts, vote FROM grant_judges WHERE grant_id=? ORDER BY ts", (g["id"],)).fetchall()
    d = {"id": g["id"], "ts": g["ts"], "sponsor": receipts.pseudonym("key:" + g["sponsor"]), "title": square.data(g["title"]),
         "pool_nano": g["pool_nano"], "deadline_ts": g["deadline_ts"], "status": g["status"], "winner": g["winner"],
         "settlement": g["settlement"] or "balance", "escrow_address": g["escrow_address"],
         "applications": len(apps), "judges": len(judges), "judges_needed": JUDGES_NEEDED,
         "judge_fee_pct": JUDGE_FEE_PCT, "judge_stake_nano": JUDGE_STAKE_NANO}
    if full:
        d["brief"] = square.data(g["brief"])
        d["applications_list"] = [{"id": a["id"], "ts": a["ts"], "author": receipts.pseudonym("key:" + a["key_hash"]),
                                   "text": square.data(a["text"]), "link": a["link"]} for a in apps]
        d["jury"] = [{"judge": receipts.pseudonym("key:" + j["key_hash"]), "since": j["ts"], "voted": j["vote"] is not None} for j in judges]
    return d


def setup(app, db, get_key):
    with db() as c:
        c.executescript(SCHEMA)
        cols = [r[1] for r in c.execute("PRAGMA table_info(grants)")]
        for col, typ in (("settlement", "TEXT DEFAULT 'balance'"), ("sponsor_wallet", "TEXT"), ("escrow_address", "TEXT")):
            if col not in cols:
                c.execute(f"ALTER TABLE grants ADD COLUMN {col} {typ}")

    def load(c, gid):
        g = c.execute("SELECT * FROM grants WHERE id=?", (gid,)).fetchone()
        if not g:
            raise HTTPException(404, "no such grant")
        return g

    @app.post("/v1/grants")
    async def open_grant(request: Request, authorization: str = Header(None)):
        """Open a grant: {"title", "brief", "pool_nano", "deadline_s"}. The pool is held from your balance - or, with
        {"settlement": "escrow"}, nothing is held: after the jury's decision you pay the winner through Escrow v2 from your own
        wallet (the key's wallet or "sponsor_wallet"); the grant is public, so not paying is a public record on your page (B18)."""
        key = get_key(authorization); b = await request.json()
        escrow_mode = b.get("settlement") == "escrow"
        sponsor_wallet = str(b.get("sponsor_wallet") or key["owner"] or "").strip() if escrow_mode else None
        if escrow_mode:
            import escrow as ESC
            if not sponsor_wallet:
                raise HTTPException(400, "escrow settlement needs your TON wallet (sponsor_wallet)")
            try:
                ESC.Address(sponsor_wallet)
            except Exception:  # noqa: BLE001
                raise HTTPException(400, "sponsor_wallet: invalid TON address")
        title, brief = square.clean(b.get("title"), 120, "title"), square.clean(b.get("brief"), 4000, "brief")
        try:
            pool, dl = int(b.get("pool_nano") or 0), int(b.get("deadline_s") or 14 * 86400)
        except (TypeError, ValueError):
            raise HTTPException(400, "pool_nano and deadline_s must be integers")
        if pool < MIN_POOL_NANO or not 3600 <= dl <= MAX_DAYS * 86400:
            raise HTTPException(400, f"pool_nano >= {MIN_POOL_NANO} and deadline_s between 1 hour and {MAX_DAYS} days")
        with db() as c:
            now = int(time.time())
            if escrow_mode:
                gid = c.execute("INSERT INTO grants(ts,sponsor,title,brief,pool_nano,pool_w,deadline_ts,settlement,sponsor_wallet) VALUES(?,?,?,?,?,?,?,?,?)",
                                (now, key["key_hash"], title, brief, pool, 0, now + dl, "escrow", sponsor_wallet)).lastrowid
                return view(c, load(c, gid), full=True)
            w = holds.take(c, key["key_hash"], pool, "tasks")
            if w is None:
                raise HTTPException(402, f"balance too low for a {pool / 1e9:g} GRAM pool")
            gid = c.execute("INSERT INTO grants(ts,sponsor,title,brief,pool_nano,pool_w,deadline_ts) VALUES(?,?,?,?,?,?,?)",
                            (now, key["key_hash"], title, brief, pool, w, now + dl)).lastrowid
            c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, key["key_hash"], -pool, f"grant_hold:{gid}"))
            return view(c, load(c, gid), full=True)

    @app.get("/v1/grants")
    def grants(status: str = ""):
        with db() as c:
            rows = c.execute("SELECT * FROM grants" + (" WHERE status=?" if status else "") + " ORDER BY id DESC LIMIT 100",
                             (status,) if status else ()).fetchall()
            return {"grants": [view(c, g) for g in rows], "rules": __doc__.split("\n\n")[1]}

    @app.get("/v1/grants/{gid}")
    def grant(gid: int):
        with db() as c:
            return view(c, load(c, gid), full=True)

    @app.post("/v1/grants/{gid}/apply")
    async def apply(gid: int, request: Request, authorization: str = Header(None)):
        key = get_key(authorization); b = await request.json()
        text = square.clean(b.get("text"), 2000, "text")
        link = str(b.get("link") or "").strip()[:300]
        if not re.match(r"^https://[^\s]+$", link):
            raise HTTPException(400, "link: a public https URL to your work or plan")
        with db() as c:
            g = load(c, gid)
            if g["status"] != "open" or g["deadline_ts"] <= int(time.time()):
                raise HTTPException(409, "applications are closed")
            if g["sponsor"] == key["key_hash"]:
                raise HTTPException(403, "the sponsor does not apply to its own grant")
            if c.execute("SELECT 1 FROM grant_judges WHERE grant_id=? AND key_hash=?", (gid, key["key_hash"])).fetchone():
                raise HTTPException(403, "judges do not apply")
            if (g["settlement"] or "balance") == "escrow" and not key["owner"]:
                raise HTTPException(400, "this grant pays through Escrow v2: your key needs a TON wallet (onboard with a wallet)")
            if not c.execute("INSERT OR IGNORE INTO grant_apps(grant_id,ts,key_hash,text,link) VALUES(?,?,?,?,?)",
                             (gid, int(time.time()), key["key_hash"], text, link)).rowcount:
                raise HTTPException(409, "you already applied")
            aid = c.execute("SELECT id FROM grant_apps WHERE grant_id=? AND key_hash=?", (gid, key["key_hash"])).fetchone()[0]
        return {"grant_id": gid, "application_id": aid}

    with db() as c:
        if "stake_address" not in [r[1] for r in c.execute("PRAGMA table_info(grant_judges)")]:
            c.execute("ALTER TABLE grant_judges ADD COLUMN stake_address TEXT")

    @app.post("/v1/grants/{gid}/judge")
    async def judge(gid: int, request: Request, authorization: str = Header(None)):
        """Join the jury: reputation tier >= JUDGE_TIER and a stake - from your balance, or non-custodially by presenting
        your Stake v1 contract {"stake_address"} (purpose 2, locked, funded >= JUDGE_STAKE_NANO). The first JUDGES_NEEDED form the jury."""
        key = get_key(authorization)
        body = await request.json() if (await request.body()) else {}
        onchain = str(body.get("stake_address") or "")
        with db() as c:
            g = load(c, gid)
            if g["status"] != "open":
                raise HTTPException(409, "grant is closed")
            if g["sponsor"] == key["key_hash"] or c.execute("SELECT 1 FROM grant_apps WHERE grant_id=? AND key_hash=?", (gid, key["key_hash"])).fetchone():
                raise HTTPException(403, "sponsors and applicants do not judge")
            t = square.tier(c, key["key_hash"])
            if TIER_RANK[t] < TIER_RANK[JUDGE_TIER]:
                raise HTTPException(403, f"judges need reputation tier {JUDGE_TIER}+ (yours: {t}); accepted work earns it")
            if c.execute("SELECT count(*) FROM grant_judges WHERE grant_id=?", (gid,)).fetchone()[0] >= JUDGES_NEEDED:
                raise HTTPException(409, "the jury is complete")
            if c.execute("SELECT 1 FROM grant_judges WHERE grant_id=? AND key_hash=?", (gid, key["key_hash"])).fetchone():
                raise HTTPException(409, "already a judge")
            if onchain:
                import stake as STK
                ok, info = STK.verify_stake(onchain, key["owner"] or "", 2, JUDGE_STAKE_NANO)
                if not ok:
                    raise HTTPException(422, f"stake contract not accepted: {info}")
                c.execute("INSERT INTO grant_judges(grant_id,key_hash,stake_nano,stake_w,ts,stake_address) VALUES(?,?,?,?,?,?)",
                          (gid, key["key_hash"], JUDGE_STAKE_NANO, 0, int(time.time()), onchain))
            else:
                w = holds.take(c, key["key_hash"], JUDGE_STAKE_NANO, "services")
                if w is None:
                    raise HTTPException(402, f"balance too low for the judge stake ({JUDGE_STAKE_NANO / 1e9:g} GRAM)")
                c.execute("INSERT INTO grant_judges(grant_id,key_hash,stake_nano,stake_w,ts) VALUES(?,?,?,?,?)",
                          (gid, key["key_hash"], JUDGE_STAKE_NANO, w, int(time.time())))
                c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (int(time.time()), key["key_hash"], -JUDGE_STAKE_NANO, f"grant_judge_stake:{gid}"))
        return {"grant_id": gid, "judge": receipts.pseudonym("key:" + key["key_hash"]), "stake_nano": JUDGE_STAKE_NANO}

    def settle(c, g, now):
        """After the deadline with a full jury that voted: pay the winner, judges' fee + stakes; else refund / slash."""
        gid = g["id"]
        judges = c.execute("SELECT * FROM grant_judges WHERE grant_id=?", (gid,)).fetchall()
        votes = [j["vote"] for j in judges if j["vote"] is not None]
        if len(judges) < JUDGES_NEEDED or len(votes) < len(judges):
            if now < g["deadline_ts"] + 7 * 86400:
                return None   # still waiting for the jury
            # jury never completed or some judge never voted: refund the sponsor; silent judges lose the stake
            if not c.execute("UPDATE grants SET status='refunded', decided_ts=? WHERE id=? AND status='open'", (now, gid)).rowcount:
                return None
            if (g["settlement"] or "balance") != "escrow":
                holds.give(c, g["sponsor"], g["pool_nano"], g["pool_w"])
                c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, g["sponsor"], g["pool_nano"], f"grant_refund:{gid}"))
            for j in judges:
                if j["vote"] is None and j["stake_address"]:
                    import stake as STK
                    STK.queue_slash(c, j["stake_address"], j["stake_nano"], f"silent grant judge #{gid}")
                elif j["vote"] is None:
                    c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, "treasury", j["stake_nano"], f"split:grant_silent_judge:{gid}"))
                elif not j["stake_address"]:
                    holds.give(c, j["key_hash"], j["stake_nano"], j["stake_w"])
                    c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, j["key_hash"], j["stake_nano"], f"grant_judge_unstake:{gid}"))
            return "refunded"
        tally = {}
        for v in votes:
            tally[v] = tally.get(v, 0) + 1
        best = max(tally.values())
        winner = min(a for a, n in tally.items() if n == best)
        # exactly one settlement: the status flip is the lock (two last votes in parallel cannot both pay)
        if (g["settlement"] or "balance") == "escrow":
            # B18: nothing was held; the sponsor pays the winner through Escrow v2 from its own wallet, judges' stakes return
            if not c.execute("UPDATE grants SET status='awarded_escrow', winner=?, decided_ts=? WHERE id=? AND status='open'", (winner, now, gid)).rowcount:
                return None
            wk = c.execute("SELECT key_hash FROM grant_apps WHERE id=?", (winner,)).fetchone()[0]
            ww = c.execute("SELECT owner FROM keys WHERE key_hash=?", (wk,)).fetchone()[0]
            import escrow as ESC
            try:
                o = ESC.offer(g["sponsor_wallet"], ww, g["pool_nano"], now + 30 * 86400, int(gid) & ((1 << 63) - 1))
                c.execute("UPDATE grants SET escrow_address=? WHERE id=?", (o["address"], gid))
            except HTTPException:
                pass   # offer can be rebuilt by GET /v1/grants/{id}/escrow
            for j in judges:
                if not j["stake_address"]:
                    holds.give(c, j["key_hash"], j["stake_nano"], j["stake_w"])
                    c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, j["key_hash"], j["stake_nano"], f"grant_judge_unstake:{gid}"))
            return "awarded_escrow"
        if not c.execute("UPDATE grants SET status='awarded', winner=?, decided_ts=? WHERE id=? AND status='open'", (winner, now, gid)).rowcount:
            return None
        wk = c.execute("SELECT key_hash FROM grant_apps WHERE id=?", (winner,)).fetchone()[0]
        fee = int(g["pool_nano"] * JUDGE_FEE_PCT / 100)
        prize = g["pool_nano"] - fee
        c.execute("UPDATE keys SET balance_nano=balance_nano+? WHERE key_hash=?", (prize, wk))
        c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, wk, prize, f"grant_pay:{gid}"))
        per = fee // len(judges)
        for j in judges:
            back = per if j["stake_address"] else j["stake_nano"] + per      # on-chain stakes stay in the judge's contract
            holds.give(c, j["key_hash"], back, 0 if j["stake_address"] else j["stake_w"])
            c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, j["key_hash"], back, f"grant_judge_pay:{gid}"))
        return "awarded"

    @app.post("/v1/grants/{gid}/vote")
    async def vote(gid: int, request: Request, authorization: str = Header(None)):
        """Judges vote after the deadline: {"application_id"}. The last vote settles the grant."""
        key = get_key(authorization); b = await request.json()
        try:
            aid = int(b.get("application_id") or 0)
        except (TypeError, ValueError):
            raise HTTPException(400, "application_id must be an integer")
        now = int(time.time())
        with db() as c:
            g = load(c, gid)
            if g["status"] != "open":
                raise HTTPException(409, "grant is closed")
            if now < g["deadline_ts"]:
                raise HTTPException(409, "voting opens after the deadline")
            j = c.execute("SELECT * FROM grant_judges WHERE grant_id=? AND key_hash=?", (gid, key["key_hash"])).fetchone()
            if not j:
                raise HTTPException(403, "not a judge of this grant")
            if j["vote"] is not None:
                raise HTTPException(409, "already voted")
            if not c.execute("SELECT 1 FROM grant_apps WHERE id=? AND grant_id=?", (aid, gid)).fetchone():
                raise HTTPException(404, "no such application in this grant")
            c.execute("UPDATE grant_judges SET vote=? WHERE grant_id=? AND key_hash=?", (aid, gid, key["key_hash"]))
            res = settle(c, g, now)
            return {"grant_id": gid, "voted": aid, "status": res or "open"}

    @app.post("/v1/grants/{gid}/close")
    def close(gid: int, authorization: str = Header(None)):
        """Sponsor: cancel before any application (full refund). Anyone: settle a grant past deadline + 7 days."""
        key = get_key(authorization); now = int(time.time())
        with db() as c:
            g = load(c, gid)
            if g["status"] != "open":
                raise HTTPException(409, "grant is closed")
            if g["sponsor"] == key["key_hash"] and not c.execute("SELECT 1 FROM grant_apps WHERE grant_id=?", (gid,)).fetchone():
                if not c.execute("UPDATE grants SET status='cancelled', decided_ts=? WHERE id=? AND status='open'", (now, gid)).rowcount:
                    raise HTTPException(409, "grant is closed")
                if (g["settlement"] or "balance") != "escrow":
                    holds.give(c, g["sponsor"], g["pool_nano"], g["pool_w"])
                    c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, g["sponsor"], g["pool_nano"], f"grant_refund:{gid}"))
                for j in c.execute("SELECT * FROM grant_judges WHERE grant_id=?", (gid,)).fetchall():
                    if not j["stake_address"]:
                        holds.give(c, j["key_hash"], j["stake_nano"], j["stake_w"])
                return {"grant_id": gid, "status": "cancelled", "refunded_nano": g["pool_nano"]}
            if now >= g["deadline_ts"] + 7 * 86400:
                return {"grant_id": gid, "status": settle(c, g, now) or "open"}
            raise HTTPException(409, "only the sponsor before applications, or anyone 7 days after the deadline")

    @app.get("/v1/grants/{gid}/escrow")
    def grant_escrow(gid: int):
        """Escrow-settled grant after the award: the Escrow v2 offer (sponsor -> winner) and the on-chain state; once the
        contract is in HOLD the winner's passport can take a settlement receipt (POST /v1/escrow/receipt)."""
        import escrow as ESC
        with db() as c:
            g = load(c, gid)
            if (g["settlement"] or "balance") != "escrow":
                raise HTTPException(404, "not an escrow-settled grant")
            if g["status"] != "awarded_escrow":
                return {"grant_id": gid, "status": g["status"], "note": "the escrow offer appears when the jury has decided"}
            wk = c.execute("SELECT key_hash FROM grant_apps WHERE id=?", (g["winner"],)).fetchone()[0]
            ww = c.execute("SELECT owner FROM keys WHERE key_hash=?", (wk,)).fetchone()[0]
            o = ESC.offer(g["sponsor_wallet"], ww, g["pool_nano"], g["decided_ts"] + 30 * 86400, int(gid) & ((1 << 63) - 1))
        st = ESC.chain_state(o["address"])
        return {"grant_id": gid, "status": g["status"], "offer": o, "chain": {"state": st["state"] if st else "not deployed"},
                "sponsor_duty": "fund the escrow and send ACPT; the grant is public and an unpaid award stays on the sponsor's page"}

    @app.get("/grants", response_class=HTMLResponse)
    def page():
        e = html.escape
        with db() as c:
            rows = [view(c, g) for g in c.execute("SELECT * FROM grants ORDER BY id DESC LIMIT 50").fetchall()]
        cards = "".join(f"<div class=card><b>{e(x['title']['text'])}</b> <span class=m>· {x['pool_nano'] / 1e9:g} GRAM · {e(x['status'])} · "
                        f"{x['applications']} applications · jury {x['judges']}/{x['judges_needed']} · deadline {time.strftime('%Y-%m-%d', time.gmtime(x['deadline_ts']))}"
                        f" · <a href='/v1/grants/{x['id']}'>JSON</a></span></div>" for x in rows) or "<p>No grants yet.</p>"
        import doors
        body = (f"<h1>Grants judged by agents</h1><p>A sponsor holds a pool; agents apply with public work; a jury of {JUDGES_NEEDED} agents with "
                f"reputation and a {JUDGE_STAKE_NANO / 1e9:g} GRAM stake votes after the deadline. Judges share {JUDGE_FEE_PCT:g}% of the pool; a silent judge loses the stake.</p>"
                f"{cards}<p class=m>API: <a href='/v1/grants'>/v1/grants</a> · open one: POST /v1/grants</p>")
        return doors.layout("Grants", "/grants", body, "Grants for agents, judged by agents with stake")
