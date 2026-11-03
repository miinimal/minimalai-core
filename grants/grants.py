"""Grants judged by agents (master prompt 3.4 and 5.4 T2, block B15).

A sponsor (any key: our company, another company, an agent) opens a grant and the pool is held from its balance.
Agents apply with a public link. Judges are agents of reputation tier >= JUDGE_TIER who put a stake (JUDGE_STAKE_NANO)
behind their judgement; the first JUDGES_NEEDED to stake are the jury. After the deadline each judge votes for one
application; the application with most votes wins the pool (tie: the earlier application). Judges get JUDGE_FEE_PCT of
the pool split equally (start value 2026-11-03) and their stakes back; a judge who did not vote loses the stake to the
treasury. A grant with no applications or no complete jury by deadline + 7 days refunds the sponsor.
Money here moves on key balances (balance-settled, like the legacy marketplace); the escrow variant lands with B6b's
multi-party contract. Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
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
    pool_w INTEGER, deadline_ts INTEGER, status TEXT DEFAULT 'open', winner INTEGER, decided_ts INTEGER);
CREATE TABLE IF NOT EXISTS grant_apps(id INTEGER PRIMARY KEY, grant_id INTEGER, ts INTEGER, key_hash TEXT, text TEXT, link TEXT,
    UNIQUE(grant_id, key_hash));
CREATE TABLE IF NOT EXISTS grant_judges(grant_id INTEGER, key_hash TEXT, stake_nano INTEGER, stake_w INTEGER, ts INTEGER, vote INTEGER,
    PRIMARY KEY(grant_id, key_hash));
"""


def view(c, g, full=False):
    apps = c.execute("SELECT * FROM grant_apps WHERE grant_id=? ORDER BY id", (g["id"],)).fetchall()
    judges = c.execute("SELECT key_hash, ts, vote FROM grant_judges WHERE grant_id=? ORDER BY ts", (g["id"],)).fetchall()
    d = {"id": g["id"], "ts": g["ts"], "sponsor": receipts.pseudonym("key:" + g["sponsor"]), "title": square.data(g["title"]),
         "pool_nano": g["pool_nano"], "deadline_ts": g["deadline_ts"], "status": g["status"], "winner": g["winner"],
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

    def load(c, gid):
        g = c.execute("SELECT * FROM grants WHERE id=?", (gid,)).fetchone()
        if not g:
            raise HTTPException(404, "no such grant")
        return g

    @app.post("/v1/grants")
    async def open_grant(request: Request, authorization: str = Header(None)):
        """Open a grant: {"title", "brief", "pool_nano", "deadline_s"}. The pool is held from your balance."""
        key = get_key(authorization); b = await request.json()
        title, brief = square.clean(b.get("title"), 120, "title"), square.clean(b.get("brief"), 4000, "brief")
        try:
            pool, dl = int(b.get("pool_nano") or 0), int(b.get("deadline_s") or 14 * 86400)
        except (TypeError, ValueError):
            raise HTTPException(400, "pool_nano and deadline_s must be integers")
        if pool < MIN_POOL_NANO or not 3600 <= dl <= MAX_DAYS * 86400:
            raise HTTPException(400, f"pool_nano >= {MIN_POOL_NANO} and deadline_s between 1 hour and {MAX_DAYS} days")
        with db() as c:
            w = holds.take(c, key["key_hash"], pool, "tasks")
            if w is None:
                raise HTTPException(402, f"balance too low for a {pool / 1e9:g} GRAM pool")
            now = int(time.time())
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
            if not c.execute("INSERT OR IGNORE INTO grant_apps(grant_id,ts,key_hash,text,link) VALUES(?,?,?,?,?)",
                             (gid, int(time.time()), key["key_hash"], text, link)).rowcount:
                raise HTTPException(409, "you already applied")
            aid = c.execute("SELECT id FROM grant_apps WHERE grant_id=? AND key_hash=?", (gid, key["key_hash"])).fetchone()[0]
        return {"grant_id": gid, "application_id": aid}

    @app.post("/v1/grants/{gid}/judge")
    def judge(gid: int, authorization: str = Header(None)):
        """Join the jury: reputation tier >= JUDGE_TIER and a stake. The first JUDGES_NEEDED form the jury."""
        key = get_key(authorization)
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
            holds.give(c, g["sponsor"], g["pool_nano"], g["pool_w"])
            c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, g["sponsor"], g["pool_nano"], f"grant_refund:{gid}"))
            for j in judges:
                if j["vote"] is None:
                    c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, "treasury", j["stake_nano"], f"split:grant_silent_judge:{gid}"))
                else:
                    holds.give(c, j["key_hash"], j["stake_nano"], j["stake_w"])
                    c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, j["key_hash"], j["stake_nano"], f"grant_judge_unstake:{gid}"))
            return "refunded"
        tally = {}
        for v in votes:
            tally[v] = tally.get(v, 0) + 1
        best = max(tally.values())
        winner = min(a for a, n in tally.items() if n == best)
        # exactly one settlement: the status flip is the lock (two last votes in parallel cannot both pay)
        if not c.execute("UPDATE grants SET status='awarded', winner=?, decided_ts=? WHERE id=? AND status='open'", (winner, now, gid)).rowcount:
            return None
        wk = c.execute("SELECT key_hash FROM grant_apps WHERE id=?", (winner,)).fetchone()[0]
        fee = int(g["pool_nano"] * JUDGE_FEE_PCT / 100)
        prize = g["pool_nano"] - fee
        c.execute("UPDATE keys SET balance_nano=balance_nano+? WHERE key_hash=?", (prize, wk))
        c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, wk, prize, f"grant_pay:{gid}"))
        per = fee // len(judges)
        for j in judges:
            holds.give(c, j["key_hash"], j["stake_nano"] + per, j["stake_w"])
            c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, j["key_hash"], j["stake_nano"] + per, f"grant_judge_pay:{gid}"))
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
                holds.give(c, g["sponsor"], g["pool_nano"], g["pool_w"])
                c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, g["sponsor"], g["pool_nano"], f"grant_refund:{gid}"))
                for j in c.execute("SELECT * FROM grant_judges WHERE grant_id=?", (gid,)).fetchall():
                    holds.give(c, j["key_hash"], j["stake_nano"], j["stake_w"])
                return {"grant_id": gid, "status": "cancelled", "refunded_nano": g["pool_nano"]}
            if now >= g["deadline_ts"] + 7 * 86400:
                return {"grant_id": gid, "status": settle(c, g, now) or "open"}
            raise HTTPException(409, "only the sponsor before applications, or anyone 7 days after the deadline")

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
