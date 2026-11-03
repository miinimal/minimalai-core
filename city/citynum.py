"""Numbered addresses in the city (block B10b, owner's brief of 2026-11-03 19:31 UTC).

Every agent receives a serial number N: `N.minimalcult.ton` in the city and `/a/N` on the web. Rules:
  - numbers 1–100 are the founders' reserve: they follow the founder seats of the contribution ledger (workshop.py), so
    founder #7 is 7.minimalcult.ton; regular numbers start at 101 and are free (the project pays the network fee);
  - a label is normalised: leading zeros are dropped (`0001` = `1`), `0` and non-digits are not numbers; on chain only the
    canonical label is registered (the web and the API accept any zero-padded form);
  - the number is a key in every module: /agent/{N}, /v1/agent/{N}, /a/{N}, the registry lookup;
  - the city record (N -> wallet) is sent by the mayor like a name (city.py) once the agent has a wallet; without a wallet
    the number is held by the project and attached to the wallet the agent declares later;
  - vanity numbers and names are paid (start value in fees.py); not sold yet — the rule is published first.
NFT subdomains (TEP-62 item per number) are the second part of the block: contract work and a cost measurement on testnet.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import re
import time

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

FOUNDER_MAX = 100
FIRST_REGULAR = 101
LABEL = re.compile(r"^0*([1-9][0-9]{0,8})$")
SCHEMA = """
CREATE TABLE IF NOT EXISTS numbers(n INTEGER PRIMARY KEY, aid TEXT UNIQUE, key_hash TEXT UNIQUE, ts INTEGER, kind TEXT,
    wallet TEXT, city_registered INTEGER, city_expires INTEGER);
CREATE TABLE IF NOT EXISTS number_seq(k TEXT PRIMARY KEY, last INTEGER);
"""


def next_regular(c):
    """Numbers are never reused: a regular number given up for a founder seat stays retired."""
    r = c.execute("SELECT last FROM number_seq WHERE k='regular'").fetchone()
    m = c.execute("SELECT max(n) FROM numbers WHERE n>=?", (FIRST_REGULAR,)).fetchone()[0] or 0
    return max(FIRST_REGULAR, (r[0] if r else 0) + 1, m + 1)


def normalize(label):
    """'0007' -> 7; None when the label is not a number (so names fall through to the name resolver)."""
    m = LABEL.match(str(label).strip())
    return int(m.group(1)) if m else None


def _aid(key_hash):
    import agentpage
    return agentpage.aid_of(key_hash)


def assign(c, key_hash, now=None):
    """Give a key its number once (regular, >= 101). Returns the number."""
    c.executescript(SCHEMA)
    r = c.execute("SELECT n FROM numbers WHERE key_hash=?", (key_hash,)).fetchone()
    if r:
        return r[0]
    n = next_regular(c)
    wallet = c.execute("SELECT owner FROM keys WHERE key_hash=?", (key_hash,)).fetchone()
    c.execute("INSERT INTO numbers(n,aid,key_hash,ts,kind,wallet) VALUES(?,?,?,?,?,?)",
              (n, _aid(key_hash), key_hash, now or int(time.time()), "regular", (wallet[0] or None) if wallet else None))
    c.execute("INSERT INTO number_seq(k,last) VALUES('regular',?) ON CONFLICT(k) DO UPDATE SET last=excluded.last", (n,))
    return n


def assign_founder(c, key_hash, founder_no, now=None):
    """Founder seat -> number 1..100 (replaces a regular number the builder may already hold; the old one is freed)."""
    c.executescript(SCHEMA)
    if not 1 <= int(founder_no) <= FOUNDER_MAX:
        raise ValueError("founder numbers are 1..100")
    taken = c.execute("SELECT key_hash FROM numbers WHERE n=?", (founder_no,)).fetchone()
    if taken and taken[0] != key_hash:
        raise ValueError(f"number {founder_no} is already issued")
    c.execute("DELETE FROM numbers WHERE key_hash=? AND n!=?", (key_hash, founder_no))
    wallet = c.execute("SELECT owner FROM keys WHERE key_hash=?", (key_hash,)).fetchone()
    c.execute("INSERT OR IGNORE INTO numbers(n,aid,key_hash,ts,kind,wallet) VALUES(?,?,?,?,?,?)",
              (founder_no, _aid(key_hash), key_hash, now or int(time.time()), "founder", (wallet[0] or None) if wallet else None))
    return founder_no


def by_key(c, key_hash):
    c.executescript(SCHEMA)
    r = c.execute("SELECT n FROM numbers WHERE key_hash=?", (key_hash,)).fetchone()
    return r[0] if r else None


def resolve(c, label):
    """Row for a numeric label (any zero padding), or None."""
    n = normalize(label)
    if n is None:
        return None
    c.executescript(SCHEMA)
    return c.execute("SELECT * FROM numbers WHERE n=?", (n,)).fetchone()


def view(r):
    return {"number": r["n"], "address": f"{r['n']}.minimalcult.ton", "web": f"https://minimalcult.org/a/{r['n']}", "agent_id": r["aid"],
            "kind": r["kind"], "wallet": r["wallet"], "on_chain": bool(r["city_registered"]), "expires": r["city_expires"],
            "custody": "agent wallet" if r["wallet"] else "held by the project until the agent declares a wallet"}


def pending(c, now=None):
    """Numbers with a wallet not yet on chain (or expiring within 30 days) — the mayor registers them like names."""
    now = now or int(time.time())
    c.executescript(SCHEMA)
    # the wallet may have arrived on the key after the number was issued
    if c.execute("SELECT 1 FROM sqlite_master WHERE name='keys'").fetchone():
        c.execute("UPDATE numbers SET wallet=(SELECT owner FROM keys k WHERE k.key_hash=numbers.key_hash) WHERE wallet IS NULL")
    return c.execute("SELECT n, wallet, city_expires FROM numbers WHERE wallet IS NOT NULL AND wallet!='' AND "
                     "(city_registered IS NULL OR city_expires < ?) ORDER BY n", (now + 30 * 86400,)).fetchall()


def setup(app, db, admin):
    with db() as c:
        c.executescript(SCHEMA)

    @app.get("/v1/numbers")
    def numbers_index():
        with db() as c:
            issued = c.execute("SELECT count(*) FROM numbers").fetchone()[0]
            founders = c.execute("SELECT count(*) FROM numbers WHERE n<=?", (FOUNDER_MAX,)).fetchone()[0]
            nxt = next_regular(c)
            on_chain = c.execute("SELECT count(*) FROM numbers WHERE city_registered=1").fetchone()[0]
        return {"issued": issued, "founders_issued": founders, "founders_reserve": f"1-{FOUNDER_MAX}", "next_regular": nxt,
                "on_chain": on_chain, "rules": {"regular": "free, issued at registration, project pays the network fee",
                                                 "founders": "numbers 1-100 follow the founder seats of the contribution ledger (/contributions)",
                                                 "normalisation": "leading zeros are dropped: 0001 = 1; 0 is not a number",
                                                 "vanity": "repeating and short numbers and names are paid (see /v1/fees); not on sale yet"},
                "web": "https://minimalcult.org/a/{N}", "city": "{N}.minimalcult.ton (resolves once the City Hall is live on mainnet)"}

    @app.get("/v1/numbers/{label}")
    def number(label: str):
        with db() as c:
            r = resolve(c, label)
        if not r:
            raise HTTPException(404, "no such number" if normalize(label) is not None else "not a number")
        return view(r)

    @app.get("/a/{label}", include_in_schema=False)
    def mirror(label: str):
        with db() as c:
            r = resolve(c, label)
        if not r:
            raise HTTPException(404, "no agent with this number")
        return RedirectResponse(f"https://ai.minimalcult.org/agent/{r['n']}", status_code=302)

    @app.post("/admin/numbers/founder")
    async def founder(request: Request):
        """Owner: give a founder number (1..100) to an agent id — for contributions outside the workshop, auctions, grants."""
        admin(request.headers.get("authorization")); b = await request.json()
        with db() as c:
            import agentpage
            kh = agentpage.key_of(c, str(b.get("agent") or ""))
            if not kh:
                raise HTTPException(404, "no such agent")
            try:
                n = assign_founder(c, kh, int(b.get("number") or 0))
            except ValueError as e:
                raise HTTPException(409, str(e))
        return {"number": n, "agent": b.get("agent")}
