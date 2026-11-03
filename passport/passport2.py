"""Agent passport v2 (master prompt 3.1, block B5): the agent's own Ed25519 key is its identity.

POST /v1/passport/challenge {pubkey}                  -> nonce (10 min)
POST /v1/passport {pubkey, nonce, sig, name?, owner?} -> signed passport; sig = Ed25519 over "minimalai-passport:<nonce>"
GET  /v1/passport/{id}                                -> signed passport (public)

id = first 32 hex of SHA-256(pubkey). status: "owned" when the agent names an owner (claimed, unverified), else "free".
Optional login with Moltbook: header X-Moltbook-Identity (token from POST moltbook.com/api/v1/agents/me/identity-token)
is verified server-side via POST moltbook.com/api/v1/agents/verify-identity with X-Moltbook-App-Key (moltbook.com/
developers, read 2026-11-03); the verified Moltbook id/name/karma/claim are added to the passport. Moltbook is an extra
way in, never required. City address (name.minimalcult.ton) is reserved here and resolves after block B10.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import base64
import hashlib
import os
import re
import secrets
import time

import httpx
from fastapi import Header, HTTPException, Request
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import receipts

MOLTBOOK_APP_KEY = os.environ.get("MOLTBOOK_APP_KEY", "")
MOLTBOOK_VERIFY = os.environ.get("MOLTBOOK_VERIFY_URL", "https://www.moltbook.com/api/v1/agents/verify-identity")
PER_IP_DAY = int(os.environ.get("PASSPORT_PER_IP_DAY", "10"))
NONCE_TTL = 600
SCHEMA = """
CREATE TABLE IF NOT EXISTS passports(id TEXT PRIMARY KEY, pubkey TEXT UNIQUE, name TEXT, owner TEXT, status TEXT,
  settled_at INTEGER, city_name TEXT UNIQUE, moltbook_id TEXT, moltbook TEXT, ip_hash TEXT);
CREATE TABLE IF NOT EXISTS passport_nonces(nonce TEXT PRIMARY KEY, pubkey TEXT, exp INTEGER);
"""


def pid(pubkey_hex):
    return hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()[:32]


def slug(name, id_):
    s = re.sub(r"[^a-z0-9-]+", "-", (name or "").lower()).strip("-")[:24]
    return s if len(s) >= 3 else "agent-" + id_[:8]


def check_pubkey(pk):
    try:
        if len(pk) != 64:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk))
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "pubkey must be 64 hex chars (Ed25519)")
    return pk.lower()


def record(row):
    import json
    payload = {"v": 2, "kind": "agent_passport", "issuer": "MINIMALAI", "id": row["id"], "pubkey": row["pubkey"],
               "name": row["name"], "owner": row["owner"], "status": row["status"], "settled_at": row["settled_at"],
               "city": {"name": row["city_name"] + ".minimalcult.ton", "resolves": False, "note": "resolves after block B10"},
               "moltbook": json.loads(row["moltbook"]) if row["moltbook"] else None}
    return receipts.sign(payload)


def moltbook_verify(token, post=None):
    """Verified Moltbook profile for an identity token, or HTTPException. post: injectable for tests."""
    if not MOLTBOOK_APP_KEY:
        raise HTTPException(503, "Moltbook login is not configured yet; register without it")
    post = post or (lambda url, **kw: httpx.post(url, timeout=15, **kw))
    try:
        r = post(MOLTBOOK_VERIFY, headers={"X-Moltbook-App-Key": MOLTBOOK_APP_KEY}, json={"token": token})
        d = r.json()
    except Exception:  # noqa: BLE001
        raise HTTPException(502, "Moltbook verification unavailable")
    if r.status_code != 200 or not d.get("valid"):
        raise HTTPException(401, "invalid or expired Moltbook identity token")
    a = d.get("agent") or {}
    o = a.get("owner") or {}
    return {"id": a.get("id"), "name": a.get("name"), "karma": a.get("karma"), "is_claimed": a.get("is_claimed"),
            "owner_x": o.get("x_handle"), "owner_x_verified": o.get("x_verified"), "verified_at": int(time.time())}


class Challenge(BaseModel):
    pubkey: str


class Register(BaseModel):
    pubkey: str
    nonce: str
    sig: str
    name: str = ""
    owner: str = ""


def setup(app, db, client_ip, moltbook_post=None):
    with db() as c:
        c.executescript(SCHEMA)

    @app.post("/v1/passport/challenge")
    def challenge(b: Challenge):
        """Step 1: get a nonce to sign with your Ed25519 key (proves you hold it)."""
        pk = check_pubkey(b.pubkey)
        n = secrets.token_hex(16)
        with db() as c:
            c.execute("DELETE FROM passport_nonces WHERE exp<?", (int(time.time()),))
            c.execute("INSERT INTO passport_nonces VALUES(?,?,?)", (n, pk, int(time.time()) + NONCE_TTL))
        return {"nonce": n, "sign": f"minimalai-passport:{n}", "expires_in": NONCE_TTL}

    @app.post("/v1/passport")
    def register(b: Register, request: Request, x_moltbook_identity: str = Header(None)):
        """Step 2: send the signature, get your signed passport. Same key again returns the same passport (updated)."""
        pk = check_pubkey(b.pubkey)
        now = int(time.time())
        with db() as c:
            n = c.execute("DELETE FROM passport_nonces WHERE nonce=? AND pubkey=? AND exp>=? RETURNING nonce",
                          (b.nonce, pk, now)).fetchone()
            if not n:
                raise HTTPException(400, "unknown or expired nonce; call /v1/passport/challenge")
            try:
                Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(
                    base64.b64decode(b.sig), f"minimalai-passport:{b.nonce}".encode())
            except Exception:  # noqa: BLE001
                raise HTTPException(401, "bad signature")
            mb = moltbook_verify(x_moltbook_identity, moltbook_post) if x_moltbook_identity else None
            import json
            id_ = pid(pk)
            row = c.execute("SELECT * FROM passports WHERE id=?", (id_,)).fetchone()
            name = (b.name or "").strip()[:60] or (mb or {}).get("name") or ""
            owner = (b.owner or "").strip()[:100] or None
            if row is None:
                ih = hashlib.sha256(client_ip(request).encode()).hexdigest()[:16]
                if c.execute("SELECT count(*) FROM passports WHERE ip_hash=? AND settled_at>?", (ih, now - 86400)).fetchone()[0] >= PER_IP_DAY:
                    raise HTTPException(429, "too many new passports from this address today")
                city = slug(name, id_)
                if c.execute("SELECT 1 FROM passports WHERE city_name=?", (city,)).fetchone():
                    city = f"{city}-{id_[:6]}"
                c.execute("INSERT INTO passports VALUES(?,?,?,?,?,?,?,?,?,?)",
                          (id_, pk, name, owner, "owned" if owner else "free", now, city,
                           mb and mb["id"], mb and json.dumps(mb), ih))
            else:
                c.execute("UPDATE passports SET name=coalesce(nullif(?,''),name), owner=coalesce(?,owner), "
                          "status=CASE WHEN coalesce(?,owner) IS NULL THEN 'free' ELSE 'owned' END, "
                          "moltbook_id=coalesce(?,moltbook_id), moltbook=coalesce(?,moltbook) WHERE id=?",
                          (name, owner, owner, mb and mb["id"], mb and json.dumps(mb), id_))
            return record(c.execute("SELECT * FROM passports WHERE id=?", (id_,)).fetchone())

    @app.get("/v1/passport/{id_}")
    def get_passport(id_: str):
        """Public signed passport (verify: Ed25519 over canonical JSON without sig, key at gateway_key)."""
        with db() as c:
            row = c.execute("SELECT * FROM passports WHERE id=?", (id_.lower()[:32],)).fetchone()
        if not row:
            raise HTTPException(404, "no such passport")
        return record(row)
