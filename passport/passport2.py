"""Agent passport v2 (master prompt 3.1, block B5): the agent's own Ed25519 key is its identity.

POST /v1/passport/challenge {pubkey}                  -> nonce (10 min)
POST /v1/passport {pubkey, nonce, sig, name?, owner?, wallet?} -> signed passport; sig = Ed25519 over "minimalai-passport:<nonce>"
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
CHALLENGES_PER_IP_HOUR = int(os.environ.get("PASSPORT_CHALLENGES_PER_IP_HOUR", "60"))
NONCE_TTL = 600
SCHEMA = """
CREATE TABLE IF NOT EXISTS passports(id TEXT PRIMARY KEY, pubkey TEXT UNIQUE, name TEXT, owner TEXT, status TEXT,
  settled_at INTEGER, city_name TEXT UNIQUE, moltbook_id TEXT, moltbook TEXT, ip_hash TEXT, wallet TEXT, wallet_verified INTEGER);
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
               "name": row["name"], "owner": row["owner"], "wallet": row["wallet"],
               "wallet_verified": bool(row["wallet_verified"]) if "wallet_verified" in row.keys() else False, "status": row["status"], "settled_at": row["settled_at"],
               "city": {"name": row["city_name"] + ".minimalcult.ton", "resolves": bool(row["city_registered"]) if "city_registered" in row.keys() else False,
                        "note": "GET /v1/city/<name>: registered on chain by the mayor once the City Hall is live"},
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
    wallet: str = ""


PROOF_DOMAINS = {d.strip() for d in os.environ.get("TON_PROOF_DOMAINS", "ai.minimalcult.org,minimalcult.org").split(",") if d.strip()}
PROOF_MAX_AGE_S = 86400


def verify_ton_proof(address, public_key_hex, state_init_b64, proof, expected_payload, now=None):
    """TON Connect ton_proof check (docs.ton.org, 'ton-proof-item-v2'): the Ed25519 signature of the wallet key over
    sha256(0xffff ++ 'ton-connect' ++ sha256('ton-proof-item-v2/' ++ workchain:int32be ++ hash ++ len(domain):u32le ++
    domain ++ timestamp:u64le ++ payload)). The key must belong to the address: the address is the hash of the given
    state_init and the key's 32 bytes sit in its data cell (wallets v3/v4/v5 keep the public key there).
    Returns the raw address; raises ValueError with the reason."""
    from pytoniq_core import Address, Cell
    now = now or int(time.time())
    try:
        a = Address(str(address or ""))
    except Exception:  # noqa: BLE001
        raise ValueError("bad address")
    try:
        pk = bytes.fromhex(str(public_key_hex or ""))
        if len(pk) != 32:
            raise ValueError
    except Exception:  # noqa: BLE001
        raise ValueError("public_key must be 32 bytes hex")
    try:
        si = Cell.one_from_boc(base64.b64decode(state_init_b64 or ""))
    except Exception:  # noqa: BLE001
        raise ValueError("state_init must be a base64 BOC")
    if si.hash != a.hash_part:
        raise ValueError("state_init does not match the address")
    sl = si.begin_parse()
    try:
        sl.load_bit(); sl.load_bit()          # split_depth, special: absent for wallets
        if not sl.load_bit():
            raise ValueError("state_init without code")
        sl.load_ref()
        if not sl.load_bit():
            raise ValueError("state_init without data")
        bits = sl.load_ref().begin_parse().bits.to01()
    except ValueError:
        raise
    except Exception:  # noqa: BLE001
        raise ValueError("malformed state_init")
    want = bin(int.from_bytes(pk, "big"))[2:].zfill(256)
    if want not in bits:
        raise ValueError("public_key is not the key of this wallet")
    dom = proof.get("domain")
    dom = dom.get("value") if isinstance(dom, dict) else dom
    if not dom or dom not in PROOF_DOMAINS:
        raise ValueError(f"domain must be one of {sorted(PROOF_DOMAINS)}")
    try:
        ts = int(proof.get("timestamp"))
    except Exception:  # noqa: BLE001
        raise ValueError("timestamp missing")
    if abs(now - ts) > PROOF_MAX_AGE_S:
        raise ValueError("proof older than a day")
    if proof.get("payload") != expected_payload:
        raise ValueError(f"payload must be '{expected_payload}'")
    try:
        sig = base64.b64decode(proof.get("signature") or "")
    except Exception:  # noqa: BLE001
        raise ValueError("signature must be base64")
    msg = (b"ton-proof-item-v2/" + a.wc.to_bytes(4, "big", signed=True) + a.hash_part
           + len(dom.encode()).to_bytes(4, "little") + dom.encode() + ts.to_bytes(8, "little") + expected_payload.encode())
    digest = hashlib.sha256(b"\xff\xff" + b"ton-connect" + hashlib.sha256(msg).digest()).digest()
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, digest)
    except Exception:  # noqa: BLE001
        raise ValueError("signature does not verify")
    return a.to_str(is_user_friendly=False).upper()


def setup(app, db, client_ip, moltbook_post=None):
    with db() as c:
        c.executescript(SCHEMA)

    @app.post("/v1/passport/challenge")
    def challenge(b: Challenge, request: Request):
        """Step 1: get a nonce to sign with your Ed25519 key (proves you hold it)."""
        pk = check_pubkey(b.pubkey)
        n = secrets.token_hex(16)
        with db() as c:
            c.execute("DELETE FROM passport_nonces WHERE exp<?", (int(time.time()),))
            # one key keeps one live nonce; a client address gets at most CHALLENGES_PER_IP_HOUR (nonce-table spam)
            c.execute("DELETE FROM passport_nonces WHERE pubkey=?", (pk,))
            c.execute("CREATE TABLE IF NOT EXISTS passport_acts(ts INTEGER, ip_hash TEXT)")
            ih = hashlib.sha256(client_ip(request).encode()).hexdigest()[:16]; now = int(time.time())
            c.execute("DELETE FROM passport_acts WHERE ts<?", (now - 3600,))
            if c.execute("SELECT count(*) FROM passport_acts WHERE ip_hash=? AND ts>?", (ih, now - 3600)).fetchone()[0] >= CHALLENGES_PER_IP_HOUR:
                raise HTTPException(429, "too many challenges from this address; try later")
            c.execute("INSERT INTO passport_acts VALUES(?,?)", (now, ih))
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
            wallet = None
            if b.wallet:
                try:
                    from pytoniq_core import Address
                    wallet = Address(b.wallet.strip()).to_str(is_user_friendly=False).upper()
                except Exception:  # noqa: BLE001
                    raise HTTPException(400, "invalid TON wallet")
            if row is None:
                ih = hashlib.sha256(client_ip(request).encode()).hexdigest()[:16]
                if c.execute("SELECT count(*) FROM passports WHERE ip_hash=? AND settled_at>?", (ih, now - 86400)).fetchone()[0] >= PER_IP_DAY:
                    raise HTTPException(429, "too many new passports from this address today")
                city = slug(name, id_)
                if c.execute("SELECT 1 FROM passports WHERE city_name=?", (city,)).fetchone():
                    city = f"{city}-{id_[:6]}"
                c.execute("INSERT INTO passports(id,pubkey,name,owner,status,settled_at,city_name,moltbook_id,moltbook,ip_hash,wallet) "
                          "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                          (id_, pk, name, owner, "owned" if owner else "free", now, city,
                           mb and mb["id"], mb and json.dumps(mb), ih, wallet))
            else:
                c.execute("UPDATE passports SET name=coalesce(nullif(?,''),name), owner=coalesce(?,owner), "
                          "status=CASE WHEN coalesce(?,owner) IS NULL THEN 'free' ELSE 'owned' END, "
                          "moltbook_id=coalesce(?,moltbook_id), moltbook=coalesce(?,moltbook), wallet=coalesce(?,wallet) WHERE id=?",
                          (name, owner, owner, mb and mb["id"], mb and json.dumps(mb), wallet, id_))
            return record(c.execute("SELECT * FROM passports WHERE id=?", (id_,)).fetchone())

    @app.post("/v1/passport/{id_}/wallet/verify")
    async def verify_wallet(id_: str, request: Request):
        """Prove the passport's declared wallet (B6b): send any amount (>= 0.001 GRAM) from that wallet to the project's
        GRAM-402 address with the comment `passport:<id>`; then call this. The transfer is the price of the check (project
        revenue, not credited back; start value 2026-11-03); the proof is the on-chain sender."""
        import pay402
        id_ = id_.lower()[:32]
        with db() as c:
            row = c.execute("SELECT wallet, wallet_verified FROM passports WHERE id=?", (id_,)).fetchone() \
                if "wallet_verified" in [r[1] for r in c.execute("PRAGMA table_info(passports)")] else None
            if row is None:
                c.execute("ALTER TABLE passports ADD COLUMN wallet_verified INTEGER")
                row = c.execute("SELECT wallet, wallet_verified FROM passports WHERE id=?", (id_,)).fetchone()
        if not row:
            raise HTTPException(404, "no such passport")
        if not row["wallet"]:
            raise HTTPException(400, "declare a wallet first (POST /v1/passport with wallet)")
        if row["wallet_verified"]:
            return {"id": id_, "wallet": row["wallet"], "verified": True}
        if not pay402.enabled():
            raise HTTPException(503, "wallet proof needs the GRAM-402 address; not configured")
        txs = await pay402.fetch_incoming()
        found = None
        want = "passport:" + id_
        for t in txs:
            im = t.get("in_msg") or {}
            dec = ((im.get("message_content") or {}).get("decoded") or {})
            if dec.get("comment", "").strip() != want or not im.get("source"):
                continue
            desc = t.get("description") or {}
            if desc.get("aborted") or (desc.get("compute_ph") or {}).get("success") is False:
                continue
            if im["source"].upper() != row["wallet"].upper():
                raise HTTPException(403, "the transfer came from another wallet than the one declared")
            found = t
            break
        if not found:
            raise HTTPException(402, detail={"error": f"no transfer with comment '{want}' from {row['wallet']} yet",
                                             "pay_to": pay402.PAY_TO, "network": pay402.network_id(), "comment": want, "min_nano": 1_000_000})
        with db() as c:
            c.execute("UPDATE passports SET wallet_verified=? WHERE id=?", (int(time.time()), id_))
        return {"id": id_, "wallet": row["wallet"], "verified": True, "tx": found.get("hash")}

    @app.post("/v1/passport/{id_}/wallet/proof")
    async def wallet_proof(id_: str, request: Request):
        """Prove the wallet for free with TON Connect ton_proof (B20): the wallet signs payload `passport:<id>` for domain
        ai.minimalcult.org; send {address, public_key (hex), state_init (base64 BOC), proof: {timestamp, domain, payload,
        signature}} exactly as the wallet returns them. No transfer, no fee; the on-chain variant (wallet/verify) stays."""
        id_ = id_.lower()[:32]
        b = await request.json()
        with db() as c:   # same per-address hourly budget as challenges: a proof check costs a BOC parse and a signature
            c.execute("CREATE TABLE IF NOT EXISTS passport_acts(ts INTEGER, ip_hash TEXT)")
            ih = hashlib.sha256(client_ip(request).encode()).hexdigest()[:16]; now = int(time.time())
            if c.execute("SELECT count(*) FROM passport_acts WHERE ip_hash=? AND ts>?", (ih, now - 3600)).fetchone()[0] >= CHALLENGES_PER_IP_HOUR:
                raise HTTPException(429, "too many passport actions from this address; try later")
            c.execute("INSERT INTO passport_acts VALUES(?,?)", (now, ih))
        try:
            addr = verify_ton_proof(b.get("address"), b.get("public_key"), b.get("state_init"), b.get("proof") or {},
                                    expected_payload="passport:" + id_)
        except ValueError as e:
            raise HTTPException(403, f"ton_proof rejected: {e}")
        with db() as c:
            if "wallet_verified" not in [r[1] for r in c.execute("PRAGMA table_info(passports)")]:
                c.execute("ALTER TABLE passports ADD COLUMN wallet_verified INTEGER")
            row = c.execute("SELECT wallet, wallet_verified FROM passports WHERE id=?", (id_,)).fetchone()
            if not row:
                raise HTTPException(404, "no such passport")
            if row["wallet"] and row["wallet"].upper() != addr.upper():
                raise HTTPException(403, "the proof is for another wallet than the one declared on this passport")
            c.execute("UPDATE passports SET wallet=?, wallet_verified=coalesce(wallet_verified, ?) WHERE id=?", (addr, int(time.time()), id_))
        return {"id": id_, "wallet": addr, "verified": True, "method": "ton_proof"}

    @app.get("/v1/passport/{id_}")
    def get_passport(id_: str):
        """Public signed passport (verify: Ed25519 over canonical JSON without sig, key at gateway_key)."""
        with db() as c:
            row = c.execute("SELECT * FROM passports WHERE id=?", (id_.lower()[:32],)).fetchone()
        if not row:
            raise HTTPException(404, "no such passport")
        return record(row)
