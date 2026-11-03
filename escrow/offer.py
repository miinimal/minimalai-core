"""Non-custodial escrow between agents (master prompt 4.2 and 3.4, blocks B2 and B6 "the Circle").

The gateway only *describes* an escrow: it builds the StateInit of contract Escrow v1 (oracle-contract/contracts/
escrow.fc, v2) for given poster, worker, optional reviewer, deadline and task, screens both parties against the sanctions list and returns
what the poster's own wallet must sign. The project holds no key of the contract and is never a party: funds go
poster -> escrow -> worker (and the fee -> treasury). The hot wallet does not appear in any of these messages.

Fee: ESCROW_FEE_BPS, default 1500 = 15%, the same test rate as the task market (gateway/market.py MARKET_FEE_PCT,
2026-11-03); reviewer ESCROW_REVIEWER_BPS default 1500 = 15% and holdback 50% for ESCROW_HOLD_S default 14 days
(master prompt 3.4 start values, 2026-11-03, A/B later); the contract caps each rate at 20%.
Treasury: PROFIT_WALLET (minimalcult.ton), the project's own revenue.

After the poster accepts on chain (state HOLD), POST /v1/escrow/receipt issues a signed, hash-chained settlement
receipt (RECEIPTS v1 style) that binds the escrow address, the notarized submission hash and the worker's passport;
GET /v1/passport/{id}/settlements lists them. The gateway only reads the chain; it never signs a transfer.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import base64
import os
import time
import urllib.parse

from fastapi import HTTPException, Request
from pydantic import BaseModel
from pytoniq_core import Address, Builder, Cell, StateInit

import sanctions

CODE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "escrow_code.b64")
FEE_BPS = int(os.environ.get("ESCROW_FEE_BPS", "1500"))
REVIEWER_BPS = int(os.environ.get("ESCROW_REVIEWER_BPS", "1500"))
HOLD_S = int(os.environ.get("ESCROW_HOLD_S", str(14 * 86400)))
TONCENTER = {"testnet": "https://testnet.toncenter.com/api/v3", "mainnet": "https://toncenter.com/api/v3"}
TREASURY = os.environ.get("PROFIT_WALLET", "UQBR7mOMjcAAIiyyArjJtLNy3qT6bIATvQMu1zIsaudS3jS5")
NETWORK = os.environ.get("ESCROW_NETWORK", "testnet")      # mainnet only after B2 review on testnet
MIN_NANO = int(os.environ.get("ESCROW_MIN_NANO", "100000000"))   # 0.1 GRAM: below this the 0.01 reserve dominates
MAX_DAYS = 90
OP = {"accept": 0x41435054, "claim": 0x434c414d, "defect": 0x44464354, "release": 0x52454c53, "decline": 0x4445434c,
      "refund": 0x52464e44}
STATES = {0: "open", 1: "hold", 2: "defect"}


def code():
    return Cell.one_from_boc(base64.b64decode(open(CODE_PATH).read().strip()))


def hot_wallet():
    return os.environ.get("PAY402_ADDRESS", "")


def same(a, b):
    try:
        return Address(a) == Address(b)
    except Exception:  # noqa: BLE001
        return False


def state_init(poster, worker, deadline_ts, task_id, fee_bps=FEE_BPS, treasury=TREASURY, reviewer=None,
               reviewer_bps=REVIEWER_BPS, hold_s=HOLD_S):
    terms = Builder().store_address(Address(treasury)).store_uint(fee_bps, 16) \
        .store_address(Address(reviewer) if reviewer else None).store_uint(reviewer_bps, 16) \
        .store_uint(deadline_ts, 32).store_uint(task_id, 64).store_uint(hold_s, 32).end_cell()
    data = Builder().store_address(Address(poster)).store_address(Address(worker)).store_uint(0, 2).store_uint(0, 32) \
        .store_uint(0, 32).store_ref(terms).end_cell()
    return StateInit(code=code(), data=data)


def address_of(si):
    return Address((0, si.serialize().hash))


def op_body(name):
    return Builder().store_uint(OP[name], 32).store_uint(0, 64).end_cell()


def b64(cell):
    return base64.urlsafe_b64encode(cell.to_boc()).decode()


ARBITER_BPS = 0   # B19: the arbiter (anchor wallet) takes nothing on chain; the arbitration fee is the off-chain 0.05 GRAM of B16
RULING_OP = {"upheld": "refund", "rejected": "release"}   # dispute outcome -> contract op by the reviewer in state defect


def arbiter_address():
    """B19: the anchor wallet is named reviewer of marketplace escrows so a jury verdict (B16) can reach the contract.
    The contract lets the reviewer act only after the poster flagged a defect, and only RELS (worker) or RFND (poster):
    it can never move funds to itself. None until the anchor service has published its address."""
    import stake
    return stake.slasher_address()


def queue_ruling(c, receipt_id, outcome, dispute_id):
    """A decided dispute (jury or owner) on an escrow settlement receipt -> queued on-chain ruling for the anchor wallet
    (anchor.send_rulings): upheld -> RFND to the poster, rejected -> RELS to the worker. receipt_id is the id of the
    settlement record (canonical JSON without sig); escrow_receipts stores the hash with the signature, so the small
    table is scanned."""
    import json
    import receipts
    op = RULING_OP.get(outcome or "")
    if not op:
        return None
    c.execute("CREATE TABLE IF NOT EXISTS escrow_rulings(id INTEGER PRIMARY KEY, ts INTEGER, address TEXT, op TEXT, dispute_id TEXT UNIQUE, "
              "status TEXT DEFAULT 'queued', sent_ts INTEGER, result TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS escrow_receipts(seq INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT UNIQUE, "
              "passport_id TEXT, sha256 TEXT, record TEXT)")
    for row in c.execute("SELECT address, record FROM escrow_receipts").fetchall():
        if receipts.receipt_id(json.loads(row[1])) == receipt_id:
            c.execute("INSERT OR IGNORE INTO escrow_rulings(ts,address,op,dispute_id) VALUES(?,?,?,?)",
                      (int(time.time()), row[0], op, dispute_id))
            return {"address": row[0], "op": op}
    return None


def offer(poster, worker, amount_nano, deadline_ts, task_id, now=None, reviewer=None, reviewer_bps=None):
    now = int(now or time.time())
    reviewer = reviewer or None
    reviewer_bps = REVIEWER_BPS if reviewer_bps is None else int(reviewer_bps)
    try:
        Address(poster), Address(worker)
        if reviewer:
            Address(reviewer)
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "invalid TON address")
    if same(poster, worker):
        raise HTTPException(400, "poster and worker must differ")
    hw = hot_wallet()
    if reviewer and (same(reviewer, poster) or same(reviewer, worker)):
        raise HTTPException(400, "the reviewer must be a third party")
    if hw and any(same(x, hw) for x in (poster, worker, reviewer) if x):
        raise HTTPException(400, "the project wallet is never a party to an agent escrow")
    if amount_nano < MIN_NANO:
        raise HTTPException(400, f"amount below {MIN_NANO} nano")
    if not now < deadline_ts <= now + MAX_DAYS * 86400:
        raise HTTPException(400, f"deadline must be in the next {MAX_DAYS} days")
    try:
        sanctions.check(*[x for x in (poster, worker, reviewer) if x])
    except sanctions.Blocked as e:
        raise HTTPException(403, str(e))
    si = state_init(poster, worker, deadline_ts, task_id, reviewer=reviewer, reviewer_bps=reviewer_bps)
    addr = address_of(si)
    friendly = addr.to_str(is_user_friendly=True, is_bounceable=True, is_test_only=NETWORK == "testnet")
    init = b64(si.serialize())
    q = lambda amount, **kw: urllib.parse.urlencode({"amount": amount, **kw})
    return {
        "network": NETWORK, "contract": "minimalai-escrow-v2", "address": friendly,
        "address_raw": addr.to_str(is_user_friendly=False),
        "poster": poster, "worker": worker, "amount_nano": amount_nano, "deadline_ts": deadline_ts, "task_id": task_id,
        "fee_bps": FEE_BPS, "reviewer": reviewer, "reviewer_bps": reviewer_bps if reviewer else 0, "hold_s": HOLD_S,
        "split": "on accept: fee to treasury, reviewer share, 50% of the rest to worker; the other 50% after hold_s "
                 "unless the poster flags a defect (the reviewer rules; no ruling in 30 days = split equally)",
        "treasury": TREASURY, "custody": "none: the project holds no key of this contract",
        "state_init_boc": init,
        "fund": {"from": "poster", "amount_nano": amount_nano, "deeplink": f"ton://transfer/{friendly}?{q(amount_nano, init=init)}"},
        "actions": {name: {"from": who, "amount_nano": 50000000, "body_boc": b64(op_body(name)),
                           "deeplink": f"ton://transfer/{friendly}?{q(50000000, bin=b64(op_body(name)))}"}
                    for name, who in (("accept", "poster"), ("claim", "anyone after hold"), ("defect", "poster within hold"),
                                      ("release", "poster, or reviewer on a defect"), ("decline", "worker"),
                                      ("refund", "poster after deadline, or reviewer on a defect"))},
        "source": "https://github.com/miinimal/minimalai-core (contracts/escrow.fc)",
    }


class Offer(BaseModel):
    poster: str
    worker: str
    amount_nano: int
    deadline_ts: int
    task_id: int = 0
    reviewer: str = ""


def _slice_addr(item):
    from pytoniq_core import Cell as C
    return C.one_from_boc(base64.b64decode(item["value"])).begin_parse().load_address()


FETCH = None   # tests replace the chain reader here


def chain_state(address, fetch=None):
    """Read get_escrow from toncenter v3 (runGetMethod). fetch: injectable (tests)."""
    import httpx
    fetch = fetch or FETCH or (lambda url, body: httpx.post(url, json=body, timeout=20).json())
    d = fetch(TONCENTER[NETWORK] + "/runGetMethod", {"address": address, "method": "get_escrow", "stack": []})
    if d.get("exit_code", 0) != 0 or not d.get("stack"):
        return None
    st = d["stack"]
    num = lambda i: int(st[i]["value"], 16)
    try:
        reviewer = _slice_addr(st[7])
    except Exception:  # noqa: BLE001
        reviewer = None   # addr_none: no reviewer
    return {"poster": _slice_addr(st[0]), "worker": _slice_addr(st[1]), "state": STATES.get(num(2), "?"),
            "accepted_at": num(3), "defect_at": num(4), "reviewer": reviewer, "task_id": num(10)}


def settle_message(address, submission_sha256):
    return f"minimalai-settle:{Address(address).to_str(is_user_friendly=False)}:{submission_sha256}".encode()


def settlement(c, address, submission_sha256, passport_id, sig_b64, fetch=None):
    """The worker proves the passport is theirs (Ed25519 sig by the passport key) and that its declared wallet is the
    escrow's worker on chain. Limit: the wallet is declared, not proven by ton_proof yet (next step)."""
    import receipts
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    cols = [r[1] for r in c.execute("PRAGMA table_info(passports)")]
    p = c.execute("SELECT pubkey, wallet" + (", wallet_verified" if "wallet_verified" in cols else ", NULL AS wallet_verified")
                  + " FROM passports WHERE id=?", (passport_id,)).fetchone()
    if not p:
        raise HTTPException(404, "no such passport")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(p["pubkey"])).verify(
            base64.b64decode(sig_b64), settle_message(address, submission_sha256))
    except Exception:  # noqa: BLE001
        raise HTTPException(401, "sig: Ed25519 by the passport key over minimalai-settle:<escrow raw>:<sha256>")
    st = chain_state(address, fetch)
    if not st:
        raise HTTPException(404, "no active escrow at this address")
    if st["state"] == "open":
        raise HTTPException(409, "not accepted yet: the poster sends ACPT first")
    if not p["wallet"] or not same(p["wallet"], st["worker"].to_str(is_user_friendly=False)):
        raise HTTPException(403, "this passport's wallet is not the escrow's worker")
    if not p["wallet_verified"]:
        raise HTTPException(403, "prove the wallet first: POST /v1/passport/{id}/wallet/verify")
    c.execute("CREATE TABLE IF NOT EXISTS escrow_receipts(seq INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT UNIQUE, "
              "passport_id TEXT, sha256 TEXT, record TEXT)")
    raw = Address(address).to_str(is_user_friendly=False)
    old = c.execute("SELECT record FROM escrow_receipts WHERE address=?", (raw,)).fetchone()
    if old:
        import json
        return json.loads(old[0])
    prev = c.execute("SELECT sha256 FROM escrow_receipts ORDER BY seq DESC LIMIT 1").fetchone()
    rec = receipts.sign({"v": 1, "kind": "escrow_settlement", "issuer": "MINIMALAI", "ts": int(time.time()),
                         "network": NETWORK, "escrow": raw, "task_id": st["task_id"], "accepted_at": st["accepted_at"],
                         "worker_wallet": st["worker"].to_str(is_user_friendly=False),
                         "poster_wallet": st["poster"].to_str(is_user_friendly=False),
                         "worker_passport": passport_id, "submission_sha256": submission_sha256,
                         "prev_sha256": prev[0] if prev else None})
    import json
    if not c.execute("INSERT OR IGNORE INTO escrow_receipts(address, passport_id, sha256, record) VALUES(?,?,?,?)",
                     (raw, passport_id, receipts.sha256(rec), json.dumps(rec))).rowcount:
        return json.loads(c.execute("SELECT record FROM escrow_receipts WHERE address=?", (raw,)).fetchone()[0])   # parallel twin
    return rec


class Settle(BaseModel):
    escrow: str
    submission_sha256: str
    worker_passport: str
    sig: str


def setup(app, db=None):
    if hot_wallet() and same(TREASURY, hot_wallet()):
        raise RuntimeError("treasury must not be the hot wallet")

    OFFERS_PER_IP_HOUR = int(os.environ.get("ESCROW_OFFERS_PER_IP_HOUR", "120"))
    _offers = {}

    @app.post("/v1/escrow/offer")
    def escrow_offer(o: Offer, request: Request):
        ip = request.client.host if request.client else ""
        now = int(time.time())
        hits = [t for t in _offers.get(ip, []) if t > now - 3600]
        if len(hits) >= OFFERS_PER_IP_HOUR:
            raise HTTPException(429, "too many offers from this address; try later")
        _offers[ip] = hits + [now]
        if len(_offers) > 10000:
            _offers.clear()
        """Non-custodial escrow for paying another agent: returns the contract address and what the poster signs.
        The project never receives or holds these funds; only the fee goes to the treasury on release."""
        return offer(o.poster, o.worker, o.amount_nano, o.deadline_ts, o.task_id, reviewer=o.reviewer)

    if db is None:
        return

    @app.post("/v1/escrow/receipt")
    def escrow_receipt(b: Settle):
        """After the poster accepted on chain: signed settlement receipt for the worker's passport (read-only check)."""
        if len(b.submission_sha256) != 64:
            raise HTTPException(400, "submission_sha256: 64 hex (notarize the work first: POST /v1/notary)")
        with db() as c:
            return settlement(c, b.escrow, b.submission_sha256.lower(), b.worker_passport.lower(), b.sig)

    @app.get("/v1/passport/{id_}/settlements")
    def settlements(id_: str):
        import json
        with db() as c:
            try:
                rows = c.execute("SELECT record FROM escrow_receipts WHERE passport_id=? ORDER BY seq", (id_.lower(),)).fetchall()
            except Exception:  # noqa: BLE001  table not created yet
                rows = []
        return {"passport": id_, "count": len(rows), "settlements": [json.loads(r[0]) for r in rows]}

    @app.get("/v1/sanctions/status")
    def sanctions_status():
        return sanctions.status()
