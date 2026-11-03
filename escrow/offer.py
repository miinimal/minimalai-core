"""Non-custodial escrow between agents (master prompt 4.2, block B2).

The gateway only *describes* an escrow: it builds the StateInit of contract Escrow v1 (oracle-contract/contracts/
escrow.fc) for given poster, worker, deadline and task, screens both parties against the sanctions list and returns
what the poster's own wallet must sign. The project holds no key of the contract and is never a party: funds go
poster -> escrow -> worker (and the fee -> treasury). The hot wallet does not appear in any of these messages.

Fee: ESCROW_FEE_BPS, default 1500 = 15%, the same test rate as the task market (gateway/market.py MARKET_FEE_PCT,
2026-11-03); the contract caps any rate at 20%. Treasury: PROFIT_WALLET (minimalcult.ton), the project's own revenue.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import base64
import os
import time
import urllib.parse

from fastapi import HTTPException
from pydantic import BaseModel
from pytoniq_core import Address, Builder, Cell, StateInit

import sanctions

CODE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "escrow_code.b64")
FEE_BPS = int(os.environ.get("ESCROW_FEE_BPS", "1500"))
TREASURY = os.environ.get("PROFIT_WALLET", "UQBR7mOMjcAAIiyyArjJtLNy3qT6bIATvQMu1zIsaudS3jS5")
NETWORK = os.environ.get("ESCROW_NETWORK", "testnet")      # mainnet only after B2 review on testnet
MIN_NANO = int(os.environ.get("ESCROW_MIN_NANO", "100000000"))   # 0.1 GRAM: below this the 0.01 reserve dominates
MAX_DAYS = 90
OP = {"release": 0x52454c53, "decline": 0x4445434c, "refund": 0x52464e44}


def code():
    return Cell.one_from_boc(base64.b64decode(open(CODE_PATH).read().strip()))


def hot_wallet():
    return os.environ.get("PAY402_ADDRESS", "")


def same(a, b):
    try:
        return Address(a) == Address(b)
    except Exception:  # noqa: BLE001
        return False


def state_init(poster, worker, deadline_ts, task_id, fee_bps=FEE_BPS, treasury=TREASURY):
    terms = Builder().store_address(Address(treasury)).store_uint(fee_bps, 16).store_uint(deadline_ts, 32) \
        .store_uint(task_id, 64).end_cell()
    data = Builder().store_address(Address(poster)).store_address(Address(worker)).store_ref(terms).end_cell()
    return StateInit(code=code(), data=data)


def address_of(si):
    return Address((0, si.serialize().hash))


def op_body(name):
    return Builder().store_uint(OP[name], 32).store_uint(0, 64).end_cell()


def b64(cell):
    return base64.urlsafe_b64encode(cell.to_boc()).decode()


def offer(poster, worker, amount_nano, deadline_ts, task_id, now=None):
    now = int(now or time.time())
    try:
        Address(poster), Address(worker)
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "invalid TON address")
    if same(poster, worker):
        raise HTTPException(400, "poster and worker must differ")
    hw = hot_wallet()
    if hw and (same(poster, hw) or same(worker, hw)):
        raise HTTPException(400, "the project wallet is never a party to an agent escrow")
    if amount_nano < MIN_NANO:
        raise HTTPException(400, f"amount below {MIN_NANO} nano")
    if not now < deadline_ts <= now + MAX_DAYS * 86400:
        raise HTTPException(400, f"deadline must be in the next {MAX_DAYS} days")
    try:
        sanctions.check(poster, worker)
    except sanctions.Blocked as e:
        raise HTTPException(403, str(e))
    si = state_init(poster, worker, deadline_ts, task_id)
    addr = address_of(si)
    friendly = addr.to_str(is_user_friendly=True, is_bounceable=True, is_test_only=NETWORK == "testnet")
    init = b64(si.serialize())
    q = lambda amount, **kw: urllib.parse.urlencode({"amount": amount, **kw})
    return {
        "network": NETWORK, "contract": "minimalai-escrow-v1", "address": friendly,
        "address_raw": addr.to_str(is_user_friendly=False),
        "poster": poster, "worker": worker, "amount_nano": amount_nano, "deadline_ts": deadline_ts, "task_id": task_id,
        "fee_bps": FEE_BPS, "treasury": TREASURY, "custody": "none: the project holds no key of this contract",
        "state_init_boc": init,
        "fund": {"from": "poster", "amount_nano": amount_nano, "deeplink": f"ton://transfer/{friendly}?{q(amount_nano, init=init)}"},
        "actions": {name: {"from": who, "amount_nano": 50000000, "body_boc": b64(op_body(name)),
                           "deeplink": f"ton://transfer/{friendly}?{q(50000000, bin=b64(op_body(name)))}"}
                    for name, who in (("release", "poster"), ("decline", "worker"), ("refund", "poster after deadline"))},
        "source": "https://github.com/miinimal/minimalai-core (contracts/escrow.fc)",
    }


class Offer(BaseModel):
    poster: str
    worker: str
    amount_nano: int
    deadline_ts: int
    task_id: int = 0


def setup(app):
    if hot_wallet() and same(TREASURY, hot_wallet()):
        raise RuntimeError("treasury must not be the hot wallet")

    @app.post("/v1/escrow/offer")
    def escrow_offer(o: Offer):
        """Non-custodial escrow for paying another agent: returns the contract address and what the poster signs.
        The project never receives or holds these funds; only the fee goes to the treasury on release."""
        return offer(o.poster, o.worker, o.amount_nano, o.deadline_ts, o.task_id)

    @app.get("/v1/sanctions/status")
    def sanctions_status():
        return sanctions.status()
