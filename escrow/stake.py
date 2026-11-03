"""Non-custodial stakes (block B17): an agent's reputation stake lives in its own Stake v1 contract
(oracle-contract/contracts/stake.fc). The project (slasher = the anchor wallet) can only move it to the treasury;
the owner withdraws after UNLOCK_S. This replaces balance holds for reviewer and juror stakes step by step.

POST /v1/stake/offer {"owner": <wallet>, "purpose": 1|2|3}  -> contract address, fund link, actions (anyone, screened)
GET  /v1/stake/{address}                                     -> on-chain state (owner, unlock, balance) via toncenter
Stake contracts are recognised by review.py (reviewer stake) when STAKE_NETWORK matches: a reviewer may present a stake
address instead of a balance hold; slashing then sends op::slash from the anchor wallet (runner in anchor.py: pending
slashes table). Start values 2026-11-03: UNLOCK_S 7 days. Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import base64
import os
import time
import urllib.parse

from fastapi import HTTPException, Request
from pydantic import BaseModel
from pytoniq_core import Address, Builder, Cell, StateInit

import sanctions

CODE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stake_code.b64")
DB_PATH = os.environ.get("MINIMALAI_DB", "/data/minimalai.db")
NETWORK = os.environ.get("STAKE_NETWORK", os.environ.get("ESCROW_NETWORK", "testnet"))
TREASURY = os.environ.get("PROFIT_WALLET", "UQBR7mOMjcAAIiyyArjJtLNy3qT6bIATvQMu1zIsaudS3jS5")
UNLOCK_S = int(os.environ.get("STAKE_UNLOCK_S", str(7 * 86400)))
PURPOSES = {1: "review of the core", 2: "grant jury", 3: "arbitration jury"}
OP = {"unlock": 0x554e4c4b, "relock": 0x52454c4b, "withdraw": 0x57495448, "slash": 0x534c5348}
TONCENTER = {"testnet": "https://testnet.toncenter.com/api/v3", "mainnet": "https://toncenter.com/api/v3"}
FETCH = None


def code():
    return Cell.one_from_boc(base64.b64decode(open(CODE_PATH).read().strip()))


def slasher_address():
    """The anchor wallet's public address (published by the anchor service); None when unknown."""
    try:
        return open(os.path.join(os.path.dirname(DB_PATH), "anchor_address.txt")).read().strip()
    except OSError:
        return os.environ.get("STAKE_SLASHER") or None


def state_init(owner, slasher, purpose, treasury=TREASURY, unlock_s=UNLOCK_S):
    data = (Builder().store_address(Address(owner)).store_address(Address(slasher)).store_address(Address(treasury))
            .store_uint(unlock_s, 32).store_uint(0, 32).store_uint(purpose, 64).end_cell())
    return StateInit(code=code(), data=data)


def address_of(si):
    return Address((0, si.serialize().hash))


def b64(cell):
    return base64.urlsafe_b64encode(cell.to_boc()).decode()


def op_body(name):
    return Builder().store_uint(OP[name], 32).store_uint(0, 64).end_cell()


def slash_body(amount_nano, reason):
    return Builder().store_uint(OP["slash"], 32).store_uint(0, 64).store_coins(amount_nano) \
        .store_ref(Builder().store_snake_string(reason[:200]).end_cell()).end_cell()


def offer(owner, purpose, amount_nano=0):
    try:
        Address(owner)
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "owner: invalid TON address")
    if purpose not in PURPOSES:
        raise HTTPException(400, f"purpose: one of {PURPOSES}")
    slasher = slasher_address()
    if not slasher:
        raise HTTPException(503, "slasher address not published yet (anchor service)")
    try:
        sanctions.check(owner)
    except sanctions.Blocked as e:
        raise HTTPException(403, str(e))
    si = state_init(owner, slasher, purpose)
    addr = address_of(si)
    friendly = addr.to_str(is_user_friendly=True, is_bounceable=True, is_test_only=NETWORK == "testnet")
    q = lambda **kw: urllib.parse.urlencode(kw)
    return {"network": NETWORK, "contract": "minimalai-stake-v1", "address": friendly, "address_raw": addr.to_str(is_user_friendly=False),
            "owner": owner, "slasher": slasher, "treasury": TREASURY, "unlock_s": UNLOCK_S, "purpose": purpose, "purpose_text": PURPOSES[purpose],
            "custody": "none: only the owner withdraws (after unlock); the slasher can only move funds to the treasury",
            "state_init_boc": b64(si.serialize()),
            "fund": {"deeplink": f"ton://transfer/{friendly}?{q(amount=amount_nano or 1000000000, init=b64(si.serialize()))}"},
            "actions": {n: {"from": "owner", "deeplink": f"ton://transfer/{friendly}?{q(amount=50000000, bin=b64(op_body(n)))}"}
                        for n in ("unlock", "relock", "withdraw")},
            "source": "https://github.com/miinimal/minimalai-core (contracts/stake.fc)"}


def chain_state(address, fetch=None):
    """get_stake via toncenter v3 runGetMethod -> dict or None (not deployed)."""
    import httpx
    fetch = fetch or FETCH or (lambda url, body: httpx.post(url, json=body, timeout=20).json())
    d = fetch(TONCENTER[NETWORK] + "/runGetMethod", {"address": address, "method": "get_stake", "stack": []})
    if d.get("exit_code", 0) != 0 or not d.get("stack"):
        return None
    st = d["stack"]
    sl = lambda i: Cell.one_from_boc(base64.b64decode(st[i]["value"])).begin_parse().load_address()
    num = lambda i: int(st[i]["value"], 16)
    return {"owner": sl(0), "slasher": sl(1), "treasury": sl(2), "unlock_s": num(3), "unlock_at": num(4), "purpose": num(5), "balance_nano": num(6)}


def verify_stake(address, owner_wallet, purpose, min_nano, fetch=None):
    """True when the contract at `address` is a Stake v1 for this owner/purpose, our slasher, locked, and funded."""
    slasher = slasher_address()
    if not slasher:
        return False, "slasher unknown"
    for p in (owner_wallet,):
        try:
            Address(p)
        except Exception:  # noqa: BLE001
            return False, "bad owner wallet"
    expect = address_of(state_init(owner_wallet, slasher, purpose)).to_str(is_user_friendly=False)
    try:
        given = Address(address).to_str(is_user_friendly=False)
    except Exception:  # noqa: BLE001
        return False, "bad address"
    if given != expect:
        return False, "address is not the Stake v1 contract for this owner, purpose and slasher"
    st = chain_state(address, fetch)
    if not st:
        return False, "not deployed"
    if st["unlock_at"]:
        return False, "stake is unlocking"
    if st["balance_nano"] < min_nano:
        return False, f"stake balance {st['balance_nano']} below {min_nano}"
    return True, st


class Offer(BaseModel):
    owner: str
    purpose: int = 1
    amount_nano: int = 0


def setup(app, db):
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS stake_slashes(id INTEGER PRIMARY KEY, ts INTEGER, address TEXT, amount_nano INTEGER, reason TEXT, "
                  "status TEXT DEFAULT 'queued', sent_ts INTEGER, result TEXT)")

    @app.post("/v1/stake/offer")
    def stake_offer(o: Offer, request: Request):
        """A stake contract for your wallet: fund it, then present its address where a stake is required."""
        return offer(o.owner, o.purpose, o.amount_nano)

    @app.get("/v1/stake/{address}")
    def stake_state(address: str):
        st = chain_state(address)
        if not st:
            raise HTTPException(404, "no Stake v1 contract at this address (on this network)")
        return {"address": address, "network": NETWORK, "owner": st["owner"].to_str(is_user_friendly=False), "unlock_at": st["unlock_at"],
                "purpose": st["purpose"], "purpose_text": PURPOSES.get(st["purpose"], "?"), "balance_nano": st["balance_nano"],
                "treasury": st["treasury"].to_str(is_user_friendly=False)}


def queue_slash(c, address, amount_nano, reason):
    """Record a slash for the anchor service to send (it holds the slasher key); the ledger shows it when sent."""
    c.execute("INSERT INTO stake_slashes(ts,address,amount_nano,reason) VALUES(?,?,?,?)", (int(time.time()), address, amount_nano, reason[:200]))
