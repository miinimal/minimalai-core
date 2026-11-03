"""The city (master prompt 3.5, block B10): name.minimalcult.ton -> the agent's wallet, through the City Hall contract
(oracle-contract/contracts/mayor.fc, a TEP-81 subresolver). The mayor is the project's anchor wallet (anchor.py): it
registers names reserved in passports (passport2.py: city_name + wallet) and renews them; it holds no agent funds.

GET /v1/city                 -> contract address (per network), mayor, how resolution works, counts
GET /v1/city/{name}          -> the reservation (wallet from the passport) and whether it is registered on chain
Runner: `python city.py once` (server, like anchor.py) sends SET messages for pending names; `--dry` only builds them.
Go-live needs two owner steps (master prompt, owner needs): deploy the contract and set dns_next_resolver of
minimalcult.ton to its address. Until then names are reserved, not resolving (passport says "resolves": false).
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import base64
import hashlib
import os
import re
import sqlite3
import sys
import time

from fastapi import HTTPException
from pytoniq_core import Address, Builder, Cell, StateInit

CODE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mayor_code.b64")
DB_PATH = os.environ.get("MINIMALAI_DB", "/data/minimalai.db")
NETWORK = os.environ.get("CITY_NETWORK", "testnet")
CONTRACT = os.environ.get("CITY_CONTRACT", "")          # set after deployment; empty = reserved only
PARENT = "minimalcult.ton"
TERM_S = 365 * 86400                                      # names are renewed yearly (master prompt 3.5)
OP_SET = 0x53455421
NAME_RE = re.compile(r"^(?:[a-z0-9][a-z0-9-]{1,30}[a-z0-9]|[1-9][0-9]{0,8})$")   # names 3..32, or a canonical number


def code():
    return Cell.one_from_boc(base64.b64decode(open(CODE_PATH).read().strip()))


def state_init(mayor):
    data = Builder().store_address(Address(mayor)).store_dict(None).store_maybe_ref(None).end_cell()   # numbers: none at deploy (B10c)
    return StateInit(code=code(), data=data)


def address_for(mayor):
    return Address((0, state_init(mayor).serialize().hash))


def set_body(name, wallet, expires, query_id=0):
    """Internal message body for op::set (mayor -> City Hall)."""
    if not NAME_RE.match(name):
        raise ValueError("name: 3..32 chars a-z 0-9 -, no leading/trailing dash")
    label = Builder().store_bytes(name.encode()).end_cell()
    return (Builder().store_uint(OP_SET, 32).store_uint(query_id, 64).store_uint(expires, 32)
            .store_address(Address(wallet)).store_ref(label).end_cell())


def dns_query(name):
    """TEP-81 subdomain slice for the initial request to the subresolver: b'\\0' + label + b'\\0'."""
    return b"\0" + name.encode() + b"\0"


def wallet_category():
    return int.from_bytes(hashlib.sha256(b"wallet").digest(), "big")


def migrate(c):
    cols = [r[1] for r in c.execute("PRAGMA table_info(passports)")]
    if cols and "city_registered" not in cols:
        c.execute("ALTER TABLE passports ADD COLUMN city_registered INTEGER")
    if cols and "city_expires" not in cols:
        c.execute("ALTER TABLE passports ADD COLUMN city_expires INTEGER")


def pending(c, now=None):
    """Names with a wallet that are not on chain yet, or expire within 30 days."""
    now = now or int(time.time())
    migrate(c)
    return c.execute("SELECT id, city_name, wallet, city_expires FROM passports WHERE wallet IS NOT NULL AND city_name IS NOT NULL "
                     "AND (city_registered IS NULL OR city_expires < ?) ORDER BY settled_at", (now + 30 * 86400,)).fetchall()


def build_pending(c, now=None):
    now = now or int(time.time())
    out = []
    for r in pending(c, now):
        try:
            body = set_body(r["city_name"], r["wallet"], now + TERM_S)
        except Exception:  # noqa: BLE001  a reserved slug the contract would refuse: skipped, visible in /v1/city
            continue
        out.append({"id": r["id"], "name": r["city_name"], "wallet": r["wallet"], "expires": now + TERM_S,
                    "body_boc": base64.b64encode(body.to_boc()).decode(), "body_hash": body.hash.hex()})
    import citynum as NUM   # B10b/B10c: numbered addresses — an NFT mint when the collection is live, a SET record otherwise
    for r in NUM.pending(c, now):
        try:
            if NUM.NUMBERS_COLLECTION:
                body, to, value = NUM.mint_body(r["n"], r["wallet"]), NUM.NUMBERS_COLLECTION, 70_000_000
            else:
                body, to, value = set_body(str(r["n"]), r["wallet"], now + TERM_S), CONTRACT, 50_000_000
        except Exception:  # noqa: BLE001
            continue
        out.append({"number": r["n"], "name": str(r["n"]), "wallet": r["wallet"], "expires": 0 if NUM.NUMBERS_COLLECTION else now + TERM_S,
                    "to": to, "value_nano": value, "body_boc": base64.b64encode(body.to_boc()).decode(), "body_hash": body.hash.hex()})
    return out


def setup(app, db):
    with db() as c:
        migrate(c)

    def mayor_address():
        """The anchor wallet's public address as published by the anchor service (anchor_address.txt); the gateway has no
        access to wallet seeds and never creates one."""
        try:
            a = open(os.path.join(os.path.dirname(DB_PATH), "anchor_address.txt")).read().strip()
            return Address(a).to_str(is_user_friendly=True, is_bounceable=False, is_test_only=NETWORK == "testnet")
        except Exception:  # noqa: BLE001
            return None

    @app.get("/v1/city")
    def city():
        """The city: how name.minimalcult.ton resolves and what is registered."""
        with db() as c:
            migrate(c)   # passports table is created by passport2.py, mounted after this module
            n_all = c.execute("SELECT count(*) FROM passports WHERE city_name IS NOT NULL").fetchone()[0]
            n_wallet = c.execute("SELECT count(*) FROM passports WHERE city_name IS NOT NULL AND wallet IS NOT NULL").fetchone()[0]
            n_chain = c.execute("SELECT count(*) FROM passports WHERE city_registered=1").fetchone()[0]
            pend = len(pending(c))
        m = mayor_address()
        return {"parent": PARENT, "network": NETWORK, "contract": CONTRACT or None, "mayor": m,
                "contract_if_deployed_by_mayor": address_for(m).to_str(is_user_friendly=True, is_bounceable=True, is_test_only=NETWORK == "testnet") if m else None,
                "live": bool(CONTRACT),
                "resolution": "TEP-81: minimalcult.ton -> dns_next_resolver -> City Hall; dnsresolve(\"\\0name\\0\", sha256('wallet')) "
                              "-> dns_smc_address of the agent's passport wallet",
                "names": {"reserved": n_all, "with_wallet": n_wallet, "on_chain": n_chain, "pending_registration": pend},
                "term_days": TERM_S // 86400, "source": "https://github.com/miinimal/minimalai-core (contracts/mayor.fc)"}

    @app.get("/v1/city/{name}")
    def city_name(name: str):
        name = name.lower().removesuffix("." + PARENT)
        import citynum as NUM
        with db() as c:
            migrate(c)
            nrow = NUM.resolve(c, name)
            if nrow:
                v = NUM.view(nrow)
                return {"name": v["address"], "number": v["number"], "agent_id": v["agent_id"], "wallet": v["wallet"], "on_chain": v["on_chain"],
                        "expires": v["expires"], "live": bool(CONTRACT), "dns_query_hex": dns_query(str(v["number"])).hex(),
                        "category_wallet": hex(wallet_category()), "note": "leading zeros are dropped; on chain the canonical label is registered"}
            r = c.execute("SELECT id, wallet, city_registered, city_expires FROM passports WHERE city_name=?", (name,)).fetchone()
        if not r:
            raise HTTPException(404, "no such name in the city")
        return {"name": f"{name}.{PARENT}", "passport": r["id"], "wallet": r["wallet"],
                "on_chain": bool(r["city_registered"]), "expires": r["city_expires"], "live": bool(CONTRACT),
                "dns_query_hex": dns_query(name).hex(), "category_wallet": hex(wallet_category())}


def send_internal(anchor, key, addr, to, value_nano, body_cell, state_init=None, bounce=False):
    """One internal message from the anchor wallet (v3r2-style external with seqno); returns (status, response)."""
    st, acc = anchor.account(addr.to_str())
    seqno = int(acc.get("seqno") or 0)
    b = (Builder().store_uint(0, 1).store_uint(1, 1).store_uint(1 if bounce else 0, 1).store_uint(0, 1).store_uint(0, 2)
         .store_address(Address(to) if isinstance(to, str) else to).store_coins(value_nano).store_uint(0, 1).store_coins(0).store_coins(0)
         .store_uint(0, 64).store_uint(0, 32))
    if state_init is not None:
        b = b.store_uint(1, 1).store_uint(1, 1).store_ref(state_init)
    else:
        b = b.store_uint(0, 1)
    b = b.store_uint(1, 1).store_ref(body_cell)
    internal = b.end_cell()
    body = (Builder().store_uint(anchor.SUBWALLET, 32).store_uint(int(time.time()) + 300, 32).store_uint(seqno, 32)
            .store_uint(0, 8).store_uint(3, 8).store_ref(internal).end_cell())
    signed = Builder().store_bytes(key.sign(body.hash)).store_slice(body.begin_parse()).end_cell()
    msg = (Builder().store_uint(0b10, 2).store_uint(0, 2).store_address(addr).store_coins(0).store_uint(0, 1).store_uint(1, 1)
           .store_ref(signed).end_cell())
    api = "https://testnet.toncenter.com" if NETWORK == "testnet" else "https://toncenter.com"
    return anchor.http("POST", api + "/api/v2/sendBoc", {"boc": base64.b64encode(msg.to_boc()).decode()})


def numbers_collection_init(mayor):
    """StateInit of the city numbers collection (B10c) owned by the mayor; TEP-64 content points at the gateway."""
    import citynum
    here = os.path.dirname(os.path.abspath(__file__))
    item_code = Cell.one_from_boc(base64.b64decode(open(os.path.join(here, "number_item_code.b64")).read().strip()))
    coll_code = Cell.one_from_boc(base64.b64decode(open(os.path.join(here, "number_collection_code.b64")).read().strip()))
    meta = "https://ai.minimalcult.org/v1/numbers/meta/"
    content = (Builder().store_ref(Builder().store_uint(1, 8).store_bytes((meta + "collection.json").encode()).end_cell())
               .store_ref(Builder().store_bytes(meta.encode()).end_cell()).end_cell())
    data = (Builder().store_address(Address(mayor)).store_uint(citynum.FIRST_REGULAR, 64).store_ref(item_code).store_ref(content).end_cell())
    return StateInit(code=coll_code, data=data), item_code


def deploy(argv):
    """Go-live of the city from the anchor wallet (owner need: ~0.5 TON on it): deploy the City Hall and the numbers
    collection, then NUMB (hall -> collection). Idempotent: skips what is already active. --dry prints addresses only."""
    import anchor
    dry = "--dry" in argv
    key, si, addr = anchor.wallet()
    mayor = addr.to_str(is_user_friendly=False)
    hall_init = state_init(mayor)
    hall = Address((0, hall_init.serialize().hash))
    coll_init, item_code = numbers_collection_init(mayor)
    coll = Address((0, coll_init.serialize().hash))
    uf = lambda a: a.to_str(is_user_friendly=True, is_bounceable=True, is_test_only=NETWORK == "testnet")
    print(f"network {NETWORK} mayor {addr.to_str(is_user_friendly=True, is_bounceable=False, is_test_only=NETWORK == 'testnet')}")
    print(f"CITY_CONTRACT={uf(hall)}\nNUMBERS_COLLECTION={uf(coll)}")
    if dry:
        return 0
    st, acc = anchor.account(addr.to_str())
    bal = int(acc.get("balance") or 0)
    if bal < 400_000_000:
        print(f"mayor wallet balance {bal / 1e9} TON < 0.4: top it up first (owner need)"); return 1
    def active(a):
        s2, d = anchor.account(a.to_str())
        return s2 == 200 and str(d.get("status") or d.get("state") or "").lower() == "active"
    steps = []
    if not active(hall):
        steps.append(("deploy City Hall", hall, 100_000_000, Builder().end_cell(), hall_init.serialize()))
    if not active(coll):
        steps.append(("deploy numbers collection", coll, 80_000_000, Builder().end_cell(), coll_init.serialize()))
    numb = (Builder().store_uint(0x4E554D42, 32).store_uint(0, 64).store_address(coll).store_ref(item_code).end_cell())
    steps.append(("NUMB: hall delegates numbers to the collection", hall, 30_000_000, numb, None))
    for name, to, value, body, init in steps:
        st, d = send_internal(anchor, key, addr, to, value, body, init)
        print(name, "->", "sent" if st == 200 else f"failed {st}: {str(d)[:160]}")
        if st != 200:
            return 1
        time.sleep(12)
    print("done: set CITY_CONTRACT and NUMBERS_COLLECTION in the gateway env, then the owner sets dns_next_resolver of minimalcult.ton to CITY_CONTRACT")
    return 0


def main(argv):
    """Server runner: register pending names from the mayor wallet. --dry builds the messages and prints them."""
    import anchor
    if argv and argv[0] == "deploy":
        return deploy(argv[1:])
    dry = "--dry" in argv
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row
    todo = build_pending(c)
    if not CONTRACT:
        print(f"city: contract not deployed (CITY_CONTRACT empty); {len(todo)} name(s) waiting")
        return 0
    key, si, addr = anchor.wallet()
    for item in todo:
        print("set", item["name"], "->", item["wallet"], "body", item["body_hash"][:16], "(dry)" if dry else "")
        if dry:
            continue
        st, acc = anchor.account(addr.to_str())
        seqno = int(acc.get("seqno") or 0)
        internal = (Builder().store_uint(0, 1).store_uint(1, 1).store_uint(1, 1).store_uint(0, 1).store_uint(0, 2)
                    .store_address(Address(item.get("to") or CONTRACT)).store_coins(item.get("value_nano") or 50_000_000).store_uint(0, 1).store_coins(0).store_coins(0)
                    .store_uint(0, 64).store_uint(0, 32).store_uint(0, 1).store_uint(1, 1)
                    .store_ref(Cell.one_from_boc(base64.b64decode(item["body_boc"]))).end_cell())
        body = (Builder().store_uint(anchor.SUBWALLET, 32).store_uint(int(time.time()) + 300, 32).store_uint(seqno, 32)
                .store_uint(0, 8).store_uint(1, 8).store_ref(internal).end_cell())
        signed = Builder().store_bytes(key.sign(body.hash)).store_slice(body.begin_parse()).end_cell()
        msg = (Builder().store_uint(0b10, 2).store_uint(0, 2).store_address(addr).store_coins(0).store_uint(0, 1).store_uint(1, 1)
               .store_ref(signed).end_cell())
        api = "https://testnet.toncenter.com" if NETWORK == "testnet" else "https://toncenter.com"
        st, d = anchor.http("POST", api + "/api/v2/sendBoc", {"boc": base64.b64encode(msg.to_boc()).decode()})
        print("sent" if st == 200 else f"send failed {st}: {str(d)[:200]}")
        if st == 200:
            if item.get("number"):
                c.execute("UPDATE numbers SET city_registered=1, city_expires=? WHERE n=?", (item["expires"], item["number"]))
            else:
                c.execute("UPDATE passports SET city_registered=1, city_expires=? WHERE id=?", (item["expires"], item["id"]))
            c.commit()
            time.sleep(3)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
