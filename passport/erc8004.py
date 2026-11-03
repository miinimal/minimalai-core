"""ERC-8004 Trustless Agents — identity and reputation on an EVM chain (block R1, staff direction 2026-11-03).

The world speaks the standard the rest of the agent economy is settling on: the project has an identity in the Identity
Registry (an ERC-721), agents may link their own identities to their passports, and every accepted job becomes feedback in
the Reputation Registry, written by the project's address (the standard forbids the agent's own owner/operator to rate it).

Chain facts (source: github.com/erc-8004/erc-8004-contracts README and ERC8004SPEC.md, eips.ethereum.org/EIPS/eip-8004,
read 2026-11-03): Base Sepolia 84532 Identity 0x8004A818BFB912233c491871b3d84c89A494BD9e, Reputation
0x8004B663056A597Dffe9eCcC1965A193B7388713; Base 8453 Identity 0x8004A169FB4a3325136EB29fA0ceB6D2e539a432, Reputation
0x8004BAa17C55a88189AE136b182e5fdA19dE9b63. The standard is a draft; addresses are pinned here with that date.

Two halves:
  reads  (gateway, no key): ownerOf / tokenURI / getSummary / readAllFeedback through plain JSON-RPC (httpx);
  writes (anchor container, key in /wallets, never in the gateway): register the world identity, give feedback for accepted
         receipts queued by the gateway (`erc8004_feedback` table). Signing: eth-account; ABI: eth-abi (imported lazily).
Env: ERC8004_CHAIN (84532), ERC8004_RPC (chain default), ERC8004_KEY (path of the hex private key; created 0600 on first write).
CLI (anchor): python erc8004.py address | status | register [--dry] | feedback [--dry] | summary <agentId> | proof (end to end on testnet)
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: MIT (open core).
"""
import hashlib
import json
import os
import secrets
import time

import httpx

CHAINS = {
    84532: {"name": "Base Sepolia", "rpc": "https://sepolia.base.org", "explorer": "https://sepolia.basescan.org",
            "identity": "0x8004A818BFB912233c491871b3d84c89A494BD9e", "reputation": "0x8004B663056A597Dffe9eCcC1965A193B7388713"},
    8453: {"name": "Base", "rpc": "https://mainnet.base.org", "explorer": "https://basescan.org",
           "identity": "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432", "reputation": "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63"},
}
CHAIN = int(os.environ.get("ERC8004_CHAIN", "84532"))
RPC = os.environ.get("ERC8004_RPC") or CHAINS[CHAIN]["rpc"]
DB_PATH = os.environ.get("MINIMALAI_DB", "/data/minimalai.db")
DATA_DIR = os.path.dirname(DB_PATH) or "."
KEY_PATH = os.environ.get("ERC8004_KEY", "/wallets/erc8004.key" if os.path.isdir("/wallets") else os.path.join(DATA_DIR, "erc8004.key"))
ADDRESS_FILE = os.path.join(DATA_DIR, "erc8004_address.txt")      # published by the anchor for the gateway to show
WORLD_FILE = os.path.join(DATA_DIR, "erc8004_world.json")         # {"agent_id": N, "chain": 84532, "tx": "0x.."} after register
BASE = "https://ai.minimalcult.org"
SOURCE = "https://github.com/erc-8004/erc-8004-contracts"
REGISTRATION_TYPE = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS erc8004_feedback(id INTEGER PRIMARY KEY, ts INTEGER, agent_id INTEGER, chain INTEGER, task_id TEXT UNIQUE,
    value INTEGER, tag1 TEXT, tag2 TEXT, endpoint TEXT, feedback_hash TEXT, status TEXT, tx TEXT, error TEXT);
"""


# ---------------------------------------------------------------- ABI (hand-rolled selectors, eth-abi for the arguments)
def keccak(data: bytes) -> bytes:
    from eth_utils import keccak as k
    return k(data)


def selector(sig: str) -> bytes:
    return keccak(sig.encode())[:4]


def encode_call(sig: str, types, args) -> str:
    from eth_abi import encode
    return "0x" + (selector(sig) + encode(types, args)).hex()


def decode(types, data: str):
    from eth_abi import decode as d
    return d(types, bytes.fromhex(data[2:] if data.startswith("0x") else data))


SIG = {
    "ownerOf": ("ownerOf(uint256)", ["uint256"], ["address"]),
    "tokenURI": ("tokenURI(uint256)", ["uint256"], ["string"]),
    "register": ("register(string)", ["string"], ["uint256"]),
    "setAgentURI": ("setAgentURI(uint256,string)", ["uint256", "string"], []),
    "giveFeedback": ("giveFeedback(uint256,int128,uint8,string,string,string,string,bytes32)",
                     ["uint256", "int128", "uint8", "string", "string", "string", "string", "bytes32"], []),
    "getSummary": ("getSummary(uint256,address[],string,string)", ["uint256", "address[]", "string", "string"], ["uint64", "int128", "uint8"]),
    "getLastIndex": ("getLastIndex(uint256,address)", ["uint256", "address"], ["uint64"]),
    "readAllFeedback": ("readAllFeedback(uint256,address[],string,string,bool)", ["uint256", "address[]", "string", "string", "bool"],
                        ["address[]", "uint64[]", "int128[]", "uint8[]", "string[]", "string[]", "bool[]"]),
}
def registered_topic():
    return "0x" + keccak(b"Registered(uint256,string,address)").hex()


# ---------------------------------------------------------------- RPC
def rpc(method, params, url=None, timeout=20):
    r = httpx.post(url or RPC, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=timeout)
    r.raise_for_status()
    d = r.json()
    if "error" in d:
        raise RuntimeError(f"{method}: {d['error']}")
    return d["result"]


def call(contract, name, args, chain=None, _rpc=None):
    sig, ins, outs = SIG[name]
    data = encode_call(sig, ins, args)
    out = (_rpc or rpc)("eth_call", [{"to": contract, "data": data}, "latest"])
    res = decode(outs, out) if outs else ()
    return res[0] if len(res) == 1 else res


def registries(chain=None):
    return CHAINS[chain or CHAIN]


# ---------------------------------------------------------------- reads (gateway side)
def owner_of(agent_id, chain=None, _rpc=None):
    return call(registries(chain)["identity"], "ownerOf", [int(agent_id)], chain, _rpc)


def token_uri(agent_id, chain=None, _rpc=None):
    return call(registries(chain)["identity"], "tokenURI", [int(agent_id)], chain, _rpc)


def summary(agent_id, clients, tag1="", tag2="", chain=None, _rpc=None):
    """count, value (scaled by 10**decimals), decimals — from the given client addresses (the standard requires at least one)."""
    cnt, val, dec = call(registries(chain)["reputation"], "getSummary", [int(agent_id), list(clients), tag1, tag2], chain, _rpc)
    return {"count": int(cnt), "value": int(val) / (10 ** int(dec)) if cnt else 0, "decimals": int(dec)}


def project_address():
    try:
        return open(ADDRESS_FILE).read().strip() or None
    except OSError:
        return None


def world_identity():
    try:
        return json.load(open(WORLD_FILE))
    except (OSError, ValueError):
        return None


def registration_json(agent_id=None, chain=None):
    """The world's own registration file (ERC-8004 registration-v1): what MINIMAL AI is and how to reach it."""
    chain = chain or CHAIN
    w = world_identity() or {}
    aid = agent_id if agent_id is not None else w.get("agent_id")
    regs = [{"agentId": int(aid), "agentRegistry": f"eip155:{chain}:{registries(chain)['identity']}"}] if aid is not None else []
    return {"type": REGISTRATION_TYPE, "name": "MINIMAL AI", "description": "An open world for AI agents by MINIMALCULT: identity on the "
            "agent's own key, paid work with signed receipts, payment through non-custodial contracts on TON; every agent gets a numbered "
            "address N.minimalcult.ton.", "image": f"{BASE}/brand-og.png",
            "services": [{"name": "web", "endpoint": "https://minimalcult.org/"},
                         {"name": "A2A", "endpoint": f"{BASE}/.well-known/agent-card.json", "version": "0.3.0"},
                         {"name": "MCP", "endpoint": "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.miinimal/minimalai-mcp", "version": "2025-06-18"},
                         {"name": "GRAM-402", "endpoint": f"{BASE}/docs/gram-402"}],
            "x402Support": True, "active": True, "registrations": regs, "supportedTrust": ["reputation"]}


def parse_registration(uri_or_json, passport_id):
    """Does an agent's registration file point at this passport? Accepts the fetched JSON; the proof is a service endpoint
    or a `minimalai` field that names {BASE}/v1/passport/<id> (the agent controls the file through tokenURI)."""
    d = uri_or_json if isinstance(uri_or_json, dict) else json.loads(uri_or_json)
    needle = f"/v1/passport/{passport_id}".lower()
    for s in d.get("services") or []:
        if isinstance(s, dict) and needle in str(s.get("endpoint", "")).lower():
            return True
    return needle in str(d.get("minimalai", "")).lower()


def fetch_uri(uri, limit=64_000):
    """Fetch an agentURI: https only, data: URIs decoded in place; never ipfs gateways of our choosing (the agent names its host)."""
    import base64
    if uri.startswith("data:application/json;base64,"):
        return json.loads(base64.b64decode(uri.split(",", 1)[1])[:limit])
    if uri.startswith("data:application/json,"):
        from urllib.parse import unquote
        return json.loads(unquote(uri.split(",", 1)[1])[:limit])
    if not uri.startswith("https://"):
        raise ValueError("agentURI must be https:// or data:application/json")
    with httpx.stream("GET", uri, timeout=15, follow_redirects=False, headers={"User-Agent": "minimalai-erc8004/1"}) as r:
        r.raise_for_status()
        body = b""
        for chunk in r.iter_bytes():
            body += chunk
            if len(body) > limit:
                raise ValueError("registration file too large")
    return json.loads(body)


def verify_link(agent_id, passport_id, chain=None, _rpc=None, _fetch=None):
    """The passport's claim 'my ERC-8004 identity is N': the token exists and its registration file names the passport."""
    uri = token_uri(agent_id, chain, _rpc)
    d = (_fetch or fetch_uri)(uri)
    if not parse_registration(d, passport_id):
        raise ValueError("the registration file at tokenURI does not name this passport (add a service endpoint " +
                         f"{BASE}/v1/passport/{passport_id})")
    return {"agent_id": int(agent_id), "chain": chain or CHAIN, "owner": owner_of(agent_id, chain, _rpc), "uri": uri}


# ---------------------------------------------------------------- queue (gateway side): accepted work -> feedback
def queue_feedback(c, agent_id, task_id, receipt_sha256, chain=None, value=1):
    """One accepted task = one feedback of value 1 (tag1 minimalai, tag2 task), endpoint = the public receipt, hash = its sha256."""
    c.executescript(SCHEMA)
    c.execute("INSERT OR IGNORE INTO erc8004_feedback(ts,agent_id,chain,task_id,value,tag1,tag2,endpoint,feedback_hash,status) VALUES(?,?,?,?,?,?,?,?,?,?)",
              (int(time.time()), int(agent_id), chain or CHAIN, task_id, value, "minimalai", "task", f"{BASE}/v1/receipts/task/{task_id}",
               receipt_sha256, "queued"))


# ---------------------------------------------------------------- writes (anchor side)
def load_key(create=False):
    from eth_account import Account
    if os.path.exists(KEY_PATH):
        return Account.from_key(open(KEY_PATH).read().strip())
    if not create:
        return None
    acct = Account.from_key("0x" + secrets.token_hex(32))
    os.makedirs(os.path.dirname(KEY_PATH) or ".", exist_ok=True)
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(acct.key.hex())
    return acct


def publish_address():
    acct = load_key(create=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    open(ADDRESS_FILE, "w").write(acct.address + "\n")
    return acct.address


def balance_wei(address, _rpc=None):
    return int((_rpc or rpc)("eth_getBalance", [address, "latest"]), 16)


def send(contract, data, acct, chain=None, _rpc=None, dry=False, wait=True):
    """Sign and send a type-2 transaction; returns {"tx": hash, "status": 1|0} (or the unsigned fields when dry)."""
    r = _rpc or rpc
    chain = chain or CHAIN
    nonce = int(r("eth_getTransactionCount", [acct.address, "pending"]), 16)
    gas = int(r("eth_estimateGas", [{"from": acct.address, "to": contract, "data": data}]), 16)
    base_fee = int(r("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
    try:
        tip = int(r("eth_maxPriorityFeePerGas", []), 16)
    except Exception:  # noqa: BLE001
        tip = 1_000_000
    tx = {"chainId": chain, "nonce": nonce, "to": contract, "value": 0, "data": data, "gas": int(gas * 1.2),
          "maxFeePerGas": base_fee * 2 + tip, "maxPriorityFeePerGas": tip, "type": 2}
    if dry:
        return {"dry": True, **{k: (v if k != "data" else v[:20] + "…") for k, v in tx.items()}}
    raw = acct.sign_transaction(tx).raw_transaction
    h = r("eth_sendRawTransaction", ["0x" + raw.hex()])
    if not wait:
        return {"tx": h}
    for _ in range(60):
        rec = r("eth_getTransactionReceipt", [h])
        if rec:
            return {"tx": h, "status": int(rec["status"], 16), "logs": rec.get("logs", [])}
        time.sleep(2)
    return {"tx": h, "status": None}


def register_world(acct, chain=None, _rpc=None, dry=False, uri=None):
    """Mint the world's identity with agentURI = our registration file; remembers the agentId in WORLD_FILE."""
    chain = chain or CHAIN
    uri = uri or f"{BASE}/.well-known/agent-registration.json"
    data = encode_call(*SIG["register"][:2], [uri])
    res = send(registries(chain)["identity"], data, acct, chain, _rpc, dry)
    if dry or res.get("status") != 1:
        return res
    topic = registered_topic()
    for lg in res["logs"]:
        if lg.get("topics") and lg["topics"][0].lower() == topic and len(lg["topics"]) > 1:
            aid = int(lg["topics"][1], 16)
            json.dump({"agent_id": aid, "chain": chain, "tx": res["tx"], "uri": uri, "ts": int(time.time())}, open(WORLD_FILE, "w"))
            res["agent_id"] = aid
    return res


def send_feedback(c, acct, chain=None, _rpc=None, dry=False, limit=5):
    """Queued feedback -> chain. One transaction per accepted task; failures are kept with the error for the next round."""
    c.executescript(SCHEMA)
    rows = c.execute("SELECT * FROM erc8004_feedback WHERE status='queued' ORDER BY id LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        fh = bytes.fromhex(r["feedback_hash"]) if r["feedback_hash"] else b"\0" * 32
        data = encode_call(*SIG["giveFeedback"][:2], [int(r["agent_id"]), int(r["value"]), 0, r["tag1"], r["tag2"], r["endpoint"], r["endpoint"], fh])
        try:
            res = send(registries(r["chain"] or chain)["reputation"], data, acct, r["chain"] or chain, _rpc, dry)
            if not dry:
                c.execute("UPDATE erc8004_feedback SET status=?, tx=?, error=NULL WHERE id=?",
                          ("sent" if res.get("status") == 1 else "failed", res.get("tx"), r["id"]))
        except Exception as e:  # noqa: BLE001
            res = {"error": str(e)[:200]}
            if not dry:
                c.execute("UPDATE erc8004_feedback SET error=? WHERE id=?", (res["error"], r["id"]))
        out.append({"task_id": r["task_id"], **res})
    return out


def proof(acct, gw=None, admin_token=None, chain=None, _rpc=None, log=print):
    """The whole R1 proof on the public testnet, from the anchor: a throwaway agent key funded by the project registers its own
    identity whose registration file (a data: URI) names a fresh passport; the passport is linked through the gateway (tokenURI
    check on chain); a poster hires that agent for one task and accepts; the queued feedback is written to the Reputation
    Registry by the project key. Prints every address and transaction. Needs ~0.001 ETH on the project address and the admin
    token (one credit of test GRAM for the poster). Idempotent per run: a new agent each time."""
    import base64, sqlite3
    from eth_account import Account
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization as S
    gw = gw or ("http://" + os.environ.get("GW_HOST", "127.0.0.1") + ":8090")
    admin_token = admin_token or os.environ.get("ADMIN_TOKEN", "")
    chain = chain or CHAIN
    r = _rpc or rpc
    H = lambda key: {"Authorization": f"Bearer {key}"}
    # 1. a passport for the agent (public API), its API key bound to it
    worker = httpx.post(f"{gw}/v1/signup", json={"name": "erc8004-proof"}, timeout=30).json()
    if "api_key" not in worker:
        raise RuntimeError(f"signup refused: {worker}")
    pk = Ed25519PrivateKey.generate(); pub = pk.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw).hex()
    ch = httpx.post(f"{gw}/v1/passport/challenge", json={"pubkey": pub}, timeout=30).json()
    pp = httpx.post(f"{gw}/v1/passport", json={"pubkey": pub, "nonce": ch["nonce"], "sig": base64.b64encode(pk.sign(ch["sign"].encode())).decode(), "name": "erc8004-proof"}, timeout=30).json()
    httpx.post(f"{gw}/v1/passport/{pp['id']}/bind", json={"sig": base64.b64encode(pk.sign(f"minimalai-bind:{pp['id']}:{worker['agent_id']}".encode())).decode()}, headers=H(worker["api_key"]), timeout=30).raise_for_status()
    log(f"PASSPORT {pp['id']} agent {worker['agent_id']} number {worker.get('number')}")
    # 2. the agent's own EVM key, funded by the project with 0.0004 ETH, registers its identity (agentURI = data: file naming the passport)
    agent = Account.from_key("0x" + secrets.token_hex(32))
    fund = send_eth(acct, agent.address, 400_000_000_000_000, chain, r)
    log(f"AGENT_KEY {agent.address} funded tx {fund.get('tx')} status {fund.get('status')}")
    reg = {"type": REGISTRATION_TYPE, "name": "erc8004-proof agent", "description": "a MINIMAL AI worker proving the passport link",
           "services": [{"name": "minimalai", "endpoint": f"{BASE}/v1/passport/{pp['id']}"}], "active": True}
    uri = "data:application/json;base64," + base64.b64encode(json.dumps(reg).encode()).decode()
    res = send(registries(chain)["identity"], encode_call(*SIG["register"][:2], [uri]), agent, chain, r)
    aid = None
    for lg in res.get("logs", []):
        if lg.get("topics") and lg["topics"][0].lower() == registered_topic() and len(lg["topics"]) > 1:
            aid = int(lg["topics"][1], 16)
    log(f"AGENT_IDENTITY agentId {aid} tx {res.get('tx')} status {res.get('status')}")
    if aid is None:
        raise RuntimeError("registration produced no Registered event")
    # 3. the gateway links passport <- identity after reading tokenURI on chain
    link = httpx.post(f"{gw}/v1/passport/{pp['id']}/erc8004", json={"agent_id": aid, "chain": chain}, timeout=60)
    log(f"LINK {link.status_code} {link.text[:160]}")
    link.raise_for_status()
    # 4. one job: a poster hires the agent and accepts; the gateway queues the feedback
    poster = httpx.post(f"{gw}/v1/signup", json={"name": "erc8004-poster"}, timeout=30).json()
    httpx.post(f"{gw}/admin/credit", json={"api_key": poster["api_key"], "nano": 300_000_000}, headers=H(admin_token), timeout=30).raise_for_status()
    t = httpx.post(f"{gw}/v1/tasks", json={"title": "ERC-8004 proof: say which chain this is", "instructions": "Answer with the chain name and id of the test network used for this proof.", "price_nano": 100_000_000}, headers=H(poster["api_key"]), timeout=30).json()
    httpx.post(f"{gw}/v1/work/{t['id']}/take", headers=H(worker["api_key"]), timeout=30).raise_for_status()
    httpx.post(f"{gw}/v1/work/{t['id']}/submit", json={"submission": f"Base Sepolia, eip155:{chain}"}, headers=H(worker["api_key"]), timeout=30).raise_for_status()
    acc = httpx.post(f"{gw}/v1/tasks/{t['id']}/accept", headers=H(poster["api_key"]), timeout=30).json()
    log(f"TASK {t['id']} {acc.get('status')} receipt {BASE}/v1/receipts/task/{t['id']}")
    # 5. the project key writes the queued feedback
    c = sqlite3.connect(DB_PATH, timeout=10); c.row_factory = sqlite3.Row
    out = send_feedback(c, acct, chain, r); c.commit(); c.close()
    log(f"FEEDBACK {json.dumps(out, default=str)[:300]}")
    log(f"SUMMARY {json.dumps(summary(aid, [acct.address], chain=chain, _rpc=r))} · {registries(chain)['explorer']}/address/{registries(chain)['reputation']}")
    return {"passport": pp["id"], "agent_id": aid, "agent_address": agent.address, "task": t["id"], "feedback": out}


def send_eth(acct, to, wei, chain=None, _rpc=None):
    r = _rpc or rpc; chain = chain or CHAIN
    nonce = int(r("eth_getTransactionCount", [acct.address, "pending"]), 16)
    base_fee = int(r("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
    tx = {"chainId": chain, "nonce": nonce, "to": to, "value": int(wei), "data": "0x", "gas": 21000, "maxFeePerGas": base_fee * 2 + 1_000_000, "maxPriorityFeePerGas": 1_000_000, "type": 2}
    h = r("eth_sendRawTransaction", ["0x" + acct.sign_transaction(tx).raw_transaction.hex()])
    for _ in range(60):
        rec = r("eth_getTransactionReceipt", [h])
        if rec:
            return {"tx": h, "status": int(rec["status"], 16)}
        time.sleep(2)
    return {"tx": h, "status": None}


def status(_rpc=None):
    addr = project_address()
    d = {"chain": CHAIN, "network": registries()["name"], "rpc": RPC, "identity_registry": registries()["identity"],
         "reputation_registry": registries()["reputation"], "explorer": registries()["explorer"], "project_address": addr,
         "world": world_identity(), "source": SOURCE, "spec": "https://eips.ethereum.org/EIPS/eip-8004 (draft)"}
    if addr:
        try:
            d["project_balance_eth"] = balance_wei(addr, _rpc) / 1e18
        except Exception as e:  # noqa: BLE001
            d["project_balance_eth"] = None; d["rpc_error"] = str(e)[:120]
    return d


def main(argv):
    import sqlite3
    cmd = argv[0] if argv else "status"
    dry = "--dry" in argv
    if cmd == "address":
        print(publish_address()); return 0
    if cmd == "status":
        print(json.dumps(status(), indent=1)); return 0
    if cmd == "summary":
        aid = int(argv[1]); print(json.dumps(summary(aid, [project_address() or "0x" + "0" * 40]))); return 0
    acct = load_key(create=True); publish_address()
    if cmd == "register":
        print(json.dumps(register_world(acct, dry=dry), indent=1, default=str)); return 0
    if cmd == "proof":
        print(json.dumps(proof(acct), indent=1, default=str)); return 0
    if cmd == "feedback":
        c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row
        print(json.dumps(send_feedback(c, acct, dry=dry), indent=1, default=str)); c.commit(); return 0
    print(__doc__); return 2


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
