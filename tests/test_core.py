"""Open-core tests: receipts sign/verify round trip across issuer and standalone verifier, tamper detection,
hash chain, secret scanner self-test, MCP server import. Run: python -m pytest -q tests"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.dirname(HERE)


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(CORE, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


os.environ["RECEIPT_KEY_PATH"] = os.path.join(tempfile.mkdtemp(), "k.key")
issuer = load("issuer", "receipts/issuer.py")
verify = load("verify", "receipts/verify.py")
scan = load("secret_scan", "tools/secret_scan.py")


def test_receipt_round_trip_and_tamper():
    req, resp = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}, {"choices": [{"text": "hello"}]}
    r = issuer.make(req, resp, "fallback", None)
    key = issuer.public_key_hex()
    assert verify.verify(r, key)
    assert verify.receipt_id(r) == issuer.receipt_id(r)
    assert verify.check_bodies(r, req, resp) is not False
    assert not verify.verify({**r, "model": "other"}, key)          # tampered field
    assert not verify.verify(r, "00" * 32)                          # wrong pinned key


def test_task_receipt_chain():
    row = {"id": 1, "title": "t", "instructions": "i", "proof": "text", "submission": "s", "worker": 7, "poster": 9,
           "price_nano": 10, "review": None}
    a = issuer.make_task(row, "accepted", None)
    b = issuer.make_task({**row, "id": 2}, "accepted", issuer.sha256({k: v for k, v in a.items()}))
    assert verify.verify(a, issuer.public_key_hex()) and verify.verify(b, issuer.public_key_hex())


def test_secret_scanner_catches_and_passes():
    bad = {
        "private key block": "-----BEGIN " + "PRIVATE KEY-----",
        "telegram bot token": "123456789:AA" + "b" * 33,
        "anthropic key": "sk-ant-" + "x" * 30,
        "github token": "ghp_" + "a" * 36,
        "hard-coded secret": 'API_KEY = "' + "Q" * 24 + '"',
        "seed phrase": " ".join(["word"] * 24),
    }
    for name, line in bad.items():
        assert name in [n for _, n in scan.scan_text(line)], name
    assert scan.scan_text('key = os.environ["API_KEY"]') == []
    assert scan.scan(CORE) == [], scan.scan(CORE)


def test_mcp_server_imports():
    sys.path.insert(0, os.path.join(CORE, "mcp", "src"))
    import minimalai_mcp.server as s  # noqa: F401
    assert hasattr(s, "main")


def test_escrow_offer_address_matches_contract_build():
    sys.path.insert(0, os.path.join(CORE, "escrow"))
    import offer as E
    a = lambda ch: "0:" + ch * 64
    si = E.state_init(a("a"), a("b"), 1800000000, 7, 1500, a("c"))
    assert E.address_of(si).to_str(is_user_friendly=False) == \
        "0:d1aee0d69ec547e383e6ef20c52ce35731daf9cc22eeee4fdabf663e5f3a2c7e"
