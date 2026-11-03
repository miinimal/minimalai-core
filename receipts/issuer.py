"""Signed receipts for every answer ("notarized AI").

A receipt binds: request hash, response hash, model, route, time, and the latest independent RA-TLS evidence of the
Cocoon proxy (TEE type, image hash, MRTD, check time). It is signed with the gateway's Ed25519 key, published at
/.well-known/minimalai.json. What it proves: this gateway received exactly this request, returned exactly this
answer, and at `tee.checked_at` the Cocoon proxy presented an Intel TDX quote bound to its TLS key with an image hash
on the root-contract allowlist. What it does not prove: per-request execution inside TEE (Cocoon does not expose a
per-response signature yet) or the Intel DCAP signature over the quote (not verified yet).
"""
import base64
import hashlib
import json
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KEY_PATH = os.environ.get("RECEIPT_KEY_PATH", os.path.join(os.path.dirname(os.environ.get("MINIMALAI_DB", "./x.db")),
                                                            "receipt_ed25519.key"))
_key = None


def key():
    global _key
    if _key is None:
        if os.path.exists(KEY_PATH):
            _key = Ed25519PrivateKey.from_private_bytes(open(KEY_PATH, "rb").read())
        else:
            _key = Ed25519PrivateKey.generate()
            os.makedirs(os.path.dirname(KEY_PATH) or ".", exist_ok=True)
            with open(KEY_PATH, "wb") as f:
                f.write(_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                           serialization.NoEncryption()))
            os.chmod(KEY_PATH, 0o600)
    return _key


def public_key_hex():
    return key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha256(obj):
    return hashlib.sha256(canon(obj) if not isinstance(obj, (bytes, bytearray)) else obj).hexdigest()


def make(request_body, response_body, route, attestation, payment=None):
    """payment (GRAM-402): {network, transaction, payer, charged_nano} binds the on-chain payment to this answer."""
    a = attestation or {}
    payload = {
        "v": 1, "issuer": "MINIMALAI", "ts": int(time.time()), "route": route,
        "model": request_body.get("model"),
        "request_sha256": sha256(request_body),
        "response_sha256": sha256({k: v for k, v in response_body.items() if k != "minimalai"}),
        "tee": None if route != "cocoon" else {
            "type": a.get("tee"), "image_hash": a.get("image_hash"), "mr_td": a.get("mr_td"),
            "key_bound": a.get("reportdata_binds_tls_key"), "image_allowed_by_root": a.get("image_hash_allowed_by_root"),
            "intel_signature_verified": a.get("quote_signature_verified", False), "checked_at": a.get("checked_at"),
        },
        "gateway_key": public_key_hex(),
    }
    if payment:
        payload["payment"] = {k: payment.get(k) for k in ("network", "transaction", "payer", "charged_nano")}
    sig = key().sign(canon(payload))
    return {**payload, "sig": base64.b64encode(sig).decode()}


def receipt_id(receipt):
    """Stable id of any signed record (receipt, task receipt, dispute): SHA-256 of its canonical JSON without 'sig'.
    Ed25519 is deterministic, so the id is unique per signed content. Disputes and the oracle reference records by it."""
    return sha256({k: v for k, v in receipt.items() if k != "sig"})


def verify_with_key(record, pubkey_hex):
    """Portable check (RECEIPTS v1): the signature over canonical JSON without 'sig' is valid for the pinned key.
    Needs no call to this gateway; any party holding the record and the pinned key can run it."""
    r = dict(record)
    if r.get("gateway_key") != pubkey_hex:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(base64.b64decode(r.pop("sig")), canon(r))
    except Exception:  # noqa: BLE001  bad signature, bad base64 or bad key all mean "not valid"
        return False
    return True


def sign(payload):
    """Sign any record payload with the gateway key (adds gateway_key, returns record with 'sig')."""
    payload = {**payload, "gateway_key": public_key_hex()}
    return {**payload, "sig": base64.b64encode(key().sign(canon(payload))).decode()}


def verify(receipt, request_body=None, response_body=None):
    r = dict(receipt)
    sig = base64.b64decode(r.pop("sig"))
    # The signer must be THIS gateway's published key; a receipt carrying any other key is a forgery even if self-consistent.
    if r.get("gateway_key") != public_key_hex():
        return False
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(r["gateway_key"])).verify(sig, canon(r))
    if request_body is not None and sha256(request_body) != r["request_sha256"]:
        return False
    if response_body is not None and sha256({k: v for k, v in response_body.items() if k != "minimalai"}) != r["response_sha256"]:
        return False
    return True


def pseudonym(account):
    """Public pseudonymous id of an account in task receipts: first 32 hex of SHA-256 of its internal id."""
    return hashlib.sha256(str(account).encode()).hexdigest()[:32]


def make_task(row, decision, prev_sha256, extra=None):
    """Proof of work done, not just proof of payment: a signed, hash-chained record that a specific submission for a
    specific task was accepted and paid. Texts are committed by SHA-256 only; anyone holding the texts can check them."""
    review = row["review"] or "{}"
    th = lambda t: hashlib.sha256((t or "").encode("utf-8")).hexdigest()  # plain UTF-8 text hash, easy to recheck
    payload = {
        "v": 1, "kind": "task_completion", "issuer": "MINIMALAI", "ts": int(time.time()),
        "task_id": row["id"], "title_sha256": th(row["title"]), "instructions_sha256": th(row["instructions"]),
        "proof_type": row["proof"], "submission_sha256": th(row["submission"]),
        "worker": pseudonym(row["worker"]),
        # poster pseudonym in the same id space as workers (an agent's key posts as "key:<hash>" and works as the same
        # id), so anyone can build the public who-paid-whom graph and spot reciprocal pairs (RECEIPTS v1, reputation)
        "poster": pseudonym("key:" + str(row["poster"])) if row["poster"] else None,
        "price_nano": row["price_nano"], "decision": decision,
        "ai_review": (json.loads(review) or {}).get("verdict"),
        "prev_sha256": prev_sha256, "gateway_key": public_key_hex(),
    }
    if extra:
        payload.update(extra)   # e.g. work_order (workorders.py); signed with the rest
    sig = key().sign(canon(payload))
    return {**payload, "sig": base64.b64encode(sig).decode()}
