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
# O-2: in production the key lives only in the isolated signer process (signer.py, no network, key mounted read-only);
# every service reaches it through this unix socket and never sees the key bytes. Unset = local key file (tests, dev).
SIGNER_SOCKET = os.environ.get("SIGNER_SOCKET", "")
_key = None
_pub = None


PQ_KEY_PATH = os.environ.get("RECEIPT_PQ_KEY_PATH", os.path.join(os.path.dirname(KEY_PATH) or ".", "receipt_mldsa65.seed"))
PQ_ALG = "ML-DSA-65"
_pq_key = None
_pq_pub = None          # hex, "" = the signer has no post-quantum key


class SignerUnavailable(RuntimeError):
    """The isolated signer did not answer: the caller must fail the request, never fall back to a new key."""


def _signer_call(req, timeout=5.0, attempts=3):
    import socket
    data = (json.dumps(req) + "\n").encode()
    last = None
    for i in range(attempts):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as so:
                so.settimeout(timeout)
                so.connect(SIGNER_SOCKET)
                so.sendall(data)
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = so.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            resp = json.loads(buf or b"{}")
            if "error" in resp:
                raise SignerUnavailable("signer refused: " + str(resp["error"])[:120])
            return resp
        except SignerUnavailable:
            raise
        except (OSError, ValueError) as e:
            last = e
            time.sleep(0.2 * (i + 1))
    raise SignerUnavailable(f"signer socket {SIGNER_SOCKET} not answering: {type(last).__name__}")


def key():
    """The local private key (tests and development only). With SIGNER_SOCKET set this refuses: nothing in production
    may load or mint the key outside the signer."""
    global _key
    if SIGNER_SOCKET:
        raise RuntimeError("receipt key is held by the isolated signer (SIGNER_SOCKET); use raw_sign()")
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


def raw_sign(message):
    """Ed25519 signature of `message` (bytes) by the gateway key, wherever the key lives."""
    if SIGNER_SOCKET:
        return base64.b64decode(_signer_call({"op": "sign", "msg": base64.b64encode(bytes(message)).decode()})["sig"])
    return key().sign(bytes(message))


def signing_available():
    """True when a signature can be made without minting a key (a socket is configured, or the key file exists)."""
    return bool(SIGNER_SOCKET) or os.path.exists(KEY_PATH)


def public_key_hex():
    global _pub
    if _pub is None:
        if SIGNER_SOCKET:
            _pub = _signer_call({"op": "pub"})["pub"]
        else:
            return key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return _pub


def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha256(obj):
    return hashlib.sha256(canon(obj) if not isinstance(obj, (bytes, bytearray)) else obj).hexdigest()


# RECEIPTS v2 (H2-2): a receipt says how far the thing it describes got, and what it saw versus what it assumes.
DELIVERY = {
    "executed": "the work was done on our side (an answer produced, a submission recorded); the other party has not confirmed receipt",
    "delivered": "the other party confirmed receipt (an acknowledgement of the answer, or the poster accepted the work)",
    "maybe_sent": "closed by a rule without the other party's word (a silent poster, an auto-accept); treat as unconfirmed",
    "failed": "rejected or not done; nothing to deliver",
}


# ---- W0: post-quantum hybrid. NIST IR 8547 (final 27.10.2026): EdDSA deprecated after 2030, disallowed after 2035.
# Construction (backward compatible with every Ed25519 verifier already in use, which checks canonical JSON without 'sig'):
#   1. payload P gets `pq_key` = sha256 of the raw ML-DSA-65 public key;
#   2. ML-DSA-65 signs canon(P);  P' = P + {"pq": {"alg": "ML-DSA-65", "sig": base64}};
#   3. Ed25519 signs canon(P') as before -> record = P' + {"sig": ...}.
# Post-quantum check: drop `sig` and `pq`, verify pq.sig over the canonical rest with the published key whose sha256 = pq_key.
# A forger with a quantum computer can make a new Ed25519 signature, but not an ML-DSA one over changed content.
def _pq_local():
    global _pq_key
    from cryptography.hazmat.primitives.asymmetric import mldsa
    if _pq_key is None:
        if not os.path.exists(PQ_KEY_PATH):
            os.makedirs(os.path.dirname(PQ_KEY_PATH) or ".", exist_ok=True)
            with open(PQ_KEY_PATH, "wb") as f:
                f.write(os.urandom(32))
            os.chmod(PQ_KEY_PATH, 0o600)
        _pq_key = mldsa.MLDSA65PrivateKey.from_seed_bytes(open(PQ_KEY_PATH, "rb").read())
    return _pq_key


def pq_public_key_hex():
    """Hex of the raw ML-DSA-65 public key, or "" when the signer runs without one (Ed25519-only records)."""
    global _pq_pub
    if _pq_pub is None:
        if SIGNER_SOCKET:
            _pq_pub = _signer_call({"op": "pub"}).get("pub_mldsa65") or ""
        else:
            if os.environ.get("RECEIPT_PQ", "1") != "1":
                return ""
            _pq_pub = _pq_local().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return _pq_pub


def raw_sign_pq(message):
    if SIGNER_SOCKET:
        return base64.b64decode(_signer_call({"op": "sign_pq", "msg": base64.b64encode(bytes(message)).decode()})["sig"])
    return _pq_local().sign(bytes(message))


def _seal(payload):
    """Hybrid signature of a record payload (W0 construction above); Ed25519 only when no ML-DSA key is available."""
    payload = {k: v for k, v in payload.items() if k not in ("sig", "pq", "pq_key")}
    pub = pq_public_key_hex()
    if pub:
        payload["pq_key"] = hashlib.sha256(bytes.fromhex(pub)).hexdigest()
        payload["pq"] = {"alg": PQ_ALG, "sig": base64.b64encode(raw_sign_pq(canon(payload))).decode()}
    return {**payload, "sig": base64.b64encode(raw_sign(canon(payload))).decode()}


def verify_pq(record, pq_pub_hex):
    """True: the ML-DSA-65 signature is valid for the published key; False: invalid or key mismatch; None: no PQ signature."""
    pq = record.get("pq")
    if not isinstance(pq, dict) or "pq_key" not in record:
        return None
    try:
        if pq.get("alg") != PQ_ALG or record["pq_key"] != hashlib.sha256(bytes.fromhex(pq_pub_hex)).hexdigest():
            return False
        from cryptography.hazmat.primitives.asymmetric import mldsa
        rest = {k: v for k, v in record.items() if k not in ("sig", "pq")}
        mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(pq_pub_hex)).verify(base64.b64decode(pq["sig"]), canon(rest))
    except Exception:  # noqa: BLE001
        return False
    return True


def delivery(status, observed, assumed, by=None, ack=None):
    """`delivery` + `distrust` blocks: what we observed ourselves versus what the next agent should not take on faith."""
    return {"delivery": {"status": status, "by": by, "ack": ack, "meaning": DELIVERY[status]},
            "distrust": {"observed": observed, "assumed": assumed}}


def make(request_body, response_body, route, attestation, payment=None):
    """payment (GRAM-402): {network, transaction, payer, charged_nano} binds the on-chain payment to this answer."""
    a = attestation or {}
    payload = {
        "v": 2, "issuer": "MINIMALAI", "ts": int(time.time()), "route": route,
        "model": request_body.get("model"),
        "request_sha256": sha256(request_body),
        "response_sha256": sha256({k: v for k, v in response_body.items() if k != "minimalai"}),
        "tee": None if route != "cocoon" else {
            "type": a.get("tee"), "image_hash": a.get("image_hash"), "mr_td": a.get("mr_td"),
            "key_bound": a.get("reportdata_binds_tls_key"), "image_allowed_by_root": a.get("image_hash_allowed_by_root"),
            "intel_signature_verified": a.get("quote_signature_verified", False), "checked_at": a.get("checked_at"),
        },
        "gateway_key": public_key_hex(), "check": CHECK_URL,
    }
    if payment:
        payload["payment"] = {k: payment.get(k) for k in ("network", "transaction", "payer", "charged_nano")}
    payload.update(delivery("executed",
                            observed=["request hash", "response hash", "route and model", "time of issue"] + (["payment transaction on chain"] if payment else []),
                            assumed=["the client received these bytes (confirm with POST /v1/receipts/{receipt_id}/ack)", "the answer is correct"],
                            ack="POST /v1/receipts/{receipt_id}/ack"))
    return _seal(payload)


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


CHECK_URL = "https://ai.minimalcult.org/check"   # A1: every record says where anyone can check it (paste the record, or open it by id)


def sign(payload):
    """Sign any record payload with the gateway key (adds gateway_key and the check link, returns record with 'sig')."""
    payload = {**payload, "gateway_key": public_key_hex()}
    payload.setdefault("check", CHECK_URL)
    return _seal(payload)


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
        "v": 2, "kind": "task_completion", "issuer": "MINIMALAI", "ts": int(time.time()),
        "task_id": row["id"], "title_sha256": th(row["title"]), "instructions_sha256": th(row["instructions"]),
        "proof_type": row["proof"], "submission_sha256": th(row["submission"]),
        "worker": pseudonym(row["worker"]),
        # poster pseudonym in the same id space as workers (an agent's key posts as "key:<hash>" and works as the same
        # id), so anyone can build the public who-paid-whom graph and spot reciprocal pairs (RECEIPTS v1, reputation)
        "poster": pseudonym("key:" + str(row["poster"])) if row["poster"] else None,
        "price_nano": row["price_nano"], "decision": decision,
        "ai_review": (json.loads(review) or {}).get("verdict"),
        "prev_sha256": prev_sha256, "gateway_key": public_key_hex(), "check": CHECK_URL,
    }
    if extra:
        payload.update(extra)   # e.g. work_order (workorders.py); signed with the rest
    status = "delivered" if decision == "accepted_by_poster" else ("failed" if decision.startswith("reject") else "maybe_sent")
    payload.update(delivery(status, by=("poster" if status == "delivered" else "rule"),
                            observed=["the submission hash was recorded", f"the decision '{decision}' was recorded", "the payment moved on the ledger or the contract"]
                            if status != "failed" else ["the submission hash was recorded", f"the decision '{decision}' was recorded"],
                            assumed=["the submission text matches its hash (only the hash is signed)", "the worker is the holder of its key"]
                            + (["the poster saw the work: it was closed by a rule, not by the poster's word"] if status == "maybe_sent" else [])))
    return _seal(payload)
