"""Attestations (block ATT): verification of the formats other logs and services already use. Pure functions, no network:
callers pass fetched documents and keys in. The same file ships in the open CLI (sdk/python/minimalcult/formats.py), so
anyone can repeat every check offline.

Formats accepted for anchoring:
  checkpoint      C2SP signed note / transparency-log checkpoint (origin, tree size, base64 root, extensions; Ed25519 note
                  keys "name+hash+base64", or ECDSA P-256 keys as PEM, the Sigstore Rekor convention)
  rfc6962_sth     RFC 6962 signed tree head as served by get-sth (TreeHeadSignature, DigitallySigned: ECDSA, RSA, Ed25519)
  rfc9162_checkpoint  RFC 9162 tree heads published as checkpoints: verified as `checkpoint`
  sigstore_bundle Sigstore bundle over an artifact digest, verified by sigstore-python against the public-good trust root
  x402_receipt    x402 "offer-receipt" extension receipt: JWS (EdDSA, ES256, ES256K; key from a did:web document) or EIP-712
  sha256          any 32-byte digest: only the fact that the writer presented it at this time
Consistency between two tree heads of one log: RFC 9162 section 2.1.4.2.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: Apache-2.0 (open core).
"""
import base64
import hashlib
import json

TYPES = ("checkpoint", "rfc6962_sth", "rfc9162_checkpoint", "sigstore_bundle", "x402_receipt", "sha256")


class FormatError(ValueError):
    """The payload is malformed or its signature does not verify; `code` is the machine-readable reason."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def b64d(s):
    s = s.strip()
    return base64.b64decode(s + "=" * (-len(s) % 4))


def b64url_d(s):
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- signed notes and checkpoints (C2SP signed-note, tlog-checkpoint)
def parse_note(text):
    """-> (body_bytes, [(name, key_hint_bytes, signature_bytes)]). The signed message is the body up to and including the
    newline before the blank line."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    if "\n\n" not in text:
        raise FormatError("note_malformed", "a signed note needs a body, a blank line and signature lines")
    body, sigs = text.split("\n\n", 1)
    body = body + "\n"
    out = []
    for line in sigs.split("\n"):
        if not line:
            continue
        if not line.startswith("— "):
            raise FormatError("note_malformed", "signature lines start with an em dash and a space")
        try:
            name, b = line[2:].rsplit(" ", 1)
            raw = b64d(b)
        except Exception:
            raise FormatError("note_malformed", "signature line is not 'name base64'") from None
        if len(raw) < 5:
            raise FormatError("note_malformed", "signature too short")
        out.append((name, raw[:4], raw[4:]))
    if not out:
        raise FormatError("note_unsigned", "the note carries no signature")
    return body.encode("utf-8"), out


def parse_checkpoint(body):
    """C2SP tlog-checkpoint body -> {origin, tree_size, root_hash (hex), extensions}."""
    lines = body.decode("utf-8").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if len(lines) < 3:
        raise FormatError("checkpoint_malformed", "a checkpoint has origin, tree size and root hash lines")
    try:
        size = int(lines[1])
        root = b64d(lines[2])
    except Exception:
        raise FormatError("checkpoint_malformed", "tree size must be decimal and the root hash base64") from None
    if size < 0 or str(size) != lines[1] or len(root) != 32:
        raise FormatError("checkpoint_malformed", "tree size must be a canonical decimal and the root 32 bytes")
    return {"origin": lines[0], "tree_size": size, "root_hash": root.hex(), "extensions": lines[3:]}


def note_key(vkey):
    """A verifier key: Ed25519 note vkey 'name+hash+base64(0x01||key)' or an ECDSA/Ed25519 public key in PEM.
    -> dict(name or None, alg, key object, hint bytes or a list of accepted hints, key_id text)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    vkey = vkey.strip()
    if vkey.startswith("-----BEGIN"):
        k = serialization.load_pem_public_key(vkey.encode())
        der = k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if isinstance(k, ec.EllipticCurvePublicKey):
            alg = "ecdsa_p256_sha256"
        elif isinstance(k, ed25519.Ed25519PublicKey):
            alg = "ed25519"
        else:
            raise FormatError("key_unsupported", "PEM keys must be ECDSA P-256 or Ed25519")
        # Sigstore Rekor: hint = sha256(DER SPKI)[:4]; C2SP: hint = sha256(name || '\n' || 0x02 || DER)[:4] (name-bound, checked later)
        return {"name": None, "alg": alg, "key": k, "der": der, "hints": [hashlib.sha256(der).digest()[:4]], "key_id": "sha256:" + sha256_hex(der)}
    try:
        name, hint_hex, keyb64 = vkey.split("+", 2)
        raw = b64d(keyb64)
    except Exception:
        raise FormatError("key_malformed", "note keys look like name+hash+base64") from None
    if len(raw) != 33 or raw[0] != 1:
        raise FormatError("key_unsupported", "only Ed25519 note keys (type 0x01) are accepted in this form")
    hint = hashlib.sha256(name.encode() + b"\n" + raw).digest()[:4]
    if hint.hex() != hint_hex.lower():
        raise FormatError("key_malformed", "the key hash in the vkey does not match its name and key")
    return {"name": name, "alg": "ed25519", "key": ed25519.Ed25519PublicKey.from_public_bytes(raw[1:]), "hints": [hint], "key_id": vkey}


def verify_note(text, vkey, expect_origin=None):
    """Verify a signed note by one known key. -> {origin, tree_size, root_hash, extensions, key_id, signer} or FormatError."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    body, sigs = parse_note(text)
    k = note_key(vkey)
    hints = list(k["hints"])
    for name, hint, sig in sigs:
        if k["name"] is not None and name != k["name"]:
            continue
        if k.get("der") is not None:
            hints = list(k["hints"]) + [hashlib.sha256(name.encode() + b"\n\x02" + k["der"]).digest()[:4]]
        if hint not in hints:
            continue
        try:
            if k["alg"] == "ed25519":
                k["key"].verify(sig, body)
            else:
                k["key"].verify(sig, body, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise FormatError("signature_invalid", f"the signature of {name} does not verify over the note body") from None
        cp = parse_checkpoint(body)
        if expect_origin and cp["origin"] != expect_origin:
            raise FormatError("origin_mismatch", f"checkpoint origin is {cp['origin']!r}, expected {expect_origin!r}")
        return {**cp, "key_id": k["key_id"], "signer": name}
    raise FormatError("signature_missing", "no signature line from the given key")


# ---------------------------------------------------------------- RFC 6962 signed tree head
_SIG_ALG = {1: "rsa", 3: "ecdsa", 7: "ed25519"}


def verify_sth(sth, key_pem):
    """RFC 6962 section 3.5 get-sth JSON: tree_size, timestamp (ms), sha256_root_hash (base64), tree_head_signature (base64
    DigitallySigned). Signed data: version 0, signature_type tree_hash (1), timestamp u64, tree_size u64, root 32 bytes."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding
    try:
        size, ts = int(sth["tree_size"]), int(sth["timestamp"])
        root = b64d(sth["sha256_root_hash"])
        ds = b64d(sth["tree_head_signature"])
    except Exception:
        raise FormatError("sth_malformed", "get-sth needs tree_size, timestamp, sha256_root_hash and tree_head_signature") from None
    if len(root) != 32 or len(ds) < 4 or size < 0 or ts < 0:
        raise FormatError("sth_malformed", "root hash must be 32 bytes and the signature a DigitallySigned struct")
    hash_alg, sig_alg, n = ds[0], ds[1], int.from_bytes(ds[2:4], "big")
    sig = ds[4:4 + n]
    if len(sig) != n or (hash_alg != 4 and sig_alg != 7) or sig_alg not in _SIG_ALG:
        raise FormatError("sth_unsupported", "DigitallySigned must be SHA-256 with RSA or ECDSA, or Ed25519")
    data = b"\x00\x01" + ts.to_bytes(8, "big") + size.to_bytes(8, "big") + root
    key = serialization.load_pem_public_key(key_pem.encode() if isinstance(key_pem, str) else key_pem)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        if _SIG_ALG[sig_alg] == "ecdsa":
            key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        elif _SIG_ALG[sig_alg] == "rsa":
            key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            key.verify(sig, data)
    except (InvalidSignature, TypeError, AttributeError):
        raise FormatError("signature_invalid", "the tree head signature does not verify with the log key") from None
    return {"tree_size": size, "timestamp_ms": ts, "root_hash": root.hex(), "key_id": "sha256:" + sha256_hex(der),
            "log_id": base64.b64encode(hashlib.sha256(der).digest()).decode()}


# ---------------------------------------------------------------- RFC 9162 Merkle consistency
def _node(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def verify_consistency(first, second, first_hash, second_hash, proof):
    """RFC 9162 section 2.1.4.2. Hashes as hex or bytes. True or False, never an exception for a well-typed input."""
    fh = bytes.fromhex(first_hash) if isinstance(first_hash, str) else first_hash
    sh = bytes.fromhex(second_hash) if isinstance(second_hash, str) else second_hash
    path = [bytes.fromhex(p) if isinstance(p, str) else p for p in proof]
    if first < 0 or second < 0 or first > second:
        return False
    if first == second:
        return not path and fh == sh
    if first == 0:
        return not path   # the empty tree is consistent with every tree
    if not path:
        return False
    if first & (first - 1) == 0:
        path = [fh] + path
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _node(c, fr)
            sr = _node(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == fh and sr == sh


# ---------------------------------------------------------------- x402 offer-receipt extension receipts
def _jws_key(header, did_doc):
    """The public key for a JWS kid from a did:web document (verificationMethod with publicKeyJwk)."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    kid = header.get("kid") or ""
    for vm in (did_doc or {}).get("verificationMethod") or []:
        if vm.get("id") == kid or (kid.startswith("#") and str(vm.get("id", "")).endswith(kid)):
            jwk = vm.get("publicKeyJwk") or {}
            if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
                return "EdDSA", ed25519.Ed25519PublicKey.from_public_bytes(b64url_d(jwk["x"]))
            if jwk.get("kty") == "EC" and jwk.get("crv") in ("P-256", "secp256k1"):
                curve = ec.SECP256R1() if jwk["crv"] == "P-256" else ec.SECP256K1()
                nums = ec.EllipticCurvePublicNumbers(int.from_bytes(b64url_d(jwk["x"]), "big"), int.from_bytes(b64url_d(jwk["y"]), "big"), curve)
                return ("ES256" if jwk["crv"] == "P-256" else "ES256K"), nums.public_key()
    raise FormatError("key_not_authorized", "the kid is not a verificationMethod of the service's did:web document")


def did_web_url(kid):
    """did:web:example.com#key-1 -> https://example.com/.well-known/did.json (path form did:web:host:a:b -> /a/b/did.json)."""
    did = kid.split("#", 1)[0]
    if not did.startswith("did:web:"):
        raise FormatError("key_unsupported", "only did:web key ids are resolved")
    parts = [p.replace("%3A", ":") for p in did[len("did:web:"):].split(":")]
    host = parts[0]
    return f"https://{host}/" + ("/".join(parts[1:]) + "/did.json" if len(parts) > 1 else ".well-known/did.json"), host


def verify_x402_receipt(receipt, did_doc=None, allowed_addresses=()):
    """A signed receipt from the x402 offer-receipt extension. JWS: the kid resolves (did_doc fetched by the caller from
    did_web_url(kid)) and its host must be the host of resourceUrl. EIP-712: the recovered signer must be one of
    allowed_addresses (the writer's registered addresses or the payTo address). -> the receipt payload plus signer."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from urllib.parse import urlparse
    if not isinstance(receipt, dict) or receipt.get("format") not in ("jws", "eip712"):
        raise FormatError("receipt_malformed", "a receipt has format 'jws' or 'eip712'")
    if receipt["format"] == "jws":
        try:
            h64, p64, s64 = receipt["signature"].split(".")
            header, payload, sig = json.loads(b64url_d(h64)), json.loads(b64url_d(p64)), b64url_d(s64)
        except Exception:
            raise FormatError("receipt_malformed", "signature must be a JWS compact serialization") from None
        _, host = did_web_url(header.get("kid", ""))
        if urlparse(str(payload.get("resourceUrl", ""))).hostname != host:
            raise FormatError("key_not_authorized", "the signing key's did:web host is not the host of resourceUrl")
        alg, key = _jws_key(header, did_doc)
        if header.get("alg") != alg:
            raise FormatError("receipt_malformed", f"JWS alg {header.get('alg')!r} does not match the key ({alg})")
        signing_input = (h64 + "." + p64).encode()
        try:
            if alg == "EdDSA":
                key.verify(sig, signing_input)
            else:
                if len(sig) != 64:
                    raise InvalidSignature()
                key.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise FormatError("signature_invalid", "the JWS signature does not verify") from None
        _receipt_fields(payload)
        return {"receipt": payload, "signer": header["kid"], "alg": alg}
    payload = receipt.get("payload") or {}
    _receipt_fields(payload)
    try:
        from eth_account import Account
        from eth_account.messages import encode_typed_data
        msg = encode_typed_data(full_message={
            "types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"}, {"name": "chainId", "type": "uint256"}],
                      "Receipt": [{"name": "version", "type": "uint256"}, {"name": "network", "type": "string"}, {"name": "resourceUrl", "type": "string"},
                                  {"name": "payer", "type": "string"}, {"name": "issuedAt", "type": "uint256"}, {"name": "transaction", "type": "string"}]},
            "primaryType": "Receipt", "domain": {"name": "x402 receipt", "version": "1", "chainId": 1},
            "message": {"version": int(payload["version"]), "network": payload["network"], "resourceUrl": payload["resourceUrl"],
                        "payer": payload["payer"], "issuedAt": int(payload["issuedAt"]), "transaction": payload.get("transaction") or ""}})
        signer = Account.recover_message(msg, signature=receipt["signature"])
    except FormatError:
        raise
    except Exception:
        raise FormatError("signature_invalid", "the EIP-712 signature does not recover") from None
    if signer.lower() not in {a.lower() for a in allowed_addresses}:
        raise FormatError("key_not_authorized", "the EIP-712 signer is not an address registered by the writer")
    return {"receipt": payload, "signer": signer, "alg": "EIP-712"}


def _receipt_fields(p):
    for k in ("version", "network", "resourceUrl", "payer", "issuedAt"):
        if k not in p:
            raise FormatError("receipt_malformed", f"receipt payload lacks {k}")


# ---------------------------------------------------------------- Sigstore bundles
_SIGSTORE = {}


def verify_sigstore_bundle(bundle_json, artifact_sha256_hex, identity, issuer):
    """Standard Sigstore verification (sigstore-python, public-good trust root): certificate chain to Fulcio, transparency
    log inclusion, signature over the artifact digest, and the signer identity and OIDC issuer the writer registered."""
    try:
        from sigstore.hashes import Hashed
        from sigstore.models import Bundle
        from sigstore.verify import Verifier, policy
        from sigstore_models.common.v1 import HashAlgorithm
    except ImportError:
        raise FormatError("verifier_unavailable", "sigstore-python is not installed on this verifier") from None
    try:
        b = Bundle.from_json(bundle_json if isinstance(bundle_json, (str, bytes)) else json.dumps(bundle_json))
    except Exception as e:
        raise FormatError("bundle_malformed", f"not a Sigstore bundle: {str(e)[:120]}") from None
    if "v" not in _SIGSTORE:
        _SIGSTORE["v"] = Verifier.production()
    try:
        _SIGSTORE["v"].verify_artifact(Hashed(algorithm=HashAlgorithm.SHA2_256, digest=bytes.fromhex(artifact_sha256_hex)), b,
                                       policy.Identity(identity=identity, issuer=issuer))
    except Exception as e:
        raise FormatError("signature_invalid", f"Sigstore verification failed: {str(e)[:160]}") from None
    return {"identity": identity, "issuer": issuer}
