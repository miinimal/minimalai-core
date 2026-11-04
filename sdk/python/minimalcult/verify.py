"""Offline verification of MINIMALCULT signed documents — statements (kind `statement`), checks (kind `check`) and any
RECEIPTS v2 record — without calling MINIMALCULT. Needs only the `cryptography` package (>= 50 for ML-DSA-65).

    python -m minimalcult verify statement.json --key <Ed25519 hex> [--pq-key <ML-DSA-65 hex>]

What is checked:
  1. signature: Ed25519 over the canonical document without `sig`, by the pinned key (the document's gateway_key must match);
     with --pq-key also ML-DSA-65 in `pq` over the canonical document without `sig` and `pq`, and pq_key = sha256(key);
  2. for every fact of a statement: leaf = sha256(canonical observation); the Merkle path folds the leaf to the batch root;
     head = sha256(canonical batch record); the batch signature (same keys) signs that head and record; the observation
     time is at or before `as_of`;
  3. anchors are listed with their proof URLs and the command that checks each one (Bitcoin through OpenTimestamps,
     RFC 3161, Sigstore Rekor): their check needs the proof files, which are public.
Keys: receipt_key_ed25519 and receipt_key_mldsa65 at https://ai.minimalcult.org/.well-known/minimalai.json (pin them once).
"""
import argparse
import base64
import hashlib
import json
import sys


def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def sha(obj):
    return hashlib.sha256(obj if isinstance(obj, (bytes, bytearray)) else canon(obj)).hexdigest()


def check_signature(doc, key_hex, pq_key_hex=None):
    """{'ed25519': bool, 'ml_dsa_65': bool|None}"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    out = {"ed25519": False, "ml_dsa_65": None}
    rest = {k: v for k, v in doc.items() if k != "sig"}
    try:
        if doc.get("gateway_key") == key_hex:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(base64.b64decode(doc["sig"]), canon(rest))
            out["ed25519"] = True
    except Exception:  # noqa: BLE001
        pass
    if pq_key_hex and isinstance(doc.get("pq"), dict):
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa
            key = bytes.fromhex(pq_key_hex)
            ok = doc.get("pq_key") == hashlib.sha256(key).hexdigest() and doc["pq"].get("alg") == "ML-DSA-65"
            if ok:
                mldsa.MLDSA65PublicKey.from_public_bytes(key).verify(base64.b64decode(doc["pq"]["sig"]),
                                                                     canon({k: v for k, v in doc.items() if k not in ("sig", "pq")}))
            out["ml_dsa_65"] = ok
        except Exception:  # noqa: BLE001
            out["ml_dsa_65"] = False
    return out


def fold(leaf_hex, path):
    acc = hashlib.sha256(b"\x00" + bytes.fromhex(leaf_hex)).digest()
    for step in path:
        sib = bytes.fromhex(step["hash"])
        acc = hashlib.sha256(b"\x01" + (sib + acc if step["side"] == "L" else acc + sib)).digest()
    return acc.hex()


def _ts(v):
    import datetime
    return datetime.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()


def check_fact(f, as_of, key_hex, pq_key_hex=None):
    r = {"id": f.get("id"), "type": f.get("type"), "version": f.get("version")}
    obs = f["observation"]
    r["leaf"] = sha(obs) == f["leaf"]
    r["digest"] = obs.get("digest") == (f.get("digest") or {}).get("value")
    r["observed_before_as_of"] = as_of is None or _ts(obs["observed_at"]) <= _ts(as_of)
    b = f.get("batch")
    if not b:
        r["sealed"] = False
        r["ok"] = r["leaf"] and r["digest"] and r["observed_before_as_of"]
        return r
    r["sealed"] = True
    r["merkle"] = fold(f["leaf"], f.get("merkle_path") or []) == b["record"]["merkle_root"]
    r["head"] = sha(b["record"]) == b["head"]
    sig = b.get("signature") or {}
    r["batch_signature"] = (check_signature(sig, key_hex, pq_key_hex) if sig else {"ed25519": False, "ml_dsa_65": None})
    r["batch_signature_matches"] = bool(sig) and sig.get("head") == b["head"] and sig.get("record") == b["record"]
    r["anchors"] = {k: {"status": a.get("status"), "proof_url": "https://ai.minimalcult.org" + a.get("proof_url", ""), "verify": a.get("verify")}
                    for k, a in (b.get("anchors") or {}).items()}
    pq_ok = r["batch_signature"]["ml_dsa_65"] is not False
    r["ok"] = all([r["leaf"], r["digest"], r["observed_before_as_of"], r["merkle"], r["head"], r["batch_signature"]["ed25519"], pq_ok,
                   r["batch_signature_matches"]])
    return r


def verify(doc, key_hex, pq_key_hex=None):
    """Full report; report['ok'] is the verdict."""
    rep = {"kind": doc.get("kind"), "id": doc.get("statement_id") or doc.get("check_id") or doc.get("verdict_id"),
           "signature": check_signature(doc, key_hex, pq_key_hex)}
    ok = rep["signature"]["ed25519"] and rep["signature"]["ml_dsa_65"] is not False
    if doc.get("kind") == "statement":
        rep["as_of"] = doc.get("as_of")
        rep["facts"] = [check_fact(f, doc.get("as_of"), key_hex, pq_key_hex) for f in doc.get("facts") or []]
        ok = ok and all(f["ok"] for f in rep["facts"])
        rep["unsealed_facts"] = sum(1 for f in rep["facts"] if not f.get("sealed"))
    rep["ok"] = bool(ok)
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser(prog="minimalcult", description="Verify MINIMALCULT signed documents offline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify a statement, check or record (JSON file)")
    v.add_argument("file")
    v.add_argument("--key", required=True, help="Ed25519 public key, hex (receipt_key_ed25519)")
    v.add_argument("--pq-key", help="ML-DSA-65 public key, hex (receipt_key_mldsa65)")
    v.add_argument("--json", action="store_true", help="print the full report as JSON")
    a = ap.parse_args(argv)
    doc = json.load(open(a.file, encoding="utf-8"))
    rep = verify(doc, a.key.strip().lower(), (a.pq_key or "").strip().lower() or None)
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        s = rep["signature"]
        print(f"{rep['kind']} {rep['id']}: signature Ed25519 {'ok' if s['ed25519'] else 'FAILED'}, ML-DSA-65 "
              f"{'ok' if s['ml_dsa_65'] else ('not checked' if s['ml_dsa_65'] is None else 'FAILED')}")
        for f in rep.get("facts") or []:
            print(f"  {f['type']} {f['version']} {f['id']}: {'ok' if f['ok'] else 'FAILED'}" + ("" if f.get("sealed") else " (not sealed at issue: signature only)"))
            for k, an in (f.get("anchors") or {}).items():
                print(f"    anchor {k}: {an['status']}  {an['proof_url']}")
        print("VERIFIED" if rep["ok"] else "NOT VERIFIED")
    return 0 if rep["ok"] else 1
