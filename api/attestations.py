"""Attestations (block ATT): any log, service or seller anchors its own checkpoints, tree heads, bundles and receipts in the
MINIMALCULT record and gets independent proof — the hourly seal (hybrid Ed25519 + ML-DSA-65 signature, Merkle inclusion)
and anchors in OpenTimestamps, RFC 3161, Sigstore Rekor (hourly), TON and EAS on Base (daily).

  POST /v1/writers                         register a writer (status pending until its identity is verified)
  POST /v1/writers/{id}/verify             verify: domain file, GitHub file or gist, Web Bot Auth key directory, ERC-8004 id
  GET  /v1/writers/{id}                    the writer: identity, since, how many attestations, conflicts of interest
  POST /v1/attestations                    anchor one payload (checkpoint, rfc6962_sth, rfc9162_checkpoint, sigstore_bundle,
                                           x402_receipt, sha256); idempotent by client_operation_id
  GET  /v1/attestations/{id}               status: quarantined -> received -> recorded -> sealed
  GET  /v1/attestations/{id}/proof         everything needed to check it without us (python -m minimalcult verify)
  GET  /record/writers/{id}                the writer's public page

Neutrality: the same terms for every writer; records are only appended; we keep hashes and minimal metadata, the payload
itself only when it is public (log heads) or the writer asks us to keep it; every record says whether it is an assertion
(the writer states it) or an observation (MINIMALCULT read it from a public log). Writers whose identity is not verified
are quarantined: their attestations wait and are recorded only after verification (7 days, then dropped).
The record is written by the witness service (one writer to witness.db): it drains `attestations` rows with status
`received` before each hourly seal (witness.drain_attestations).
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: Apache-2.0 (open core).
"""
import asyncio
import hashlib
import json
import re
import secrets
import time
import urllib.parse

import attest_formats as F

BASE = "https://minimalcult.org"
API = "https://ai.minimalcult.org"
DOC = API + "/docs/attestations"
SCHEMA = """
CREATE TABLE IF NOT EXISTS writers(id TEXT PRIMARY KEY, created INTEGER, name TEXT, method TEXT, claim TEXT, identity TEXT,
    status TEXT NOT NULL DEFAULT 'pending', verified_at INTEGER, doc TEXT, contact TEXT, conflicts TEXT, last_error TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS writers_identity ON writers(identity) WHERE identity IS NOT NULL;
CREATE TABLE IF NOT EXISTS attestations(id TEXT PRIMARY KEY, created INTEGER, writer TEXT, client_operation_id TEXT, subject TEXT,
    payload_type TEXT, payload_sha256 TEXT, status TEXT, envelope TEXT, w_object TEXT, w_version TEXT, w_seq INTEGER,
    UNIQUE(writer, client_operation_id));
CREATE INDEX IF NOT EXISTS attestations_status ON attestations(status, created);
CREATE INDEX IF NOT EXISTS attestations_writer ON attestations(writer, created);
CREATE TABLE IF NOT EXISTS att_divergences(id INTEGER PRIMARY KEY, ts INTEGER, log TEXT, from_size INTEGER, to_size INTEGER,
    detail TEXT, status TEXT NOT NULL DEFAULT 'private_notice', publish_after INTEGER);
"""
METHODS = ("domain", "github", "web_bot_auth", "erc8004")
MAX_PAYLOAD = 64 * 1024
PER_DAY = {"verified": 5000, "pending": 20}
QUARANTINE_S = 7 * 86400
FIELDS = ("question", "consequence_class", "reconciled_at", "authority_version", "void_if")   # optional envelope fields (spec section 4)
CONSEQUENCE = ("authorize", "block", "inform")
WRITER_FILE = "/.well-known/minimalcult-writer.json"


class AttError(Exception):
    def __init__(self, status, code, message, next_step=""):
        super().__init__(message)
        self.status = status
        self.body = {"type": "invalid_request" if status < 500 else "api_error", "code": code, "message": message, "next_step": next_step,
                     "doc_url": DOC}


def migrate(c):
    c.executescript(SCHEMA)


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def new_id(prefix):
    return prefix + secrets.token_hex(10)


def subject_key(subject):
    """A stable record object for a subject: 'log:' + lower-case host/path without scheme, query or trailing slash."""
    s = str(subject or "").strip()
    if not s or len(s) > 300 or any(ch in s for ch in "\r\n\t "):
        raise AttError(400, "subject_invalid", "subject must be a URL or a log identifier up to 300 characters, without spaces",
                       "use the log's origin line or its public URL")
    u = urllib.parse.urlsplit(s if "://" in s else "x://" + s)
    k = ((u.hostname or "") + (u.path or "")).rstrip("/").lower()
    if not k or not re.fullmatch(r"[a-z0-9._~:/@+\-]+", k):
        raise AttError(400, "subject_invalid", "subject must be a URL or a log identifier (letters, digits, . _ ~ : / @ + -)")
    return "log:" + k[:200]


# ---------------------------------------------------------------- writers
def writer_doc_keys(doc, writer_id):
    """A writer document names the writer and lists Ed25519 keys (JWK). -> {kid: Ed25519PublicKey}."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(doc, dict) or doc.get("minimalcult_writer") != writer_id:
        raise AttError(409, "writer_doc_mismatch", f"the writer document must contain \"minimalcult_writer\": \"{writer_id}\"",
                       f"publish the file shown in GET /v1/writers/{writer_id} and verify again")
    keys = {}
    for k in doc.get("keys") or []:
        if isinstance(k, dict) and k.get("kty") == "OKP" and k.get("crv") == "Ed25519" and k.get("kid") and k.get("x"):
            try:
                keys[str(k["kid"])[:64]] = Ed25519PublicKey.from_public_bytes(F.b64url_d(k["x"]))
            except Exception:  # noqa: BLE001
                continue
    if not keys:
        raise AttError(409, "writer_doc_no_keys", "the writer document lists no Ed25519 key (JWK with kid, kty OKP, crv Ed25519, x)")
    return keys


def _get(url, fetch):
    st, _h, body = fetch(url)
    if st != 200:
        raise AttError(409, "writer_doc_unreachable", f"{url} answered {st}", "make the file public over HTTPS without redirects")
    try:
        return json.loads(body)
    except Exception:  # noqa: BLE001
        raise AttError(409, "writer_doc_invalid", f"{url} is not JSON") from None


def claim_of(method, b):
    """What the writer claims to be, as a canonical identity string, and where its document lives."""
    if method == "domain":
        host = str(b.get("domain") or "").strip().lower().rstrip(".")
        if not re.fullmatch(r"(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}", host):
            raise AttError(400, "domain_invalid", "domain must be a public host name, e.g. log.example.com")
        return "domain:" + host, "https://" + host + WRITER_FILE
    if method == "github":
        url = str(b.get("github_url") or "").strip()
        m = re.fullmatch(r"https://(raw\.githubusercontent\.com|gist\.githubusercontent\.com)/([A-Za-z0-9-]{1,39})/[^?#\s]{1,300}", url)
        if not m:
            raise AttError(400, "github_url_invalid", "github_url must be a raw.githubusercontent.com or gist.githubusercontent.com URL of the file",
                           "e.g. https://raw.githubusercontent.com/OWNER/REPO/main/.well-known/minimalcult-writer.json")
        return "github:" + m.group(2).lower(), url
    if method == "web_bot_auth":
        host = str(b.get("host") or "").strip().lower()
        if not re.fullmatch(r"(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}", host):
            raise AttError(400, "host_invalid", "host must be the host serving /.well-known/http-message-signatures-directory")
        return "web_bot_auth:" + host, f"https://{host}/.well-known/http-message-signatures-directory"
    if method == "erc8004":
        try:
            aid = int(b.get("agent_id"))
        except Exception:  # noqa: BLE001
            raise AttError(400, "agent_id_invalid", "agent_id must be the ERC-8004 identity token id") from None
        import erc8004
        return f"erc8004:{erc8004.CHAIN}:{aid}", None
    raise AttError(400, "method_invalid", f"method must be one of {', '.join(METHODS)}")


def verify_writer(c, w, b, fetch, now=None, erc_uri=None):
    """Run the writer's proof. On success the writer is verified, its keys stored, quarantined attestations released."""
    now = now or int(time.time())
    method = w["method"]
    _ident, url = claim_of(method, json.loads(w["claim"]))
    if method in ("domain", "github"):
        doc = _get(url, fetch)
    elif method == "erc8004":
        import erc8004
        reg = (erc_uri or (lambda: erc8004.fetch_uri(erc8004.token_uri(json.loads(w["claim"])["agent_id"]))))()
        doc = (reg or {}).get("minimalcult_writer_doc") if isinstance(reg, dict) else None
        if not isinstance(doc, dict):
            raise AttError(409, "writer_doc_mismatch", "the ERC-8004 registration file at tokenURI needs a \"minimalcult_writer_doc\" object",
                           "add the writer document as that field of the registration file, then verify again")
    else:   # web_bot_auth: a key of the host's directory signs "minimalcult-writer:<id>"
        jwks = _get(url, fetch)
        keyid, sig = str(b.get("keyid") or ""), str(b.get("signature") or "")
        if not keyid or not sig:
            raise AttError(400, "proof_missing", "web_bot_auth needs keyid (JWK thumbprint) and signature (base64url Ed25519 over "
                           f"\"minimalcult-writer:{w['id']}\")")
        import botauth
        k = botauth._find(jwks, keyid)
        if not k:
            raise AttError(409, "key_not_in_directory", "keyid is not a key of the host's signature directory")
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            Ed25519PublicKey.from_public_bytes(F.b64url_d(k["x"])).verify(F.b64url_d(sig), f"minimalcult-writer:{w['id']}".encode())
        except (InvalidSignature, ValueError):
            raise AttError(409, "signature_invalid", "the signature does not verify with the directory key") from None
        doc = {"minimalcult_writer": w["id"], "keys": [{"kid": keyid, "kty": "OKP", "crv": "Ed25519", "x": k["x"]}]}
    keys = writer_doc_keys(doc, w["id"])
    c.execute("UPDATE writers SET status='verified', verified_at=coalesce(verified_at, ?), doc=?, last_error=NULL WHERE id=?",
              (now, json.dumps(doc, sort_keys=True)[:32_000], w["id"]))
    # quarantined attestations were accepted before the writer's keys were known: their signatures are checked now
    released = 0
    for r in c.execute("SELECT id, envelope, created FROM attestations WHERE writer=? AND status='quarantined'", (w["id"],)).fetchall():
        env = json.loads(r["envelope"])
        ok = r["created"] > now - QUARANTINE_S and env.get("writer_key_ref") in keys
        if ok:
            try:
                keys[env["writer_key_ref"]].verify(F.b64url_d(env["writer_signature"]), F.canon(signed_part(env | {"writer_id": env["writer"]}, env["payload_sha256"])))
            except Exception:  # noqa: BLE001
                ok = False
        c.execute("UPDATE attestations SET status=? WHERE id=? AND status='quarantined'", ("received" if ok else "rejected", r["id"]))
        released += ok
    return released


def writer_view(c, w):
    n = c.execute("SELECT count(*) FROM attestations WHERE writer=? AND status!='quarantined'", (w["id"],)).fetchone()[0]
    claim = json.loads(w["claim"] or "{}")
    out = {"id": w["id"], "object": "writer", "name": w["name"], "status": w["status"], "method": w["method"], "identity": w["identity"],
           "created_at": iso(w["created"]), "verified_at": iso(w["verified_at"]) if w["verified_at"] else None, "attestations_count": n,
           "conflicts_of_interest": w["conflicts"] or "none declared", "url": f"{BASE}/record/writers/{w['id']}"}
    if w["status"] != "verified":
        out["next_step"] = verify_instructions(w["id"], w["method"], claim)
        out["last_error"] = w["last_error"]
    return out


def verify_instructions(wid, method, claim):
    doc = {"minimalcult_writer": wid, "keys": [{"kid": "k1", "kty": "OKP", "crv": "Ed25519", "x": "<base64url Ed25519 public key>"}],
           "logs": [{"origin": "<checkpoint origin>", "key": "<note vkey or PEM>"}]}
    where = {"domain": f"https://{claim.get('domain', '<domain>')}{WRITER_FILE}",
             "github": claim.get("github_url", "<raw GitHub or gist URL>"),
             "erc8004": "field \"minimalcult_writer_doc\" of the ERC-8004 registration file at tokenURI",
             "web_bot_auth": f"sign \"minimalcult-writer:{wid}\" with a key of https://{claim.get('host', '<host>')}/.well-known/http-message-signatures-directory "
                             "and send {keyid, signature} to POST /v1/writers/{id}/verify"}[method]
    return {"publish": where, "document": doc if method != "web_bot_auth" else None, "then": f"POST {API}/v1/writers/{wid}/verify"}


# ---------------------------------------------------------------- attestations
def payload_digest(payload_type, payload, payload_hash):
    """sha256 of exactly what was presented: note text (UTF-8) as is; JSON payloads in canonical form; sha256 type: the hash."""
    if payload_type == "sha256":
        h = str(payload_hash or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", h):
            raise AttError(400, "payload_hash_invalid", "payload_hash must be 64 lower-case hex characters (SHA-256)")
        return h, None
    if payload is None:
        raise AttError(400, "payload_missing", f"{payload_type} needs `payload`")
    raw = payload.encode("utf-8") if isinstance(payload, str) else F.canon(payload)
    if len(raw) > MAX_PAYLOAD:
        raise AttError(413, "payload_too_large", f"payload is limited to {MAX_PAYLOAD} bytes", "anchor its sha256 instead (payload_type sha256)")
    h = hashlib.sha256(raw).hexdigest()
    if payload_hash and str(payload_hash).lower() != h:
        raise AttError(400, "payload_hash_mismatch", "payload_hash is not the sha256 of the payload as sent (JSON: canonical form, keys sorted, no spaces)")
    return h, raw


def signed_part(b, payload_sha256):
    """What the writer signs: canonical JSON of these keys (absent optional ones as null)."""
    return {"writer_id": b.get("writer_id"), "subject": b.get("subject"), "payload_type": b.get("payload_type"), "payload_sha256": payload_sha256,
            "fields": b.get("fields") or None, "client_operation_id": b.get("client_operation_id")}


def check_fields(fields):
    if fields is None:
        return None
    if not isinstance(fields, dict) or set(fields) - set(FIELDS) or len(F.canon(fields)) > 4096:
        raise AttError(400, "fields_invalid", f"fields may contain only {', '.join(FIELDS)} (4 KB at most)")
    cc = fields.get("consequence_class")
    if cc is not None and cc not in CONSEQUENCE:
        raise AttError(400, "fields_invalid", "consequence_class is authorize, block or inform")
    return fields


def verify_payload(ptype, payload, raw, b, doc, fetch):
    """Type-specific check with the log's or issuer's key. -> dict of what was verified (goes into the envelope)."""
    logs = {str(x.get("origin")): x.get("key") for x in (doc or {}).get("logs") or [] if isinstance(x, dict)}
    try:
        if ptype in ("checkpoint", "rfc9162_checkpoint"):
            if not isinstance(payload, str):
                raise AttError(400, "payload_invalid", "a checkpoint payload is the signed note text")
            origin = payload.split("\n", 1)[0]
            key = b.get("log_key") or logs.get(origin)
            if not key:
                raise AttError(400, "log_key_missing", "give log_key (note vkey or PEM) or list the log under `logs` in the writer document")
            r = F.verify_note(payload, key)
            return {"check": "signed_note", "origin": r["origin"], "tree_size": r["tree_size"], "root_hash": r["root_hash"], "log_key": key,
                    "log_key_id": r["key_id"], "log_key_source": "writer_document" if logs.get(origin) == key else "request"}
        if ptype == "rfc6962_sth":
            key = b.get("log_key")
            if not key or not isinstance(payload, dict):
                raise AttError(400, "log_key_missing", "rfc6962_sth needs the get-sth JSON as payload and the log's PEM public key as log_key")
            r = F.verify_sth(payload, key)
            return {"check": "rfc6962_sth", **r, "log_key": key, "log_key_source": "request"}
        if ptype == "sigstore_bundle":
            art, ident, iss = b.get("artifact_sha256"), b.get("sigstore_identity"), b.get("sigstore_issuer")
            if not (art and ident and iss) or not re.fullmatch(r"[0-9a-f]{64}", str(art)):
                raise AttError(400, "sigstore_params_missing", "sigstore_bundle needs artifact_sha256, sigstore_identity and sigstore_issuer")
            F.verify_sigstore_bundle(payload, art, ident, iss)
            return {"check": "sigstore", "artifact_sha256": art, "identity": ident, "issuer": iss}
        if ptype == "x402_receipt":
            did = None
            if isinstance(payload, dict) and payload.get("format") == "jws":
                try:
                    kid = json.loads(F.b64url_d(payload["signature"].split(".")[0])).get("kid", "")
                except Exception:  # noqa: BLE001
                    raise AttError(400, "payload_invalid", "receipt signature is not a JWS") from None
                url, _host = F.did_web_url(kid)
                did = _get(url, fetch)
            r = F.verify_x402_receipt(payload, did, (doc or {}).get("addresses") or ())
            return {"check": "x402_receipt", "signer": r["signer"], "alg": r["alg"], "network": r["receipt"].get("network"),
                    "resource_url": r["receipt"].get("resourceUrl"), "issued_at": r["receipt"].get("issuedAt")}
        return {"check": "none", "note": "sha256: the fact that the writer presented this digest at this time"}
    except F.FormatError as e:
        raise AttError(422, e.code, str(e), "fix the payload or the key and send it again (a new client_operation_id is not needed)") from None


def submit(c, b, fetch, now=None):
    now = now or int(time.time())
    if not isinstance(b, dict):
        raise AttError(400, "body_invalid", "send a JSON object")
    ptype = b.get("payload_type")
    if ptype not in F.TYPES:
        raise AttError(400, "payload_type_invalid", f"payload_type must be one of {', '.join(F.TYPES)}")
    w = c.execute("SELECT * FROM writers WHERE id=?", (str(b.get("writer_id") or ""),)).fetchone()
    if not w:
        raise AttError(404, "writer_not_found", "unknown writer_id", f"register with POST {API}/v1/writers")
    op = b.get("client_operation_id")
    if op is not None and (not isinstance(op, str) or not 1 <= len(op) <= 128):
        raise AttError(400, "client_operation_id_invalid", "client_operation_id is a string of 1-128 characters chosen before the first attempt")
    if op:
        prev = c.execute("SELECT * FROM attestations WHERE writer=? AND client_operation_id=?", (w["id"], op)).fetchone()
        if prev:
            return view(c, prev), False
    obj = subject_key(b.get("subject"))
    fields = check_fields(b.get("fields"))
    h, raw = payload_digest(ptype, b.get("payload"), b.get("payload_hash"))
    # the writer's own signature binds it to exactly this payload
    if w["status"] == "verified":
        keys = writer_doc_keys(json.loads(w["doc"]), w["id"])
    else:
        keys = None
    kid = str(b.get("writer_key_ref") or "")
    sig = str(b.get("writer_signature") or "")
    if not kid or not sig:
        raise AttError(400, "writer_signature_missing", "writer_key_ref (kid) and writer_signature (base64url Ed25519 over the canonical "
                       "signed part) are required", "see `signed_part` in the documentation")
    if keys is not None:
        from cryptography.exceptions import InvalidSignature
        if kid not in keys:
            raise AttError(403, "writer_key_unknown", "writer_key_ref is not a key in the writer document")
        try:
            keys[kid].verify(F.b64url_d(sig), F.canon(signed_part(b, h)))
        except (InvalidSignature, ValueError):
            raise AttError(403, "writer_signature_invalid", "writer_signature does not verify over the canonical signed part",
                           "sign canonical JSON (keys sorted, no spaces, UTF-8) of writer_id, subject, payload_type, payload_sha256, fields, client_operation_id") from None
    status = "received" if w["status"] == "verified" else "quarantined"
    day = c.execute("SELECT count(*) FROM attestations WHERE writer=? AND created>?", (w["id"], now - 86400)).fetchone()[0]
    if day >= PER_DAY["verified" if status == "received" else "pending"]:
        raise AttError(429, "writer_daily_limit", f"{PER_DAY['verified' if status == 'received' else 'pending']} attestations per writer per 24 h",
                       "verify the writer to lift the quarantine limit" if status == "quarantined" else "anchor a batch hash (payload_type sha256)")
    checked = verify_payload(ptype, b.get("payload"), raw, b, json.loads(w["doc"]) if w["doc"] else None, fetch)
    keep = ptype in ("checkpoint", "rfc9162_checkpoint", "rfc6962_sth") or bool(b.get("store_payload"))
    aid = new_id("att_")
    env = {"v": 1, "type": "attestation", "id": aid, "record_type": "assertion", "writer": w["id"], "writer_identity": w["identity"],
           "subject": str(b["subject"]), "payload_type": ptype, "payload_sha256": h, "payload": b.get("payload") if keep else None,
           "verified": checked, "fields": fields, "client_operation_id": op, "writer_key_ref": kid, "writer_signature": sig,
           "received_at": iso(now)}
    version = str(checked.get("tree_size")) if "tree_size" in checked else h[:16]
    c.execute("INSERT INTO attestations(id, created, writer, client_operation_id, subject, payload_type, payload_sha256, status, envelope, w_object, w_version) "
              "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (aid, now, w["id"], op, env["subject"], ptype, h, status, json.dumps(env, sort_keys=True), obj, version))
    return view(c, c.execute("SELECT * FROM attestations WHERE id=?", (aid,)).fetchone()), True


def sealed_state(r, wc=None):
    """Status with the witness record: recorded -> sealed once its batch exists."""
    if r["status"] != "recorded" or r["w_seq"] is None:
        return r["status"], None
    if wc is None:
        import witness as W
        wc = W.open_ro()
    if wc is None:
        return "recorded", None
    o = wc.execute("SELECT batch_id FROM w_obs WHERE seq=?", (r["w_seq"],)).fetchone()
    return ("sealed", o["batch_id"]) if o and o["batch_id"] else ("recorded", None)


def view(c, r, wc=None):
    status, batch = sealed_state(r, wc)
    env = json.loads(r["envelope"])
    return {"id": r["id"], "object": "attestation", "writer": r["writer"], "subject": r["subject"], "payload_type": r["payload_type"],
            "record_type": env.get("record_type"), "status": status, "received_at": iso(r["created"]), "payload_sha256": r["payload_sha256"],
            "verified": {k: v for k, v in (env.get("verified") or {}).items() if k != "log_key"}, "record": {"object": r["w_object"], "version": r["w_version"]},
            "batch": batch, "proof_url": f"{API}/v1/attestations/{r['id']}/proof",
            "next_step": {"quarantined": "verify the writer: POST /v1/writers/{id}/verify".replace("{id}", r["writer"]),
                          "received": "recorded at the next hourly seal", "recorded": "sealed within the hour"}.get(status)}


def proof_doc(c, r, wc):
    """The attestation, its envelope and its fact proof: checkable with `python -m minimalcult verify` and the public keys."""
    import witness as W
    out = {"kind": "attestation", "attestation_id": r["id"], "envelope": json.loads(r["envelope"]), "fact": None}
    if r["w_seq"] is not None and wc is not None:
        o = wc.execute("SELECT * FROM w_obs WHERE seq=?", (r["w_seq"],)).fetchone()
        if o:
            out["fact"] = W.fact_proof(wc, o)
    out["how_to_verify"] = [
        "envelope: sha256(canonical JSON of `envelope`) equals fact.observation.digest",
        "fact: leaf = sha256(canonical fact.observation); fold fact.merkle_path to fact.batch.record.merkle_root; head = sha256(canonical "
        "fact.batch.record); fact.batch.signature (Ed25519 + ML-DSA-65, keys at /.well-known/record-keys.json) signs that head and record",
        "payload: for checkpoints and tree heads the log's own signature is checked again with envelope.verified.log_key",
        "anchors: each batch head is fixed in OpenTimestamps (Bitcoin), RFC 3161 and Sigstore Rekor every hour; TON and EAS on Base daily (/v1/anchors)"]
    return out


# ---------------------------------------------------------------- HTTP
def setup(app, db, client_ip, fetch=None):
    from fastapi import Request
    from fastapi.responses import HTMLResponse, JSONResponse
    import shield
    import witness as W
    get = fetch or (lambda url: W.fetch(url, guard=True, timeout=15))

    with db() as c:
        migrate(c)

    def err(e):
        return JSONResponse({"error": e.body}, status_code=e.status)

    def limit(request, name, per_min):
        if not shield.take(f"att:{name}:{client_ip(request)}", per_min)[0]:
            raise AttError(429, "rate_limited", f"at most {per_min} requests per minute for {name}", "retry after a minute")

    async def body(request):
        try:
            raw = await request.body()
            if len(raw) > MAX_PAYLOAD + 16384:
                raise AttError(413, "body_too_large", "request body too large")
            return json.loads(raw or b"{}")
        except AttError:
            raise
        except Exception:  # noqa: BLE001
            raise AttError(400, "body_invalid", "send a JSON object") from None

    @app.post("/v1/writers")
    async def writers_create(request: Request):
        """Register a writer: name, method (domain | github | web_bot_auth | erc8004) and its claim (domain, github_url, host or
        agent_id); optional contact (private, for notices) and conflicts_of_interest (public)."""
        try:
            limit(request, "writers", 5)
            b = await body(request)
            method = b.get("method")
            ident, _url = claim_of(method, b)
            name = str(b.get("name") or "").strip()[:80]
            if not name:
                raise AttError(400, "name_missing", "name is the writer's public name")
            claim = {k: b[k] for k in ("domain", "github_url", "host", "agent_id") if b.get(k) is not None}
            with db() as c:
                old = c.execute("SELECT * FROM writers WHERE identity=?", (ident,)).fetchone()
                if old:
                    raise AttError(409, "writer_exists", f"{ident} is already writer {old['id']}", f"GET {API}/v1/writers/{old['id']}")
                wid = new_id("wrt_")
                c.execute("INSERT INTO writers(id, created, name, method, claim, identity, contact, conflicts) VALUES(?,?,?,?,?,?,?,?)",
                          (wid, int(time.time()), name, method, json.dumps(claim), ident, str(b.get("contact") or "")[:200] or None,
                           str(b.get("conflicts_of_interest") or "")[:1000] or None))
                w = c.execute("SELECT * FROM writers WHERE id=?", (wid,)).fetchone()
                return JSONResponse(writer_view(c, w), status_code=201)
        except AttError as e:
            return err(e)

    @app.post("/v1/writers/{wid}/verify")
    async def writers_verify(wid: str, request: Request):
        try:
            limit(request, "verify", 10)
            b = await body(request)

            def run():   # network reads (the proof) happen off the event loop
                with db() as c:
                    w = c.execute("SELECT * FROM writers WHERE id=?", (wid[:40],)).fetchone()
                    if not w:
                        raise AttError(404, "writer_not_found", "unknown writer")
                    try:
                        released = verify_writer(c, w, b, get)
                    except AttError as e:
                        c.execute("UPDATE writers SET last_error=? WHERE id=?", (e.body["message"][:300], wid))
                        c.commit()
                        raise
                    except Exception as e:  # noqa: BLE001
                        c.execute("UPDATE writers SET last_error=? WHERE id=?", (f"{type(e).__name__}: {str(e)[:200]}", wid))
                        c.commit()
                        raise AttError(409, "verification_failed", f"could not read the proof: {type(e).__name__}") from None
                    out = writer_view(c, c.execute("SELECT * FROM writers WHERE id=?", (wid,)).fetchone())
                    out["released_from_quarantine"] = released
                    return out
            return await asyncio.to_thread(run)
        except AttError as e:
            return err(e)

    @app.get("/v1/writers/{wid}")
    def writers_get(wid: str):
        with db() as c:
            w = c.execute("SELECT * FROM writers WHERE id=?", (wid[:40],)).fetchone()
            if not w:
                return err(AttError(404, "writer_not_found", "unknown writer"))
            return writer_view(c, w)

    @app.post("/v1/attestations")
    async def attestations_create(request: Request):
        """Anchor one payload. Free (the first bridge): the record, the seal and the anchors are the same for every writer."""
        try:
            limit(request, "attestations", 120)
            b = await body(request)

            def run():
                with db() as c:
                    return submit(c, b, get)
            out, created = await asyncio.to_thread(run)
            return JSONResponse(out, status_code=201 if created else 200)
        except AttError as e:
            return err(e)

    @app.get("/v1/attestations/{aid}")
    def attestations_get(aid: str):
        with db() as c:
            r = c.execute("SELECT * FROM attestations WHERE id=?", (aid[:40],)).fetchone()
            if not r:
                return err(AttError(404, "attestation_not_found", "unknown attestation"))
            return view(c, r, W.open_ro())

    @app.get("/v1/attestations/{aid}/proof")
    def attestations_proof(aid: str):
        with db() as c:
            r = c.execute("SELECT * FROM attestations WHERE id=?", (aid[:40],)).fetchone()
            if not r or r["status"] == "quarantined":
                return err(AttError(404, "attestation_not_found", "unknown attestation (or quarantined until its writer is verified)"))
            return proof_doc(c, r, W.open_ro())

    @app.get("/record/writers/{wid}", response_class=HTMLResponse)
    def writer_page(wid: str):
        import html as H
        import ui
        with db() as c:
            w = c.execute("SELECT * FROM writers WHERE id=?", (wid[:40],)).fetchone()
            if not w or w["status"] != "verified":
                return HTMLResponse(ui.page("Writer not found", f"/record/writers/{H.escape(wid[:40])}",
                                            "<h1>Writer not found</h1><p>No verified writer with this id.</p>"), status_code=404)
            v = writer_view(c, w)
            rows = c.execute("SELECT * FROM attestations WHERE writer=? AND status!='quarantined' ORDER BY created DESC LIMIT 50", (w["id"],)).fetchall()
        items = "".join(f"<tr><td><code>{H.escape(r['id'])}</code></td><td>{H.escape(r['payload_type'])}</td><td>{H.escape(r['subject'][:80])}</td>"
                        f"<td>{iso(r['created'])}</td><td><a href=\"/v1/attestations/{H.escape(r['id'])}/proof\">proof</a></td></tr>" for r in rows)
        body_html = (f"<h1>{H.escape(v['name'])}</h1><p>Writer <code>{H.escape(v['id'])}</code> &middot; identity <code>{H.escape(v['identity'])}</code> "
                     f"verified by {H.escape(v['method'])} &middot; on record since {v['verified_at']}</p>"
                     f"<p>Attestations: {v['attestations_count']}. Conflicts of interest: {H.escape(v['conflicts_of_interest'])}</p>"
                     "<p>Records are assertions of this writer. MINIMALCULT checks signatures and seals the record; it does not judge the content.</p>"
                     f"<table><thead><tr><th>id</th><th>type</th><th>subject</th><th>received</th><th></th></tr></thead><tbody>{items}</tbody></table>")
        return HTMLResponse(ui.page(f"{v['name']} — writer", f"/record/writers/{w['id']}", body_html,
                                    desc=f"Attestations anchored by {v['name']} in the MINIMALCULT record."))
