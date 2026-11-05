"""MINIMALCULT as a C2SP transparency-log witness (c2sp.org/tlog-witness, c2sp.org/tlog-cosignature), block ATT.

  POST /tlog-witness/add-checkpoint            a log submits a checkpoint with a consistency proof; we return a cosignature
  GET  /tlog-witness/<sha256(origin) hex>/checkpoint   the latest checkpoint we cosigned for that log, with our cosignature
  GET  /tlog-witness/about                     witness name, verifier key (type 0x04), endpoints, lists, policy

Rules (tlog-witness, add-checkpoint): unknown origin 404; no valid signature from the pinned log key 403; old size above
the checkpoint size 400; old size different from the size we last cosigned 409 (body: that size, text/x.tlog.size);
a size-0 checkpoint without the empty-tree root, a proof with an old size of 0, a failed RFC 6962 consistency proof or a
different root at the same size 422. Check and update are one IMMEDIATE transaction, so we never cosign two conflicting
views or roll a log back. A checkpoint whose consistency with everything we cosigned before is not verified is never
cosigned. A conflicting checkpoint with a valid log signature is kept as private evidence (witness_conflicts), never
published at once (72-hour right of reply, as in read mode).

Every cosignature is also an observation of the MINIMALCULT record: it is sealed hourly and anchored in OpenTimestamps,
RFC 3161 and Rekor, and daily in TON and EAS on Base. Logs come from the witness-network.org staging list (discovered
hourly; a configured log is never removed or changed by a later list) and from manual configuration.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: Apache-2.0 (open core).
"""
import base64
import hashlib
import json
import os
import sqlite3
import time

import attest_formats as F

NAME = os.environ.get("C2SP_WITNESS_NAME", "minimalcult.org/witness")
PREFIX = "/tlog-witness"
BASE = os.environ.get("C2SP_WITNESS_BASE", "https://ai.minimalcult.org")
LISTS = [u for u in os.environ.get("C2SP_WITNESS_LISTS", "https://staging.witness-network.org/log-list-10qps-4klogs.1").split(",") if u]
EMPTY_ROOT = hashlib.sha256(b"").digest()
SCHEMA = """
CREATE TABLE IF NOT EXISTS witness_logs(origin TEXT PRIMARY KEY, vkey TEXT NOT NULL, qpd INTEGER NOT NULL, contact TEXT, source TEXT, added INTEGER);
CREATE TABLE IF NOT EXISTS witness_state(origin TEXT PRIMARY KEY, size INTEGER NOT NULL, root TEXT NOT NULL, note TEXT NOT NULL,
    cosig TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS witness_calls(origin TEXT, day TEXT, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(origin, day));
CREATE TABLE IF NOT EXISTS witness_conflicts(id INTEGER PRIMARY KEY, ts INTEGER, origin TEXT, reason TEXT, body TEXT,
    status TEXT NOT NULL DEFAULT 'private_notice', publish_after INTEGER);
"""


class WitnessError(Exception):
    def __init__(self, status, message, body=None, ctype="text/plain; charset=utf-8"):
        super().__init__(message)
        self.status, self.body, self.ctype = status, body if body is not None else message + "\n", ctype


def migrate(c):
    c.executescript(SCHEMA)


# ---------------------------------------------------------------- keys and cosignatures
def key_id(name, sig_type, pub):
    return hashlib.sha256(name.encode() + b"\n" + bytes([sig_type]) + pub).digest()[:4]


def vkey(pub_hex, name=NAME):
    """Our verifier key: name+hex(key id)+base64(0x04 || Ed25519 public key) — type 0x04, cosignature/v1."""
    pub = bytes.fromhex(pub_hex)
    return f"{name}+{key_id(name, 4, pub).hex()}+{base64.b64encode(b'\x04' + pub).decode()}"


def cosigned_message(ts, body):
    """cosignature/v1, time line, then the checkpoint body lines (origin, size, root, extensions), each ending in LF."""
    return b"cosignature/v1\ntime " + str(int(ts)).encode() + b"\n" + body


def cosign(body, ts, pub_hex, sign, name=NAME):
    """-> the note signature line (with the trailing newline)."""
    sig = sign(cosigned_message(ts, body))
    return "— " + name + " " + base64.b64encode(key_id(name, 4, bytes.fromhex(pub_hex)) + int(ts).to_bytes(8, "big") + sig).decode() + "\n"


def verify_cosignature(note_text, witness_vkey):
    """Check a cosignature line of type 0x04 inside a note. -> (timestamp, checkpoint dict) or FormatError."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519
    name, hint_hex, k = witness_vkey.split("+", 2)
    raw = F.b64d(k)
    if len(raw) != 33 or raw[0] != 4 or key_id(name, 4, raw[1:]).hex() != hint_hex:
        raise F.FormatError("key_malformed", "not a cosignature/v1 (0x04) verifier key")
    body, sigs = F.parse_note(note_text)
    for nm, hint, sig in sigs:
        if nm == name and hint.hex() == hint_hex and len(sig) == 72:
            ts = int.from_bytes(sig[:8], "big")
            try:
                ed25519.Ed25519PublicKey.from_public_bytes(raw[1:]).verify(sig[8:], cosigned_message(ts, body))
            except InvalidSignature:
                raise F.FormatError("signature_invalid", "the cosignature does not verify") from None
            return ts, F.parse_checkpoint(body)
    raise F.FormatError("signature_missing", "no cosignature from this witness")


# ---------------------------------------------------------------- log lists (witness-network.org format logs/v0)
def parse_log_list(text):
    """-> [{vkey, origin, qpd, contact}]. Strict order: vkey, [origin], qpd, contact; unknown or broken items are skipped."""
    lines = [ln.strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    if not lines or lines[0] != "logs/v0":
        raise ValueError("not a logs/v0 list")
    out, i = [], 1
    while i < len(lines):
        if not lines[i].startswith("vkey "):
            i += 1
            continue
        item = {"vkey": lines[i][5:].strip()}
        i += 1
        if i < len(lines) and lines[i].startswith("origin "):
            item["origin"] = lines[i][7:].strip()
            i += 1
        if i + 1 < len(lines) and lines[i].startswith("qpd ") and lines[i + 1].startswith("contact "):
            q = lines[i][4:].strip()
            if q.isdigit() and not q.startswith("0") and 1 <= int(q) < 2 ** 31:
                item["qpd"] = int(q)
                item["contact"] = lines[i + 1][8:].strip()
                item.setdefault("origin", item["vkey"].split("+", 1)[0])
                try:
                    F.note_key(item["vkey"])          # Ed25519 (0x01) only for now; others are skipped, never misread
                    out.append(item)
                except F.FormatError:
                    pass
            i += 2
    return out


def sync_lists(c, fetch, now=None, lists=None):
    """Discover new logs from the configured lists. A log already configured is never removed or changed by a list."""
    now = now or int(time.time())
    migrate(c)
    added, seen = 0, 0
    for url in (lists if lists is not None else LISTS):
        st, _h, body = fetch(url)
        if st != 200:
            raise RuntimeError(f"{url} answered {st}")
        for it in parse_log_list(body.decode("utf-8")):
            seen += 1
            added += c.execute("INSERT OR IGNORE INTO witness_logs(origin, vkey, qpd, contact, source, added) VALUES(?,?,?,?,?,?)",
                               (it["origin"], it["vkey"], it["qpd"], it["contact"], url, now)).rowcount
    c.commit()
    return {"listed": seen, "added": added}


# ---------------------------------------------------------------- add-checkpoint
def parse_request(raw):
    """old size line, up to 63 base64 proof lines, an empty line, then the checkpoint note."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise WitnessError(400, "body is not UTF-8") from None
    if "\n\n" not in text:
        raise WitnessError(400, "expected the old size line, proof lines, an empty line and a checkpoint")
    head, note = text.split("\n\n", 1)
    lines = head.split("\n")
    if not lines[0].startswith("old "):
        raise WitnessError(400, "the first line must be: old <size>")
    o = lines[0][4:]
    if not o.isdigit() or (o != "0" and o.startswith("0")):
        raise WitnessError(400, "old size must be an ASCII decimal without leading zeroes")
    proof = []
    for ln in lines[1:]:
        try:
            h = base64.b64decode(ln, validate=True)
        except ValueError:
            raise WitnessError(400, "a proof line is not base64") from None
        if len(h) != 32 or base64.b64encode(h).decode() != ln:
            raise WitnessError(400, "a proof line must be one canonical base64 SHA-256 hash")
        proof.append(h)
    if len(proof) > 63:
        raise WitnessError(400, "at most 63 consistency proof lines")
    return int(o), proof, note


def add_checkpoint(c, raw, sign, pub_hex, now=None, record=None):
    """The whole add-checkpoint call. Returns the response body (cosignature lines). WitnessError carries the HTTP status."""
    now = now or int(time.time())
    old, proof, note = parse_request(raw)
    origin = note.split("\n", 1)[0]
    log = c.execute("SELECT * FROM witness_logs WHERE origin=?", (origin,)).fetchone()
    if not log:
        raise WitnessError(404, "unknown log origin")
    try:
        cp = F.verify_note(note, log["vkey"], expect_origin=origin)
    except F.FormatError:
        raise WitnessError(403, "no valid signature from the log key configured for this origin") from None
    size, root = cp["tree_size"], bytes.fromhex(cp["root_hash"])
    if old > size:
        raise WitnessError(400, "old size is larger than the checkpoint size")
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    c.execute("BEGIN IMMEDIATE")
    try:
        calls = c.execute("SELECT n FROM witness_calls WHERE origin=? AND day=?", (origin, day)).fetchone()
        if calls and calls["n"] >= 2 * log["qpd"]:     # twice the declared rate before refusing
            raise WitnessError(429, "add-checkpoint rate above twice the declared qpd for this log")
        c.execute("INSERT INTO witness_calls(origin, day, n) VALUES(?,?,1) ON CONFLICT(origin, day) DO UPDATE SET n=n+1", (origin, day))
        st = c.execute("SELECT * FROM witness_state WHERE origin=?", (origin,)).fetchone()
        have = st["size"] if st else 0
        if old != have:
            c.execute("COMMIT")
            raise WitnessError(409, "old size does not match the latest cosigned size", body=f"{have}\n", ctype="text/x.tlog.size")
        reason = None
        if size == 0 and root != EMPTY_ROOT:
            reason = "a size-0 checkpoint must carry the root of the empty tree"
        elif old == 0 and proof:
            reason = "no consistency proof is allowed from size 0"
        elif st and old == size and bytes.fromhex(st["root"]) != root:
            reason = "a different root at a size already cosigned"
        elif st and old < size and not F.verify_consistency(old, size, bytes.fromhex(st["root"]), root, proof):
            reason = "the consistency proof does not verify"
        elif st and old == size and proof:
            reason = "no consistency proof is expected for the same size"
        if reason:
            c.execute("INSERT INTO witness_conflicts(ts, origin, reason, body, publish_after) VALUES(?,?,?,?,?)",
                      (now, origin, reason, raw.decode("utf-8")[:20000], now + 72 * 3600))
            c.execute("COMMIT")
            raise WitnessError(422, reason)
        body = note.split("\n\n", 1)[0].encode() + b"\n"
        line = cosign(body, now, pub_hex, sign)
        c.execute("INSERT INTO witness_state(origin, size, root, note, cosig, ts) VALUES(?,?,?,?,?,?) ON CONFLICT(origin) DO UPDATE SET "
                  "size=excluded.size, root=excluded.root, note=excluded.note, cosig=excluded.cosig, ts=excluded.ts",
                  (origin, size, root.hex(), note, line, now))
        if record:
            record(c, origin, log["vkey"], note, line, old, proof, size, cp, now)
        c.execute("COMMIT")
    except WitnessError:
        if c.in_transaction:
            c.execute("ROLLBACK")
        raise
    except Exception:
        if c.in_transaction:
            c.execute("ROLLBACK")
        raise
    return line


def record_cosignature(c, origin, log_vkey, note, line, old, proof, size, cp, now):
    """The cosignature becomes an observation of the MINIMALCULT record (drained into witness.db before the hourly seal)."""
    import attest   # its tables exist (setup migrates them): executescript here would end the IMMEDIATE transaction
    aid = "att_cos_" + hashlib.sha256(f"{origin}\n{size}\n{now}".encode()).hexdigest()[:16]
    env = {"v": 1, "type": "attestation", "id": aid, "record_type": "observation", "writer": "minimalcult", "writer_identity": "minimalcult.org",
           "subject": origin, "payload_type": "checkpoint", "payload_sha256": F.sha256_hex(note.encode("utf-8")), "payload": note,
           "verified": {"check": "signed_note", "origin": origin, "tree_size": size, "root_hash": cp["root_hash"], "log_key": log_vkey,
                        "log_key_id": cp["key_id"], "log_key_source": "witness configuration"},
           "consistency": {"status": "verified" if old else "first_cosignature", "from_tree_size": old,
                           "proof": [p.hex() for p in proof]},
           "witness_cosignature": {"witness": NAME, "line": line, "timestamp": now},
           "fields": None, "received_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))}
    c.execute("INSERT OR IGNORE INTO attestations(id, created, writer, client_operation_id, subject, payload_type, payload_sha256, status, envelope, "
              "w_object, w_version) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
              (aid, now, "minimalcult", None, origin, "checkpoint", env["payload_sha256"], "received", json.dumps(env, sort_keys=True),
               attest.subject_key(origin), str(size)))


def about(pub_hex):
    vk = vkey(pub_hex) if pub_hex else "(key not configured yet)"
    lists = "\n".join("  " + u for u in LISTS) or "  (none)"
    return f"""{NAME}

A witness for transparency logs (https://c2sp.org/tlog-witness), operated by MINIMALCULT (https://minimalcult.org).
Before it cosigns a log's checkpoint it checks the log's signature against the key it holds for that origin and checks,
with an RFC 6962 consistency proof, that the new checkpoint only appends to the last one it cosigned. Check and update are
atomic: it never cosigns two conflicting views of a log and never rolls a log back. It says nothing about the content of
the log.

What is different here: every cosignature is also an entry of the MINIMALCULT public record. It is sealed every hour with a
hybrid signature (Ed25519 + ML-DSA-65) and anchored in Bitcoin (OpenTimestamps), an RFC 3161 time-stamping authority and
Sigstore Rekor, and daily in TON and in EAS on Base. Anyone can check that a cosignature existed at a time without trusting
this witness.

Verifier key (type 0x04, cosignature/v1, Ed25519):

  {vk}

Endpoints:
  POST {BASE}{PREFIX}/add-checkpoint
  GET  {BASE}{PREFIX}/<sha256(origin) lowercase hex>/checkpoint

Logs: discovered every hour from the list(s) below; a configured log is never removed or changed by a later list.
{lists}

Refusals: 404 unknown log; 403 no valid log signature; 400 malformed request or old size above the checkpoint size;
409 out-of-date old size (the body is the size we hold, text/x.tlog.size); 422 a checkpoint that does not follow from
what we cosigned (failed proof, different root at a cosigned size, size-0 checkpoint without the empty-tree root);
429 more than twice the log's declared qpd in a UTC day.
A conflicting checkpoint with a valid log signature is kept as evidence and reported privately to the log operator first.

Status: staging. Contact: security@minimalcult.org, https://github.com/minimalcult
"""


# ---------------------------------------------------------------- HTTP
def setup(app, db, db_path, sign=None, pub=None):
    from fastapi import Request
    from fastapi.responses import PlainTextResponse
    import receipts
    sign = sign or receipts.raw_sign_witness
    pub = pub or receipts.witness_public_key_hex

    import attest
    with db() as c:
        migrate(c)
        attest.migrate(c)

    def conn():
        c = sqlite3.connect(db_path, timeout=30, isolation_level=None)   # explicit transactions (BEGIN IMMEDIATE)
        c.row_factory = sqlite3.Row
        return c

    @app.post(PREFIX + "/add-checkpoint")
    async def add(request: Request):
        raw = await request.body()
        if len(raw) > 16384:
            return PlainTextResponse("request too large\n", status_code=400)
        import asyncio

        def run():
            c = conn()
            try:
                return add_checkpoint(c, raw, sign, pub(), record=record_cosignature)
            finally:
                c.close()
        try:
            line = await asyncio.to_thread(run)
        except WitnessError as e:
            return PlainTextResponse(e.body, status_code=e.status, media_type=e.ctype.split(";")[0])
        return PlainTextResponse(line, status_code=200)

    @app.get(PREFIX + "/about")
    def about_page():
        return PlainTextResponse(about(pub()))

    @app.get(PREFIX + "/{origin_hash}/checkpoint")
    def latest(origin_hash: str):
        with db() as c:
            for r in c.execute("SELECT * FROM witness_state").fetchall():
                if hashlib.sha256(r["origin"].encode()).hexdigest() == origin_hash.lower():
                    return PlainTextResponse(r["note"] + r["cosig"])
        return PlainTextResponse("never cosigned a checkpoint for this log\n", status_code=404)
