"""Point-in-Time (block PIT, master prompt E13): the record as it stood at any moment, and a signed statement of it.

  GET /v1/records/{id}?as_of=<RFC 3339>                    free: the state at that moment (records_api, uses state_at)
  GET /v1/records/{id}/statements?as_of=<RFC 3339>         paid: a signed statement (kind statement, id stm_…) with every
                                                           fact's observation, leaf, Merkle path, signed batch and anchors
  GET /v1/records/{id}/statements/{stm_id}[?format=pdf]    the issued statement again (JSON, or a PDF rendering)

A statement is checkable without us: `python -m minimalcult verify statement.json` (sdk/python/minimalcult) checks the
hybrid signature, each leaf, each Merkle path, each batch head and batch signature, and that every fact was observed at or
before `as_of`; the anchors fix the batch heads in Bitcoin (OpenTimestamps), an RFC 3161 TSA and Sigstore Rekor.
Before the first observation the answer says so, with the date of the first observation, and nothing is charged.
Price: set in USD (prices.py, 0.10 USD): USD credit or a GRAM key balance at the rate of the moment, GRAM-402 (locked 15 min),
or USDC through x402 at /base/statements.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: Apache-2.0 (open core).
"""
import json
import os
import time
import uuid

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response

import receipts
import witness as W

BASE = "https://ai.minimalcult.org"
SCHEMA = """
CREATE TABLE IF NOT EXISTS statements(id TEXT PRIMARY KEY, ts INTEGER, record TEXT, as_of INTEGER, payer TEXT, price TEXT, sha256 TEXT, body TEXT);
CREATE INDEX IF NOT EXISTS statements_record ON statements(record, ts);
"""
OBS_TYPE = {"manifest": "registry_entry", "status": "registry_status", "package": "package_artifact", "tools": "tool_descriptions"}
VERIFY_STEPS = [
    "signature: Ed25519 over the canonical statement without `sig` (key receipt_key_ed25519 of /.well-known/minimalai.json); "
    "ML-DSA-65 in `pq` over the canonical statement without `sig` and `pq` (key receipt_key_mldsa65, sha256 = pq_key)",
    "each fact: leaf = sha256(canonical observation); fold merkle_path from sha256(0x00||leaf) (sibling L: sha256(0x01||sibling||acc), "
    "R: sha256(0x01||acc||sibling)) to batch.record.merkle_root; head = sha256(canonical batch.record) = batch.head; "
    "batch.signature signs that head and record",
    "time: every observation.observed_at is at or before as_of",
    "anchors: each batch head is fixed in OpenTimestamps (Bitcoin), an RFC 3161 TSA and Sigstore Rekor; proof files at the proof_url of each anchor",
    "offline tool: python -m minimalcult verify statement.json --key <ed25519 hex> [--pq-key <ml-dsa-65 hex>]"]


def build(c, o, as_of, now):
    """The unsigned statement body for object row `o` at `as_of`, or None when the object was not on record then."""
    st = W.state_at(c, o["id"], as_of)
    if not st["on_record"]:
        return None, st
    rid = o["rec_id"] if "rec_id" in o.keys() and o["rec_id"] else W.rec_id(o["id"])
    facts, cache = [], {}
    for k in W.STATE_KINDS:
        r = st["facts"].get(k)
        if r:
            pf = W.fact_proof(c, r, cache)
            facts.append({"type": OBS_TYPE[k], "id": W.ver_id(r["leaf"]), "version": r["version"], "observed_at": W.iso(r["observed_at"]),
                          "digest": {"algorithm": "sha256", "value": r["digest"]}, "sealed": bool(pf["batch"]), **pf})
    body = {"v": 2, "kind": "statement", "issuer": "MINIMALCULT", "ts": now, "created": W.iso(now), "record": rid, "source_id": o["id"],
            "name": o["name"], "as_of": W.iso(as_of), "on_record_since": st["first_observed_at"], "latest_version": st["latest_version"],
            "versions_known": len(st["versions"]), "registry_status": st["registry_status"], "facts": facts,
            "unsealed_facts": sum(1 for f in facts if not f["sealed"]), "how_to_verify": VERIFY_STEPS,
            "license": "CC BY 4.0 (the statement and its facts); cite MINIMALCULT and the statement id"}
    return body, st


# ---------------------------------------------------------------- PDF rendering (no dependency: a plain text PDF, A4)
def _pdf_escape(t):
    t = t.encode("latin-1", "replace").decode("latin-1")
    return t.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(line, width=96):
    out = []
    while len(line) > width:
        cut = line.rfind(" ", 0, width)
        cut = cut if cut > 20 else width
        out.append(line[:cut]); line = "    " + line[cut:].lstrip()
    out.append(line)
    return out


def pdf(lines, title):
    rows = [x for ln in lines for x in _wrap(ln)]
    pages = [rows[i:i + 64] for i in range(0, len(rows), 64)] or [[]]
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", None, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"]
    kids = []
    for n, pg in enumerate(pages):
        ops = ["BT", "/F1 9 Tf", "11 TL", "50 800 Td"]
        for i, ln in enumerate(pg):
            font = "/F1 13 Tf" if (n == 0 and i == 0) else ("/F2 8 Tf" if ln.startswith("    ") or ln.startswith("sha256") else "/F1 9 Tf")
            ops += [font, f"({_pdf_escape(ln)}) Tj", "T*"]
        ops += ["/F1 7 Tf", f"(MINIMALCULT statement - page {n + 1} of {len(pages)} - the signed JSON is authoritative) Tj", "ET"]
        stream = "\n".join(ops).encode("latin-1", "replace")
        objs.append(f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream")
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {len(objs)} 0 R >>")
        kids.append(f"{len(objs)} 0 R")
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>"
    objs.append(f"<< /Title ({_pdf_escape(title)}) /Producer (MINIMALCULT) >>")
    out, offs = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"), []
    for i, ob in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n".encode() + (ob if isinstance(ob, bytes) else ob.encode("latin-1", "replace")) + b"\nendobj\n"
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode() + b"".join(f"{o:010d} 00000 n \n".encode() for o in offs)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R /Info {len(objs)} 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
    return bytes(out)


def statement_pdf(s):
    lines = [f"MINIMALCULT - Statement {s['statement_id']}", "",
             f"Record: {s['name']}   ({s['record']}, {s['source_id']})",
             f"As of: {s['as_of']}        Issued: {s['created']}",
             f"On record since: {s['on_record_since']}   Versions known: {s['versions_known']}   Latest version: {s['latest_version']}",
             f"Registry status: {s['registry_status']}   Facts: {len(s['facts'])} ({s['unsealed_facts']} not sealed yet at issue)", "",
             "Facts recorded at or before the moment:"]
    for f in s["facts"]:
        b = f.get("batch") or {}
        lines += [f"- {f['type']} {f['version']}  observed {f['observed_at']}  {f['id']}",
                  f"    sha256 {f['digest']['value']}",
                  f"    leaf {f['leaf']}",
                  f"    batch {b.get('id', 'not sealed yet')}  head {b.get('head', '-')}"]
        for k, a in (b.get("anchors") or {}).items():
            lines.append(f"    anchor {k}: {a.get('status')}  {BASE}{a.get('proof_url', '')}")
    lines += ["", "Signature:", f"    Ed25519 key {s['gateway_key']}", f"    ML-DSA-65 key sha256 {s.get('pq_key', '-')}",
              f"    sha256 of the signed JSON {receipts.sha256(s)}", "", "How to verify without MINIMALCULT:"]
    lines += [f"- {x}" for x in s["how_to_verify"]]
    lines += ["", f"Signed JSON: {BASE}/v1/records/{s['record']}/statements/{s['statement_id']}", f"License: {s['license']}"]
    return pdf(lines, f"MINIMALCULT statement {s['statement_id']}")


# ---------------------------------------------------------------- API
def setup(app, db, get_key, pay_gate, client_ip, h):
    import records_api as RA
    import witness_check as WC
    with db() as c:
        c.executescript(SCHEMA)

    def ro():
        c = W.open_ro()
        if c is None:
            raise RA.ApiError(503, "api_error", "record_starting", "the record is starting", "retry in a few minutes")
        return c

    def as_of_param(v):
        try:
            t = W.parse_time(v)
        except (ValueError, TypeError):
            raise RA.ApiError(400, "invalid_request_error", "invalid_as_of", "as_of is an RFC 3339 time with a zone, e.g. 2026-11-04T21:00:00Z",
                              "send as_of=2026-11-04T21:00:00Z")
        if t > int(time.time()) + 60:
            raise RA.ApiError(400, "invalid_request_error", "as_of_in_future", "as_of is in the future", "use a moment up to now")
        return t

    async def charge(request, b, route):
        """x402 (basepay internal key) | key balance | GRAM-402. Returns (payer, price) or a JSONResponse (402)."""
        import prices
        ext = WC.internal_payment(request)
        if ext:
            return "x402:" + (ext["payer"] or "anonymous"), {"amount": ext["amount"], "currency": ext["currency"], "via": ext["via"]}, None
        auth, settlement = request.headers.get("authorization"), None
        if auth:
            key = get_key(auth)
        elif request.headers.get("x-payment"):
            gate = await prices.gram_gate(pay_gate, db, request, b, route, "statement")
            if isinstance(gate, JSONResponse):
                return gate
            key, settlement = gate
        else:
            return await prices.gram_gate(pay_gate, db, request, b, route, "statement")
        with db() as c:
            try:
                price = prices.charge_key(c, key["key_hash"], "statement")     # PAY: USD price; USD credit first, else GRAM at the rate
            except HTTPException:
                raise RA.ApiError(402, "payment_error", "balance_too_low", "the key balance does not cover a statement",
                                  "top up the key (USD credit packs at /pricing), pay without a key (GRAM-402), or pay USDC at /base/statements")
        if settlement and price["via"] == "key_balance":
            price["via"] = "gram-402"
        return "key:" + key["key_hash"], price, settlement

    @app.get("/v1/records/{rid:path}/statements/{sid}")
    def statement_get(rid: str, sid: str, format: str = "json"):
        with db() as c:
            c.executescript(SCHEMA)
            r = c.execute("SELECT body FROM statements WHERE id=?", (sid[:40],)).fetchone()
        if not r:
            raise RA.ApiError(404, "invalid_request_error", "statement_not_found", "no statement with this id", "issue one with GET /v1/records/{id}/statements?as_of=")
        s = json.loads(r["body"])
        if format == "pdf":
            return Response(statement_pdf(s), media_type="application/pdf", headers={"Content-Disposition": f'inline; filename="{sid}.pdf"'})
        return s

    @app.get("/v1/records/{rid:path}/statements")
    async def statement_create(request: Request, rid: str, as_of: str = "", format: str = "json"):
        """A signed statement of the record at `as_of` (default: now). Paid per statement; nothing is charged before the first observation."""
        now = int(time.time())
        t = as_of_param(as_of) if as_of else now
        with ro() as c:
            o = RA._resolve(c, rid)
            if not o:
                raise RA.ApiError(404, "invalid_request_error", "record_not_found", "no record with this id", "find it with GET /v1/records?query=")
            first = c.execute("SELECT min(observed_at) FROM w_obs WHERE object=?", (o["id"],)).fetchone()[0]
        if first is None or first > t:
            raise RA.ApiError(404, "invalid_request_error", "not_on_record_at_as_of",
                              f"this record was first observed at {W.iso(first) if first else 'a later time'}; at {W.iso(t)} it was not on record",
                              f"ask for as_of at or after {W.iso(first)}" if first else "retry later")
        paid = await charge(request, {"record": rid, "as_of": W.iso(t)}, "/v1/records/statements")
        if isinstance(paid, JSONResponse):
            return paid
        payer, price, settlement = paid
        with ro() as c:
            body, _st = build(c, o, t, now)
        sid = "stm_" + uuid.uuid4().hex[:24]
        s = receipts.sign({**body, "statement_id": sid, "price": price, "client": receipts.pseudonym(payer)})
        with db() as c:
            c.executescript(SCHEMA)
            c.execute("INSERT INTO statements(id, ts, record, as_of, payer, price, sha256, body) VALUES(?,?,?,?,?,?,?,?)",
                      (sid, now, s["record"], t, payer, json.dumps(price), receipts.sha256(s), json.dumps(s, ensure_ascii=False, sort_keys=True)))
            try:
                import notary
                notary.queue_answer(c, receipts.receipt_id(s))
            except Exception:  # noqa: BLE001
                pass
        if format == "pdf":
            return Response(statement_pdf(s), media_type="application/pdf", headers={"Content-Disposition": f'inline; filename="{sid}.pdf"',
                                                                                     "Link": f'<{BASE}/v1/records/{s["record"]}/statements/{sid}>; rel="alternate"; type="application/json"'})
        out = dict(s)
        if settlement:
            out["payment"] = {"transaction": settlement["tx_hash"], "payer": settlement["payer"], "api_key": settlement["api_key"],
                              "note": "api_key is shown once; the payment above the price is credit"}
        return out
