"""The public API under the official names (master prompt E12, HQ 2026-11-04): Record and Checks.

  GET  /v1/records?query=&type=&limit=&starting_after=   list records (MCP servers, npm and PyPI packages)
  GET  /v1/records/{id}                                   one record; id = rec_… or the source id (mcp:…, npm:…, pypi:…)
  GET  /v1/records/{id}/versions?limit=&starting_after=   facts recorded for it, newest first (ver_… ids, proofs)
  POST /v1/checks                                         run a check (free threshold, then a fee); answer: a check object
  GET  /v1/checks/{id}                                    a check by id (chk_…; older wc_… ids too)
  GET  /v1/checks                                         what checks do, prices, how to pay

Conventions: resources in the plural, snake_case JSON, RFC 3339 UTC times, money as integer minimal units with a currency
code, ids with a type prefix (rec_, ver_, chk_), errors as {"error": {type, code, message, next_step, doc_url}}.
Older paths (/v1/witness/*, /v1/check) keep working and answer with `Deprecation` and a `Link` to the successor
(withdrawn no earlier than 12 months after 2026-11-04).
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: Apache-2.0 (open core).
"""
import json
import urllib.parse

from fastapi import Request
from fastapi.responses import JSONResponse

import witness as W

BASE = "https://ai.minimalcult.org"
DOCS = BASE + "/docs"
KIND_TYPE = {"mcp": "mcp_server", "npm": "npm_package", "pypi": "pypi_package"}
TYPE_KIND = {v: k for k, v in KIND_TYPE.items()}
OBS_TYPE = {"manifest": "registry_entry", "status": "registry_status", "package": "package_artifact", "tools": "tool_descriptions"}
SUCCESSORS = (("/v1/witness/tools", "/v1/records"), ("/v1/witness/history", "/v1/records/{id}/versions"), ("/v1/witness/diff", "/v1/records/{id}/versions"),
              ("/v1/witness/proof", "/v1/records/{id}/versions"), ("/v1/witness/batches", "/v1/anchors"), ("/v1/witness", "/v1/records"),
              ("/v1/check", "/v1/checks"))
DEPRECATED_SINCE = "Wed, 04 Nov 2026 00:00:00 GMT"


class ApiError(Exception):
    def __init__(self, status, type_, code, message, next_step="", doc=""):
        super().__init__(message)
        self.status, self.body = status, {"type": type_, "code": code, "message": message, "next_step": next_step, "doc_url": doc or DOCS}


def error_response(e):
    return JSONResponse({"error": e.body}, status_code=e.status)


def _record(o):
    links = json.loads(o["links"] or "{}") if "links" in o.keys() else {}
    rid = o["rec_id"] if "rec_id" in o.keys() and o["rec_id"] else W.rec_id(o["id"])
    return {"id": rid, "object": "record", "type": KIND_TYPE.get(o["kind"], o["kind"]), "name": o["name"], "source_id": o["id"],
            "title": o["title"], "description": o["description"], "on_record_since": W.iso(o["first_seen"]), "last_seen_at": W.iso(o["last_seen"]),
            "latest_version": o["latest"], "versions_count": o["versions"], "changes_count": o["changes"],
            "last_changed_at": W.iso(o["last_change"]) if o["last_change"] else None, "registry_status": o["status"], "repository_url": o["repo"],
            "related_record": links.get("mcp") and W.rec_id("mcp:" + links["mcp"]),
            "url": f"{BASE}/witness/tool/" + urllib.parse.quote(o["id"], safe=":@/"), "versions_url": f"{BASE}/v1/records/{rid}/versions"}


def _version(r, rid):
    rec = json.loads(r["record"])
    return {"id": W.ver_id(r["leaf"]), "object": "version", "record": rid, "type": OBS_TYPE.get(r["kind"], r["kind"]), "version": r["version"],
            "observed_at": rec["observed_at"], "digest": {"algorithm": "sha256", "value": r["digest"]},
            "previous": W.ver_id(r["prev"]) if r["prev"] else None, "leaf": r["leaf"], "batch": r["batch_id"],
            "meta": rec.get("meta"), "proof_url": f"{BASE}/v1/witness/proof?seq={r['seq']}",
            "diff_url": f"{BASE}/v1/witness/diff?seq={r['seq']}" if r["prev"] else None}


def _resolve(c, rid):
    rid = urllib.parse.unquote(rid)[:320]
    if rid.startswith("rec_"):
        has = "rec_id" in [x[1] for x in c.execute("PRAGMA table_info(w_objects)")]
        return c.execute("SELECT * FROM w_objects WHERE rec_id=?", (rid,)).fetchone() if has else None
    return c.execute("SELECT * FROM w_objects WHERE id=?", (rid,)).fetchone()


def setup(app, db):
    import witness_check as WC

    app.add_exception_handler(ApiError, lambda request, e: error_response(e))

    @app.middleware("http")
    async def deprecations(request: Request, call_next):
        resp = await call_next(request)
        p = request.url.path
        for old, new in SUCCESSORS:
            if p == old or p.startswith(old + "/"):
                resp.headers["Deprecation"] = DEPRECATED_SINCE
                resp.headers["Link"] = f'<{BASE}{new}>; rel="successor-version"'
                break
        return resp

    def ro():
        c = W.open_ro()
        if c is None:
            raise ApiError(503, "api_error", "record_starting", "the record is starting: nothing is recorded yet", "retry in a few minutes")
        return c

    @app.get("/v1/records")
    def records(query: str = "", type: str = "", limit: int = 20, starting_after: str = ""):
        """Records: MCP servers and the npm and PyPI packages behind them, as recorded from public sources."""
        if type and type not in TYPE_KIND:
            raise ApiError(400, "invalid_request_error", "invalid_type", f"type is one of {', '.join(TYPE_KIND)}", "drop the type filter or fix it")
        limit = max(1, min(limit, 100))
        with ro() as c:
            where, args = ["kind != 'witness'"], []
            if query:
                where.append("(name LIKE ? OR title LIKE ? OR description LIKE ?)"); args += [f"%{query[:100]}%"] * 3
            if type:
                where.append("kind=?"); args.append(TYPE_KIND[type])
            if starting_after:
                cur = _resolve(c, starting_after)
                if not cur:
                    raise ApiError(400, "invalid_request_error", "invalid_cursor", "starting_after is not a record id", "use the id of the last record of the previous page")
                where.append("name > ?"); args.append(cur["name"])
            rows = c.execute(f"SELECT * FROM w_objects WHERE {' AND '.join(where)} ORDER BY name LIMIT ?", (*args, limit + 1)).fetchall()
        data = [_record(r) for r in rows[:limit]]
        return {"object": "list", "url": "/v1/records", "has_more": len(rows) > limit, "data": data}

    @app.get("/v1/records/{rid:path}/versions")
    def versions(rid: str, limit: int = 50, starting_after: str = ""):
        limit = max(1, min(limit, 500))
        with ro() as c:
            o = _resolve(c, rid)
            if not o:
                raise ApiError(404, "invalid_request_error", "record_not_found", "no record with this id", "find it with GET /v1/records?query=")
            args, extra = [o["id"]], ""
            if starting_after:
                cur = c.execute("SELECT seq FROM w_obs WHERE object=? AND leaf >= ? AND leaf < ? LIMIT 1",
                                (o["id"], starting_after[4:], starting_after[4:] + "g")).fetchone() if starting_after.startswith("ver_") else None
                if not cur:
                    raise ApiError(400, "invalid_request_error", "invalid_cursor", "starting_after is not a version id of this record", "use the id of the last version of the previous page")
                extra = " AND seq < ?"; args.append(cur["seq"])
            rows = c.execute(f"SELECT * FROM w_obs WHERE object=?{extra} ORDER BY seq DESC LIMIT ?", (*args, limit + 1)).fetchall()
            rid_ = _record(o)["id"]
        return {"object": "list", "url": f"/v1/records/{rid_}/versions", "has_more": len(rows) > limit, "data": [_version(r, rid_) for r in rows[:limit]]}

    @app.get("/v1/records/{rid:path}")
    def record(rid: str):
        with ro() as c:
            o = _resolve(c, rid)
            if not o:
                raise ApiError(404, "invalid_request_error", "record_not_found", "no record with this id", "find it with GET /v1/records?query=")
            out = _record(o)
            last = c.execute("SELECT * FROM w_obs WHERE object=? ORDER BY seq DESC LIMIT 1", (o["id"],)).fetchone()
            out["latest_fact"] = _version(last, out["id"]) if last else None
        return out

    def check_object(ctx):
        rec, p = ctx["rec"], ctx["price"]
        return {"id": rec["check_id"], "object": "check", "created": rec["created"], "type": rec["type"], "target": rec["target"],
                "status": rec["status"], "flags": rec["flags"], "facts": rec["facts"], "changes": rec["changes"],
                "record_head": rec["record_head"], "price": p, "free_checks_left_today": ctx["free_left"],
                "balance_left": {"amount": ctx["balance_left"], "currency": "gram", "unit": "nano"} if ctx["balance_left"] is not None else None,
                "payment": ({"transaction": ctx["settlement"]["tx_hash"], "payer": ctx["settlement"]["payer"],
                             "paid": {"amount": ctx["settlement"]["paid_nano"], "currency": "gram", "unit": "nano"},
                             "api_key": ctx["settlement"]["api_key"], "note": "api_key is shown once; the payment above the price is credit for more checks"}
                            if ctx["settlement"] else None),
                "signed_record": rec, "url": f"{BASE}/v1/checks/{rec['check_id']}"}

    @app.get("/v1/checks")
    def checks_about():
        return WC.about()

    @app.post("/v1/checks")
    async def checks_create(request: Request):
        try:
            b = await request.json()
        except ValueError:
            raise ApiError(400, "invalid_request_error", "invalid_json", "the body is not JSON", 'send {"type": "mcp_server", "target": "<registry name>"}')
        if not isinstance(b, dict) or b.get("type") not in WC.TYPES:
            raise ApiError(400, "invalid_request_error", "invalid_type", f"type is one of {', '.join(t for t in WC.TYPES if t != 'mcp_tool')}",
                           'send {"type": "mcp_server", "target": "<registry name>"}', DOCS + "/checks")
        if b.get("type") == "model_endpoint":
            raise ApiError(400, "invalid_request_error", "type_not_available", "model_endpoint checks are planned, not available yet", "use mcp_server, package, url or ton_address")
        from fastapi import HTTPException
        try:
            ctx = await WC.setup.perform(request, b, "/v1/checks")
        except HTTPException as e:
            code = {400: "invalid_request", 402: "payment_required", 429: "rate_limited"}.get(e.status_code, "error")
            raise ApiError(e.status_code, "invalid_request_error" if e.status_code == 400 else "api_error", code, str(e.detail),
                           {402: "top up the key balance or pay without a key (GRAM-402)", 429: "retry later or ask for volume terms"}.get(e.status_code, "fix the request"))
        if isinstance(ctx, JSONResponse):
            return ctx          # 402 invoice (x402 shape, understood by paying clients)
        return check_object(ctx)

    @app.get("/v1/checks/{cid}")
    def checks_get(cid: str):
        r = WC.get_check(db, cid)
        if not r:
            raise ApiError(404, "invalid_request_error", "check_not_found", "no check with this id", "create one with POST /v1/checks")
        return r
