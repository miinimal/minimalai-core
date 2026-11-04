"""The MINIMALCULT MCP server (bridge 2, block REG): the record and Checks inside every MCP client, nothing to install.

  POST https://ai.minimalcult.org/mcp      MCP streamable HTTP, stateless, JSON answers (protocol 2025-06-18; older clients
                                           get their own version echoed when it is one we speak)
Tools:
  check            run a check (type, target, version, sha256, integrity): the signed check object; free threshold per address,
                   then the error carries next_step (key, GRAM-402 at /v1/checks, or x402 USDC at /base/checks)
  record_search    find records (MCP servers, npm and PyPI packages) by name or words
  record_get       one record by rec_ id or source id (mcp:…, npm:…, pypi:…)
  record_versions  the recorded facts of a record, newest first, with proof links
Registry: published as org.minimalcult/minimalcult; the domain is proven by /.well-known/mcp-registry-auth (HTTP method of
the official registry), whose public key the rollout writes to /data/mcp_registry_auth.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: Apache-2.0 (open core).
"""
import json
import os

from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

import records_api as RA
import witness as W

VERSIONS = ("2025-06-18", "2025-03-26", "2025-11-25")
SERVER = {"name": "minimalcult", "title": "MINIMALCULT", "version": "1.0.0", "websiteUrl": "https://minimalcult.org"}
INSTRUCTIONS = ("MINIMALCULT keeps an independent, anchored record of MCP servers and their npm and PyPI packages: every version, "
                "package hash and public tool-description change, sealed hourly and anchored in Bitcoin, an RFC 3161 TSA and Sigstore "
                "Rekor. Before installing or calling an unfamiliar MCP server or package, run `check`: the answer is signed facts "
                "(since when it is known, what changed in the last 30 days, recorded hashes), never a judgement of intent.")
AUTH_FILE = os.environ.get("MCP_REGISTRY_AUTH_FILE", os.path.join(os.path.dirname(os.environ.get("MINIMALAI_DB", "./x.db")), "mcp_registry_auth"))
TYPES = ["mcp_server", "package", "url", "ton_address"]
TOOLS = [
    {"name": "check", "title": "Check before you trust",
     "description": "Check an MCP server, an npm or PyPI package (optionally with the hash you are about to install), an MCP endpoint URL "
                    "or a TON address against the anchored record. Returns a signed check: status (witnessed, changed_recently, "
                    "hash_mismatch, not_witnessed, sanctions_listed, not_listed), flags, facts, recent changes with diff links.",
     "inputSchema": {"type": "object", "required": ["type", "target"], "properties": {
         "type": {"type": "string", "enum": TYPES},
         "target": {"type": "string", "description": "registry name (io.github.owner/server), npm:<name> or pypi:<name>, https URL, or TON address"},
         "version": {"type": "string"}, "sha256": {"type": "string", "description": "sha256 of the PyPI file you are about to install"},
         "integrity": {"type": "string", "description": "npm dist.integrity of the tarball you are about to install"},
         "as_of": {"type": "string", "description": "RFC 3339 time: answer as the record stood at that moment"}}},
     "annotations": {"readOnlyHint": True, "openWorldHint": True}},
    {"name": "monitor_create", "title": "Watch a record",
     "description": "Subscribe a webhook to changes of a record (new version, tool description changed, removed). Returns the monitor id and "
                    "a secret shown once (HMAC-SHA256 signatures, header MINIMALCULT-Signature). 3 monitors per address are free.",
     "inputSchema": {"type": "object", "required": ["record", "url"], "properties": {
         "record": {"type": "string", "description": "rec_ id or mcp:<registry name>, npm:<name>, pypi:<name>"},
         "url": {"type": "string", "description": "public https URL that receives monitor.triggered events"}}},
     "annotations": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True}},
    {"name": "record_search", "title": "Search the record",
     "description": "Find records of MCP servers and npm/PyPI packages by name or words; returns rec_ ids, on-record-since dates, latest versions.",
     "inputSchema": {"type": "object", "required": ["query"], "properties": {"query": {"type": "string"},
                     "type": {"type": "string", "enum": list(RA.TYPE_KIND)}, "limit": {"type": "integer", "minimum": 1, "maximum": 50}}},
     "annotations": {"readOnlyHint": True}},
    {"name": "record_get", "title": "Get a record",
     "description": "One record by rec_ id or source id (mcp:<registry name>, npm:<name>, pypi:<name>) with its latest recorded fact.",
     "inputSchema": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}},
     "annotations": {"readOnlyHint": True}},
    {"name": "record_versions", "title": "List recorded facts",
     "description": "The recorded facts (versions, registry entries, package artifacts, tool descriptions) of a record, newest first, with proof and diff links.",
     "inputSchema": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}},
     "annotations": {"readOnlyHint": True}},
]


class ToolError(Exception):
    pass


def _ro():
    c = W.open_ro()
    if c is None:
        raise ToolError("the record is starting; retry in a few minutes")
    return c


def record_search(a):
    q, t, lim = str(a.get("query") or "")[:100], a.get("type"), max(1, min(int(a.get("limit") or 10), 50))
    if t and t not in RA.TYPE_KIND:
        raise ToolError(f"type is one of {', '.join(RA.TYPE_KIND)}")
    with _ro() as c:
        where, args = ["kind != 'witness'", "(name LIKE ? OR title LIKE ? OR description LIKE ?)"], [f"%{q}%"] * 3
        if t:
            where.append("kind=?"); args.append(RA.TYPE_KIND[t])
        rows = c.execute(f"SELECT * FROM w_objects WHERE {' AND '.join(where)} ORDER BY coalesce(last_change, first_seen) DESC LIMIT ?", (*args, lim)).fetchall()
    return {"object": "list", "data": [RA._record(r) for r in rows]}


def record_get(a):
    with _ro() as c:
        o = RA._resolve(c, str(a.get("id") or ""))
        if not o:
            raise ToolError("no record with this id; find it with record_search")
        out = RA._record(o)
        last = c.execute("SELECT * FROM w_obs WHERE object=? ORDER BY seq DESC LIMIT 1", (o["id"],)).fetchone()
        out["latest_fact"] = RA._version(last, out["id"]) if last else None
    return out


def record_versions(a):
    lim = max(1, min(int(a.get("limit") or 20), 100))
    with _ro() as c:
        o = RA._resolve(c, str(a.get("id") or ""))
        if not o:
            raise ToolError("no record with this id; find it with record_search")
        rid = RA._record(o)["id"]
        rows = c.execute("SELECT * FROM w_obs WHERE object=? ORDER BY seq DESC LIMIT ?", (o["id"], lim)).fetchall()
    return {"object": "list", "data": [RA._version(r, rid) for r in rows]}


PER_MIN = int(os.environ.get("MCP_PER_MIN", "120"))


_DB, _H = [None], [None]


def setup(app, client_ip, db=None, h=None):
    import witness_check as WC
    _DB[0], _H[0] = db, h

    @app.get("/.well-known/mcp-registry-auth", response_class=PlainTextResponse, include_in_schema=False)
    def registry_auth():
        """Domain proof for the official MCP Registry (HTTP method): v=MCPv1; k=ed25519; p=<base64 public key>."""
        try:
            return PlainTextResponse(open(AUTH_FILE).read().strip() + "\n")
        except OSError:
            return PlainTextResponse("not configured\n", status_code=404)

    @app.get("/mcp", include_in_schema=False)
    def mcp_get():
        return Response(status_code=405, headers={"Allow": "POST"})

    @app.post("/mcp")
    async def mcp(request: Request):
        import shield
        if not shield.allow("mcp:" + client_ip(request), PER_MIN):
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "too many requests from this address; retry in a minute"}},
                                status_code=429, headers={"Retry-After": "60"})
        try:
            msg = await request.json()
        except ValueError:
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}, status_code=400)
        if isinstance(msg, list):
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "batches are not supported (protocol 2025-06-18)"}}, status_code=400)
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}, status_code=400)
        mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
        if mid is None:                                   # a notification (notifications/initialized, cancelled, ...)
            return Response(status_code=202)

        def ok(result):
            return JSONResponse({"jsonrpc": "2.0", "id": mid, "result": result})

        if method == "initialize":
            want = params.get("protocolVersion")
            return ok({"protocolVersion": want if want in VERSIONS else VERSIONS[0], "capabilities": {"tools": {"listChanged": False}},
                       "serverInfo": SERVER, "instructions": INSTRUCTIONS})
        if method == "ping":
            return ok({})
        if method == "tools/list":
            return ok({"tools": TOOLS})
        if method != "tools/call":
            return JSONResponse({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}})
        name, args = params.get("name"), params.get("arguments") or {}
        try:
            if name == "check":
                if args.get("type") not in TYPES:
                    raise ToolError(f"type is one of {', '.join(TYPES)}")
                from fastapi import HTTPException
                try:
                    ctx = await WC.setup.perform(request, {k: args[k] for k in ("type", "target", "version", "sha256", "integrity", "as_of") if args.get(k)}, "/mcp")
                except HTTPException as e:
                    raise ToolError(str(e.detail))
                if isinstance(ctx, JSONResponse):
                    raise ToolError("today's free checks from this address are used. next_step: call POST https://ai.minimalcult.org/v1/checks with "
                                    "an API key, pay without a key through GRAM-402 at the same URL, or pay $0.01 USDC on Base (x402) at "
                                    "https://ai.minimalcult.org/base/checks")
                result = {k: v for k, v in RA_check_object(ctx).items() if k != "signed_record"}
                result["signed_record_url"] = result["url"]
            elif name == "monitor_create":
                import monitors
                try:
                    row, secret = monitors.create_monitor(_DB[0], "ip:" + _H[0]("ip:" + client_ip(request)), str(args.get("record") or ""), str(args.get("url") or ""))
                except RA.ApiError as e:
                    raise ToolError(f"{e.body['message']}. next_step: {e.body['next_step']}")
                result = {"id": row["id"], "object": "monitor", "record": row["record"], "url": row["url"], "status": row["status"], "secret": secret,
                          "secret_note": "shown once; manage the monitor with X-Monitor-Secret at /v1/monitors/{id}"}
            elif name == "record_search":
                result = record_search(args)
            elif name == "record_get":
                result = record_get(args)
            elif name == "record_versions":
                result = record_versions(args)
            else:
                return JSONResponse({"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool: {name}"}})
        except ToolError as e:
            return ok({"content": [{"type": "text", "text": str(e)}], "isError": True})
        return ok({"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}], "structuredContent": result, "isError": False})


def RA_check_object(ctx):
    rec, p = ctx["rec"], ctx["price"]
    return {"id": rec["check_id"], "object": "check", "created": rec["created"], "type": rec["type"], "target": rec["target"],
            "status": rec["status"], "flags": rec["flags"], "facts": rec["facts"], "changes": rec["changes"], "record_head": rec["record_head"],
            "price": p, "free_checks_left_today": ctx["free_left"], "signed_record": rec, "url": f"https://ai.minimalcult.org/v1/checks/{rec['check_id']}"}
