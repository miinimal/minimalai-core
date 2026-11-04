"""Monitors (block MON, master prompt E13): subscribe to changes of a record and receive a signed webhook when it moves.

  POST   /v1/monitors                {"record": "<rec_… or mcp:…/npm:…/pypi:…>", "url": "https://…"}  -> monitor + secret (shown once)
  GET    /v1/monitors                the monitors of the calling key
  GET    /v1/monitors/{mon_id}       one monitor (owner key, or X-Monitor-Secret)
  DELETE /v1/monitors/{mon_id}       stop it (owner key, or X-Monitor-Secret)
  GET    /v1/records/{id}/changes    the changes of a record (JSON); /v1/records/{id}/changes.rss — the same as RSS 2.0

Event `monitor.triggered` (id evt_…): {id, type, created, monitor, record, object, change_type (description_changed |
version_published | removed | flagged), what, version, diff, record_url, statement_url}. Delivered by POST to the monitor's
https URL with `MINIMALCULT-Signature: t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<body>" with the monitor secret>` and
`MINIMALCULT-Event-Id`; any 2xx is a delivery; otherwise retried after 1, 5, 30 minutes, 2, 6, 12 and 24 hours (7 tries).
A monitor whose URL failed 20 events in a row is paused. Webhook URLs are public https hosts only; no redirects are followed.
Delivery runs in the record service right after each hourly cycle and then every minute for retries.
Price: 3 monitors per key (or per address without a key) are free; more are 1 USD per monitor per 30 days, paid in USDC on
Base through x402 at /base/monitors (other payment methods with block PAY).
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: Apache-2.0 (open core).
"""
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse

BASE = "https://ai.minimalcult.org"
FREE_MONITORS = int(os.environ.get("MONITORS_FREE", "3"))
MONITOR_PRICE_USD = os.environ.get("MONITOR_PRICE", "$1.00")
PAID_DAYS = 30
RETRY_S = (60, 300, 1800, 7200, 21600, 43200, 86400)
PAUSE_AFTER = 20
SCHEMA = """
CREATE TABLE IF NOT EXISTS monitors(id TEXT PRIMARY KEY, created INTEGER, owner TEXT, record TEXT, source_id TEXT, url TEXT, secret TEXT,
    status TEXT DEFAULT 'active', paid_until INTEGER, cursor INTEGER DEFAULT 0, failures INTEGER DEFAULT 0, last_delivery INTEGER, note TEXT);
CREATE INDEX IF NOT EXISTS monitors_owner ON monitors(owner);
CREATE INDEX IF NOT EXISTS monitors_source ON monitors(source_id, status);
CREATE TABLE IF NOT EXISTS monitor_events(id TEXT PRIMARY KEY, monitor TEXT, change_seq INTEGER, created INTEGER, payload TEXT,
    attempts INTEGER DEFAULT 0, next_at INTEGER, delivered_at INTEGER, last_status INTEGER, last_error TEXT, UNIQUE(monitor, change_seq));
CREATE INDEX IF NOT EXISTS monitor_events_due ON monitor_events(delivered_at, next_at);
CREATE TABLE IF NOT EXISTS monitor_state(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS monitor_selftest(event TEXT PRIMARY KEY, received_at INTEGER, change_ts INTEGER, sealed_at INTEGER, valid INTEGER);
"""


def change_type(kind, what):
    if kind == "status":
        return "removed" if ("deleted" in what or "deprecated" in what) else "flagged"
    if kind == "tools":
        return "description_changed"
    if what.startswith("new version"):
        return "version_published"
    return "description_changed"


def sign(secret, t, body):
    return hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()


def verify_signature(secret, header, body, tolerance=300, now=None):
    """For receivers (and our self-test): header `t=…,v1=…`; constant-time compare; timestamp within `tolerance` seconds."""
    try:
        parts = dict(x.split("=", 1) for x in header.split(","))
        t = int(parts["t"])
    except (ValueError, KeyError):
        return False
    if abs((now or time.time()) - t) > tolerance:
        return False
    return hmac.compare_digest(sign(secret, t, body), parts.get("v1", ""))


# ---------------------------------------------------------------- dispatch (runs in the record service)
def fan_out(m, w, now):
    """New changes in the record -> one event per matching active monitor. Returns the number of events created."""
    m.executescript(SCHEMA)
    import witness as W
    cur = int((m.execute("SELECT value FROM monitor_state WHERE key='change_cursor'").fetchone() or [0])[0])
    rows = w.execute("SELECT c.seq, c.object, c.ts, c.what, o.kind, o.version, o.leaf, o.batch_id FROM w_changes c JOIN w_obs o ON o.seq=c.seq "
                     "WHERE c.seq > ? ORDER BY c.seq LIMIT 5000", (cur,)).fetchall()
    n = 0
    for r in rows:
        if not r["batch_id"]:
            break                      # events go out for sealed facts only: the statement link must prove them
        mons = m.execute("SELECT * FROM monitors WHERE status='active' AND (source_id=? OR source_id='*') AND (paid_until IS NULL OR paid_until > ?) "
                         "AND created <= ?", (r["object"], now, r["ts"])).fetchall()     # a monitor hears changes made after it was created
        rid = W.rec_id(r["object"])
        for mon in mons:
            ev = {"id": "evt_" + secrets.token_hex(12), "object": "event", "type": "monitor.triggered", "created": W.iso(now),
                  "monitor": mon["id"], "record": rid, "source_id": r["object"], "change_type": change_type(r["kind"], r["what"]),
                  "what": r["what"], "version": r["version"], "fact": W.ver_id(r["leaf"]), "changed_at": W.iso(r["ts"]),
                  "diff": f"{BASE}/v1/witness/diff?seq={r['seq']}", "record_url": f"{BASE}/v1/records/{rid}",
                  "statement_url": f"{BASE}/v1/records/{rid}/statements?as_of={W.iso(r['ts'])}"}
            cur_m = m.execute("INSERT OR IGNORE INTO monitor_events(id, monitor, change_seq, created, payload, next_at) VALUES(?,?,?,?,?,?)",
                              (ev["id"], mon["id"], r["seq"], now, json.dumps(ev), now))
            n += cur_m.rowcount
        cur = r["seq"]
    m.execute("INSERT OR REPLACE INTO monitor_state(key, value) VALUES('change_cursor', ?)", (str(cur),))
    m.commit()
    return n


def deliver(m, now, post=None, limit=200):
    """Due events -> POST with the HMAC signature. Returns {delivered, failed}."""
    import witness as W
    post = post or (lambda url, body, headers: W.fetch(url, data=body, headers=headers, timeout=10, guard=True))
    out = {"delivered": 0, "failed": 0}
    for e in m.execute("SELECT e.*, mo.url, mo.secret, mo.status FROM monitor_events e JOIN monitors mo ON mo.id=e.monitor "
                       "WHERE e.delivered_at IS NULL AND e.next_at <= ? AND e.attempts < ? ORDER BY e.next_at LIMIT ?",
                       (now, len(RETRY_S) + 1, limit)).fetchall():
        if e["status"] != "active":
            continue
        body = e["payload"].encode()
        t = int(time.time())
        hdr = {"Content-Type": "application/json", "MINIMALCULT-Event-Id": json.loads(e["payload"])["id"], "MINIMALCULT-Signature": f"t={t},v1={sign(e['secret'], t, body)}",
               "Accept": "*/*"}
        try:
            st, _h, _b = post(e["url"], body, hdr)
            err = None if 200 <= st < 300 else f"HTTP {st}"
        except Exception as x:  # noqa: BLE001
            st, err = 0, f"{type(x).__name__}: {str(x)[:120]}"
        if err is None:
            m.execute("UPDATE monitor_events SET delivered_at=?, attempts=attempts+1, last_status=?, last_error=NULL WHERE id=?", (now, st, e["id"]))
            m.execute("UPDATE monitors SET failures=0, last_delivery=? WHERE id=?", (now, e["monitor"]))
            out["delivered"] += 1
        else:
            a = e["attempts"] + 1
            nxt = now + RETRY_S[a - 1] if a <= len(RETRY_S) else None
            m.execute("UPDATE monitor_events SET attempts=?, next_at=coalesce(?, next_at), last_status=?, last_error=? WHERE id=?", (a, nxt, st, err, e["id"]))
            if a > len(RETRY_S):
                m.execute("UPDATE monitors SET failures=failures+1, status=CASE WHEN failures+1>=? THEN 'paused' ELSE status END WHERE id=?",
                          (PAUSE_AFTER, e["monitor"]))
            out["failed"] += 1
        m.commit()
    return out


def dispatch(main_db, w, now=None, post=None):
    import sqlite3
    now = now or int(time.time())
    m = sqlite3.connect(main_db, timeout=30)
    m.row_factory = sqlite3.Row
    try:
        made = fan_out(m, w, now)
        return {"events": made, **deliver(m, now, post)}
    finally:
        m.close()


# ---------------------------------------------------------------- API (gateway)
def create_monitor(db, owner, rec, url, paid=None):
    """Shared by POST /v1/monitors and the MCP tool monitor_create. Returns (row, secret); raises records_api.ApiError."""
    import records_api as RA
    import witness as W
    E = RA.ApiError
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname or len(url) > 500:
        raise E(400, "invalid_request_error", "invalid_url", "url is an https URL that receives the webhook", "send a public https endpoint")
    try:
        W.public_host(u.hostname)
    except W.Blocked:
        raise E(400, "invalid_request_error", "url_not_public", "the webhook host does not resolve to a public address", "use a public https endpoint")
    cw = W.open_ro()
    if cw is None:
        raise E(503, "api_error", "record_starting", "the record is starting", "retry in a few minutes")
    with cw:
        o = RA._resolve(cw, rec)
    if not o:
        raise E(404, "invalid_request_error", "record_not_found", "no record with this id", "find it with GET /v1/records?query=")
    now = int(time.time())
    with db() as c:
        c.executescript(SCHEMA)
        n = c.execute("SELECT count(*) FROM monitors WHERE owner=? AND status!='deleted' AND paid_until IS NULL", (owner,)).fetchone()[0]
        if n >= FREE_MONITORS and not paid:
            raise E(402, "payment_error", "free_monitors_used", f"{FREE_MONITORS} monitors are free per key or address; more cost {MONITOR_PRICE_USD} per monitor per 30 days",
                    f"pay in USDC on Base through x402: GET {BASE}/base/monitors?record=<id>&url=<webhook> (other methods arrive with USD pricing)")
        mid, secret = "mon_" + secrets.token_hex(12), "whsec_" + secrets.token_hex(24)
        rid = o["rec_id"] if "rec_id" in o.keys() and o["rec_id"] else W.rec_id(o["id"])
        c.execute("INSERT INTO monitors(id, created, owner, record, source_id, url, secret, paid_until, cursor) VALUES(?,?,?,?,?,?,?,?,?)",
                  (mid, now, owner if not paid else "x402:" + (paid["payer"] or owner), rid, o["id"], url, secret,
                   now + PAID_DAYS * 86400 if paid else None, 0))
        return c.execute("SELECT * FROM monitors WHERE id=?", (mid,)).fetchone(), secret


def setup(app, db, get_key, client_ip, h, admin):
    from fastapi import Request
    from fastapi.responses import PlainTextResponse
    import records_api as RA
    import witness as W
    import witness_check as WC
    with db() as c:
        c.executescript(SCHEMA)
    E = RA.ApiError

    def owner_of(request):
        auth = request.headers.get("authorization")
        if auth:
            return "key:" + get_key(auth)["key_hash"]
        return "ip:" + h("ip:" + client_ip(request))

    def view(r, secret=None):
        out = {"id": r["id"], "object": "monitor", "created": W.iso(r["created"]), "record": r["record"], "source_id": r["source_id"], "url": r["url"],
               "status": r["status"], "paid_until": W.iso(r["paid_until"]) if r["paid_until"] else None,
               "last_delivery": W.iso(r["last_delivery"]) if r["last_delivery"] else None, "failures": r["failures"],
               "events": "monitor.triggered", "signature": "MINIMALCULT-Signature: t=<unix>,v1=<hex HMAC-SHA256 of '<t>.<body>'>"}
        if secret:
            out["secret"] = secret
            out["secret_note"] = "shown once: keep it to verify webhook signatures and to manage this monitor without a key"
        return out

    def find(request, mid):
        with db() as c:
            r = c.execute("SELECT * FROM monitors WHERE id=?", (mid[:40],)).fetchone()
        if not r:
            raise E(404, "invalid_request_error", "monitor_not_found", "no monitor with this id", "list yours with GET /v1/monitors")
        sec = request.headers.get("x-monitor-secret", "")
        if not ((sec and hmac.compare_digest(sec, r["secret"])) or (request.headers.get("authorization") and owner_of(request) == r["owner"])):
            raise E(403, "invalid_request_error", "not_your_monitor", "this monitor belongs to another key", "send its X-Monitor-Secret or the owner key")
        return r

    @app.post("/v1/monitors")
    async def create(request: Request):
        try:
            b = await request.json()
        except ValueError:
            raise E(400, "invalid_request_error", "invalid_json", "the body is not JSON", 'send {"record": "<id>", "url": "https://…"}')
        url, rec = str((b or {}).get("url") or "").strip(), str((b or {}).get("record") or "").strip()
        r, secret = create_monitor(db, owner_of(request), rec, url, WC.internal_payment(request))
        return view(r, secret)

    @app.get("/v1/monitors")
    def list_(request: Request):
        if not request.headers.get("authorization"):
            raise E(401, "authentication_error", "key_required", "listing needs the owner key", "send Authorization: Bearer <key>, or GET /v1/monitors/{id} with X-Monitor-Secret")
        own = owner_of(request)
        with db() as c:
            rows = c.execute("SELECT * FROM monitors WHERE owner=? AND status!='deleted' ORDER BY created DESC LIMIT 200", (own,)).fetchall()
        return {"object": "list", "data": [view(r) for r in rows], "has_more": False}

    @app.get("/v1/monitors/{mid}")
    def get(request: Request, mid: str):
        r = find(request, mid)
        with db() as c:
            ev = c.execute("SELECT payload, delivered_at, attempts, last_status, last_error FROM monitor_events WHERE monitor=? ORDER BY created DESC LIMIT 20", (r["id"],)).fetchall()
        return {**view(r), "recent_events": [{"event": json.loads(e["payload"])["id"], "change_type": json.loads(e["payload"])["change_type"],
                                              "delivered_at": W.iso(e["delivered_at"]) if e["delivered_at"] else None, "attempts": e["attempts"],
                                              "last_status": e["last_status"], "last_error": e["last_error"]} for e in ev]}

    @app.delete("/v1/monitors/{mid}")
    def delete(request: Request, mid: str):
        r = find(request, mid)
        with db() as c:
            c.execute("UPDATE monitors SET status='deleted' WHERE id=?", (r["id"],))
        return {"id": r["id"], "object": "monitor", "deleted": True}

    def changes(cw, o, limit):
        return cw.execute("SELECT c.seq, c.ts, c.what, o.kind, o.version, o.leaf FROM w_changes c JOIN w_obs o ON o.seq=c.seq WHERE c.object=? ORDER BY c.seq DESC LIMIT ?",
                          (o["id"], limit)).fetchall()

    @app.get("/v1/records/{rid:path}/changes.rss", include_in_schema=False)
    def changes_rss(rid: str):
        from xml.sax.saxutils import escape
        cw = W.open_ro()
        if cw is None:
            raise E(503, "api_error", "record_starting", "the record is starting", "retry in a few minutes")
        with cw:
            o = RA._resolve(cw, rid)
            if not o:
                raise E(404, "invalid_request_error", "record_not_found", "no record with this id", "find it with GET /v1/records?query=")
            rows = changes(cw, o, 50)
        rec = RA._record(o)
        items = "".join(f"<item><title>{escape(o['name'])}: {escape(r['what'])}</title><link>{BASE}/v1/witness/diff?seq={r['seq']}</link>"
                        f"<guid isPermaLink=\"false\">{W.ver_id(r['leaf'])}</guid><pubDate>{time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime(r['ts']))}</pubDate>"
                        f"<description>{escape(change_type(r['kind'], r['what']))} · {escape(str(r['version']))}</description></item>" for r in rows)
        xml = (f'<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>MINIMALCULT record: {escape(o["name"])}</title>'
               f"<link>{escape(rec['url'])}</link><description>Changes of {escape(o['id'])} as recorded and anchored by MINIMALCULT</description>{items}</channel></rss>")
        return PlainTextResponse(xml, media_type="application/rss+xml")

    @app.get("/v1/records/{rid:path}/changes")
    def changes_json(rid: str, limit: int = 50):
        cw = W.open_ro()
        if cw is None:
            raise E(503, "api_error", "record_starting", "the record is starting", "retry in a few minutes")
        with cw:
            o = RA._resolve(cw, rid)
            if not o:
                raise E(404, "invalid_request_error", "record_not_found", "no record with this id", "find it with GET /v1/records?query=")
            rows = changes(cw, o, max(1, min(limit, 200)))
            rid_ = RA._record(o)["id"]
        return {"object": "list", "url": f"/v1/records/{rid_}/changes", "rss": f"{BASE}/v1/records/{rid_}/changes.rss",
                "data": [{"fact": W.ver_id(r["leaf"]), "change_type": change_type(r["kind"], r["what"]), "what": r["what"], "version": r["version"],
                          "changed_at": W.iso(r["ts"]), "diff": f"{BASE}/v1/witness/diff?seq={r['seq']}"} for r in rows]}

    # ------------------------------------------------------------ self-test: our own monitor on every change, received here
    @app.post("/v1/monitors/_selftest/receive", include_in_schema=False)
    async def selftest_receive(request: Request):
        body = await request.body()
        with db() as c:
            r = c.execute("SELECT secret FROM monitors WHERE id=(SELECT value FROM monitor_state WHERE key='selftest_monitor')").fetchone()
            ok = bool(r) and verify_signature(r["secret"], request.headers.get("minimalcult-signature", ""), body)
            try:
                ev = json.loads(body)
            except ValueError:
                ev = {}
            sealed = None
            cw = W.open_ro()
            if cw is not None and ev.get("fact"):
                with cw:
                    x = cw.execute("SELECT b.ts FROM w_obs o JOIN w_batches b ON b.id=o.batch_id WHERE o.leaf LIKE ?", (ev["fact"][4:] + "%",)).fetchone()
                    sealed = x["ts"] if x else None
            c.execute("INSERT OR IGNORE INTO monitor_selftest(event, received_at, change_ts, sealed_at, valid) VALUES(?,?,?,?,?)",
                      (str(ev.get("id"))[:40], int(time.time()), int(W.parse_time(ev["changed_at"])) if ev.get("changed_at") else None, sealed, int(ok)))
        return {"received": True, "valid": ok}

    @app.post("/admin/monitors/selftest", include_in_schema=False)
    def selftest_setup(request: Request):
        admin(request.headers.get("authorization"))
        with db() as c:
            have = c.execute("SELECT value FROM monitor_state WHERE key='selftest_monitor'").fetchone()
            if have and c.execute("SELECT 1 FROM monitors WHERE id=? AND status='active'", (have[0],)).fetchone():
                mid = have[0]
            else:
                mid, now = "mon_" + secrets.token_hex(12), int(time.time())
                c.execute("INSERT INTO monitors(id, created, owner, record, source_id, url, secret, cursor) VALUES(?,?,?,?,?,?,?,0)",
                          (mid, now, "selftest", "*", "*", f"{BASE}/v1/monitors/_selftest/receive", "whsec_" + secrets.token_hex(24)))
                c.execute("INSERT OR REPLACE INTO monitor_state(key, value) VALUES('selftest_monitor', ?)", (mid,))
            rows = c.execute("SELECT * FROM monitor_selftest ORDER BY received_at DESC LIMIT 200").fetchall()
        lat = sorted(r["received_at"] - r["sealed_at"] for r in rows if r["sealed_at"])
        return {"monitor": mid, "received": len(rows), "valid": sum(r["valid"] for r in rows),
                "seconds_after_seal": {"median": lat[len(lat) // 2] if lat else None, "max": lat[-1] if lat else None},
                "target": "a change reaches the webhook less than 5 minutes after the cycle that sealed it"}
