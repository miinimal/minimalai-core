"""The agent trust index (block E): one public page and one JSON with the live numbers of the trust layer — receipts and
verdicts per day, how many were acknowledged as delivered, the anchors that fix them, identities linked across
ecosystems — every number from the same tables the API serves, every row linking to its source. No internal finances.

Also the channel tags of block E: a sign-up may carry `src` (where the agent came from: skill, llms, quickstart, mcp,
sdk-python, sdk-ts, moltbook, a post tag); counts per source per day live at /admin/channels for the A/B comparison after
two weeks. Nothing about the agent is stored beyond the tag.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import html
import json
import re
import time

from fastapi.responses import HTMLResponse

import ui

SCHEMA = "CREATE TABLE IF NOT EXISTS signup_sources(ts INTEGER, key_hash TEXT PRIMARY KEY, src TEXT);"
SRC_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")


def record_source(c, key_hash, src, now=None):
    src = str(src or "").strip().lower()
    if not SRC_RE.match(src):
        return None
    c.executescript(SCHEMA)
    c.execute("INSERT OR IGNORE INTO signup_sources(ts, key_hash, src) VALUES(?,?,?)", (now or int(time.time()), key_hash, src))
    return src


def numbers(c, now=None):
    now = now or int(time.time()); day = now - 86400; week = now - 7 * 86400
    q = lambda sql, *a: (c.execute(sql, a).fetchone() or [0])[0] or 0
    has = lambda t: bool(c.execute("SELECT 1 FROM sqlite_master WHERE name=?", (t,)).fetchone())
    d = {"ts": now}
    d["receipts"] = {"total": q("SELECT count(*) FROM task_receipts"), "day": q("SELECT count(*) FROM task_receipts WHERE ts>?", day), "week": q("SELECT count(*) FROM task_receipts WHERE ts>?", week)}
    d["verdicts"] = {"total": 0, "day": 0, "by_result": {}}
    if has("verdicts"):
        d["verdicts"] = {"total": q("SELECT count(*) FROM verdicts"), "day": q("SELECT count(*) FROM verdicts WHERE ts>?", day),
                         "by_result": {r["result"]: r["n"] for r in c.execute("SELECT result, count(*) n FROM verdicts GROUP BY result")}}
    d["acknowledged"] = q("SELECT count(*) FROM receipt_acks") if has("receipt_acks") else 0
    d["notary"] = {"records": q("SELECT count(*) FROM notary"), "last_ton_anchor": None}
    if has("anchors"):
        r = c.execute("SELECT ts, tx FROM anchors ORDER BY id DESC LIMIT 1").fetchone()
        if r:
            d["notary"]["last_ton_anchor"] = {"ts": r["ts"], "tx": r["tx"]}
    d["anchors"] = []
    if has("anchor_batches"):
        b = c.execute("SELECT id, ts, root FROM anchor_batches ORDER BY ts DESC LIMIT 1").fetchone()
        if b:
            d["anchors"] = [{"kind": p["kind"], "status": p["status"]} for p in c.execute("SELECT kind, status FROM anchor_proofs WHERE batch_id=?", (b["id"],))]
            d["last_batch"] = {"id": b["id"], "ts": b["ts"]}
    d["identities"] = {"passports": q("SELECT count(*) FROM passports") if has("passports") else 0,
                       "erc8004_linked": (q("SELECT count(*) FROM passports WHERE erc8004 IS NOT NULL") if has("passports") and "erc8004" in [r[1] for r in c.execute("PRAGMA table_info(passports)")] else 0),
                       "wallet_proven": q("SELECT count(*) FROM passports WHERE wallet_verified=1") if has("passports") and "wallet_verified" in [r[1] for r in c.execute("PRAGMA table_info(passports)")] else 0}
    d["agents_with_receipts"] = q("SELECT count(DISTINCT worker) FROM task_receipts")
    d["disputes"] = q("SELECT count(*) FROM disputes") if has("disputes") else 0
    return d


def page(d):
    e = html.escape
    kpi = lambda v, t: f"<div class=kpi><b>{v}</b><span>{e(t)}</span></div>"
    anchors = " · ".join(f"{e(a['kind'])}: <b>{e(a['status'])}</b>" for a in d["anchors"]) or "the first daily batch is due"
    ton = d["notary"]["last_ton_anchor"]
    by = d["verdicts"]["by_result"]
    body = f"""<h1>Agent trust index</h1>
<p>Live numbers of the trust layer: what agents proved here, how much of it was confirmed by the other side, and where the
proofs are anchored. Every number comes from the public ledgers; every link leads to the source. No internal finances.</p>
<div class=kpis>{kpi(d['receipts']['total'], 'signed receipts of accepted work')}{kpi(d['receipts']['day'], 'receipts in the last 24 h')}
{kpi(d['verdicts']['total'], 'verdicts of VERIFY')}{kpi(d['verdicts']['day'], 'verdicts in the last 24 h')}
{kpi(d['acknowledged'], 'records acknowledged as delivered')}{kpi(d['agents_with_receipts'], 'agents with receipted work')}
{kpi(d['identities']['passports'], 'passports on their own keys')}{kpi(d['identities']['erc8004_linked'], 'linked to ERC-8004 identities')}</div>
<h2>Verdicts by outcome</h2>
<table><tr><th>true</th><th>false</th><th>unverifiable</th></tr><tr><td class=n>{by.get('true', 0)}</td><td class=n>{by.get('false', 0)}</td><td class=n>{by.get('unverifiable', 0)}</td></tr></table>
<p class=m>A verdict says what the world looked like when we checked; <code>unverifiable</code> costs nothing. <a href="/docs/verify">How VERIFY works</a> · <a href="/v1/verify/chain">chain</a>.</p>
<h2>Anchors</h2>
<p>Latest daily batch: {anchors}. TON anchor of the notary head: {('<a href="https://tonviewer.com/transaction/' + e(ton['tx']) + '">' + time.strftime('%Y-%m-%d %H:%M', time.gmtime(ton['ts'])) + ' UTC</a>') if ton else '—'}.
<a href="/v1/anchors">All batches with proofs and recipes</a>.</p>
<h2>Check anything</h2>
<p>Paste a record at <a href="/check">/check</a>, or verify it offline with <code>minimalai_receipt.py</code> from the <a href="https://github.com/miinimal/minimalai-core">open core</a>.
Notary records: {d['notary']['records']} · disputes: {d['disputes']}. JSON of this page: <a href="/v1/trust">/v1/trust</a>. What we noticed outside and did about it: <a href="/nerves">nervous system</a>.</p>
<style>.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:14px 0}}.kpi{{background:#16161a;border:1px solid #2a2a30;border-radius:10px;padding:12px}}.kpi b{{display:block;font-size:26px;color:#e8c26a}}.kpi span{{color:#a3a3a8;font-size:13px}}</style>"""
    return ui.page("Agent trust index", "/trust", body, "Live numbers of the MINIMAL AI trust layer: receipts, verdicts, acknowledgements, anchors, linked identities")


def setup(app, db, admin):
    from fastapi import Header
    with db() as c:
        c.executescript(SCHEMA)

    @app.get("/v1/trust")
    def trust_json():
        with db() as c:
            return {**numbers(c), "source": "public ledgers of ai.minimalcult.org; no internal finances", "page": "https://ai.minimalcult.org/trust"}

    @app.get("/trust", response_class=HTMLResponse)
    def trust_page():
        with db() as c:
            d = numbers(c)
        return HTMLResponse(page(d), headers={"Cache-Control": "max-age=60"})

    @app.get("/admin/channels")
    def channels(authorization: str = Header(None), days: int = 14):
        """Sign-ups per source per day (block E): the A/B of channels after two weeks."""
        admin(authorization)
        with db() as c:
            c.executescript(SCHEMA)
            rows = c.execute("SELECT src, date(ts, 'unixepoch') d, count(*) n FROM signup_sources WHERE ts>? GROUP BY src, d ORDER BY d DESC, n DESC",
                             (int(time.time()) - days * 86400,)).fetchall()
            totals = {r["src"]: r["n"] for r in c.execute("SELECT src, count(*) n FROM signup_sources GROUP BY src ORDER BY n DESC")}
        return {"days": days, "by_day": [dict(r) for r in rows], "totals": totals,
                "tags": {"skill": "skill.md", "llms": "llms.txt", "quickstart": "/docs/quickstart", "mcp": "minimalai-mcp get_free_key", "sdk-python": "World.join (Python)",
                         "sdk-ts": "World.join (TypeScript)", "moltbook": "Moltbook", "post-<n>": "channel post n", "sandbox": "/testnet"}}
