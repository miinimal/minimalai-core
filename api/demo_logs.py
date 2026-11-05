"""DEMO: one private page per log we offer to anchor — /record/logs/{project}. Closed to search engines (noindex, nofollow,
X-Robots-Tag), absent from menus, sitemaps and llms.txt; the link is given only in the letter to that log's operator.
Each page shows what MINIMALCULT recorded about that log in the last 7 days — every head it read or cosigned, its tree size
and root, whether it is sealed and anchored — with the proof of each and the offline command that checks it.
Self-contained markup in the new design (white, monochrome, gold only for the seal); it does not use the old site shell.
Pages exist only for recipients HQ approved (docs/hq/2026-11-04_answer_read_mode.md): mcp-transparency-log, HISTOR,
MCP Census. AxioRank (not read without written consent) and Plumbline (never named publicly) have none.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: Apache-2.0 (open core).
"""
import html
import json
import time

PROJECTS = {
    "mcp-transparency-log": {"name": "mcp-transparency-log", "objects": ["log:github.com/yassinht/mcp-transparency-log"],
                             "what": "the signed daily head (mcp-observatory/v1, Ed25519) read from the repository"},
    "histor": {"name": "HISTOR", "objects": ["log:histor.modelmarket.dev", "log:histor.modelmarket.dev/log"],
               "what": "the C2SP checkpoint, with RFC 9162 consistency checked against the previous head through HISTOR's proof API"},
    "mcp-census": {"name": "MCP Census", "objects": ["log:api.mcpcensus.com"],
                   "what": "our own SHA-256 of each page of the change feed and its newest event id (your data is not republished)"},
}
WINDOW_S = 7 * 86400
CONS = {"verified": "consistent with the previous head (proof checked)", "first_cosignature": "first head cosigned",
        "same_head": "same head as before", "new_origin": "new log origin", "not_available": "first head read"}
# how to get the open verifier today; block ORG replaces this with the minimalcult package once it is published on PyPI
CLI_INSTALL = ("git clone --depth 1 https://github.com/miinimal/minimalai-core\ncd minimalai-core/sdk/python\npip install 'cryptography>=50'")
CSS = """<style>
:root{--ink:#111417;--muted:#5b6168;--line:#e3e5e8;--gold:#8a6a1f;--ok:#1d6b3a;--wait:#8a4b0f;--bg:#fff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 48px}h1{font-size:24px;line-height:1.25;margin:8px 0 4px}p{margin:8px 0}
a{color:var(--ink);text-decoration:underline;text-underline-offset:2px}.muted{color:var(--muted);font-size:14px}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.brand{font-weight:700;letter-spacing:.08em;font-size:13px}.seal{color:var(--gold);font-weight:600}
.ok{color:var(--ok)}.wait{color:var(--wait)}
ul.rows{list-style:none;padding:0;margin:16px 0;border-top:1px solid var(--line)}
ul.rows li{padding:12px 0;border-bottom:1px solid var(--line);display:grid;grid-template-columns:1fr;gap:4px}
@media(min-width:720px){ul.rows li{grid-template-columns:170px 120px 1fr 150px;align-items:center;gap:12px}}
.hash{overflow-wrap:anywhere}.hash .muted{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;font-size:13px}button.copy{border:1px solid var(--line);background:#fff;border-radius:4px;padding:0 6px;font-size:12px;cursor:pointer;margin-left:4px}
pre{background:#f6f7f8;border:1px solid var(--line);padding:12px;overflow-x:auto;font-size:13px;border-radius:4px}
</style>"""


def mid(h, keep=8):
    h = str(h or "")
    return h if len(h) <= 2 * keep + 1 else h[:keep] + "…" + h[-keep:]


def rows_for(c, project, wc, now):
    import attest
    objs = PROJECTS[project]["objects"]
    q = "SELECT * FROM attestations WHERE writer='minimalcult' AND w_object IN (%s) AND created>? ORDER BY created DESC LIMIT 500" % ",".join("?" * len(objs))
    out = []
    for r in c.execute(q, (*objs, now - WINDOW_S)).fetchall():
        env = json.loads(r["envelope"])
        status, batch = attest.sealed_state(r, wc)
        anchors = {}
        if batch and wc is not None:
            import witness as W
            anchors = {k: v.get("status") for k, v in W.anchors_of(wc, batch).items()}
        ver = env.get("verified") or {}
        out.append({"id": r["id"], "at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(r["created"])), "size": r["w_version"],
                    "root": ver.get("root_hash") or env.get("payload_sha256"), "status": status, "anchors": anchors,
                    "cosigned": bool(env.get("witness_cosignature")), "consistency": (env.get("consistency") or {}).get("status")})
    return out


def render(project, rows, now):
    p = PROJECTS[project]
    e = html.escape
    items = []
    for x in rows:
        sealed = x["status"] == "sealed"
        an = ", ".join(f"{k} {v}" for k, v in sorted(x["anchors"].items())) or "anchors follow the hourly seal"
        items.append(
            f"<li><span class=mono>{e(x['at'])}</span><span class=mono>size {e(str(x['size']))}</span>"
            f"<span class='mono hash' title='{e(str(x['root']))}'>{e(mid(x['root']))}<button class=copy data-v='{e(str(x['root']))}' aria-label='Copy hash'>copy</button>"
            f"<br><span class=muted>{'cosigned by our witness; ' if x['cosigned'] else ''}{e(CONS.get(x['consistency'], '')) + '; ' if CONS.get(x['consistency']) else ''}{e(an)}</span></span>"
            f"<span>{'<span class=seal>sealed</span>' if sealed else '<span class=wait>recorded, sealing within the hour</span>'} &middot; "
            f"<a href='/v1/attestations/{e(x['id'])}/proof'>proof</a></span></li>")
    first = rows[0]["id"] if rows else "att_..."
    body = (f"<main><div class=brand>MINIMALCULT</div><h1>{e(p['name'])}: independent record</h1>"
            f"<p>What MINIMALCULT recorded about {e(p['name'])} in the last 7 days: {e(p['what'])}. Each entry is sealed every hour with a "
            "hybrid signature (Ed25519 + ML-DSA-65) and anchored in Bitcoin (OpenTimestamps), an RFC 3161 time-stamping authority and "
            "Sigstore Rekor, and daily in TON and EAS on Base. Nothing here is a judgement of your log.</p>"
            f"<p class=muted>{len(rows)} entries &middot; page generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(now))}</p>"
            + (f"<ul class=rows>{''.join(items)}</ul>" if rows else "<p class=muted>No entries yet: the first read is recorded at the next hourly run.</p>")
            + "<h2 style='font-size:18px;margin-top:24px'>Check any entry yourself</h2>"
            f"<pre>curl -s https://ai.minimalcult.org/v1/attestations/{e(first)}/proof -o proof.json\n"
            f"{e(CLI_INSTALL)}\npython -m minimalcult verify proof.json --key &lt;receipt_key_ed25519&gt; --pq-key &lt;receipt_key_mldsa65&gt;</pre>"
            "<p class=muted>Keys: https://ai.minimalcult.org/.well-known/minimalai.json. Specification: /docs/attestations. "
            "The check needs no access to our servers beyond downloading the proof once.</p></main>"
            "<script>document.querySelectorAll('button.copy').forEach(b=>b.onclick=()=>{try{navigator.clipboard.writeText(b.dataset.v);b.textContent='copied'}catch(e){}})</script>")
    return ("<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<meta name=robots content='noindex,nofollow'><title>{e(p['name'])} — MINIMALCULT record</title>{CSS}</head><body>{body}</body></html>")


def setup(app, db):
    from fastapi.responses import HTMLResponse
    import witness as W

    @app.get("/record/logs/{project}", response_class=HTMLResponse, include_in_schema=False)
    def demo(project: str):
        hdr = {"X-Robots-Tag": "noindex, nofollow", "Cache-Control": "no-store"}
        if project not in PROJECTS:
            return HTMLResponse("<!doctype html><title>Not found</title><p>Not found.</p>", status_code=404, headers=hdr)
        now = int(time.time())
        with db() as c:
            import attest
            attest.migrate(c)
            rows = rows_for(c, project, W.open_ro(), now)
        return HTMLResponse(render(project, rows, now), headers=hdr)
