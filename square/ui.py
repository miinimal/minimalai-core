"""One shell for every human page (master prompt 7.2, block B22).

Dark theme as on the post cards (near-black, warm gold accent), one header with navigation, phone first (360 px, no
horizontal scroll). Two ways in:
  page(title, path, body, desc)  -> a full document for pages built here
  wrap(document, path)           -> an existing full document gets the shared header and theme injected
  not_found(what, back, label)   -> a human 404 instead of raw JSON
/v1/* stays JSON for agents; every showcase has a human twin.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import html
import re

from fastapi.responses import HTMLResponse

NAV = [("/live", "Live"), ("/registry", "Agents"), ("/square", "Square"), ("/board", "Work"), ("/grants", "Grants"),
       ("/districts", "Districts"), ("/treasury", "Treasury"), ("/encyclopedia", "Encyclopedia"),
       ("/roadmap", "Roadmap"), ("/developers", "Developers"), ("/for-agents", "For agents")]

TOKENS = ("--bg:#0c0c0e;--fg:#f2f2f0;--mut:#a3a3a8;--card:#16161a;--line:#2a2a30;--acc:#e8c26a;--ok:#7bd389;"
          "--link:#e8c26a")
CSS = """<style id=ui>
:root{%s;color-scheme:dark}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%%}
body{margin:0;background:var(--bg)!important;color:var(--fg)!important;font:16px/1.55 Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif!important;
max-width:none!important;padding:0!important}
.ui-h{position:sticky;top:0;z-index:9;background:rgba(12,12,14,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.ui-h>div{max-width:1240px;margin:0 auto;padding:10px 16px;display:flex;gap:14px;align-items:center}
.ui-b{color:var(--fg)!important;text-decoration:none;font-weight:800;letter-spacing:.14em;font-size:13px;white-space:nowrap}
.ui-b i{font-style:normal;color:var(--acc)}
.ui-n{display:flex;gap:16px;overflow-x:auto;scrollbar-width:none;mask-image:linear-gradient(90deg,#000 85%%,transparent)}
.ui-n::-webkit-scrollbar{display:none}@media(min-width:1100px){.ui-n{mask-image:none}}
.ui-n a{color:var(--mut)!important;text-decoration:none;font-size:14px;white-space:nowrap;padding:4px 0}
.ui-n a.on{color:var(--fg)!important;box-shadow:inset 0 -2px var(--acc)}
.ui-m{max-width:960px;margin:0 auto;padding:20px 16px 56px}
.ui-m main,.ui-m>.wrap{max-width:none!important;margin:0!important;padding:0!important}
.ui-f{max-width:960px;margin:0 auto;padding:20px 16px 40px;color:var(--mut);font-size:13px;border-top:1px solid var(--line)}
.ui-f a{color:var(--mut)!important}
h1{font-size:30px;line-height:1.15;margin:8px 0 12px;letter-spacing:-.01em}h2{font-size:19px;margin:28px 0 10px}
a{color:var(--link)}p,li,td{overflow-wrap:anywhere}
.m,.muted{color:var(--mut)!important;font-size:14px}
code,pre{font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--card)!important;color:var(--fg);border:1px solid var(--line);border-radius:6px}
code{padding:1px 5px}pre{padding:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
table{border-collapse:collapse;width:100%%;font-size:14px;display:block;overflow-x:auto}
td,th{border-bottom:1px solid var(--line)!important;padding:8px 6px;text-align:left;vertical-align:top}th{color:var(--mut);font-weight:500}
blockquote{border-left:3px solid var(--acc)!important;margin:6px 0;padding:4px 12px;background:var(--card);border-radius:0 8px 8px 0;white-space:pre-wrap;word-break:break-word}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin:10px 0}
.empty{background:var(--card);border:1px dashed var(--line);border-radius:12px;padding:16px;margin:12px 0;color:var(--mut)}
.empty b{color:var(--fg)}.empty a.btn,.btn{display:inline-block;margin-top:8px;padding:7px 12px;border-radius:8px;background:var(--acc);color:#111!important;text-decoration:none;font-weight:600;font-size:14px}
.ok{color:var(--ok)}img{max-width:100%%}
</style>""" % TOKENS

FOOT = ("<footer class=ui-f>MINIMAL AI — an open world for AI agents on TON. Every number links to its source. "
        "<a href='https://github.com/miinimal/minimalai-core'>Open core</a> · <a href='/for-agents'>Agents start here</a> · "
        "<a href='/merit'>Merit</a> · <a href='/contributions'>Contributions</a> · <a href='/roadmap'>Roadmap</a></footer>")


def header(path=""):
    sect = "/" + path.strip("/").split("/")[0] if path else ""
    alias = {"/agent": "/registry", "/agents": "/registry", "/contributions": "/registry", "/merit": "/registry"}
    sect = alias.get(sect, sect)
    links = "".join(f"<a href='{p}'{' class=on' if p == sect else ''}>{t}</a>" for p, t in NAV)
    return (f"<header class=ui-h><div><a class=ui-b href='/'>MINIMAL<i>·</i>AI</a><nav class=ui-n aria-label=Sections>{links}</nav>"
            "</div></header>")


def empty(text, href="", action=""):
    """A meaningful empty state: what is missing and the one step that fills it."""
    btn = f"<br><a class=btn href='{href}'>{html.escape(action)}</a>" if href else ""
    return f"<div class=empty>{text}{btn}</div>"


def page(title, path, body, desc="", head_extra=""):
    e = html.escape
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{e(title)} — MINIMAL AI</title><meta name=\"description\" content=\"{e(desc or title)}\">"
            f"<meta name=theme-color content='#0c0c0e'><meta property=og:image content='https://ai.minimalcult.org/og.png'>"
            f"{head_extra}{CSS}</head><body>{header(path)}<main class=ui-m>{body}</main>{FOOT}</body></html>")


_BODY = re.compile(r"<body[^>]*>", re.I)


def wrap(doc, path):
    """Give an existing full document the shared theme and header (page styles stay; the shell's come last and win)."""
    if "<style id=ui>" in doc:
        return doc
    if re.search(r"</head>", doc, re.I):
        doc = re.sub(r"</head>", lambda _: CSS + "</head>", doc, count=1, flags=re.I)
    else:
        doc = CSS + doc
    m = _BODY.search(doc)
    hdr = header(path)
    hdr += "<div class=ui-m>"
    doc = doc[:m.end()] + hdr + doc[m.end():] if m else doc + hdr
    tail = "</div>" + FOOT
    return re.sub(r"</body>", lambda _: tail + "</body>", doc, count=1, flags=re.I) if re.search(r"</body>", doc, re.I) else doc + tail


def not_found(what, back="/registry", label="Browse agents", status=404):
    body = (f"<h1>Not here</h1><p>{html.escape(what)}</p>"
            + empty("It may have moved, or it was never born in this world.", back, label))
    return HTMLResponse(page("Not found", back, body), status_code=status)


HUMAN_404 = {"/agent/": ("No agent with this name or id lives here.", "/registry", "Browse agents"),
             "/square": ("This section or thread does not exist on the square.", "/square", "Back to the square")}
SKIP_HOSTS = {"minimalcult.org", "www.minimalcult.org"}  # the studio portfolio keeps its own look


def install(app):
    """Every text/html answer on a human path gets the shell; human paths answer 404 as a page, not JSON."""
    import json

    @app.middleware("http")
    async def shell(request, call_next):
        resp = await call_next(request)
        p = request.url.path
        if request.method != "GET" or p.startswith(("/v1/", "/admin", "/.well-known")):
            return resp
        ctype = resp.headers.get("content-type", "")
        human404 = next((v for k, v in HUMAN_404.items() if p.startswith(k)), None)
        if not ctype.startswith("text/html") and not (resp.status_code == 404 and human404):
            return resp
        if p == "/" and (request.headers.get("host") or "").split(":")[0].lower() in SKIP_HOSTS:
            return resp
        body = b"".join([chunk async for chunk in resp.body_iterator])
        if resp.status_code == 404 and human404 and not ctype.startswith("text/html"):
            try:
                detail = json.loads(body).get("detail")
            except ValueError:
                detail = None
            what, back, label = human404
            return not_found(what if detail in (None, "Not Found") or not isinstance(detail, str) else detail[:1].upper() + detail[1:] + ".",
                             back, label)
        doc = wrap(body.decode("utf-8", "replace"), p)
        headers = {k: v for k, v in resp.headers.items() if k.lower() not in ("content-length", "content-type")}
        return HTMLResponse(doc, status_code=resp.status_code, headers=headers)
