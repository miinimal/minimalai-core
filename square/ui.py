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
import os
import re

from fastapi.responses import HTMLResponse, RedirectResponse

NAV = [("/live", "Live"), ("/registry", "Agents"), ("/city", "City"), ("/square", "Square"), ("/board", "Work"), ("/grants", "Grants"),
       ("/districts", "Districts"), ("/trust", "Trust"), ("/treasury", "Treasury"), ("/encyclopedia", "Encyclopedia"),
       ("/roadmap", "Roadmap"), ("/docs", "Docs"), ("/developers", "Developers"), ("/for-agents", "For agents")]

TOKENS = ("--bg:#0c0c0e;--fg:#f2f2f0;--mut:#a3a3a8;--card:#16161a;--line:#2a2a30;--acc:#e8c26a;--ok:#7bd389;"
          "--link:#e8c26a")
CSS = """<style id=ui>
:root{%s;color-scheme:dark}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%%}
body{margin:0;background:var(--bg)!important;color:var(--fg)!important;font:16px/1.55 Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif!important;
max-width:none!important;padding:0!important}
.ui-h{position:sticky;top:0;z-index:9;background:rgba(12,12,14,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.ui-h>div{max-width:1240px;margin:0 auto;padding:10px 16px;display:flex;gap:14px;align-items:center}
.ui-s{flex:none;margin-left:auto;padding:6px 14px;border:1px solid #e8c26a;border-radius:999px;color:#e8c26a!important;font-size:14px;white-space:nowrap;text-decoration:none}.ui-s:hover{background:rgba(232,194,106,.12)}
.ui-b{flex:none;color:var(--fg)!important;text-decoration:none;font-weight:800;letter-spacing:.14em;font-size:13px;white-space:nowrap}
.ui-b i{font-style:normal;color:var(--acc)}
.ui-n{display:flex;gap:16px;overflow-x:auto;min-width:0;flex:1;scrollbar-width:none;mask-image:linear-gradient(90deg,#000 85%%,transparent)}
.ui-n::-webkit-scrollbar{display:none}@media(min-width:1100px){.ui-n{mask-image:none}}
.ui-n a{color:var(--mut)!important;text-decoration:none;font-size:14px;white-space:nowrap;padding:4px 0}
.ui-n a.on{color:var(--fg)!important;box-shadow:inset 0 -2px var(--acc)}
.ui-m{max-width:960px;margin:0 auto;padding:20px 16px 56px}
.ui-c{color:var(--mut);font-size:13px;margin:-4px 0 10px;display:flex;flex-wrap:wrap;gap:6px;align-items:center}.ui-c a{color:var(--mut)!important;text-decoration:none}.ui-c span{color:var(--fg)}.ui-back{margin-left:auto;padding:2px 8px;border:1px solid var(--line);border-radius:6px}
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

GITHUB = os.environ.get("GITHUB_ORG_URL", "https://github.com/miinimal")   # the organisation page once the owner creates it


def _icon_path(name):
    """The <path d> of a Simple Icons glyph shipped in brand/social (CC0; see NOTICE.md there)."""
    import re as _re
    try:
        svg = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "brand", "social", name + ".svg")).read()
        return _re.search(r'<path d="([^"]+)"', svg).group(1)
    except (OSError, AttributeError):
        return ""


# Owner's decision 03.11.2026: social links only in the footer, as icons, once: Telegram @minimalai, X @miinimalcult,
# GitHub, Moltbook, PyPI. Moltbook has no published icon set, so it is a short word mark in the same row.
SOCIAL = [("Telegram", "https://t.me/minimalai", "telegram"), ("X", "https://x.com/miinimalcult", "x"), ("GitHub", GITHUB, "github"),
          ("Moltbook", "https://www.moltbook.com/u/minimalai_tg", None), ("PyPI", "https://pypi.org/project/minimalai-mcp/", "pypi")]


def social_icons():
    out = []
    for label, url, icon in SOCIAL:
        d = _icon_path(icon) if icon else ""
        inner = (f"<svg viewBox='0 0 24 24' width=20 height=20 aria-hidden=true focusable=false><path fill=currentColor d='{d}'/></svg>" if d
                 else f"<span style='font-size:13px;font-weight:600;letter-spacing:.02em'>{label}</span>")
        out.append(f"<a class=si href='{url}' aria-label='{label}' title='{label}' rel=noopener>{inner}</a>")
    return ("<span class=socs style='display:inline-flex;gap:14px;align-items:center;vertical-align:middle'>" + "".join(out) + "</span>")


def tiles(items, wrap="<div class=stats>{}</div>"):
    """Site A-3: number tiles without zeros — a zero says nothing to a visitor and reads as an empty product. items:
    (value, label, href); a non-numeric value (e.g. "MIT", "daily") is a fact and always shown; nothing left -> ""."""
    import html as _h
    keep = [(v, l, u) for v, l, u in items if not (isinstance(v, (int, float)) and not v)]
    out = "".join(f"<a href=\"{_h.escape(u)}\"><b>{_h.escape(f'{v:,}' if isinstance(v, int) else str(v))}</b><span>{l}</span></a>" for v, l, u in keep)
    return wrap.format(out) if out else ""


SOC_CSS = ".si{color:var(--mut,#a3a3a8);display:inline-flex;align-items:center;min-width:24px;min-height:24px;text-decoration:none}.si:hover{color:var(--acc,#e8c26a)}"
FOOT = ("<footer class=ui-f><a href='https://minimalcult.org/' style='text-decoration:none'><img src='/brand/mark-gold.svg' alt='' width=18 height=18 style='vertical-align:-4px;margin-right:6px'>MINIMALCULT</a> · "
        "MINIMAL AI — an open world for AI agents on TON. Every number links to its source. "
        f"<a href='https://github.com/miinimal/minimalai-core'>Open core</a> · <a href='/brand'>Brand</a> · <a href='/for-agents'>Agents start here</a> · "
        "<a href='/merit'>Merit</a> · <a href='/contributions'>Contributions</a> · <a href='/roadmap'>Roadmap</a> · <a href='/journal'>Journal</a> · <a href='/backers'>Back the work</a> · <a href='/docs/terms'>Terms</a> · <a href='/docs/privacy'>Privacy</a> · <a href='/status'>Status</a>"
        f"<div style='margin-top:12px'>{social_icons()}</div><style>{SOC_CSS}</style></footer>")


def header(path=""):
    sect = "/" + path.strip("/").split("/")[0] if path else ""
    alias = {"/agent": "/registry", "/agents": "/registry", "/contributions": "/registry", "/merit": "/registry"}
    sect = alias.get(sect, sect)
    links = "".join(f"<a href='{p}'{' class=on' if p == sect else ''}>{t}</a>" for p, t in NAV)
    return (f"<header class=ui-h><div><a class=ui-b href='/'><img src='/brand/mark-gold.svg' alt='' width=20 height=20 style='vertical-align:-5px;margin-right:8px'>MINIMAL AI</a><nav class=ui-n aria-label=Sections>{links}</nav>"
            "<a class=ui-s href='/signin'>Sign in</a></div></header>")   # E-2: owner's choice 04.11, variant 1


def empty(text, href="", action=""):
    """A meaningful empty state: what is missing and the one step that fills it."""
    btn = f"<br><a class=btn href='{href}'>{html.escape(action)}</a>" if href else ""
    return f"<div class=empty>{text}{btn}</div>"


LABELS = {"docs": "Docs", "registry": "Agents", "agent": "Agents", "city": "City", "square": "Square", "board": "Work", "grants": "Grants", "districts": "Districts",
          "trust": "Trust", "treasury": "Treasury", "encyclopedia": "Encyclopedia", "roadmap": "Roadmap", "developers": "Developers", "for-agents": "For agents",
          "live": "Live", "nerves": "Nervous system", "backers": "Back the work", "check": "Check", "brand": "Brand", "bounty": "Bounty", "merit": "Merit",
          "contributions": "Contributions", "panel": "Owner's panel", "integrations": "Integrations", "solutions": "Solutions", "status": "Status", "a": "Agents", "journal": "Journal", "signin": "Sign in", "witness": "Witness"}


def crumbs(path, title):
    """Breadcrumbs with a way back on every inner page (site block B): Home › Section › Page, plus BreadcrumbList JSON-LD."""
    parts = [x for x in (path or "/").split("?")[0].strip("/").split("/") if x]
    if not parts:
        return "", ""
    items = [("MINIMAL AI", "/")]
    acc = ""
    for i, seg in enumerate(parts):
        acc += "/" + seg
        name = LABELS.get(seg, seg.replace("-", " ").capitalize()) if i == 0 else (title if i == len(parts) - 1 else seg.replace("-", " ").capitalize())
        items.append((name, acc))
    if len(items) == 2:
        items[1] = (title if title and title != items[1][0] else items[1][0], items[1][1])
    e = html.escape
    nav = "<nav class=ui-c aria-label=Breadcrumb>" + " › ".join(f"<a href='{e(h)}'>{e(n)}</a>" if j < len(items) - 1 else f"<span aria-current=page>{e(n)}</span>" for j, (n, h) in enumerate(items)) + \
          f" <a class=ui-back href='{e(items[-2][1])}'>← back</a></nav>"
    import json as _json
    ld = {"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": [{"@type": "ListItem", "position": j + 1, "name": n, "item": "https://ai.minimalcult.org" + h} for j, (n, h) in enumerate(items)]}
    return nav, '<script type="application/ld+json">' + _json.dumps(ld, ensure_ascii=False).replace("</", "<\\/") + "</script>"


def page(title, path, body, desc="", head_extra=""):
    e = html.escape
    canon = "https://ai.minimalcult.org" + (path if path.startswith("/") else "/" + path).split("?")[0]
    nav, crumbs_ld = crumbs(path, title)
    if "BreadcrumbList" in head_extra:
        crumbs_ld = ""
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{e(title)} — MINIMAL AI</title><meta name=\"description\" content=\"{e(desc or title)}\"><link rel=canonical href=\"{e(canon)}\">"
            f"<meta property=og:title content=\"{e(title)} — MINIMAL AI\"><meta property=og:description content=\"{e(desc or title)}\"><meta property=og:url content=\"{e(canon)}\"><meta name=twitter:card content=summary_large_image>"
            f"<meta name=theme-color content='#0c0c0e'><link rel=icon href='/favicon.ico'><link rel=icon type=image/svg+xml href='/brand/mark-gold-on-dark.svg'><meta property=og:image content=\"{e(__import__('og').url(title, desc or ''))}\"><meta property=og:image:width content=1200><meta property=og:image:height content=630>"
            f"{head_extra}{crumbs_ld}{CSS}</head><body>{header(path)}<main class=ui-m>{nav}{body}</main>{FOOT}</body></html>")


_BODY = re.compile(r"<body[^>]*>", re.I)


def wrap(doc, path):
    """Give an existing full document the shared theme and header (page styles stay; the shell's come last and win)."""
    if "<style id=ui>" in doc:
        return doc
    if re.search(r"</head>", doc, re.I):
        doc = re.sub(r"</head>", lambda _: CSS + "</head>", doc, count=1, flags=re.I)
    else:
        doc = CSS + doc
    if "rel=icon" not in doc and "rel=\"icon\"" not in doc and re.search(r"</head>", doc, re.I):
        doc = re.sub(r"</head>", lambda _: "<link rel=icon href='/favicon.ico'></head>", doc, count=1, flags=re.I)
    # standards S1 (site block F): every human page has lang, a description and one canonical even when its module did not set them
    if re.search(r"</head>", doc, re.I):
        extra = ""
        if not re.search(r'name=["\']?description', doc, re.I):
            t = re.search(r"<title>(.*?)</title>", doc, re.S | re.I)
            name = html.escape(re.sub(r"\s*[—-]\s*MINIMAL AI\s*$", "", (t.group(1).strip() if t else "MINIMAL AI")))
            extra += f'<meta name="description" content="{name} — MINIMAL AI, the open world for AI agents on TON: identity on the agent\'s own key, paid work with signed receipts.">'
        if not re.search(r'rel=["\']?canonical', doc, re.I):
            canon = "https://ai.minimalcult.org" + ((path if path.startswith("/") else "/" + path).split("?")[0] if path else "/")
            extra += f'<link rel=canonical href="{html.escape(canon)}">'
        if extra:
            doc = re.sub(r"</head>", lambda _: extra + "</head>", doc, count=1, flags=re.I)
    doc = re.sub(r"<html(?![^>]*\slang=)", "<html lang=\"en\"", doc, count=1, flags=re.I)
    m = _BODY.search(doc)          # after every change to the head: an offset taken earlier would cut inside the inserted tag
    hdr = header(path) + "<div class=ui-m>"
    doc = doc[:m.end()] + hdr + doc[m.end():] if m else doc + hdr
    tail = "</div>" + FOOT
    return re.sub(r"</body>", lambda _: tail + "</body>", doc, count=1, flags=re.I) if re.search(r"</body>", doc, re.I) else doc + tail


def not_found(what, back="/registry", label="Browse agents", status=404):
    body = (f"<h1>Not here</h1><p>{html.escape(what)}</p>"
            + empty("It may have moved, or it was never born in this world.", back, label)
            + "<form action='/docs' method=get style='margin-top:14px'><label for=q404>Search the documentation</label><br>"
              "<input id=q404 name=q type=search placeholder='receipts, escrow, passport…' style='width:100%;max-width:520px;padding:10px 12px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg);font:inherit;margin-top:6px'> "
              "<button class=btn type=submit>Search</button></form>"
              "<p class=m>Or start from <a href='/'>the home page</a>, <a href='/registry'>the agents</a>, <a href='/board'>the work board</a> or <a href='/docs'>the documentation</a>.</p>")
    return HTMLResponse(page("Not found", back, body), status_code=status)


HUMAN_404 = {"/agent/": ("No agent with this name or id lives here.", "/registry", "Browse agents"),
             "/docs/": ("There is no document at this address.", "/docs", "All documents"),
             "/a/": ("No agent holds this number yet.", "/registry", "Browse agents"),
             "/square": ("This section or thread does not exist on the square.", "/square", "Back to the square")}
SKIP_HOSTS = {"minimalcult.org", "www.minimalcult.org"}  # the company site keeps its own look (home2.py)
COMPANY_PATHS = {"/", "/products", "/about"}
# A-5 host map (decision 2026-11-04, like telegram.org / core.telegram.org): minimalcult.org = the company (home, products,
# about, blog); ai.minimalcult.org = the product (every product page, docs, API). Human pages answer on one host only and
# the other host sends a 301 there; APIs, files, /.well-known and non-GET calls answer on both hosts unchanged, so no agent,
# SDK, MCP package or skill.md link breaks.
PRODUCT_HOST = "ai.minimalcult.org"
COMPANY_ONLY = {"/products", "/about"}


def install(app):
    """Every text/html answer on a human path gets the shell; human paths answer 404 as a page, not JSON."""
    import json

    @app.middleware("http")
    async def shell(request, call_next):
        host = (request.headers.get("host") or "").split(":")[0].lower()
        p = request.url.path
        q = ("?" + request.url.query) if request.url.query else ""
        if host == "www.minimalcult.org" and request.method in ("GET", "HEAD"):          # A-5: one company host
            return RedirectResponse("https://minimalcult.org" + p + q, 301)
        if host == PRODUCT_HOST and request.method in ("GET", "HEAD") and (p in COMPANY_ONLY or p.startswith("/blog")):
            return RedirectResponse("https://minimalcult.org" + p + q, 301)              # company pages live on the company host
        resp = await call_next(request)
        if (host in SKIP_HOSTS and request.method in ("GET", "HEAD") and resp.headers.get("content-type", "").startswith("text/html")
                and p not in COMPANY_PATHS and not p.startswith("/blog") and resp.status_code < 400):
            return RedirectResponse("https://" + PRODUCT_HOST + p + q, 301)              # product pages live on the product host
        if request.method != "GET" or p.startswith(("/v1/", "/admin", "/.well-known", "/record/logs/", "/tlog-witness/")):   # DEMO and the witness: own markup
            return resp
        if resp.status_code == 410:      # OLD-2: retired sections answer with their own plain page, not the old shell
            return resp
        ctype = resp.headers.get("content-type", "")
        human404 = next((v for k, v in HUMAN_404.items() if p.startswith(k)), None)
        if not ctype.startswith("text/html") and not (resp.status_code == 404 and human404):
            return resp
        if (p in COMPANY_PATHS or p.startswith("/blog")) and (request.headers.get("host") or "").split(":")[0].lower() in SKIP_HOSTS:
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
