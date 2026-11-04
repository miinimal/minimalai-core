"""PAY (master prompt E16, founder decision 2026-11-04): one price list in USD; any payment method is converted at the rate of
the moment, plus the method's markup; the rate is locked in the invoice for 15 minutes; every paid record carries the USD
price, the rate and the markup.

Units: USD prices are integer micro-dollars (1 USD = 1 000 000), the same unit as USDC (6 decimals). GRAM amounts are nano.

  GET /v1/prices      the price list, payment methods with their markups, the current GRAM rate and its age, credit packs
  GET /pricing        the same for people

Rate (GRAM in USD): sources in order (CoinGecko, then exchange tickers), cached in the main database. A rate younger than
FRESH_S is used as is; up to MAX_STALE_S old it is used with a safety margin (we charge more, never less); older or missing,
GRAM payments are refused with a next_step to USDC — never a sale at a loss.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: Apache-2.0 (open core).
"""
import json
import math
import os
import time
import urllib.request

USD = 1_000_000                       # micro-dollars per dollar
PRICES = {                            # product -> (micro-USD, what it buys)
    "check": (int(os.environ.get("PRICE_CHECK_USD_MICRO", "10000")), "one check (POST /v1/checks) beyond the free threshold"),
    "statement": (int(os.environ.get("PRICE_STATEMENT_USD_MICRO", "100000")), "one signed statement of a record at a moment"),
    "monitor_30d": (int(os.environ.get("PRICE_MONITOR_USD_MICRO", "1000000")), "one monitor for 30 days beyond the free three"),
}
FREE = {"check": "100 a day per key or address", "monitor_30d": "3 per key or address", "statement": "viewing a past state is free; the signed statement is paid"}
METHODS = {                           # method -> markup in basis points (DECISIONS 2026-11-04)
    "usdc_base": {"markup_bp": 0, "how": "x402 on Base at /base/<product>; 1 USDC = 1 USD"},
    "usd_credit": {"markup_bp": 0, "how": "prepaid USD credit on an API key: GET /base/credits-50 | -500 | -5000 with Authorization (x402 USDC)"},
    "gram": {"markup_bp": int(os.environ.get("MARKUP_GRAM_BP", "300")), "how": "GRAM-402 or a GRAM key balance, at the locked rate"},
}
PACKS = [                             # prepaid USD credit: pay, bonus
    {"pack": "50", "pay_usd_micro": 50 * USD, "credit_usd_micro": 50 * USD},
    {"pack": "500", "pay_usd_micro": 500 * USD, "credit_usd_micro": 525 * USD},
    {"pack": "5000", "pay_usd_micro": 5000 * USD, "credit_usd_micro": 5500 * USD},
]
LOCK_S = int(os.environ.get("PRICE_LOCK_S", "900"))             # the rate in an invoice holds 15 minutes
FRESH_S = int(os.environ.get("RATE_FRESH_S", "900"))
MAX_STALE_S = int(os.environ.get("RATE_MAX_STALE_S", str(6 * 3600)))
STALE_MARGIN = float(os.environ.get("RATE_STALE_MARGIN", "0.05"))  # a stale rate is cut by 5%: GRAM counts as cheaper, we charge more
SOURCES = [
    ("coingecko", "https://api.coingecko.com/api/v3/simple/price?ids=the-open-network&vs_currencies=usd",
     lambda d: d["the-open-network"]["usd"]),
    ("okx", "https://www.okx.com/api/v5/market/ticker?instId=TON-USDT", lambda d: d["data"][0]["last"]),
    ("bybit", "https://api.bybit.com/v5/market/tickers?category=spot&symbol=TONUSDT", lambda d: d["result"]["list"][0]["lastPrice"]),
]
SCHEMA = "CREATE TABLE IF NOT EXISTS fx_rates(ts INTEGER, pair TEXT, rate REAL, source TEXT, PRIMARY KEY(pair, ts));"


class RateUnavailable(RuntimeError):
    pass


def gram_nano(usd_micro, rate, markup_bp):
    """Exact decimal: micro-USD -> nano-GRAM at `rate` USD per GRAM plus the markup, rounded up (never under-charge)."""
    from decimal import ROUND_CEILING, Decimal
    v = Decimal(usd_micro) * (10000 + markup_bp) * 1000 / (Decimal(10000) * Decimal(str(rate)))
    return int(v.to_integral_value(rounding=ROUND_CEILING))


def fetch_rate(get=None):
    """First source that answers with a plausible positive number: (rate, source)."""
    def _get(url):
        rq = urllib.request.Request(url, headers={"User-Agent": "minimalcult-prices/1", "Accept": "application/json"})
        with urllib.request.urlopen(rq, timeout=10) as r:
            return json.loads(r.read())
    get = get or _get
    errs = []
    for name, url, pick in SOURCES:
        try:
            v = float(pick(get(url)))
            if 0.01 < v < 10000:
                return v, name
            errs.append(f"{name}: implausible {v}")
        except Exception as e:  # noqa: BLE001
            errs.append(f"{name}: {type(e).__name__}")
    raise RateUnavailable("; ".join(errs))


def record_rate(c, rate, source="manual", now=None):
    """Store a rate (tests, or an operator override recorded with its source)."""
    c.executescript(SCHEMA)
    c.execute("INSERT OR REPLACE INTO fx_rates(ts, pair, rate, source) VALUES(?,?,?,?)", (now or int(time.time()), "GRAM/USD", float(rate), source))
    c.commit()


def gram_rate(c, now=None, get=None):
    """(usd per GRAM to use, info). Refreshes a cached rate older than FRESH_S; applies the stale margin; refuses beyond MAX_STALE_S."""
    now = now or int(time.time())
    c.executescript(SCHEMA)
    last = c.execute("SELECT ts, rate, source FROM fx_rates WHERE pair='GRAM/USD' ORDER BY ts DESC LIMIT 1").fetchone()
    if not last or now - last[0] >= FRESH_S:
        try:
            v, src = fetch_rate(get)
            c.execute("INSERT OR REPLACE INTO fx_rates(ts, pair, rate, source) VALUES(?,?,?,?)", (now, "GRAM/USD", v, src))
            c.commit()
            last = (now, v, src)
        except RateUnavailable:
            pass
    if not last:
        raise RateUnavailable("no GRAM/USD rate yet")
    age = now - last[0]
    if age > MAX_STALE_S:
        raise RateUnavailable(f"GRAM/USD rate is {age // 3600} h old")
    use = last[1] * (1 - STALE_MARGIN) if age >= FRESH_S else last[1]
    return use, {"usd_per_gram": round(use, 6), "source": last[2], "observed_at": last[0], "age_s": age, "stale_margin": age >= FRESH_S}


def quote(c, product, method="gram", now=None, get=None):
    """Price of `product` in a payment method: {usd_micro, amount, currency, unit, rate, markup_bp, locked_until}."""
    usd_micro = PRICES[product][0]
    now = now or int(time.time())
    if method in ("usdc_base", "usd_credit"):
        return {"product": product, "usd_micro": usd_micro, "amount": usd_micro, "currency": "usdc" if method == "usdc_base" else "usd",
                "unit": "micro", "markup_bp": 0, "method": method}
    rate, info = gram_rate(c, now, get)
    bp = METHODS["gram"]["markup_bp"]
    nano = gram_nano(usd_micro, rate, bp)
    return {"product": product, "usd_micro": usd_micro, "amount": nano, "currency": "gram", "unit": "nano", "markup_bp": bp,
            "rate": info, "locked_until": now + LOCK_S, "method": "gram"}


def price_object(q, via):
    """What a paid record carries: the USD price, what was paid, the rate and the markup."""
    out = {"amount": q["amount"], "currency": q["currency"], "unit": q.get("unit"), "via": via, "usd_micro": q["usd_micro"],
           "markup_bp": q.get("markup_bp", 0)}
    if q.get("rate"):
        out["usd_per_gram"] = q["rate"]["usd_per_gram"]
        out["rate_source"] = q["rate"]["source"]
    return out


def charge_key(c, key_hash, product, now=None, get=None):
    """Charges a key for a product: USD credit first (no conversion), then the GRAM balance at the current rate (starter credit
    as before). Returns the price object; raises fastapi HTTPException(402) when nothing covers it."""
    from fastapi import HTTPException
    import starter
    _ensure_usd(c)
    usd_micro = PRICES[product][0]
    now = now or int(time.time())
    if c.execute("UPDATE keys SET usd_micro=usd_micro-? WHERE key_hash=? AND usd_micro>=?", (usd_micro, key_hash, usd_micro)).rowcount:
        c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now, key_hash, 0, f"usd_credit:{product}:{usd_micro}"))
        return price_object(quote(c, product, "usd_credit", now), "usd_credit")
    try:
        q = quote(c, product, "gram", now, get)
    except RateUnavailable:
        raise HTTPException(402, "the key has no USD credit and GRAM cannot be priced right now (no fresh rate); pay in USDC through x402")
    starter.spend(c, key_hash, q["amount"], product)
    return price_object(q, "key_balance")


async def gram_gate(pay_gate, db, request, body, route, product):
    """GRAM-402 for a USD-priced product: the invoice amount is the USD price at the locked rate (+markup), valid LOCK_S."""
    from fastapi.responses import JSONResponse
    try:
        with db() as c:
            q = quote(c, product, "gram")
    except RateUnavailable as e:
        return JSONResponse({"error": {"type": "api_error", "code": "rate_unavailable", "message": f"GRAM cannot be priced right now ({e})",
                                       "next_step": f"pay in USDC on Base through x402 at https://ai.minimalcult.org/base/{product.split('_')[0]}s",
                                       "doc_url": "https://ai.minimalcult.org/pricing"}}, status_code=503, headers={"Retry-After": "300"})
    return await pay_gate(request, body, route, q["amount"], ttl=LOCK_S)


def _ensure_usd(c):
    if "usd_micro" not in [r[1] for r in c.execute("PRAGMA table_info(keys)")]:
        c.execute("ALTER TABLE keys ADD COLUMN usd_micro INTEGER NOT NULL DEFAULT 0")


def add_credit(c, key_hash, pack, paid, now=None):
    """A paid USD credit pack lands on the key (x402 USDC through basepay). Returns the new USD balance in micro-dollars."""
    _ensure_usd(c)
    p = next(x for x in PACKS if x["pack"] == pack)
    if paid["amount"] < p["pay_usd_micro"] or paid["currency"] != "usdc":
        raise ValueError("payment does not cover the pack")
    c.execute("UPDATE keys SET usd_micro=usd_micro+? WHERE key_hash=?", (p["credit_usd_micro"], key_hash))
    c.execute("INSERT INTO ledger(ts,key_hash,delta_nano,reason) VALUES(?,?,?,?)", (now or int(time.time()), key_hash, 0,
                                                                                    f"usd_credit_pack:{pack}:{p['credit_usd_micro']}:{paid.get('via')}"))
    return c.execute("SELECT usd_micro FROM keys WHERE key_hash=?", (key_hash,)).fetchone()[0]


def price_list(c, get=None):
    try:
        rate, info = gram_rate(c, get=get)
    except RateUnavailable as e:
        rate, info = None, {"error": str(e)}
    items = []
    for k, (usd_micro, what) in PRICES.items():
        it = {"product": k, "usd_micro": usd_micro, "usd": usd_micro / USD, "what": what, "free": FREE.get(k)}
        if rate:
            it["gram_nano_now"] = gram_nano(usd_micro, rate, METHODS["gram"]["markup_bp"])
        items.append(it)
    return {"object": "price_list", "currency": "usd", "unit": "micro", "items": items, "methods": METHODS, "gram_rate": info,
            "rate_lock_s": LOCK_S, "credit_packs": PACKS,
            "notes": ["prices are set in USD; other currencies are converted at the rate of the moment, locked for the invoice",
                      "inside Telegram, digital goods are sold for Stars only",
                      "companies: prepaid USD credit packs now; cards and invoices after the company is registered (January 2027)"]}


def setup(app, db, get_key, client_ip, h):
    from fastapi import Request
    from fastapi.responses import HTMLResponse
    import html as H
    import records_api as RA
    import ui
    import witness_check as WC

    @app.get("/v1/prices")
    def prices():
        with db() as c:
            return price_list(c)

    @app.post("/v1/credits")
    async def credits(request: Request, pack: str = ""):
        """A USD credit pack on the calling key — paid in USDC on Base through x402 at /base/credits (basepay forwards the key)."""
        paid = WC.internal_payment(request)
        if not paid:
            raise RA.ApiError(402, "payment_error", "payment_required", "credit packs are paid in USDC on Base through x402",
                              f"GET https://ai.minimalcult.org/base/credits-{pack or '50'} with your Authorization header")
        if pack not in {p["pack"] for p in PACKS}:
            raise RA.ApiError(400, "invalid_request_error", "invalid_pack", f"pack is one of {', '.join(p['pack'] for p in PACKS)}", "send pack=50, 500 or 5000")
        key = get_key(request.headers.get("authorization"))
        with db() as c:
            try:
                bal = add_credit(c, key["key_hash"], pack, paid)
            except ValueError as e:
                raise RA.ApiError(402, "payment_error", "underpaid", str(e), "pay the full pack price")
        return {"object": "credit", "pack": pack, "balance": {"amount": bal, "currency": "usd", "unit": "micro"}}

    @app.get("/pricing", response_class=HTMLResponse)
    def pricing():
        with db() as c:
            pl = price_list(c)
        e = H.escape
        rows = "".join(f"<tr><td>{e(i['what'])}</td><td><b>${i['usd']:.2f}</b></td><td>{e(i['free'] or '')}</td></tr>" for i in pl["items"])
        packs = "".join(f"<li>${p['pay_usd_micro'] // USD:,} → ${p['credit_usd_micro'] // USD:,} of credit</li>" for p in pl["credit_packs"])
        rate = pl["gram_rate"].get("usd_per_gram")
        body = (f"<h1>Pricing</h1><p class=lead>Prices are set in US dollars. Pay with USDC on Base (x402, no account), prepaid USD credit, "
                f"or GRAM at the rate of the moment (+{METHODS['gram']['markup_bp'] / 100:g}%), locked for {LOCK_S // 60} minutes in the invoice.</p>"
                f"<table class=pt><thead><tr><th>What</th><th>Price</th><th>Free</th></tr></thead><tbody>{rows}</tbody></table>"
                f"<h2>Prepaid credit</h2><ul>{packs}</ul><p class=m>Credit is spent in USD with no conversion. Companies: cards and invoices after "
                "the company is registered (January 2027); until then USDC or GRAM against an invoice.</p>"
                + (f"<p class=m>GRAM now: ${rate:.4f} ({e(pl['gram_rate'].get('source', ''))}).</p>" if rate else "")
                + "<p class=m>For machines: <a href='/v1/prices'>/v1/prices</a>.</p>"
                "<style>.pt{border-collapse:collapse;width:100%;max-width:720px}.pt td,.pt th{border-bottom:1px solid var(--line);padding:9px 6px;text-align:left}</style>")
        return HTMLResponse(ui.page("Pricing — checks, statements, monitors", "/pricing", body,
                                    "MINIMALCULT prices in US dollars: checks, signed statements and monitors; pay with USDC, credit or GRAM."))
