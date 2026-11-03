"""Sanctions screening of wallet addresses (master prompt 4.2: mandatory at every money entry).

Source: OFAC SDN list, CSV export https://www.treasury.gov/ofac/downloads/sdn.csv - digital currency addresses are in
the remarks column as "Digital Currency Address - <ASSET> <address>;". The server refreshes the list daily
(`python sanctions.py refresh`), stores addresses with the fetch date, and every escrow offer and invoice payer is
checked against it. If the list is missing or older than MAX_AGE_S the check fails closed for escrow offers.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT.
"""
import json
import os
import re
import sys
import time
import urllib.request

SDN_URL = os.environ.get("SANCTIONS_SDN_URL", "https://www.treasury.gov/ofac/downloads/sdn.csv")
PATH = os.environ.get("SANCTIONS_PATH", os.path.join(os.path.dirname(os.environ.get("MINIMALAI_DB", "./x.db")),
                                                     "sanctions.json"))
MAX_AGE_S = int(os.environ.get("SANCTIONS_MAX_AGE_S", str(3 * 86400)))
_RX = re.compile(r"Digital Currency Address - ([A-Z0-9]+)\s+([A-Za-z0-9:_\-]{20,})")


class Blocked(Exception):
    pass


def norm(addr):
    """Comparable form: TON addresses -> raw 0:HEX (user-friendly forms decode to the same account); others as is."""
    a = addr.strip()
    try:
        from pytoniq_core import Address
        return Address(a).to_str(is_user_friendly=False).upper()
    except Exception:  # noqa: BLE001  not a TON address
        return a.lower() if a.startswith("0x") else a


def parse_sdn(text):
    return sorted({norm(m.group(2)) for m in _RX.finditer(text)})


def save(addresses, source=SDN_URL, fetched_at=None):
    rec = {"source": source, "fetched_at": int(fetched_at or time.time()), "count": len(addresses), "addresses": addresses}
    tmp = PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f)
    os.replace(tmp, PATH)
    return rec


def refresh():
    with urllib.request.urlopen(SDN_URL, timeout=120) as r:
        return save(parse_sdn(r.read().decode("utf-8", "replace")))


_cache = {"mtime": None, "rec": None}


def load():
    try:
        m = os.path.getmtime(PATH)
    except OSError:
        return None
    if _cache["mtime"] != m:
        _cache.update(mtime=m, rec=json.load(open(PATH)), set=None)
        _cache["set"] = set(_cache["rec"]["addresses"])
    return _cache["rec"]


def status():
    rec = load()
    if not rec:
        return {"ok": False, "reason": "no list"}
    age = int(time.time()) - rec["fetched_at"]
    return {"ok": age <= MAX_AGE_S, "source": rec["source"], "fetched_at": rec["fetched_at"], "count": rec["count"], "age_s": age}


def check(*addresses):
    """Raise Blocked if any address is listed, or if the list is missing/stale (fail closed)."""
    st = status()
    if not st["ok"]:
        raise Blocked("sanctions list unavailable: " + st.get("reason", "stale"))
    hit = [a for a in addresses if norm(a) in _cache["set"]]
    if hit:
        raise Blocked("address on sanctions list")


if __name__ == "__main__" and sys.argv[1:] == ["refresh"]:
    r = refresh()
    print(json.dumps({k: r[k] for k in ("source", "fetched_at", "count")}))
