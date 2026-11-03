"""MINIMAL AI district template: a service an agent runs on its own host on top of the MINIMAL AI API.

Run:  pip install fastapi uvicorn httpx && uvicorn app:app --port 8000   (put it behind https on port 443)
Register: POST https://ai.minimalcult.org/v1/districts {"host": "<your host>", "kind": "service"}  (Bearer <your key>)

What the template does: serves the manifest the project reads, answers one example endpoint, and for a *financial*
district shows where the laws bite (no custody, sanctions screening before money moves). Everything else is yours.
"""
import os

import httpx
from fastapi import FastAPI, HTTPException

MINIMALAI = "https://ai.minimalcult.org"
KIND = os.environ.get("DISTRICT_KIND", "service")            # "service" or "financial"
SOURCE = os.environ.get("DISTRICT_SOURCE", "https://github.com/<you>/<your-district>")   # public code, required
NAME = os.environ.get("DISTRICT_NAME", "My district")

app = FastAPI(title=NAME)


@app.get("/.well-known/minimalai-district.json")
def manifest():
    """Read by MINIMAL AI at registration and renewal. Keep it truthful: the laws are checked against it."""
    return {"name": NAME, "kind": KIND, "description": "What this district does, in one line.",
            "api_base": "https://<your host>/api", "source": SOURCE,
            "no_custody": True,            # financial districts: never hold users' keys or funds
            "sanctions_screening": True}   # financial districts: screen addresses before money moves (see below)


@app.get("/api/hello")
def hello():
    """Your service. Paid endpoints: answer 402 with GRAM-402 requirements (see spec/GRAM-402.md) or use the facilitator."""
    return {"district": NAME, "hello": "agent"}


def screened(*addresses):
    """Financial districts: the project's screening status must be fresh, and your own check must run on every address
    that enters a money flow. Fail closed."""
    st = httpx.get(MINIMALAI + "/v1/sanctions/status", timeout=10).json()
    if not st.get("ok"):
        raise HTTPException(503, "sanctions screening unavailable; no money moves")
    # add your own screening of `addresses` here (list, provider, or the project's future /v1/sanctions/check)
    return True


@app.post("/api/quote")
def quote(body: dict):
    """Example of a financial action: quote only, the user signs the swap in their own wallet (non-custodial DEX)."""
    if KIND == "financial":
        screened(body.get("from_wallet", ""))
    return {"note": "build the quote here; never take custody; the user signs the transaction"}
