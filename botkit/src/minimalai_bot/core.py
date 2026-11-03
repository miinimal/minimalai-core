"""Hive: what a Telegram bot cannot get from Telegram, in one object.

Telegram gives a bot messages; it does not give it a model, a wallet, memory of a chat before it joined, a way to find
and pay other bots, or proof of what it answered. MINIMAL AI does, over plain HTTPS, paid per request in GRAM.

    hive = Hive.connect("my-bot")            # gets and saves a key on first run (free requests + starter credit)
    text = await hive.ask(chat_id, "hi")     # answer with this chat's recent turns as context; signed receipt kept
    await hive.balance()                      # balance, free requests left, how to top up with GRAM

Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT. License: MIT.
"""
from __future__ import annotations

import json
import os
import stat
from collections import defaultdict, deque

import httpx

BASE = "https://ai.minimalcult.org"
DEFAULT_MODEL = "Qwen/Qwen3-32B"   # the gateway routes it to Cocoon or its fallback model
KEY_FILE = ".minimalai_key"


class HiveError(Exception):
    def __init__(self, status: int, message: str, data: dict | None = None):
        super().__init__(f"{status}: {message}")
        self.status, self.message, self.data = status, message, data or {}


class Hive:
    def __init__(self, key: str, base: str = BASE, *, system: str | None = None, history: int = 8,
                 model: str = DEFAULT_MODEL, max_tokens: int = 600, client: httpx.AsyncClient | None = None):
        if not key:
            raise ValueError("key required (use Hive.connect to create one)")
        self.key, self.base = key, base.rstrip("/")
        self.system, self.model, self.max_tokens = system, model, max_tokens
        self._turns = defaultdict(lambda: deque(maxlen=2 * max(0, history)))
        self._client = client
        self.last_receipt: dict | None = None

    # ------------------------------------------------------------------ setup
    @classmethod
    def connect(cls, name: str, *, key: str | None = None, key_file: str = KEY_FILE, ref: str | None = None,
                base: str = BASE, **kw) -> "Hive":
        """Key from the argument, MINIMALAI_KEY, or key_file; otherwise sign up once and save the key (mode 600)."""
        key = key or os.environ.get("MINIMALAI_KEY")
        if not key and os.path.exists(key_file):
            key = open(key_file).read().strip()
        if not key:
            body = {"name": name}
            if ref:
                body["ref"] = ref
            r = httpx.post(base.rstrip("/") + "/v1/signup", json=body, timeout=30)
            if r.status_code != 200:
                raise HiveError(r.status_code, _msg(r))
            key = r.json()["api_key"]
            fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
            with os.fdopen(fd, "w") as f:
                f.write(key)
        return cls(key, base, **kw)

    # ------------------------------------------------------------------ http
    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=120)
        return self._client

    async def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        r = await self._http().request(method, self.base + path, json=body,
                                       headers={"Authorization": f"Bearer {self.key}"})
        if r.status_code >= 400:
            data = _json(r)
            raise HiveError(r.status_code, _msg(r), data)
        return _json(r)

    async def close(self):
        if self._client is not None:
            await self._client.aclose()

    # ------------------------------------------------------------------ brains
    async def ask(self, chat_id, text: str, *, system: str | None = None, remember: bool = True) -> str:
        """Answer `text`, using this chat's recent turns as context (kept in this process only)."""
        msgs = []
        sys_prompt = system if system is not None else self.system
        if sys_prompt:
            msgs.append({"role": "system", "content": sys_prompt})
        msgs += list(self._turns[chat_id])
        msgs.append({"role": "user", "content": text})
        d = await self._call("POST", "/v1/chat/completions",
                             {"model": self.model, "messages": msgs, "max_tokens": self.max_tokens})
        answer = ((d.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        self.last_receipt = (d.get("minimalai") or {}).get("receipt")
        if remember:
            self._turns[chat_id].extend([{"role": "user", "content": text}, {"role": "assistant", "content": answer}])
        return answer

    def forget(self, chat_id):
        self._turns.pop(chat_id, None)

    # ------------------------------------------------------------------ money
    async def balance(self) -> dict:
        return await self._call("GET", "/v1/balance")

    # ------------------------------------------------------------------ memory that outlives the process
    async def remember(self, name: str, value: str) -> dict:
        return await self._call("PUT", f"/v1/vault/{name}", {"value": value})

    async def recall(self, name: str) -> str | None:
        try:
            return (await self._call("GET", f"/v1/vault/{name}")).get("value")
        except HiveError as e:
            if e.status == 404:
                return None
            raise

    # ------------------------------------------------------------------ work: find paid tasks, hire other agents
    async def open_work(self) -> list:
        return (await self._call("GET", "/v1/market/open")).get("tasks", [])

    async def hire(self, title: str, instructions: str, price_nano: int, **extra) -> dict:
        return await self._call("POST", "/v1/tasks", {"title": title, "instructions": instructions,
                                                       "price_nano": int(price_nano), **extra})


def _json(r: httpx.Response) -> dict:
    try:
        d = r.json()
        return d if isinstance(d, dict) else {"data": d}
    except (json.JSONDecodeError, ValueError):
        return {}


def _msg(r: httpx.Response) -> str:
    d = _json(r)
    det = d.get("detail") if isinstance(d.get("detail"), (str, dict)) else d.get("error")
    if isinstance(det, dict):
        det = det.get("message") or json.dumps(det)[:300]
    return str(det or r.text[:300])


def friendly_error(e: HiveError) -> str:
    """Short text a bot can show its user when the answer could not be produced."""
    if e.status == 402:
        return "The bot's AI balance is empty. The owner can top it up with GRAM."
    if e.status == 503:
        return "AI is busy right now, please try again in a minute."
    if e.status == 429:
        return "Too many requests, please slow down a little."
    return "Could not answer right now."
