"""Adapters: aiogram router handles /ai, private text, /reset, owner-only /balance; python-telegram-bot handlers register."""
import asyncio, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
from minimalai_bot import Hive, HiveError, hive_router


class FakeHive(Hive):
    def __init__(self):
        super().__init__("k", "http://none")
        self.asked, self.fail = [], False

    async def ask(self, chat_id, text, **kw):
        self.asked.append((chat_id, text))
        if self.fail:
            raise HiveError(402, "balance")
        return "answer:" + text

    async def balance(self):
        return {"balance_ton": 1.5, "free_requests": 0}


async def aiogram_case():
    from aiogram import Bot, Dispatcher
    from aiogram.client.session.base import BaseSession
    from aiogram.types import Update

    sent = []

    class Session(BaseSession):
        async def make_request(self, bot, method, timeout=None):
            sent.append((type(method).__name__, getattr(method, "text", None)))
            return True if type(method).__name__ == "SendChatAction" else method.model_construct()

        async def stream_content(self, *a, **k):
            yield b""

        async def close(self):
            pass

    bot = Bot("123456:" + "A" * 35, session=Session())
    hive = FakeHive()
    dp = Dispatcher()
    dp.include_router(hive_router(hive, owner_id=1))

    def upd(uid, chat_type, text, n):
        return Update.model_validate({"update_id": n, "message": {
            "message_id": n, "date": 0, "text": text, "chat": {"id": 100 + uid, "type": chat_type},
            "from": {"id": uid, "is_bot": False, "first_name": "u"},
            **({"entities": [{"type": "bot_command", "offset": 0, "length": len(text.split()[0])}]} if text.startswith("/") else {})}},
            context={"bot": bot})

    await dp.feed_update(bot, upd(5, "group", "/ai what is GRAM", 1))
    await dp.feed_update(bot, upd(5, "private", "hello there", 2))
    await dp.feed_update(bot, upd(5, "group", "just chatting", 3))      # group text without /ai: ignored
    await dp.feed_update(bot, upd(5, "private", "/balance", 4))          # not the owner: silent
    await dp.feed_update(bot, upd(1, "private", "/balance", 5))          # owner
    hive.fail = True
    await dp.feed_update(bot, upd(5, "private", "x", 6))
    assert hive.asked == [(105, "what is GRAM"), (105, "hello there"), (105, "x")], hive.asked
    texts = [t for n, t in sent if n == "SendMessage"]
    assert texts[0] == "answer:what is GRAM" and texts[1] == "answer:hello there", texts
    assert any("balance_ton: 1.5" in t for t in texts) and sum("balance_ton" in t for t in texts) == 1, texts
    assert "top it up" in texts[-1], texts
    await bot.session.close()


def ptb_case():
    from telegram.ext import ApplicationBuilder
    from minimalai_bot.ptb_kit import add_hive
    app = ApplicationBuilder().token("123456:" + "A" * 35).build()
    add_hive(app, FakeHive(), owner_id=1)
    names = sorted(type(h).__name__ for h in app.handlers[0])
    assert names == ["CommandHandler", "CommandHandler", "CommandHandler", "MessageHandler"], names


asyncio.run(aiogram_case())
ptb_case()
print("adapters OK")
