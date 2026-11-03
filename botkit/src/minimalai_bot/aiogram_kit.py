"""aiogram 3 adapter.

    from minimalai_bot import Hive
    hive = Hive.connect("my-bot", system="You are a friendly shop assistant.")
    dp.include_router(hive_router(hive))

Gives the bot: /ai <question> anywhere, plain-text answers in private chats, /reset to forget the chat's context,
/balance for the bot owner (owner_id). Long answers are split under Telegram's 4096-character limit.
"""
from __future__ import annotations

from .core import Hive, HiveError, friendly_error

LIMIT = 4000


def chunks(text: str, n: int = LIMIT):
    text = text or "…"
    return [text[i:i + n] for i in range(0, len(text), n)]


def hive_router(hive: Hive, *, owner_id: int | None = None, private_chat_replies: bool = True):
    from aiogram import F, Router
    from aiogram.enums import ChatAction, ChatType
    from aiogram.filters import Command, CommandObject
    from aiogram.types import Message

    router = Router(name="minimalai")

    async def answer(m: Message, text: str):
        try:
            await m.bot.send_chat_action(m.chat.id, ChatAction.TYPING)
            reply = await hive.ask(m.chat.id, text)
        except HiveError as e:
            reply = friendly_error(e)
        for part in chunks(reply):
            await m.answer(part)

    @router.message(Command("ai"))
    async def ai_cmd(m: Message, command: CommandObject):
        if not command.args:
            await m.answer("Usage: /ai <your question>")
            return
        await answer(m, command.args)

    @router.message(Command("reset"))
    async def reset_cmd(m: Message):
        hive.forget(m.chat.id)
        await m.answer("Context cleared.")

    @router.message(Command("balance"))
    async def balance_cmd(m: Message):
        if owner_id is None or not m.from_user or m.from_user.id != owner_id:
            return
        b = await hive.balance()
        await m.answer("\n".join(f"{k}: {v}" for k, v in b.items() if not isinstance(v, (dict, list))))

    if private_chat_replies:
        @router.message(F.chat.type == ChatType.PRIVATE, F.text, ~F.text.startswith("/"))
        async def private_text(m: Message):
            await answer(m, m.text)

    return router
