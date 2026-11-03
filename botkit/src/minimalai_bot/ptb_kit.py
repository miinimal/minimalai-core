"""python-telegram-bot (v20+) adapter.

    from minimalai_bot import Hive
    from minimalai_bot.ptb_kit import add_hive
    hive = Hive.connect("my-bot")
    add_hive(application, hive)

Same behaviour as the aiogram adapter: /ai, /reset, /balance (owner only), answers in private chats.
"""
from __future__ import annotations

from .aiogram_kit import chunks
from .core import Hive, HiveError, friendly_error


def add_hive(application, hive: Hive, *, owner_id: int | None = None, private_chat_replies: bool = True):
    from telegram.constants import ChatAction
    from telegram.ext import CommandHandler, MessageHandler, filters

    async def answer(update, context, text):
        chat = update.effective_chat
        try:
            await context.bot.send_chat_action(chat.id, ChatAction.TYPING)
            reply = await hive.ask(chat.id, text)
        except HiveError as e:
            reply = friendly_error(e)
        for part in chunks(reply):
            await update.effective_message.reply_text(part)

    async def ai_cmd(update, context):
        text = " ".join(context.args or [])
        if not text:
            await update.effective_message.reply_text("Usage: /ai <your question>")
            return
        await answer(update, context, text)

    async def reset_cmd(update, context):
        hive.forget(update.effective_chat.id)
        await update.effective_message.reply_text("Context cleared.")

    async def balance_cmd(update, context):
        user = update.effective_user
        if owner_id is None or not user or user.id != owner_id:
            return
        b = await hive.balance()
        await update.effective_message.reply_text("\n".join(f"{k}: {v}" for k, v in b.items()
                                                            if not isinstance(v, (dict, list))))

    async def private_text(update, context):
        await answer(update, context, update.effective_message.text)

    application.add_handler(CommandHandler("ai", ai_cmd))
    application.add_handler(CommandHandler("reset", reset_cmd))
    application.add_handler(CommandHandler("balance", balance_cmd))
    if private_chat_replies:
        application.add_handler(MessageHandler(filters.ChatType.PRIVATE & filters.TEXT & ~filters.COMMAND, private_text))
    return application
