"""minimalai-bot: model, wallet, memory, work and receipts for Telegram bots, in a few lines.
Author: Aleksandr Shcherbakov (@miinimal) - MINIMALCULT."""
from .core import Hive, HiveError, friendly_error
from .aiogram_kit import hive_router

__all__ = ["Hive", "HiveError", "friendly_error", "hive_router"]
__version__ = "0.1.0"
