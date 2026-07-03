from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage
from app.core.config import settings

bot = Bot(token=settings.TELEGRAM_BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())
