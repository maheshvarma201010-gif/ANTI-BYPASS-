import asyncio
import logging
from app.bot.bot import dp, bot
from app.bot.handlers import router
from app.models.database import connect_to_mongo

async def main():
    logging.basicConfig(level=logging.INFO)
    dp.include_router(router)

    # We need to connect to mongo for the bot handlers too
    await connect_to_mongo()

    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
