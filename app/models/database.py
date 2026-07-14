from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

class Database:
    client: AsyncIOMotorClient = None
    db = None

db = Database()

import asyncio

async def _initialize_indices_and_seeding():
    """Asynchronously create indexes and seed default domains without blocking server boot."""
    try:
        # Create indices for performance
        await db.db.users.create_index("telegram_id", unique=True)
        await db.db.users.create_index("api_key", unique=True)
        await db.db.protected_links.create_index("short_id", unique=True)
        await db.db.protected_links.create_index("user_id")
        await db.db.request_logs.create_index([("short_id", 1), ("timestamp", -1)])

        # Verifications collection for Referrer validation
        await db.db.verifications.create_index("token", unique=True)
        await db.db.verifications.create_index([("ip", 1), ("short_id", 1)])
        await db.db.verifications.create_index("created_at", expireAfterSeconds=settings.TOKEN_EXPIRY_SECONDS)

        # Allowed domains collection
        await db.db.allowed_domains.create_index("domain", unique=True)
        count = await db.db.allowed_domains.count_documents({})
        if count == 0:
            default_domains = [
                {"domain": "arolinks.com", "created_at": datetime.utcnow()},
                {"domain": "gplinks.co", "created_at": datetime.utcnow()},
                {"domain": "shortzon.com", "created_at": datetime.utcnow()}
            ]
            await db.db.allowed_domains.insert_many(default_domains)
    except Exception as e:
        # Prevent index failure from crashing the entire process
        import logging
        logging.getLogger(__name__).error(f"Database initialization error: {e}", exc_info=True)

async def connect_to_mongo():
    db.client = AsyncIOMotorClient(settings.MONGODB_URL, serverSelectionTimeoutMS=2000)
    db.db = db.client[settings.DATABASE_NAME]

    # Spawn index creation in the background to ensure fast server boot
    asyncio.create_task(_initialize_indices_and_seeding())

async def close_mongo_connection():
    db.client.close()

def get_database():
    return db.db
