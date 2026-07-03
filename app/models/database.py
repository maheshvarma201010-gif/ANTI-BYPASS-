from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

class Database:
    client: AsyncIOMotorClient = None
    db = None

db = Database()

async def connect_to_mongo():
    db.client = AsyncIOMotorClient(settings.MONGODB_URL)
    db.db = db.client[settings.DATABASE_NAME]

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

async def close_mongo_connection():
    db.client.close()

def get_database():
    return db.db
