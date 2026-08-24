from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

class Database:
    client: AsyncIOMotorClient = None
    db = None

db = Database()

async def connect_to_mongo():
    try:
        db.client = AsyncIOMotorClient(settings.MONGODB_URL, serverSelectionTimeoutMS=2000)
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

        # Sessions collection for Anti-Bypass flow
        await db.db.sessions.create_index("token", unique=True)
        await db.db.sessions.create_index("session_id", unique=True)
        await db.db.sessions.create_index("created_at", expireAfterSeconds=60)
    except Exception as e:
        print("Mongo connection note:", e)

async def close_mongo_connection():
    if db.client:
        db.client.close()

def get_database():
    return db.db
