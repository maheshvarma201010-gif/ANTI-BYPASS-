import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
import secrets

async def setup_test_data():
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client["test_db"]

    user_id = ObjectId()
    await db.users.insert_one({
        "_id": user_id,
        "api_key": "test_api_key",
        "config": {"base_url": "https://shortener.com"},
        "telegram_id": "123456"
    })

    short_id = "test_short"
    await db.protected_links.insert_one({
        "short_id": short_id,
        "user_id": str(user_id),
        "original_url": "https://example.com"
    })

    print(f"Setup complete. short_id: {short_id}")
    client.close()

if __name__ == "__main__":
    asyncio.run(setup_test_data())
