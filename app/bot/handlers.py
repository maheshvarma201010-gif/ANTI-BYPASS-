from aiogram import types, Router, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from app.bot.bot import bot
from app.models.database import get_database
from app.schemas.models import ShortenerConfig, User
from app.core.security import generate_api_key
from app.core.config import settings
from datetime import datetime, timedelta
import httpx

router = Router()

class ConnectStates(StatesGroup):
    waiting_for_url = State()
    waiting_for_api_key = State()

@router.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "👋 Welcome to Anti-Bypass Protection Bot!\n\n"
        "Use /connect to link your shortener and start protecting your links."
    )

@router.message(Command("help"))
async def cmd_help(message: types.Message):
    help_text = (
        "Available Commands:\n"
        "/start - Start the bot\n"
        "/help - Show this help message\n"
        "/connect - Connect your shortener\n"
        "/api - Show your API details\n"
        "/regenerate - Regenerate your API key\n"
        "/stats - View your statistics\n"
        "/delete - Delete your account"
    )
    await message.answer(help_text)

@router.message(Command("connect"))
async def cmd_connect(message: types.Message, state: FSMContext):
    await message.answer("Step 1: Enter your Shortener Base URL.\nExample: https://arolinks.com")
    await state.set_state(ConnectStates.waiting_for_url)

@router.message(ConnectStates.waiting_for_url)
async def process_url(message: types.Message, state: FSMContext):
    url = message.text.strip().rstrip('/')
    if not url.startswith("http"):
        await message.answer("❌ Invalid URL. Please start with http:// or https://")
        return
    await state.update_data(url=url)
    await message.answer("Step 2: Enter your Shortener API Key.")
    await state.set_state(ConnectStates.waiting_for_api_key)

@router.message(ConnectStates.waiting_for_api_key)
async def process_api_key(message: types.Message, state: FSMContext):
    api_key = message.text.strip()
    data = await state.get_data()
    url = data['url']

    # Validate the API key by trying to shorten a test URL
    test_url = "https://google.com"
    validate_url = f"{url}/api?api={api_key}&url={test_url}"

    await message.answer("⏳ Validating API key...")

    is_valid = False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(validate_url, timeout=10.0)
            if resp.status_code == 200:
                result = resp.json()
                if result.get("status") == "success" or result.get("short_url") or result.get("shortenedUrl"):
                    is_valid = True
    except Exception as e:
        await message.answer(f"❌ Validation Error: {str(e)}")

    if not is_valid:
        await message.answer("❌ Invalid API Key or Shortener URL. Please try /connect again.")
        await state.clear()
        return

    db = get_database()
    telegram_id = str(message.from_user.id)

    user_data = await db.users.find_one({"telegram_id": telegram_id})
    new_api_key = generate_api_key()

    config = {
        "base_url": url,
        "api_key": api_key
    }

    if user_data:
        await db.users.update_one(
            {"telegram_id": telegram_id},
            {"$set": {"config": config, "api_key": new_api_key}}
        )
    else:
        new_user = {
            "telegram_id": telegram_id,
            "username": message.from_user.username,
            "api_key": new_api_key,
            "config": config,
            "created_at": datetime.utcnow(),
            "is_active": True
        }
        await db.users.insert_one(new_user)

    await state.clear()
    await message.answer(
        f"✅ Connected Successfully\n\n"
        f"Base URL: {settings.BASE_URL}\n"
        f"Your API Key: {new_api_key}\n"
        f"Shortener: {url}\n"
        f"Status: Active"
    )

@router.message(Command("api"))
async def cmd_api(message: types.Message):
    db = get_database()
    user = await db.users.find_one({"telegram_id": str(message.from_user.id)})
    if not user:
        await message.answer("❌ You are not connected. Use /connect first.")
        return

    links_count = await db.protected_links.count_documents({"user_id": str(user['_id'])})

    response = (
        f"Base URL: {settings.BASE_URL}\n"
        f"API Key: {user['api_key']}\n"
        f"Total Protected Links: {links_count}\n"
        f"Created Date: {user['created_at'].strftime('%Y-%m-%d')}\n"
        f"Status: {'Active' if user['is_active'] else 'Inactive'}"
    )
    await message.answer(response)

@router.message(Command("regenerate"))
async def cmd_regenerate(message: types.Message):
    db = get_database()
    new_api_key = generate_api_key()
    result = await db.users.update_one(
        {"telegram_id": str(message.from_user.id)},
        {"$set": {"api_key": new_api_key}}
    )

    if result.modified_count > 0:
        await message.answer(f"✅ API Key Regenerated\n\nNew API Key: {new_api_key}")
    else:
        await message.answer("❌ User not found.")

@router.message(Command("stats"))
async def cmd_stats(message: types.Message):
    db = get_database()
    user = await db.users.find_one({"telegram_id": str(message.from_user.id)})
    if not user:
        await message.answer("❌ User not found.")
        return

    user_id_str = str(user['_id'])

    # Get all short_ids for this user
    links = await db.protected_links.find({"user_id": user_id_str}).to_list(length=1000)
    short_ids = [l['short_id'] for l in links]

    total_links = len(short_ids)

    # Statistics
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    today_requests = await db.request_logs.count_documents({
        "short_id": {"$in": short_ids},
        "timestamp": {"$gte": today}
    })

    success_count = await db.request_logs.count_documents({
        "short_id": {"$in": short_ids},
        "status": "success"
    })

    blocked_count = await db.request_logs.count_documents({
        "short_id": {"$in": short_ids},
        "status": "blocked"
    })

    referer_failures = await db.request_logs.count_documents({
        "short_id": {"$in": short_ids},
        "reason": "referer_empty"
    })

    js_failures = await db.request_logs.count_documents({
        "short_id": {"$in": short_ids},
        "reason": "invalid_token"
    })

    stats_text = (
        f"📊 Statistics\n\n"
        f"Protected Links: {total_links}\n"
        f"Today's Requests: {today_requests}\n"
        f"Total Success: {success_count}\n"
        f"Total Blocked: {blocked_count}\n"
        f"Referer Failures: {referer_failures}\n"
        f"JS Failures: {js_failures}"
    )
    await message.answer(stats_text)

@router.message(Command("delete"))
async def cmd_delete(message: types.Message):
    db = get_database()
    telegram_id = str(message.from_user.id)
    user = await db.users.find_one({"telegram_id": telegram_id})
    if user:
        user_id_str = str(user['_id'])
        await db.protected_links.delete_many({"user_id": user_id_str})
        await db.users.delete_one({"telegram_id": telegram_id})
        await message.answer("✅ Account and data deleted successfully.")
    else:
        await message.answer("❌ Account not found.")
