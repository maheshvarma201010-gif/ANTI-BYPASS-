from aiogram import types, Router, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from app.bot.bot import bot
from app.models.database import get_database
from app.core.security import generate_api_key, encrypt_url, decrypt_url
from app.core.config import settings
from datetime import datetime
import httpx

router = Router()

class ConnectStates(StatesGroup):
    waiting_for_url = State()
    waiting_for_api_key = State()

@router.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "👋 Welcome to Anti-Bypass Protection Bot!\n\n"
        "Connect your existing shortener to start protecting your links with our JavaScript Referer check.\n\n"
        "Available Commands:\n"
        "/connect - Connect to shortener\n"
        "/api - View current credentials and configuration\n"
        "/regenerate - Regenerate your API key\n"
        "/stats - View bypass statistics\n"
        "/domains - List whitelisted domains\n"
        "/adddomain <domain> - Whitelist a domain\n"
        "/deldomain <domain> - Remove a domain from whitelist\n"
        "/delete - Delete your account"
    )

@router.message(Command("domains"))
async def cmd_domains(message: types.Message):
    db = get_database()
    cursor = db.allowed_domains.find({})
    domains = []
    async for doc in cursor:
        domains.append(doc["domain"])

    if not domains:
        await message.answer("⚠️ No allowed domains registered currently.")
        return

    domains_list = "\n".join(f"• {domain}" for domain in domains)
    await message.answer(f"🌐 Whitelisted Domains:\n\n{domains_list}")

@router.message(Command("adddomain"))
async def cmd_adddomain(message: types.Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("❌ Usage: /adddomain <domain>\nExample: /adddomain arolinks.com")
        return

    domain = args[1].strip().lower()
    # Basic domain validation format check
    if not domain or "." not in domain or len(domain) < 4:
        await message.answer("❌ Invalid domain format. Please provide a valid domain (e.g., example.com).")
        return

    db = get_database()
    existing = await db.allowed_domains.find_one({"domain": domain})
    if existing:
        await message.answer(f"ℹ️ Domain `{domain}` is already whitelisted.")
        return

    await db.allowed_domains.insert_one({
        "domain": domain,
        "created_at": datetime.utcnow()
    })
    await message.answer(f"✅ Domain `{domain}` added to whitelist successfully!")

@router.message(Command("deldomain"))
async def cmd_deldomain(message: types.Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.answer("❌ Usage: /deldomain <domain>\nExample: /deldomain arolinks.com")
        return

    domain = args[1].strip().lower()
    db = get_database()
    result = await db.allowed_domains.delete_one({"domain": domain})
    if result.deleted_count > 0:
        await message.answer(f"✅ Domain `{domain}` removed from whitelist successfully!")
    else:
        await message.answer(f"❌ Domain `{domain}` not found in the whitelist.")

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

    await message.answer("⏳ Validating credentials...")

    # Validate the API key with the real shortener
    test_url = "https://google.com"
    validate_url = f"{url}/api?api={api_key}&url={test_url}"

    is_valid = False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(validate_url, timeout=10.0)
            if resp.status_code == 200:
                result = resp.json()
                if result.get("status") == "success" or result.get("short_url"):
                    is_valid = True
    except Exception:
        pass

    if not is_valid:
        await message.answer("❌ Invalid API Key or Shortener URL. Please try /connect again.")
        await state.clear()
        return

    db = get_database()
    telegram_id = str(message.from_user.id)
    encrypted_api_key = encrypt_url(api_key)
    new_abp_key = generate_api_key()

    config = {
        "base_url": url,
        "api_key": encrypted_api_key
    }

    user_data = await db.users.find_one({"telegram_id": telegram_id})
    if user_data:
        await db.users.update_one(
            {"telegram_id": telegram_id},
            {"$set": {"config": config, "api_key": new_abp_key, "is_active": True}}
        )
    else:
        new_user = {
            "telegram_id": telegram_id,
            "username": message.from_user.username,
            "api_key": new_abp_key,
            "config": config,
            "created_at": datetime.utcnow(),
            "is_active": True,
            "total_requests": 0,
            "success_count": 0,
            "blocked_count": 0,
            "referer_failures": 0
        }
        await db.users.insert_one(new_user)

    await state.clear()
    await message.answer(
        f"✅ Connected Successfully\n\n"
        f"Base URL\n{settings.BASE_URL}\n\n"
        f"Your API Key\n{new_abp_key}\n\n"
        f"Connected Shortener\n{url}\n\n"
        f"Status\nActive"
    )

@router.message(Command("api"))
async def cmd_api(message: types.Message):
    db = get_database()
    user = await db.users.find_one({"telegram_id": str(message.from_user.id)})
    if not user:
        await message.answer("❌ You are not connected. Use /connect first.")
        return

    response = (
        f"Base URL: {settings.BASE_URL}\n"
        f"API Key: {user['api_key']}\n"
        f"Connected Shortener: {user['config']['base_url']}\n"
        f"Status: {'Active' if user['is_active'] else 'Inactive'}\n"
        f"Total Requests: {user.get('total_requests', 0)}"
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

    stats_text = (
        f"📊 Statistics\n\n"
        f"Total Requests: {user.get('total_requests', 0)}\n"
        f"Successful Requests: {user.get('success_count', 0)}\n"
        f"Blocked Requests: {user.get('blocked_count', 0)}\n"
        f"Referer Failures: {user.get('referer_failures', 0)}"
    )
    await message.answer(stats_text)

@router.message(Command("delete"))
async def cmd_delete(message: types.Message):
    db = get_database()
    telegram_id = str(message.from_user.id)
    await db.users.delete_one({"telegram_id": telegram_id})
    await message.answer("✅ Account deleted successfully.")
