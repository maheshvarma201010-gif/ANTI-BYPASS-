from aiogram import types, Router, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
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

def get_start_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Connect / Reconnect", callback_data="connect_shortener")],
        [InlineKeyboardButton(text="❌ Delete Account", callback_data="delete_account")]
    ])

@router.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "👋 Welcome to Anti-Bypass Protection Bot!\n\n"
        "Connect your existing shortener to start protecting your links with our JavaScript Referer check.\n\n"
        "Use /connect or click below to get started.",
        reply_markup=get_start_keyboard()
    )

@router.callback_query(F.data == "connect_shortener")
async def cb_connect(callback: types.CallbackQuery, state: FSMContext):
    await callback.message.answer("Step 1: Enter your Shortener Base URL.\nExample: https://arolinks.com")
    await state.set_state(ConnectStates.waiting_for_url)
    await callback.answer()

@router.callback_query(F.data == "delete_account")
async def cb_delete(callback: types.CallbackQuery):
    db = get_database()
    telegram_id = str(callback.from_user.id)
    await db.users.delete_one({"telegram_id": telegram_id})
    await callback.message.answer("✅ Account deleted successfully.")
    await callback.answer()

@router.callback_query(F.data == "view_stats")
async def cb_stats(callback: types.CallbackQuery):
    db = get_database()
    user = await db.users.find_one({"telegram_id": str(callback.from_user.id)})
    if not user:
        await callback.message.answer("❌ User not found.")
        await callback.answer()
        return

    stats_text = (
        f"📊 Statistics\n\n"
        f"Total Requests: {user.get('total_requests', 0)}\n"
        f"Successful Requests: {user.get('success_count', 0)}\n"
        f"Blocked Requests: {user.get('blocked_count', 0)}\n"
        f"Referer Failures: {user.get('referer_failures', 0)}"
    )
    await callback.message.answer(stats_text)
    await callback.answer()

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
        f"Status\nActive",
        reply_markup=get_start_keyboard()
    )

@router.message(Command("api"))
async def cmd_api(message: types.Message):
    db = get_database()
    user = await db.users.find_one({"telegram_id": str(message.from_user.id)})
    if not user:
        await message.answer("❌ You are not connected. Use /connect first.", reply_markup=get_start_keyboard())
        return

    response = (
        f"Base URL: {settings.BASE_URL}\n"
        f"API Key: {user['api_key']}\n"
        f"Connected Shortener: {user['config']['base_url']}\n"
        f"Status: {'Active' if user['is_active'] else 'Inactive'}\n"
        f"Total Requests: {user.get('total_requests', 0)}"
    )
    await message.answer(response, reply_markup=get_start_keyboard())

@router.message(Command("regenerate"))
async def cmd_regenerate(message: types.Message):
    db = get_database()
    new_api_key = generate_api_key()
    result = await db.users.update_one(
        {"telegram_id": str(message.from_user.id)},
        {"$set": {"api_key": new_api_key}}
    )

    if result.modified_count > 0:
        await message.answer(f"✅ API Key Regenerated\n\nNew API Key: {new_api_key}", reply_markup=get_start_keyboard())
    else:
        await message.answer("❌ User not found.", reply_markup=get_start_keyboard())

@router.message(Command("stats"))
async def cmd_stats(message: types.Message):
    db = get_database()
    user = await db.users.find_one({"telegram_id": str(message.from_user.id)})
    if not user:
        await message.answer("❌ User not found.", reply_markup=get_start_keyboard())
        return

    stats_text = (
        f"📊 Statistics\n\n"
        f"Total Requests: {user.get('total_requests', 0)}\n"
        f"Successful Requests: {user.get('success_count', 0)}\n"
        f"Blocked Requests: {user.get('blocked_count', 0)}\n"
        f"Referer Failures: {user.get('referer_failures', 0)}"
    )
    await message.answer(stats_text, reply_markup=get_start_keyboard())

@router.message(Command("delete"))
async def cmd_delete(message: types.Message):
    db = get_database()
    telegram_id = str(message.from_user.id)
    await db.users.delete_one({"telegram_id": telegram_id})
    await message.answer("✅ Account deleted successfully.", reply_markup=get_start_keyboard())
