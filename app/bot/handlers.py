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
from urllib.parse import urlparse

router = Router()

class ConnectStates(StatesGroup):
    waiting_for_url = State()
    waiting_for_api_key = State()

def get_start_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Connect / Reconnect", callback_data="connect_shortener")],
        [InlineKeyboardButton(text="❌ Delete Account", callback_data="delete_account")]
    ])

async def get_connect_keyboard(telegram_id: str, db):
    user = await db.users.find_one({"telegram_id": telegram_id})
    buttons = []
    if user:
        for s in user.get("shorteners", []):
            name = s.get("name")
            if name:
                buttons.append([InlineKeyboardButton(text=f"🔗 {name}", callback_data=f"sel_shortener:{name}")])

    buttons.append([InlineKeyboardButton(text="➕ Add", callback_data="add_shortener")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

@router.message(Command("start"))
async def cmd_start(message: types.Message):
    await message.answer(
        "👋 Welcome to Anti-Bypass Protection Bot!\n\n"
        "Connect your existing shortener to start protecting your links with anti-bypass verification.\n\n"
        "Use /connect or click below to get started.",
        reply_markup=get_start_keyboard()
    )

@router.callback_query(F.data == "connect_shortener")
async def cb_connect_button(callback: types.CallbackQuery, state: FSMContext):
    db = get_database()
    telegram_id = str(callback.from_user.id)
    # Ensure user exists in db
    user = await db.users.find_one({"telegram_id": telegram_id})
    if not user:
        new_user = {
            "telegram_id": telegram_id,
            "username": callback.from_user.username,
            "api_key": generate_api_key(),
            "shorteners": [],
            "created_at": datetime.utcnow(),
            "is_active": True,
            "total_requests": 0,
            "success_count": 0,
            "blocked_count": 0,
            "referer_failures": 0
        }
        await db.users.insert_one(new_user)

    keyboard = await get_connect_keyboard(telegram_id, db)
    await callback.message.answer("Choose a shortener or add a new one:", reply_markup=keyboard)
    await callback.answer()

@router.callback_query(F.data == "add_shortener")
async def cb_add_shortener(callback: types.CallbackQuery, state: FSMContext):
    await callback.message.answer("Step 1: Enter your Shortener Base URL.\nExample: https://arolinks.com")
    await state.set_state(ConnectStates.waiting_for_url)
    await callback.answer()

@router.callback_query(F.data.startswith("sel_shortener:"))
async def cb_select_shortener(callback: types.CallbackQuery):
    name = callback.data.split(":", 1)[1]
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="👁️ View", callback_data=f"view_shortener:{name}"),
            InlineKeyboardButton(text="❌ Delete", callback_data=f"delete_shortener:{name}")
        ],
        [InlineKeyboardButton(text="⬅️ Back", callback_data="back_to_connect")]
    ])
    await callback.message.answer(f"Shortener: *{name}*\n\nChoose an action:", parse_mode="Markdown", reply_markup=keyboard)
    await callback.answer()

@router.callback_query(F.data.startswith("view_shortener:"))
async def cb_view_shortener(callback: types.CallbackQuery):
    name = callback.data.split(":", 1)[1]
    db = get_database()
    user = await db.users.find_one({"telegram_id": str(callback.from_user.id)})
    if not user:
        await callback.message.answer("❌ User not found.")
        await callback.answer()
        return

    shortener = None
    for s in user.get("shorteners", []):
        if s.get("name") == name:
            shortener = s
            break

    if not shortener:
        await callback.message.answer("❌ Shortener configuration not found.")
        await callback.answer()
        return

    original_api_key = decrypt_url(shortener.get("api_key"))
    abp_key = shortener.get("abp_key")

    await callback.message.answer(
        f"ℹ️ *Shortener Config Details:*\n\n"
        f"• *Name:* `{name}`\n"
        f"• *Base URL:* {settings.BASE_URL}\n"
        f"• *ABP API Key:* `{abp_key}`\n"
        f"• *Original API Key:* `{original_api_key}`",
        parse_mode="Markdown",
        reply_markup=get_start_keyboard()
    )
    await callback.answer()

@router.callback_query(F.data.startswith("delete_shortener:"))
async def cb_delete_shortener(callback: types.CallbackQuery):
    name = callback.data.split(":", 1)[1]
    db = get_database()
    telegram_id = str(callback.from_user.id)

    await db.users.update_one(
        {"telegram_id": telegram_id},
        {"$pull": {"shorteners": {"name": name}}}
    )
    await callback.message.answer(f"✅ Shortener *{name}* deleted successfully.", parse_mode="Markdown", reply_markup=get_start_keyboard())
    await callback.answer()

@router.callback_query(F.data == "back_to_connect")
async def cb_back_to_connect(callback: types.CallbackQuery):
    db = get_database()
    keyboard = await get_connect_keyboard(str(callback.from_user.id), db)
    await callback.message.answer("Choose a shortener or add a new one:", reply_markup=keyboard)
    await callback.answer()

@router.callback_query(F.data == "delete_account")
async def cb_delete_account(callback: types.CallbackQuery):
    db = get_database()
    telegram_id = str(callback.from_user.id)
    await db.users.delete_one({"telegram_id": telegram_id})
    await callback.message.answer("✅ Account deleted successfully.")
    await callback.answer()

@router.message(Command("connect"))
async def cmd_connect(message: types.Message):
    db = get_database()
    telegram_id = str(message.from_user.id)
    # Ensure user exists in db
    user = await db.users.find_one({"telegram_id": telegram_id})
    if not user:
        new_user = {
            "telegram_id": telegram_id,
            "username": message.from_user.username,
            "api_key": generate_api_key(),
            "shorteners": [],
            "created_at": datetime.utcnow(),
            "is_active": True,
            "total_requests": 0,
            "success_count": 0,
            "blocked_count": 0,
            "referer_failures": 0
        }
        await db.users.insert_one(new_user)

    keyboard = await get_connect_keyboard(telegram_id, db)
    await message.answer("Choose a shortener or add a new one:", reply_markup=keyboard)

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

    db = get_database()
    telegram_id = str(message.from_user.id)
    user_data = await db.users.find_one({"telegram_id": telegram_id})

    # Strict Duplicate check: Exact URL and API Key combination cannot be added more than once
    if user_data:
        for s in user_data.get("shorteners", []):
            existing_url = s.get("base_url", "").strip().rstrip('/')
            try:
                existing_api = decrypt_url(s.get("api_key", ""))
            except Exception:
                existing_api = ""
            if existing_url.lower() == url.lower() and existing_api == api_key:
                await message.answer(
                    "❌ This Shortener URL and API Key combination has already been added.\n\n"
                    "If you want to configure this URL again, you must use a different API Key!",
                    reply_markup=get_start_keyboard()
                )
                await state.clear()
                return

    await message.answer("⏳ Validating credentials...")

    # Validate the API key with the real shortener
    test_url = "https://google.com"
    validate_url = f"{url}/api?api={api_key}&url={test_url}"

    is_valid = False
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(validate_url, timeout=5.0)
            if resp.status_code == 200:
                result = resp.json()
                if result.get("status") == "success" or result.get("short_url"):
                    is_valid = True
    except Exception:
        pass

    # We make validation permissive as requested by user to avoid blocks on slow networks/fake tests
    if not is_valid:
        await message.answer("⚠️ Notice: Verification API returned an issue (or timeout), but proceeding with permissive setup!")

    encrypted_api_key = encrypt_url(api_key)
    new_abp_key = generate_api_key()

    # Parse domain as name
    parsed = urlparse(url)
    name = parsed.netloc or url
    if name.startswith("www."):
        name = name[4:]
    # Capitalize the first letter for gorgeous UI
    name = name.capitalize()

    new_shortener = {
        "name": name,
        "base_url": url,
        "api_key": encrypted_api_key,
        "abp_key": new_abp_key
    }

    if user_data:
        # Pull any existing shortener with the same name to avoid duplicates
        await db.users.update_one(
            {"telegram_id": telegram_id},
            {"$pull": {"shorteners": {"name": name}}}
        )
        # Push the new/updated shortener configuration
        await db.users.update_one(
            {"telegram_id": telegram_id},
            {"$push": {"shorteners": new_shortener}}
        )
    else:
        new_user = {
            "telegram_id": telegram_id,
            "username": message.from_user.username,
            "api_key": generate_api_key(),
            "shorteners": [new_shortener],
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
        f"✅ *Connected Successfully!*\n\n"
        f"• *Name:* `{name}`\n"
        f"• *Base URL:* {url}\n"
        f"• *Your New ABP API Key:* `{new_abp_key}`\n\n"
        f"Use this ABP API Key to route requests with anti-bypass protection!",
        parse_mode="Markdown",
        reply_markup=get_start_keyboard()
    )

@router.message(Command("api"))
async def cmd_api(message: types.Message):
    db = get_database()
    user = await db.users.find_one({"telegram_id": str(message.from_user.id)})
    if not user:
        await message.answer("❌ You are not connected. Use /connect first.", reply_markup=get_start_keyboard())
        return

    # Aggregate configured shortener names
    shorteners = user.get("shorteners", [])
    if not shorteners:
        await message.answer("❌ No shorteners connected yet. Use /connect to add one.", reply_markup=get_start_keyboard())
        return

    response = f"📋 *Your Configured Shorteners:* \n\n"
    for i, s in enumerate(shorteners, 1):
        response += (
            f"*{i}. {s.get('name')}*\n"
            f"• Base URL: {s.get('base_url')}\n"
            f"• ABP Key: `{s.get('abp_key')}`\n\n"
        )

    await message.answer(response, parse_mode="Markdown", reply_markup=get_start_keyboard())

@router.message(Command("regenerate"))
async def cmd_regenerate(message: types.Message):
    await message.answer("ℹ️ Shorteners possess individual unique ABP Keys. To reconnect or add a new shortener, use /connect.", reply_markup=get_start_keyboard())

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
