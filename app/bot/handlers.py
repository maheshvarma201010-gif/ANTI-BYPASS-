from aiogram import types, Router, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.exceptions import TelegramBadRequest
from app.bot.bot import bot
from app.models.database import get_database
from app.core.security import generate_api_key, encrypt_url, decrypt_url
from app.core.config import settings
from datetime import datetime
import httpx
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)
router = Router()

import random

async def safe_callback_answer(callback: types.CallbackQuery, *args, **kwargs):
    try:
        await callback.answer(*args, **kwargs)
    except TelegramBadRequest:
        pass
    except Exception as e:
        logger.warning(f"Error answering callback query: {e}")

async def get_active_banner_images() -> list[str]:
    db = get_database()
    images = []
    try:
        cfg = await db.settings.find_one({"key": "banner_images"})
        if cfg and isinstance(cfg.get("urls"), list) and len(cfg["urls"]) > 0:
            images = [u for u in cfg["urls"] if u and isinstance(u, str) and u.startswith("http")]
    except Exception as e:
        logger.warning(f"Error reading banner images from db: {e}")

    if not images:
        images = settings.get_image_urls()
    return images

import aiohttp

async def fetch_valid_photo(images: list[str]) -> tuple[types.BufferedInputFile | str | None, str | None]:
    if not images:
        return None, None

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    shuffled = images.copy()
    random.shuffle(shuffled)

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            for url in shuffled[:5]:
                try:
                    async with session.get(url, timeout=4.0) as resp:
                        if resp.status == 200:
                            ct = resp.headers.get("content-type", "").lower()
                            if "image" in ct or url.lower().endswith((".jpg", ".jpeg", ".png", ".webp", ".gif")):
                                content = await resp.read()
                                filename = url.split("/")[-1].split("?")[0] or "banner.jpg"
                                input_file = types.BufferedInputFile(content, filename=filename)
                                return input_file, url
                except Exception:
                    pass
    except Exception:
        pass

    # If HTTP download failed or returned 404, fallback to passing raw URL directly
    if shuffled:
        fallback_url = shuffled[0]
        return fallback_url, fallback_url

    return None, None

async def send_bot_msg(
    target: types.Message | types.CallbackQuery,
    text: str,
    reply_markup=None,
    parse_mode="HTML"
):
    images = await get_active_banner_images()
    msg_obj = target.message if isinstance(target, types.CallbackQuery) else target

    # Telegram caption limit is 1024 characters. Send photo with caption only if text <= 1024 chars.
    if images and len(text) <= 1024:
        buffered_photo, raw_url = await fetch_valid_photo(images)
        if buffered_photo:
            try:
                return await msg_obj.answer_photo(
                    photo=buffered_photo,
                    caption=text,
                    parse_mode=parse_mode,
                    reply_markup=reply_markup
                )
            except Exception as e:
                logger.warning(f"Failed to send BufferedInputFile photo ({raw_url}): {e}")

    return await msg_obj.answer(
        text=text,
        parse_mode=parse_mode,
        reply_markup=reply_markup
    )

class ConnectStates(StatesGroup):
    waiting_for_url = State()
    waiting_for_api_key = State()
    waiting_for_manual_start_time = State()
    waiting_for_manual_end_time = State()
    waiting_for_admin_images = State()

def get_start_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⚡ Connect Shortener", callback_data="connect_shortener")],
        [InlineKeyboardButton(text="📋 My API Keys", callback_data="view_api_keys")],
        [InlineKeyboardButton(text="📊 Realtime Stats", callback_data="view_stats")],
        [InlineKeyboardButton(text="📖 Usage Guide & Help", callback_data="view_help")],
        [InlineKeyboardButton(text="🗑️ Delete Account", callback_data="delete_account")]
    ])

async def get_connect_keyboard(telegram_id: str, db):
    user = await db.users.find_one({"telegram_id": telegram_id})
    buttons = []
    if user:
        for s in user.get("shorteners", []):
            name = s.get("name")
            if name:
                buttons.append([InlineKeyboardButton(text=f"🔗 {name}", callback_data=f"sel_shortener:{name}")])

    buttons.append([InlineKeyboardButton(text="➕ Add New Shortener", callback_data="add_shortener")])
    buttons.append([InlineKeyboardButton(text="⬅️ Back to Main Menu", callback_data="back_to_main")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)

@router.message(Command("start"))
async def cmd_start(message: types.Message):
    welcome_text = (
        "<b>💎 Anti-Bypass Protection Service</b>\n\n"
        "<blockquote>Welcome to the official <b>Anti-Bypass Protection Bot</b>.\n"
        "Safeguard your shortlinks against automated scrapers, bookmarklets, and bypass tools in real time.</blockquote>\n\n"
        "<b>✨ Features:</b>\n"
        "• <code>Multi-Shortener Support</code> - Connect unlimited shortener accounts.\n"
        "• <code>Dual Modes</code> - Choose between <b>NORMAL</b> and <b>MANUAL</b> timer modes.\n"
        "• <code>Instant Alerts</code> - Get real-time notifications on bypass attempts.\n"
        "• <code>Browser Enforcement</code> - Strict Referer and DOM sandboxing.\n\n"
        "<i>Click below to connect your shorteners and protect your income!</i>"
    )
    await send_bot_msg(message, welcome_text, reply_markup=get_start_keyboard())

@router.message(Command("help"))
async def cmd_help(message: types.Message):
    help_text = (
        "<b>📖 Comprehensive Guide & Bot Documentation</b>\n\n"
        "<blockquote><b>Anti-Bypass Protection Bot</b> is designed to insulate your URL shorteners from bypass tools (e.g. NickTrick, Tampermonkey, Greasefork, and automated API scripts).</blockquote>\n\n"
        "<b>🚀 Key Commands:</b>\n"
        "• <code>/start</code> - Display main menu dashboard.\n"
        "• <code>/connect</code> - Connect, view, or configure shorteners.\n"
        "• <code>/api</code> - View all generated Anti-Bypass (ABP) API keys.\n"
        "• <code>/stats</code> - Monitor real-time traffic & blocked bypass metrics.\n"
        "• <code>/panel</code> - Admin Panel (Banner Images & Configuration).\n"
        "• <code>/help</code> - Show this detailed help manual.\n"
        "• <code>/delete</code> - Remove account and all stored configurations.\n\n"
        "<b>⚙️ Verification Modes:</b>\n"
        "1. <b>NORMAL Mode:</b> Instant browser integrity check, Referer verification, and DOM sandboxing.\n"
        "2. <b>MANUAL Mode:</b> Custom timer-based window (e.g. 20s to 40s) where links expire if completed outside the window.\n\n"
        "<b>🔌 API Integration:</b>\n"
        "Replace your default shortener API key with your generated <b>ABP API Key</b>:\n"
        "<code>https://antibypass.koyeb.app/api?api=YOUR_ABP_KEY&url=TARGET_URL</code>"
    )
    await send_bot_msg(message, help_text, reply_markup=get_start_keyboard())

@router.callback_query(F.data == "view_help")
async def cb_view_help(callback: types.CallbackQuery):
    await cmd_help(callback)
    await safe_callback_answer(callback)

@router.callback_query(F.data == "back_to_main")
async def cb_back_to_main(callback: types.CallbackQuery):
    welcome_text = (
        "<b>💎 Anti-Bypass Protection Service</b>\n\n"
        "<blockquote>Main Menu Dashboard. Choose an action below:</blockquote>"
    )
    await send_bot_msg(callback, welcome_text, reply_markup=get_start_keyboard())
    await safe_callback_answer(callback)

@router.callback_query(F.data == "connect_shortener")
async def cb_connect_button(callback: types.CallbackQuery, state: FSMContext):
    db = get_database()
    telegram_id = str(callback.from_user.id)
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
    await send_bot_msg(
        callback,
        "<b>🔗 Connect & Manage Shorteners</b>\n\n"
        "<blockquote>Select an existing shortener from the list to modify its mode, or click <b>Add New Shortener</b> to connect a new one:</blockquote>",
        reply_markup=keyboard
    )
    await safe_callback_answer(callback)

@router.callback_query(F.data == "add_shortener")
async def cb_add_shortener(callback: types.CallbackQuery, state: FSMContext):
    await send_bot_msg(
        callback,
        "<b>➕ Step 1: Enter Shortener Base URL</b>\n\n"
        "<blockquote>Please send the base domain URL of your shortener.\n"
        "<b>Example:</b> <code>https://example.com</code></blockquote>"
    )
    await state.set_state(ConnectStates.waiting_for_url)
    await safe_callback_answer(callback)

@router.callback_query(F.data.startswith("sel_shortener:"))
async def cb_select_shortener(callback: types.CallbackQuery):
    name = callback.data.split(":", 1)[1]
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="👁️ View Details & Mode", callback_data=f"view_shortener:{name}"),
            InlineKeyboardButton(text="❌ Delete Shortener", callback_data=f"delete_shortener:{name}")
        ],
        [InlineKeyboardButton(text="⬅️ Back", callback_data="back_to_connect")]
    ])
    await send_bot_msg(
        callback,
        f"<b>⚙️ Shortener Settings: <code>{name}</code></b>\n\n"
        "<blockquote>Select an action to inspect or update mode settings:</blockquote>",
        reply_markup=keyboard
    )
    await safe_callback_answer(callback)

@router.callback_query(F.data.startswith("view_shortener:"))
async def cb_view_shortener(callback: types.CallbackQuery):
    name = callback.data.split(":", 1)[1]
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="1. NORMAL Mode", callback_data=f"mode_normal:{name}"),
            InlineKeyboardButton(text="2. MANUAL Mode", callback_data=f"mode_manual:{name}")
        ],
        [InlineKeyboardButton(text="⬅️ Back", callback_data=f"sel_shortener:{name}")]
    ])
    await send_bot_msg(
        callback,
        f"<b>⚙️ Configure Verification Mode for <code>{name}</code>:</b>\n\n"
        f"<blockquote><b>1. NORMAL Mode:</b> Standard browser integrity verification.\n"
        f"<b>2. MANUAL Mode:</b> Custom timer-based verification window.</blockquote>",
        reply_markup=keyboard
    )
    await safe_callback_answer(callback)

@router.callback_query(F.data.startswith("mode_normal:"))
async def cb_mode_normal(callback: types.CallbackQuery):
    name = callback.data.split(":", 1)[1]
    db = get_database()
    telegram_id = str(callback.from_user.id)
    user = await db.users.find_one({"telegram_id": telegram_id})
    if not user:
        await send_bot_msg(callback, "<b>❌ User profile not found.</b>")
        await safe_callback_answer(callback)
        return

    await db.users.update_one(
        {"telegram_id": telegram_id, "shorteners.name": name},
        {"$set": {"shorteners.$.mode": "NORMAL"}}
    )

    shortener = next((s for s in user.get("shorteners", []) if s.get("name") == name), None)

    if not shortener:
        await send_bot_msg(callback, "<b>❌ Shortener configuration not found.</b>")
        await safe_callback_answer(callback)
        return

    original_api_key = decrypt_url(shortener.get("api_key"))
    base_url = settings.BASE_URL if settings.BASE_URL else "https://antibypass.koyeb.app"
    abp_key = shortener.get("abp_key")

    await send_bot_msg(
        callback,
        f"<b>✅ NORMAL Mode Active for <code>{name}</code></b>\n\n"
        f"<blockquote>• <b>Shortener Name:</b> <code>{name}</code>\n"
        f"• <b>Mode:</b> <code>NORMAL</code>\n"
        f"• <b>Anti-Bypass Base URL:</b> <code>{base_url}</code>\n"
        f"• <b>ABP API Key:</b> <code>{abp_key}</code>\n"
        f"• <b>Original API Key:</b> <code>{original_api_key}</code></blockquote>",
        reply_markup=get_start_keyboard()
    )
    await safe_callback_answer(callback)

@router.callback_query(F.data.startswith("mode_manual:"))
async def cb_mode_manual(callback: types.CallbackQuery, state: FSMContext):
    name = callback.data.split(":", 1)[1]
    await state.update_data(shortener_name=name)
    await state.set_state(ConnectStates.waiting_for_manual_start_time)
    await send_bot_msg(
        callback,
        f"<b>⏱️ MANUAL Mode Setup for <code>{name}</code></b>\n\n"
        f"<blockquote><b>Step 1:</b> Enter the minimum delay/start time in seconds.\n"
        f"<b>Example:</b> Send <code>200</code> for 200 seconds.</blockquote>"
    )
    await safe_callback_answer(callback)

@router.message(ConnectStates.waiting_for_manual_start_time)
async def process_manual_start_time(message: types.Message, state: FSMContext):
    text = message.text.strip()
    if not text.isdigit() or int(text) < 0:
        await send_bot_msg(
            message,
            "<b>❌ Invalid Input</b>\n\n<blockquote>Please enter a valid integer number of seconds (e.g. <code>200</code>).</blockquote>"
        )
        return

    start_seconds = int(text)
    await state.update_data(manual_start_seconds=start_seconds)
    await state.set_state(ConnectStates.waiting_for_manual_end_time)
    await send_bot_msg(
        message,
        f"<b>⏱️ Step 2: Enter End Time</b>\n\n"
        f"<blockquote>Enter the maximum valid time in seconds.\n"
        f"<b>Example:</b> Send <code>220</code> (must be >= <code>{start_seconds}</code> seconds).</blockquote>"
    )

@router.message(ConnectStates.waiting_for_manual_end_time)
async def process_manual_end_time(message: types.Message, state: FSMContext):
    text = message.text.strip()
    if not text.isdigit() or int(text) < 0:
        await send_bot_msg(
            message,
            "<b>❌ Invalid Input</b>\n\n<blockquote>Please enter a valid integer number of seconds (e.g. <code>220</code>).</blockquote>"
        )
        return

    end_seconds = int(text)
    data = await state.get_data()
    start_seconds = data.get("manual_start_seconds", 0)

    if end_seconds < start_seconds:
        await send_bot_msg(
            message,
            f"<b>❌ Invalid Time Window</b>\n\n<blockquote>End time (<code>{end_seconds}s</code>) cannot be less than start time (<code>{start_seconds}s</code>). Please try again.</blockquote>"
        )
        return

    name = data.get("shortener_name")

    db = get_database()
    telegram_id = str(message.from_user.id)
    user = await db.users.find_one({"telegram_id": telegram_id})
    if not user:
        await send_bot_msg(message, "<b>❌ User profile not found.</b>")
        await state.clear()
        return

    shortener = next((s for s in user.get("shorteners", []) if s.get("name") == name), None)

    if not shortener:
        await send_bot_msg(message, "<b>❌ Shortener configuration not found.</b>")
        await state.clear()
        return

    manual_abp_key = shortener.get("manual_abp_key") or generate_api_key()

    await db.users.update_one(
        {"telegram_id": telegram_id, "shorteners.name": name},
        {"$set": {
            "shorteners.$.mode": "MANUAL",
            "shorteners.$.manual_min_seconds": start_seconds,
            "shorteners.$.manual_max_seconds": end_seconds,
            "shorteners.$.manual_abp_key": manual_abp_key
        }}
    )

    base_url = settings.BASE_URL if settings.BASE_URL else "https://antibypass.koyeb.app"

    await state.clear()
    await send_bot_msg(
        message,
        f"<b>✅ MANUAL Mode Configured for <code>{name}</code></b>\n\n"
        f"<blockquote>• <b>Mode:</b> <code>MANUAL</code>\n"
        f"• <b>Anti-Bypass Base URL:</b> <code>{base_url}</code>\n"
        f"• <b>Verification Window:</b> <code>{start_seconds}s</code> - <code>{end_seconds}s</code>\n"
        f"• <b>MANUAL ABP API Key:</b> <code>{manual_abp_key}</code></blockquote>\n\n"
        "<i>Verification will only succeed if completed within the valid timer window.</i>",
        reply_markup=get_start_keyboard()
    )

@router.callback_query(F.data.startswith("delete_shortener:"))
async def cb_delete_shortener(callback: types.CallbackQuery):
    name = callback.data.split(":", 1)[1]
    db = get_database()
    telegram_id = str(callback.from_user.id)

    await db.users.update_one(
        {"telegram_id": telegram_id},
        {"$pull": {"shorteners": {"name": name}}}
    )
    await send_bot_msg(
        callback,
        f"<b>✅ Shortener Deleted</b>\n\n<blockquote>Shortener <code>{name}</code> has been removed from your account.</blockquote>",
        reply_markup=get_start_keyboard()
    )
    await safe_callback_answer(callback)

@router.callback_query(F.data == "back_to_connect")
async def cb_back_to_connect(callback: types.CallbackQuery):
    db = get_database()
    keyboard = await get_connect_keyboard(str(callback.from_user.id), db)
    await send_bot_msg(
        callback,
        "<b>🔗 Connect & Manage Shorteners</b>\n\n<blockquote>Choose a shortener or add a new one:</blockquote>",
        reply_markup=keyboard
    )
    await safe_callback_answer(callback)

@router.callback_query(F.data == "delete_account")
async def cb_delete_account(callback: types.CallbackQuery):
    db = get_database()
    telegram_id = str(callback.from_user.id)
    await db.users.delete_one({"telegram_id": telegram_id})
    await send_bot_msg(
        callback,
        "<b>✅ Account Deleted</b>\n\n<blockquote>Your account and connected shorteners have been permanently removed.</blockquote>"
    )
    await safe_callback_answer(callback)

@router.message(Command("connect"))
async def cmd_connect(message: types.Message):
    db = get_database()
    telegram_id = str(message.from_user.id)
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
    await send_bot_msg(
        message,
        "<b>🔗 Connect & Manage Shorteners</b>\n\n<blockquote>Choose a shortener or add a new one:</blockquote>",
        reply_markup=keyboard
    )

@router.message(ConnectStates.waiting_for_url)
async def process_url(message: types.Message, state: FSMContext):
    url = message.text.strip().rstrip('/')
    if not url.startswith("http"):
        await send_bot_msg(
            message,
            "<b>❌ Invalid URL</b>\n\n<blockquote>Please send a valid URL starting with <code>http://</code> or <code>https://</code>.</blockquote>"
        )
        return
    await state.update_data(url=url)
    await send_bot_msg(
        message,
        "<b>🔑 Step 2: Enter Shortener API Key</b>\n\n<blockquote>Send the API key provided by your shortener platform.</blockquote>"
    )
    await state.set_state(ConnectStates.waiting_for_api_key)

@router.message(ConnectStates.waiting_for_api_key)
async def process_api_key(message: types.Message, state: FSMContext):
    api_key = message.text.strip()
    data = await state.get_data()
    url = data['url']

    db = get_database()
    telegram_id = str(message.from_user.id)
    user_data = await db.users.find_one({"telegram_id": telegram_id})

    if user_data:
        for s in user_data.get("shorteners", []):
            existing_url = s.get("base_url", "").strip().rstrip('/')
            try:
                existing_api = decrypt_url(s.get("api_key", ""))
            except Exception:
                existing_api = ""
            if existing_url.lower() == url.lower() and existing_api == api_key:
                await send_bot_msg(
                    message,
                    "<b>❌ Duplicate Shortener Entry</b>\n\n<blockquote>This Shortener URL and API Key combination is already connected.</blockquote>",
                    reply_markup=get_start_keyboard()
                )
                await state.clear()
                return

    await send_bot_msg(message, "<b>⏳ Validating credentials...</b>")

    encrypted_api_key = encrypt_url(api_key)
    new_abp_key = generate_api_key()

    parsed = urlparse(url)
    name = parsed.netloc or url
    if name.startswith("www."):
        name = name[4:]
    name = name.capitalize()

    existing_names = {s.get("name", "").lower() for s in user_data.get("shorteners", [])} if user_data else set()
    unique_name = name
    counter = 1
    while unique_name.lower() in existing_names:
        counter += 1
        unique_name = f"{name} {counter}"

    new_shortener = {
        "name": unique_name,
        "base_url": url,
        "api_key": encrypted_api_key,
        "abp_key": new_abp_key
    }

    if user_data:
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
    base_app_url = settings.BASE_URL if settings.BASE_URL else "https://antibypass.koyeb.app"

    await send_bot_msg(
        message,
        f"<b>✅ Connected Successfully!</b>\n\n"
        f"<blockquote>• <b>Shortener Name:</b> <code>{unique_name}</code>\n"
        f"• <b>Base Target URL:</b> {url}\n"
        f"• <b>Anti-Bypass Base URL:</b> <code>{base_app_url}</code>\n"
        f"• <b>Generated ABP API Key:</b> <code>{new_abp_key}</code></blockquote>\n\n"
        "<i>Use this ABP API Key to route links with real-time anti-bypass protection!</i>",
        reply_markup=get_start_keyboard()
    )

@router.message(Command("api"))
async def cmd_api(message: types.Message):
    await cb_view_api_keys(message)

@router.callback_query(F.data == "view_api_keys")
async def cb_view_api_keys(target: types.Message | types.CallbackQuery):
    user_id = str(target.from_user.id)
    db = get_database()
    user = await db.users.find_one({"telegram_id": user_id})
    if not user:
        await send_bot_msg(target, "<b>❌ Profile not found. Use /connect first.</b>", reply_markup=get_start_keyboard())
        return

    shorteners = user.get("shorteners", [])
    if not shorteners:
        await send_bot_msg(target, "<b>❌ No connected shorteners found. Use /connect to add one.</b>", reply_markup=get_start_keyboard())
        return

    base_app_url = settings.BASE_URL if settings.BASE_URL else "https://antibypass.koyeb.app"

    response = "<b>📋 Your Configured Shorteners & ABP Keys:</b>\n\n"
    for i, s in enumerate(shorteners, 1):
        mode = s.get("mode", "NORMAL")
        abp = s.get("manual_abp_key") if mode == "MANUAL" else s.get("abp_key")
        response += (
            f"<b>{i}. {s.get('name')}</b>\n"
            f"<blockquote>• <b>Mode:</b> <code>{mode}</code>\n"
            f"• <b>Target Base URL:</b> {s.get('base_url')}\n"
            f"• <b>Anti-Bypass Service URL:</b> <code>{base_app_url}</code>\n"
            f"• <b>ABP API Key:</b> <code>{abp}</code></blockquote>\n\n"
        )

    await send_bot_msg(target, response, reply_markup=get_start_keyboard())
    if isinstance(target, types.CallbackQuery):
        await safe_callback_answer(target)

@router.message(Command("regenerate"))
async def cmd_regenerate(message: types.Message):
    await send_bot_msg(
        message,
        "<b>ℹ️ ABP Key Management</b>\n\n<blockquote>Each connected shortener possesses its own unique ABP API key. To reconnect or add new ones, use /connect.</blockquote>",
        reply_markup=get_start_keyboard()
    )

@router.message(Command("stats"))
async def cmd_stats(message: types.Message):
    await cb_view_stats(message)

@router.callback_query(F.data == "view_stats")
async def cb_view_stats(target: types.Message | types.CallbackQuery):
    user_id = str(target.from_user.id)
    db = get_database()
    user = await db.users.find_one({"telegram_id": user_id})
    if not user:
        await send_bot_msg(target, "<b>❌ User profile not found.</b>", reply_markup=get_start_keyboard())
        return

    stats_text = (
        "<b>📊 Real-Time Protection Statistics</b>\n\n"
        f"<blockquote>• <b>Total Requests:</b> <code>{user.get('total_requests', 0)}</code>\n"
        f"• <b>Successful Verification:</b> <code>{user.get('success_count', 0)}</code>\n"
        f"• <b>Bypass Attempts Blocked:</b> <code>{user.get('blocked_count', 0)}</code>\n"
        f"• <b>Referer Validation Failures:</b> <code>{user.get('referer_failures', 0)}</code></blockquote>"
    )
    await send_bot_msg(target, stats_text, reply_markup=get_start_keyboard())
    if isinstance(target, types.CallbackQuery):
        await safe_callback_answer(target)

@router.message(Command("delete"))
async def cmd_delete(message: types.Message):
    db = get_database()
    telegram_id = str(message.from_user.id)
    await db.users.delete_one({"telegram_id": telegram_id})
    await send_bot_msg(message, "<b>✅ Account deleted successfully.</b>", reply_markup=get_start_keyboard())

# ================= ADMIN PANEL HANDLERS =================
def is_admin(user_id: int | str) -> bool:
    admin_list = settings.get_admin_ids()
    if not admin_list:
        # Require explicit admin ID configuration for safety
        return False
    return str(user_id) in admin_list

def get_panel_keyboard():
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="🖼️ View Images", callback_data="panel_view_images"),
            InlineKeyboardButton(text="➕ Add Bulk Images", callback_data="panel_add_images")
        ],
        [
            InlineKeyboardButton(text="🗑️ Clear Images", callback_data="panel_clear_images")
        ]
    ])

@router.message(Command("panel"))
async def cmd_panel(message: types.Message):
    if not is_admin(message.from_user.id):
        await send_bot_msg(
            message,
            "<b>🚫 Access Denied</b>\n\n<blockquote>You do not have administrative privileges to access the panel.</blockquote>"
        )
        return

    images = await get_active_banner_images()
    count = len(images)
    panel_text = (
        "<b>⚡ Admin Panel & Banner Manager</b>\n\n"
        f"<blockquote>• <b>Total Banner Images:</b> <code>{count}</code>\n"
        f"• <b>Status:</b> {'Active (Randomly Selected)' if count > 0 else 'No Images (Text Only Mode)'}</blockquote>\n\n"
        "<i>Select an option below to manage banner URLs:</i>"
    )
    await send_bot_msg(message, panel_text, reply_markup=get_panel_keyboard())

@router.callback_query(F.data == "panel_view_images")
async def cb_panel_view_images(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await safe_callback_answer(callback, "Unauthorized", show_alert=True)
        return

    images = await get_active_banner_images()
    if not images:
        await send_bot_msg(
            callback,
            "<b>🖼️ Banner Images List</b>\n\n<blockquote>No banner image URLs configured yet. Sending messages in text-only mode.</blockquote>",
            reply_markup=get_panel_keyboard()
        )
        await safe_callback_answer(callback)
        return

    text = f"<b>🖼️ Configured Banner Images ({len(images)} total):</b>\n\n"
    for i, url_item in enumerate(images[:50], 1):
        text += f"{i}. <code>{url_item}</code>\n"

    if len(images) > 50:
        text += f"\n<i>...and {len(images) - 50} more images.</i>"

    await send_bot_msg(callback, text, reply_markup=get_panel_keyboard())
    await safe_callback_answer(callback)

@router.callback_query(F.data == "panel_add_images")
async def cb_panel_add_images(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin(callback.from_user.id):
        await safe_callback_answer(callback, "Unauthorized", show_alert=True)
        return

    await state.set_state(ConnectStates.waiting_for_admin_images)
    await send_bot_msg(
        callback,
        "<b>➕ Add Bulk Banner Image URLs</b>\n\n"
        "<blockquote>Send image URLs (starting with <code>http://</code> or <code>https://</code>).\n"
        "You can send 100+ URLs in a single message separated by spaces, newlines, or commas!</blockquote>"
    )
    await safe_callback_answer(callback)

@router.message(ConnectStates.waiting_for_admin_images)
async def process_admin_images(message: types.Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        await state.clear()
        return

    raw_text = message.text.strip()
    raw_urls = [u.strip() for u in raw_text.replace(",", " ").replace("\n", " ").split() if u.strip()]
    valid_urls = [u for u in raw_urls if u.startswith("http://") or u.startswith("https://")]

    if not valid_urls:
        await send_bot_msg(
            message,
            "<b>❌ Invalid Input</b>\n\n<blockquote>No valid HTTP/HTTPS URLs were found in your message. Please try again.</blockquote>"
        )
        return

    db = get_database()
    existing_cfg = await db.settings.find_one({"key": "banner_images"})
    current_urls = existing_cfg.get("urls", []) if existing_cfg else []

    # Merge while removing duplicates
    seen = set(current_urls)
    new_added = 0
    for u in valid_urls:
        if u not in seen:
            seen.add(u)
            current_urls.append(u)
            new_added += 1

    await db.settings.update_one(
        {"key": "banner_images"},
        {"$set": {"urls": current_urls, "updated_at": datetime.utcnow()}},
        upsert=True
    )

    await state.clear()
    await send_bot_msg(
        message,
        f"<b>✅ Banner Images Added Successfully!</b>\n\n"
        f"<blockquote>• <b>New Added:</b> <code>{new_added}</code>\n"
        f"• <b>Total Stored Banner URLs:</b> <code>{len(current_urls)}</code></blockquote>",
        reply_markup=get_panel_keyboard()
    )

@router.callback_query(F.data == "panel_clear_images")
async def cb_panel_clear_images(callback: types.CallbackQuery):
    if not is_admin(callback.from_user.id):
        await safe_callback_answer(callback, "Unauthorized", show_alert=True)
        return

    db = get_database()
    await db.settings.delete_one({"key": "banner_images"})
    await send_bot_msg(
        callback,
        "<b>🗑️ Banner Images Cleared!</b>\n\n<blockquote>All banner images have been removed. Bot will send messages in text-only mode.</blockquote>",
        reply_markup=get_panel_keyboard()
    )
    await safe_callback_answer(callback)
