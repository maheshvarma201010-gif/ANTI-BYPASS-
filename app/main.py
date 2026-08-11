from fastapi import FastAPI, Request, Depends, HTTPException, Body, Query
from fastapi.responses import HTMLResponse
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.referer import get_bridge_page_html, handle_validation

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(api_router)

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

import secrets
import time
from fastapi.responses import RedirectResponse
from urllib.parse import urlparse
from app.core.referer import is_allowed_referer, is_related_domain, is_whitelisted_user, is_development_environment, get_user_verification_history, is_legitimate_no_referer
from bson import ObjectId

BYPASS_DETECTED_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>⛔ BYPASS DETECTED — SECURITY BREACH LOGGED</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap');
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: radial-gradient(circle at top, #7f0000, #1a0000 70%);
            background-color: #1a0000;
        }
        .glass-panel {
            background: rgba(20, 0, 0, 0.85);
            backdrop-filter: blur(10px);
            border: 2px solid rgba(255, 0, 0, 0.5);
            box-shadow: 0 0 60px rgba(255,0,0,0.35), inset 0 0 40px rgba(255,0,0,0.08);
        }
        .siren { animation: siren 1s infinite; }
        @keyframes siren {
            0%, 100% { color: #ff1a1a; text-shadow: 0 0 20px #ff0000; }
            50% { color: #ff6666; text-shadow: 0 0 40px #ff0000, 0 0 10px #fff; }
        }
        .pulse-ring {
            animation: pulse-ring 1.4s cubic-bezier(0.4,0,0.6,1) infinite;
        }
        @keyframes pulse-ring {
            0% { box-shadow: 0 0 0 0 rgba(255,0,0,0.7); }
            70% { box-shadow: 0 0 0 25px rgba(255,0,0,0); }
            100% { box-shadow: 0 0 0 0 rgba(255,0,0,0); }
        }
        .shake { animation: shake 0.4s ease-in-out infinite; }
        @keyframes shake {
            0%,100% { transform: translateX(0); }
            25% { transform: translateX(-2px) rotate(-0.5deg); }
            75% { transform: translateX(2px) rotate(0.5deg); }
        }
        .stripe-bar {
            background: repeating-linear-gradient(45deg, #ff0000, #ff0000 12px, #1a0000 12px, #1a0000 24px);
        }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-lg glass-panel rounded-3xl overflow-hidden p-8 md:p-10 text-center relative">
        <div class="absolute top-0 left-0 right-0 h-3 stripe-bar"></div>

        <div class="mx-auto w-28 h-28 mb-6 mt-2 bg-red-950 rounded-full flex items-center justify-center border-4 border-red-600 pulse-ring shake">
            <span class="siren text-5xl"><i class="fa-solid fa-triangle-exclamation"></i></span>
        </div>

        <h1 class="text-4xl font-extrabold tracking-tight mb-2 siren">
            ⛔ BYPASS DETECTED
        </h1>
        <p class="text-red-300 text-sm font-bold uppercase tracking-widest mb-6">
            Unauthorized Access Attempt — Logged &amp; Reported
        </p>

        <div class="bg-red-950/80 border-2 border-red-600 rounded-2xl p-5 mb-6">
            <p class="text-sm font-bold text-red-200 leading-relaxed">
                🚨 Our security system has flagged this request as a deliberate circumvention attempt.
                This incident has been recorded, timestamped, and reported to the link owner.
            </p>
        </div>

        <div class="text-left mb-8 space-y-3 bg-black/40 border border-red-800 rounded-2xl p-5">
            <span class="text-xs font-bold uppercase tracking-wider text-red-400 block mb-2">
                <i class="fa-solid fa-skull"></i> This will keep happening if you:
            </span>
            <div class="flex items-start gap-3 text-sm text-red-200">
                <span class="text-red-500 mt-0.5"><i class="fa-solid fa-xmark"></i></span>
                <p>Paste, share, or bookmark the continuation link.</p>
            </div>
            <div class="flex items-start gap-3 text-sm text-red-200">
                <span class="text-red-500 mt-0.5"><i class="fa-solid fa-xmark"></i></span>
                <p>Skip the original shortlink and jump straight to this page.</p>
            </div>
            <div class="flex items-start gap-3 text-sm text-red-200">
                <span class="text-red-500 mt-0.5"><i class="fa-solid fa-xmark"></i></span>
                <p>Use a bot, script, or bypass tool to fake a session.</p>
            </div>
        </div>

        <div class="border-t-2 border-red-800 pt-6">
            <p class="text-lg font-extrabold text-red-400 mb-1 siren">
                GO BACK. START OVER. NO SHORTCUTS.
            </p>
            <p class="text-xs text-red-500/70 mt-2">Incident ID logged for review.</p>
        </div>
    </div>
</body>
</html>
"""

import httpx
import logging

logger = logging.getLogger(__name__)

def get_client_ip(request: Request) -> str:
    # Check Cloudflare
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()

    # Check X-Forwarded-For
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = xff.split(",")
        if parts:
            return parts[0].strip()

    return request.client.host if request.client else "unknown"

async def send_bypass_notification(user_id: ObjectId, short_id: str, reason: str, request: Request, db):
    try:
        user = await db.users.find_one({"_id": user_id})
        if not user or not user.get("telegram_id"):
            return

        telegram_id = user["telegram_id"]
        bot_token = settings.TELEGRAM_BOT_TOKEN
        if not bot_token:
            return

        # Fetch latest statistics for the user
        total_requests = user.get("total_requests", 0)
        success_count = user.get("success_count", 0)
        blocked_count = user.get("blocked_count", 0)
        referer_failures = user.get("referer_failures", 0)

        # Get client details
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "Unknown")

        text = (
            f"🚫 *BYPASS DETECTED*\n\n"
            f"⚡ *Link Short ID:* `{short_id}`\n"
            f"⚠️ *Reason:* `{reason}`\n\n"
            f"ℹ️ *Client Information:*\n"
            f"• *IP:* `{client_ip}`\n"
            f"• *User-Agent:* `{user_agent}`\n\n"
            f"📊 *Your Statistics:*\n"
            f"• *Total Requests:* {total_requests}\n"
            f"• *Successful:* {success_count}\n"
            f"• *Blocked Attempts:* {blocked_count}\n"
            f"• *Referer Failures:* {referer_failures}"
        )

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": telegram_id,
            "text": text,
            "parse_mode": "Markdown"
        }

        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload, timeout=5.0)
    except Exception as e:
        logger.error(f"Failed to send Telegram notification: {e}")

@app.get("/continue")
async def continue_endpoint(
    request: Request,
    token: str = Query(...),
    db = Depends(get_database)
):
    cookie_session_id = request.cookies.get("session_id")
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    referer = request.headers.get("referer", "")

    # Direct paste/share protection of the redirect URL: Referer must be present on internal continuation redirect
    if not referer:
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # Retrieve session bound to token
    session = await db.sessions.find_one({"token": token})

    # Protection 1: Invalid/missing token
    if not session:
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    user_id_str = session.get("user_id")
    user_id = ObjectId(user_id_str) if user_id_str else None
    short_id = session.get("short_id", "unknown")

    # Protection 2: Expired verification sessions
    # Tokens expire after 300 seconds for slow networks
    if time.time() - session["created_at"] > 300:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Expired verification session", request, db)
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # Protection 3: Reusing an already completed/consumed verification session
    if session.get("consumed", False):
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # Protection 4: Session validation (either Cookie match OR fallback to IP+UA match if cookies blocked/incognito)
    cookie_valid = cookie_session_id and cookie_session_id == session["session_id"]
    fallback_valid = (not cookie_session_id) and (session["client_ip"] == client_ip) and (session["user_agent"] == user_agent)

    if not (cookie_valid or fallback_valid):
        # Determine specific reason for clear security page details
        if cookie_session_id and cookie_session_id != session["session_id"]:
            reason = "Session mismatch"
        elif session["user_agent"] != user_agent:
            reason = "Session client mismatch"
        else:
            reason = "Session validation failed"

        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, reason, request, db)
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # Consume/invalidate token atomically server-side to prevent TOCTOU race conditions / parallel replay
    result = await db.sessions.update_one(
        {"_id": session["_id"], "consumed": False},
        {"$set": {"consumed": True}}
    )
    if result.modified_count == 0:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # Retrieve real/original destination URL
    destination_url = session["original_url"]

    # Redirect to the final destination
    return RedirectResponse(url=destination_url, status_code=302)

def check_referer_root(ref_netloc: str, shortener_domain: str) -> bool:
    if not ref_netloc or not shortener_domain:
        return False

    def get_root_name(domain: str) -> str:
        parts = domain.split('.')
        common_tlds = {"com", "co", "net", "org", "info", "io", "in", "xyz", "biz", "us", "uk", "cc", "me", "top", "online", "site", "live", "club", "tech", "work"}
        valid_parts = [p for p in parts if p not in common_tlds and p != "www" and p != "link" and p != "st" and p != "api"]
        if valid_parts:
            return valid_parts[0]
        return parts[0]

    shortener_root = get_root_name(shortener_domain).lower()
    ref_root = get_root_name(ref_netloc).lower()

    if shortener_root and ref_root and (shortener_root in ref_netloc or ref_root in shortener_domain):
        return True
    return False

@app.get("/{short_id}")
async def original_shortlink(
    request: Request,
    short_id: str,
    db = Depends(get_database)
):
    # Health and special routes exceptions
    if short_id in ["health", "continue"]:
        raise HTTPException(status_code=404)

    # 1. Fetch the mapping
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    user_id = ObjectId(link['user_id'])
    user = await db.users.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    referer = request.headers.get("referer", "")

    # ============== REFERER VALIDATION ==============
    # We do not block empty Referer because legitimate clicks from chat apps or browsers stripping Referer
    # must not be falsely flagged as bypasses. Referer is only verified if it is present.
    shortener_base_url = link.get("shortener_base_url") or user.get("config", {}).get("base_url")
    if not shortener_base_url:
        shortener_base_url = settings.BASE_URL

    shortener_domain = urlparse(shortener_base_url).netloc.lower()
    parsed_base = urlparse(str(request.base_url))
    base_netloc = parsed_base.netloc.lower()

    referer_valid = False
    referer_reason = ""

    if not referer:
        referer_valid = True
        referer_reason = "missing_referer_allowed"
    else:
        ref_netloc = urlparse(referer).netloc.lower()
        if shortener_domain and (shortener_domain in ref_netloc or ref_netloc in shortener_domain or check_referer_root(ref_netloc, shortener_domain)):
            referer_valid = True
            referer_reason = "shortener_match"
        elif base_netloc and (base_netloc in ref_netloc or ref_netloc in base_netloc):
            referer_valid = True
            referer_reason = "base_match"
        elif await is_allowed_referer(referer, db):
            referer_valid = True
            referer_reason = "allowed_referer"
        elif await is_related_domain(referer, shortener_domain, db):
            referer_valid = True
            referer_reason = "related_domain"

    if not referer_valid:
        if await is_whitelisted_user(user_id, db):
            referer_valid = True
            referer_reason = "whitelisted"
        elif await is_development_environment(client_ip, user_agent):
            referer_valid = True
            referer_reason = "development"

    if not referer_valid:
        # Update user's blocked/referer failures count
        await db.users.update_one(
            {"_id": user_id},
            {"$inc": {"referer_failures": 1, "blocked_count": 1}}
        )
        # Send Telegram notification
        await send_bypass_notification(user_id, short_id, "Invalid referer", request, db)
        # Return bypass detected page for invalid referer
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # 2. Referer validated! Create a secure, short-lived server-side session.
    session_id = secrets.token_urlsafe(32)
    token = secrets.token_urlsafe(32)
    timestamp = time.time()

    session_doc = {
        "session_id": session_id,
        "token": token,
        "short_id": short_id,
        "original_url": link["original_url"],
        "user_id": str(user_id),
        "client_ip": client_ip,
        "user_agent": user_agent,
        "created_at": timestamp,
        "verified": True,  # Already verified backend referer check
        "consumed": False
    }

    await db.sessions.insert_one(session_doc)

    # Increment success count on referer validation
    await db.users.update_one(
        {"_id": user_id},
        {
            "$inc": {"success_count": 1},
            "$set": {
                "last_success": timestamp,
                "last_ip": client_ip,
                "last_user_agent": user_agent
            }
        }
    )

    # 3. Set the session ID cookie and redirect to continuation endpoint
    response = RedirectResponse(url=f"/continue?token={token}", status_code=302)
    is_secure = request.url.scheme == "https"
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        path="/",
        max_age=120  # 120 seconds TTL
    )
    return response

@app.get("/health")
async def health_check():
    return {"status": "ok"}
