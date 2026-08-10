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
    <title>Bypass Detected - Security Violation</title>
    <!-- Include Tailwind CSS via CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap');
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: radial-gradient(circle at top right, #fff5f5, #ffffff);
        }
        .glass-panel {
            background: rgba(255, 255, 255, 0.85);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(229, 62, 62, 0.15);
        }
        .animate-bounce-slow {
            animation: bounce 2s infinite;
        }
        @keyframes bounce {
            0%, 100% {
                transform: translateY(-5%);
                animation-timing-function: cubic-bezier(0.8,0,1,1);
            }
            50% {
                transform: none;
                animation-timing-function: cubic-bezier(0,0,0.2,1);
            }
        }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4 bg-slate-50">
    <div class="w-full max-w-lg glass-panel rounded-3xl shadow-2xl overflow-hidden p-8 md:p-10 text-center relative border border-rose-100">
        <!-- Top Decorative Gradient Bar -->
        <div class="absolute top-0 left-0 right-0 h-2 bg-gradient-to-r from-red-500 via-rose-500 to-orange-500"></div>

        <!-- Shield / Warning Icon -->
        <div class="mx-auto w-24 h-24 mb-6 bg-rose-50 rounded-full flex items-center justify-center border-4 border-rose-100 animate-bounce-slow shadow-sm">
            <span class="text-rose-500 text-4xl"><i class="fa-solid fa-shield-halved"></i></span>
        </div>

        <!-- Heading -->
        <h1 class="text-3xl font-extrabold text-slate-800 tracking-tight mb-3">
            🚫 BYPASS DETECTED
        </h1>
        <p class="text-slate-500 text-md leading-relaxed mb-6">
            Our multi-layer security system has intercepted an abnormal request that violates session validation policies.
        </p>

        <!-- Instruction / Info Card -->
        <div class="bg-rose-50/70 border border-rose-100 rounded-2xl p-5 mb-8 text-center relative overflow-hidden">
            <p class="text-sm font-semibold text-rose-700 leading-relaxed">
                Security violation prevented. Sharing or directly pasting continuation links is strictly prohibited.
            </p>
        </div>

        <!-- Action Guide -->
        <div class="text-left mb-8 space-y-3 bg-slate-50 border border-slate-100 rounded-2xl p-5">
            <span class="text-xs font-bold uppercase tracking-wider text-slate-400 block mb-2">How to continue safely</span>
            <div class="flex items-start gap-3 text-sm text-slate-600">
                <span class="text-emerald-500 mt-0.5"><i class="fa-solid fa-circle-check"></i></span>
                <p>Go back to the <strong>original source</strong> where the link was shared.</p>
            </div>
            <div class="flex items-start gap-3 text-sm text-slate-600">
                <span class="text-emerald-500 mt-0.5"><i class="fa-solid fa-circle-check"></i></span>
                <p>Click the <strong>original shortlink</strong> directly to initialize a secure session.</p>
            </div>
            <div class="flex items-start gap-3 text-sm text-slate-600">
                <span class="text-emerald-500 mt-0.5"><i class="fa-solid fa-circle-check"></i></span>
                <p>Do not share, bookmark, or directly copy the continuation URL.</p>
            </div>
        </div>

        <!-- Footer -->
        <div class="border-t border-slate-100 pt-6">
            <p class="text-md font-bold text-rose-600 mb-1">Please start again from the original shortlink.</p>
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
        if shortener_domain and (shortener_domain in ref_netloc or ref_netloc in shortener_domain):
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
