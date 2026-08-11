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
    <meta name="theme-color" content="#09090b">
    <meta name="robots" content="noindex, nofollow, noarchive">
    <title>⛔ Bypass Detected — Access Blocked</title>

    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">

    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

        * {
            box-sizing: border-box;
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: 'Inter', sans-serif;
            color: #f4f4f5;
            background:
                radial-gradient(circle at 50% -10%, rgba(239, 68, 68, 0.22), transparent 35%),
                radial-gradient(circle at 10% 90%, rgba(127, 29, 29, 0.18), transparent 30%),
                #09090b;
            overflow-x: hidden;
        }

        .ambient {
            position: fixed;
            inset: 0;
            pointer-events: none;
            background:
                linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px);
            background-size: 40px 40px;
            mask-image: linear-gradient(to bottom, black, transparent);
        }

        .security-card {
            position: relative;
            background:
                linear-gradient(
                    145deg,
                    rgba(24, 24, 27, 0.96),
                    rgba(9, 9, 11, 0.98)
                );
            border: 1px solid rgba(239, 68, 68, 0.28);
            box-shadow:
                0 30px 100px rgba(0, 0, 0, 0.65),
                0 0 80px rgba(220, 38, 38, 0.10),
                inset 0 1px 0 rgba(255,255,255,0.04);
            backdrop-filter: blur(20px);
        }

        .security-card::before {
            content: "";
            position: absolute;
            inset: 0;
            border-radius: inherit;
            pointer-events: none;
            background:
                linear-gradient(
                    135deg,
                    rgba(239, 68, 68, 0.08),
                    transparent 30%,
                    transparent 70%,
                    rgba(239, 68, 68, 0.04)
                );
        }

        .top-line {
            height: 4px;
            background: linear-gradient(
                90deg,
                #7f1d1d,
                #ef4444,
                #fca5a5,
                #ef4444,
                #7f1d1d
            );
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.55);
        }

        .warning-icon {
            position: relative;
            width: 104px;
            height: 104px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background:
                radial-gradient(circle, rgba(127,29,29,0.95), rgba(69,10,10,0.85));
            border: 2px solid rgba(248,113,113,0.65);
            box-shadow:
                0 0 0 8px rgba(239,68,68,0.05),
                0 0 45px rgba(239,68,68,0.25),
                inset 0 0 30px rgba(239,68,68,0.12);
            animation: iconPulse 2s ease-in-out infinite;
        }

        .warning-icon::before,
        .warning-icon::after {
            content: "";
            position: absolute;
            inset: -10px;
            border: 1px solid rgba(239,68,68,0.18);
            border-radius: 50%;
            animation: ring 2.2s ease-out infinite;
        }

        .warning-icon::after {
            animation-delay: 1.1s;
        }

        .warning-icon i {
            color: #f87171;
            font-size: 42px;
            filter: drop-shadow(0 0 14px rgba(239,68,68,0.8));
            animation: warningBlink 1.6s ease-in-out infinite;
        }

        @keyframes iconPulse {
            0%, 100% {
                transform: scale(1);
            }
            50% {
                transform: scale(1.035);
            }
        }

        @keyframes warningBlink {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.65;
            }
        }

        @keyframes ring {
            0% {
                transform: scale(0.85);
                opacity: 0.65;
            }
            100% {
                transform: scale(1.45);
                opacity: 0;
            }
        }

        .danger-text {
            background: linear-gradient(90deg, #f87171, #fecaca, #f87171);
            background-size: 200% auto;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: gradientMove 3s linear infinite;
        }

        @keyframes gradientMove {
            to {
                background-position: 200% center;
            }
        }

        .alert-box {
            background:
                linear-gradient(
                    135deg,
                    rgba(127,29,29,0.25),
                    rgba(69,10,10,0.12)
                );
            border: 1px solid rgba(248,113,113,0.25);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.025);
        }

        .reason-box {
            background: rgba(3, 3, 5, 0.62);
            border: 1px solid rgba(127, 29, 29, 0.55);
        }

        .reason-item {
            transition: all 0.2s ease;
        }

        .reason-item:hover {
            transform: translateX(4px);
        }

        .reason-icon {
            width: 30px;
            height: 30px;
            min-width: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 9px;
            background: rgba(127,29,29,0.35);
            border: 1px solid rgba(239,68,68,0.20);
        }

        .status-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #ef4444;
            box-shadow: 0 0 12px #ef4444;
            animation: dotPulse 1.5s infinite;
        }

        @keyframes dotPulse {
            50% {
                opacity: 0.35;
                transform: scale(0.75);
            }
        }

        .scan-line {
            position: absolute;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(
                90deg,
                transparent,
                rgba(239,68,68,0.5),
                transparent
            );
            animation: scan 4s linear infinite;
            pointer-events: none;
        }

        @keyframes scan {
            0% {
                top: 8%;
                opacity: 0;
            }
            15% {
                opacity: 1;
            }
            85% {
                opacity: 1;
            }
            100% {
                top: 92%;
                opacity: 0;
            }
        }

        @media (prefers-reduced-motion: reduce) {
            *,
            *::before,
            *::after {
                animation: none !important;
                transition: none !important;
            }
        }
    </style>
</head>

<body class="min-h-screen flex items-center justify-center p-4 sm:p-6">

    <div class="ambient"></div>

    <main class="w-full max-w-xl relative z-10">

        <section class="security-card rounded-[28px] overflow-hidden">

            <div class="top-line"></div>
            <div class="scan-line"></div>

            <div class="relative p-6 sm:p-9 md:p-10">

                <!-- Security Status -->
                <div class="flex items-center justify-center gap-2 mb-7">
                    <span class="status-dot"></span>
                    <span class="text-[10px] sm:text-xs font-bold uppercase tracking-[0.22em] text-red-400">
                        Security System • Access Blocked
                    </span>
                </div>

                <!-- Warning Icon -->
                <div class="warning-icon mb-7">
                    <i class="fa-solid fa-triangle-exclamation"></i>
                </div>

                <!-- Main Heading -->
                <h1 class="danger-text text-3xl sm:text-4xl md:text-5xl font-black tracking-tight text-center leading-tight">
                    BYPASS DETECTED
                </h1>

                <p class="text-center text-zinc-400 text-xs sm:text-sm font-semibold uppercase tracking-[0.14em] mt-3">
                    Unauthorized access attempt detected
                </p>

                <!-- Alert -->
                <div class="alert-box rounded-2xl p-5 mt-7">
                    <div class="flex gap-3 items-start">
                        <div class="text-red-400 text-lg mt-0.5">
                            <i class="fa-solid fa-shield-halved"></i>
                        </div>

                        <div class="text-left">
                            <h2 class="text-sm font-bold text-red-300 mb-1">
                                Security verification failed
                            </h2>

                            <p class="text-xs sm:text-sm leading-6 text-zinc-300">
                                This request did not follow the required access flow.
                                The attempt has been blocked and the security event has been recorded.
                            </p>
                        </div>
                    </div>
                </div>

                <!-- Detection Reasons -->
                <div class="reason-box rounded-2xl p-5 mt-5">

                    <div class="flex items-center gap-2 mb-4">
                        <i class="fa-solid fa-fingerprint text-red-400"></i>

                        <span class="text-[11px] font-extrabold uppercase tracking-[0.16em] text-red-400">
                            Possible causes
                        </span>
                    </div>

                    <div class="space-y-3">

                        <div class="reason-item flex items-start gap-3">
                            <div class="reason-icon text-red-400 text-xs">
                                <i class="fa-solid fa-link-slash"></i>
                            </div>

                            <p class="text-xs sm:text-sm text-zinc-300 leading-5">
                                A continuation or verification link was pasted, shared, or reused directly.
                            </p>
                        </div>

                        <div class="reason-item flex items-start gap-3">
                            <div class="reason-icon text-red-400 text-xs">
                                <i class="fa-solid fa-forward"></i>
                            </div>

                            <p class="text-xs sm:text-sm text-zinc-300 leading-5">
                                The required shortlink or verification step was skipped.
                            </p>
                        </div>

                        <div class="reason-item flex items-start gap-3">
                            <div class="reason-icon text-red-400 text-xs">
                                <i class="fa-solid fa-robot"></i>
                            </div>

                            <p class="text-xs sm:text-sm text-zinc-300 leading-5">
                                Automated, modified, or invalid session information was detected.
                            </p>
                        </div>

                    </div>
                </div>

                <!-- Action -->
                <div class="mt-7 pt-6 border-t border-zinc-800/80 text-center">

                    <div class="inline-flex items-center gap-2 text-red-400 font-black text-sm sm:text-base uppercase tracking-wide">
                        <i class="fa-solid fa-rotate-left"></i>
                        Start the process again
                    </div>

                    <p class="text-xs text-zinc-500 mt-2 leading-5">
                        Return to the original link and complete the verification process normally.
                    </p>

                </div>

                <!-- Footer -->
                <div class="mt-7 flex items-center justify-center gap-2 text-[10px] uppercase tracking-[0.16em] text-zinc-600">
                    <i class="fa-solid fa-lock"></i>
                    <span>Protected Access System</span>
                    <span class="text-zinc-700">•</span>
                    <span>Event Logged</span>
                </div>

            </div>
        </section>

        <p class="text-center text-[10px] text-zinc-700 mt-4">
            Unauthorized access attempts may be automatically monitored.
        </p>

    </main>

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
    """
    Compares the registrable "root" domain name of the incoming Referer
    against the configured shortener domain, tolerant of:
      - subdomains on either side (www., link., go., s1., publisher., etc.)
      - alternate TLDs for the same brand (arolinks.com vs arolinks.co)
      - multi-label TLDs (e.g. .co.in, .com.br)
    """
    if not ref_netloc or not shortener_domain:
        return False

    def get_root_name(domain: str) -> str:
        # Strip port if present (e.g. example.com:8443)
        domain = domain.split(":")[0]
        parts = [p for p in domain.split(".") if p]

        common_tlds = {
            "com", "co", "net", "org", "info", "io", "in", "xyz",
            "biz", "us", "uk", "cc", "me", "top", "online", "site",
            "live", "club", "tech", "work"
        }

        # Strip trailing TLD label(s) from the end of the domain.
        # This correctly handles both single-label TLDs (.com) and
        # stacked ones (.co.in, .com.br) without misreading a
        # leading subdomain (go., link., s1., publisher., ...) as
        # the actual brand/root name.
        while len(parts) > 1 and parts[-1] in common_tlds:
            parts = parts[:-1]

        if not parts:
            return domain

        # The label immediately preceding the TLD is the true root
        # (registrable) domain name, regardless of how many
        # subdomain labels came before it.
        return parts[-1]

    shortener_root = get_root_name(shortener_domain).lower()
    ref_root = get_root_name(ref_netloc).lower()

    if not shortener_root or not ref_root:
        return False

    # Exact root match (preferred) — e.g. "arolinks" == "arolinks"
    if shortener_root == ref_root:
        return True

    # Fallback: containment check, but only against the *root* labels
    # (not the full netloc/domain strings) to reduce false positives
    # from unrelated domains that merely happen to contain the brand
    # name as a substring somewhere in a subdomain.
    if shortener_root in ref_root or ref_root in shortener_root:
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

