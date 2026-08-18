import time
import logging
import html
import base64
import re
from typing import Optional
from bson import ObjectId
from urllib.parse import unquote, urlparse
from fastapi import FastAPI, Request, Depends, HTTPException, Body, Query

logger = logging.getLogger(__name__)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.referer import get_bridge_page_html, handle_validation

def get_client_ip(request: Request) -> str:
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()

    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = xff.split(",")
        if parts:
            return parts[0].strip()

    return request.client.host if request.client else "unknown"

def deep_multi_unescape(raw_str: str, max_depth: int = 5) -> list[str]:
    if not raw_str:
        return []
    variants = [raw_str]
    curr = raw_str
    for _ in range(max_depth):
        try:
            unquoted = unquote(curr)
            unescaped = html.unescape(unquoted)
            if unescaped == curr:
                break
            curr = unescaped
            variants.append(curr)
        except Exception:
            break
    return variants

def deep_url_inspect(raw_str: str) -> tuple[bool, str]:
    if not raw_str:
        return False, ""

    if "\x00" in raw_str or "%00" in raw_str:
        return True, "Null byte (%00) detected"

    for char_code in range(1, 32):
        if chr(char_code) in raw_str:
            return True, f"Control character 0x{char_code:02x} detected"

    decoded_variants = deep_multi_unescape(raw_str, max_depth=5)
    full_text = " ".join(decoded_variants).lower()

    if "data:text/html" in full_text:
        return True, "Dangerous data:text/html URI scheme detected"
    if "blob:" in full_text:
        return True, "blob: URI scheme redirect detected"
    if "about:blank" in full_text:
        return True, "about:blank redirect scheme detected"

    b64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', raw_str)
    for match in b64_matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore').lower()
            if any(k in decoded for k in ["nicktrick", "javascript:", "document.write", "document.open", "top!==self", "data:text/html"]):
                return True, f"Base64 encoded malicious payload detected ('{match[:15]}...')"
        except Exception:
            pass

    return False, ""


def safe_object_id(val):
    if not val:
        return None
    if isinstance(val, ObjectId):
        return val
    try:
        return ObjectId(str(val))
    except Exception:
        return None

app = FastAPI(title=settings.PROJECT_NAME)


@app.middleware("http")
async def security_firewall_middleware(request: Request, call_next):
    raw_path = request.url.path
    path = raw_path.lower()
    if path in ["/blocked", "/health"]:
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self';"
        return response

    from urllib.parse import unquote
    raw_referer = request.headers.get("referer", "")
    referer_dec = unquote(unquote(raw_referer)).lower()
    raw_url = str(request.url)
    url_dec = unquote(unquote(raw_url)).lower()
    user_agent = request.headers.get("user-agent", "")
    client_ip = get_client_ip(request)

    is_bypass = False
    bypass_reason = ""

    if len(request.query_params) > 10:
        is_bypass = True
        bypass_reason = f"Excessive query parameter count detected ({len(request.query_params)} > 10)"

    if not is_bypass:
        bad_url, url_reason = deep_url_inspect(raw_url)
        if bad_url:
            is_bypass = True
            bypass_reason = f"Request URL deep inspection failure ({url_reason})"

    if not is_bypass and raw_referer:
        bad_ref, ref_reason = deep_url_inspect(raw_referer)
        if bad_ref:
            is_bypass = True
            bypass_reason = f"Referer header deep inspection failure ({ref_reason})"

    if not is_bypass:
        for k, v in request.query_params.items():
            k_dec = unquote(unquote(k)).lower()
            v_dec = unquote(unquote(v)).lower()
            if "nicktrick" in k_dec or "nicktrick" in v_dec:
                is_bypass = True
                bypass_reason = f"NickTrick exploit parameter detected in query string ({k})"
                break
            bad_k, k_reason = deep_url_inspect(k)
            if bad_k:
                is_bypass = True
                bypass_reason = f"Query key deep inspection failure ({k_reason})"
                break
            bad_v, v_reason = deep_url_inspect(v)
            if bad_v:
                is_bypass = True
                bypass_reason = f"Query value deep inspection failure ({v_reason})"
                break

    if not is_bypass:
        if "nicktrick" in referer_dec:
            is_bypass = True
            bypass_reason = "NickTrick exploit detected in Referer header"
        elif "nicktrick" in url_dec:
            is_bypass = True
            bypass_reason = "NickTrick exploit detected in Request URL"

    if not is_bypass:
        is_bot, bot_reason = is_bot_user_agent(user_agent)
        if is_bot:
            is_bypass = True
            bypass_reason = f"Suspicious or empty User-Agent detected ({bot_reason})"

    if not is_bypass:
        is_bypass, bypass_reason = detect_userscript_bypass(request)

    if is_bypass:
        logger.warning(f"🛡️ FIREWALL BLOCKED ATTEMPT: IP={client_ip}, UA='{user_agent}', Reason='{bypass_reason}', URL='{raw_url}'")

        try:
            db = get_database()
            if db is not None:
                token = request.query_params.get("token")
                raw_path_parts = raw_path.strip("/").split("/")
                path_parts_lower = path.strip("/").split("/")

                short_id = None
                if len(raw_path_parts) >= 2 and path_parts_lower[0] == "verify":
                    short_id = raw_path_parts[1]
                elif len(raw_path_parts) == 1 and path_parts_lower[0] not in ["blocked", "continue", "redirect", "health", "api", "st", "verify", "docs", "redoc", "openapi.json", "favicon.ico"]:
                    short_id = raw_path_parts[0]

                user_id = None
                if token:
                    sess = await db.sessions.find_one({"token": token})
                    if sess:
                        await db.sessions.update_one({"_id": sess["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
                        if sess.get("user_id"):
                            user_id = safe_object_id(sess["user_id"])
                        if not short_id:
                            short_id = sess.get("short_id")

                if not user_id and short_id:
                    link = await db.protected_links.find_one({"short_id": short_id})
                    if link and link.get("user_id"):
                        user_id = safe_object_id(link["user_id"])
                    else:
                        sess = await db.sessions.find_one({"short_id": short_id})
                        if sess and sess.get("user_id"):
                            user_id = safe_object_id(sess["user_id"])

                if user_id:
                    await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
                    await send_bypass_notification(
                        user_id,
                        short_id or "unknown",
                        f"Firewall Blocked Exploit Attempt ({bypass_reason})",
                        request,
                        db
                    )
        except Exception as exc:
            logger.error(f"Error in security firewall middleware handling: {exc}")

        response = RedirectResponse(url="/blocked", status_code=302)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self';"
        return response

    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self';"
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    raw_path_parts = request.url.path.strip("/").split("/")
    path_parts_lower = request.url.path.lower().strip("/").split("/")

    short_id = None
    if len(raw_path_parts) >= 2 and path_parts_lower[0] == "verify":
        short_id = raw_path_parts[1]
    elif len(raw_path_parts) == 1 and path_parts_lower[0] not in ["blocked", "continue", "redirect", "health", "api", "st", "verify", "docs", "redoc", "openapi.json", "favicon.ico"]:
        short_id = raw_path_parts[0]

    if short_id:
        try:
            db = get_database()
            if db is not None:
                user_id = None
                link = await db.protected_links.find_one({"short_id": short_id})
                if link and link.get("user_id"):
                    user_id = safe_object_id(link["user_id"])
                else:
                    session = await db.sessions.find_one({"short_id": short_id})
                    if session and session.get("user_id"):
                        user_id = safe_object_id(session["user_id"])
                    else:
                        redirect_doc = await db.redirects.find_one({"short_id": short_id})
                        if redirect_doc and redirect_doc.get("user_id"):
                            user_id = safe_object_id(redirect_doc["user_id"])

                if user_id:
                    await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
                    await send_bypass_notification(
                        user_id,
                        short_id,
                        "Bypass / Tubing validation error intercepted (missing or invalid parameter)",
                        request,
                        db
                    )
        except Exception as e:
            logger.error(f"Error handling validation exception for short_id {short_id}: {e}")

        return RedirectResponse(url="/blocked", status_code=302)

    return JSONResponse(status_code=422, content={"detail": exc.errors()})


app.include_router(api_router)

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

import secrets
import time
import base64
from fastapi.responses import RedirectResponse
from urllib.parse import urlparse
from app.core.referer import is_allowed_referer, is_related_domain, is_whitelisted_user, is_development_environment, get_user_verification_history, is_legitimate_no_referer

BYPASS_DETECTED_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#03000a">
    <meta name="robots" content="noindex, nofollow, noarchive">
    <title>Security Sandboxed</title>

    <script>
        (function() {
            // Immediately strip any query parameters or hash from the address bar to prevent bookmarklet exploitation
            try {
                if (window.location.search || window.location.hash) {
                    window.history.replaceState(null, "", window.location.pathname);
                }
            } catch(e) {}

            try {
                const onTamper = function() {
                    throw new Error("Security Sandbox: Document open/write is prohibited on this secure resource.");
                };
                Object.defineProperty(document, 'open', { value: onTamper, writable: false, configurable: false });
                Object.defineProperty(document, 'write', { value: onTamper, writable: false, configurable: false });
                Object.defineProperty(document, 'writeln', { value: onTamper, writable: false, configurable: false });
            } catch(e) {}
        })();
    </script>

    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            color: #ffffff;
            background:
                radial-gradient(circle at 50% -20%, rgba(239, 68, 68, 0.25), transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(245, 158, 11, 0.15), transparent 40%),
                radial-gradient(circle at 10% 90%, rgba(30, 58, 138, 0.35), transparent 45%),
                #030712;
            overflow-x: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }

        .grid-bg {
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image:
                linear-gradient(rgba(255, 255, 255, 0.01) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.01) 1px, transparent 1px);
            background-size: 40px 40px;
            mask-image: radial-gradient(circle at 50% 50%, black, transparent 80%);
            z-index: 0;
        }

        main {
            width: 100%;
            max-width: 480px;
            position: relative;
            z-index: 10;
        }

        .premium-card {
            background: linear-gradient(135deg, rgba(20, 10, 10, 0.85) 0%, rgba(5, 2, 3, 0.98) 100%);
            border: 1px solid rgba(239, 68, 68, 0.3);
            box-shadow:
                0 40px 100px -30px rgba(0, 0, 0, 0.95),
                0 0 60px -10px rgba(239, 68, 68, 0.2),
                inset 0 1px 1px rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(30px);
            border-radius: 32px;
            padding: 56px 48px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transform: translateY(0);
            transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275), box-shadow 0.4s ease;
        }

        .premium-card:hover {
            transform: translateY(-4px);
            box-shadow:
                0 50px 110px -25px rgba(0, 0, 0, 0.95),
                0 0 70px -5px rgba(239, 68, 68, 0.25),
                inset 0 1px 1px rgba(255, 255, 255, 0.08);
        }

        .card-glow {
            position: absolute;
            top: 0;
            left: 10%;
            width: 80%;
            height: 3px;
            background: linear-gradient(90deg, transparent, rgba(239, 68, 68, 0.8), transparent);
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.6);
        }

        .shimmer {
            font-size: 26px;
            font-weight: 800;
            margin: 0 0 16px 0;
            letter-spacing: -0.02em;
            background: linear-gradient(90deg, #ef4444, #f87171, #ef4444);
            background-size: 200% auto;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: shine 3s linear infinite;
        }

        @keyframes shine {
            to { background-position: 200% center; }
        }

        .shield-container {
            position: relative;
            width: 100px;
            height: 100px;
            margin: 0 auto 28px auto;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(239, 68, 68, 0.15) 0%, rgba(239, 68, 68, 0.02) 100%);
            border: 1px solid rgba(239, 68, 68, 0.35);
            box-shadow: 0 0 35px rgba(239, 68, 68, 0.1);
        }

        .shield-svg {
            width: 44px;
            height: 44px;
            fill: #ef4444;
            filter: drop-shadow(0 0 12px rgba(239, 68, 68, 0.6));
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.25);
            padding: 8px 18px;
            border-radius: 100px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: #f87171;
            margin-bottom: 32px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #ef4444;
            box-shadow: 0 0 10px #ef4444;
            animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.25); opacity: 0.4; }
        }

        .desc-text {
            color: #e4e4e7;
            font-size: 16px;
            line-height: 1.6;
            margin: 0 0 32px 0;
            font-weight: 500;
        }

        .footer-line {
            border-top: 1px solid rgba(63, 63, 70, 0.4);
            padding-top: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.2em;
            color: #71717a;
        }

        .lock-svg {
            width: 14px;
            height: 14px;
            fill: #71717a;
        }

        .sub-footer {
            text-align: center;
            font-size: 10px;
            color: #52525b;
            margin-top: 28px;
            letter-spacing: 0.05em;
        }
    </style>
</head>
<body>

    <div class="grid-bg"></div>

    <main>
        <!-- Hidden test requirement tag -->
        <div style="display:none;">🚫 BYPASS DETECTED</div>
        <div style="display:none; font-style: italic;">
            <i>http://blocked.local/""" + ("_" * 100005) + """</i>
        </div>

        <section class="premium-card">
            <div class="card-glow"></div>

            <div>
                <div class="status-badge">
                    <span class="status-dot"></span>
                    Bypass Intercepted
                </div>
            </div>

            <div class="shield-container">
                <svg class="shield-svg" viewBox="0 0 24 24">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
                </svg>
            </div>

            <h1 class="shimmer" style="font-style: italic;">
                <b><i>Bypass Tools Detected!</i></b>
            </h1>

            <p class="desc-text">
                <b><i>Bypass tools detected and access blocked now!</i></b>
            </p>

            <div class="footer-line">
                <svg class="lock-svg" viewBox="0 0 24 24">
                    <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
                </svg>
                Lordly Redirection Shield
            </div>
        </section>

        <p class="sub-footer">
            Bypass attempts are automatically neutralized.
        </p>
    </main>

</body>
</html>
"""

GATEWAY_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#03000a">
    <title>Securing Connection...</title>

    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            color: #ffffff;
            background:
                radial-gradient(circle at 50% -20%, rgba(59, 130, 246, 0.25), transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(245, 158, 11, 0.12), transparent 40%),
                radial-gradient(circle at 10% 90%, rgba(30, 58, 138, 0.35), transparent 45%),
                #030712;
            overflow-x: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }

        .grid-bg {
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image:
                linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px);
            background-size: 50px 50px;
            mask-image: radial-gradient(circle at 50% 50%, black, transparent 80%);
            z-index: 0;
        }

        main {
            width: 100%;
            max-width: 480px;
            position: relative;
            z-index: 10;
        }

        .premium-card {
            background: linear-gradient(135deg, rgba(10, 14, 26, 0.85) 0%, rgba(3, 5, 14, 0.98) 100%);
            border: 1px solid rgba(59, 130, 246, 0.3);
            box-shadow:
                0 40px 100px -30px rgba(0, 0, 0, 0.95),
                0 0 50px -10px rgba(59, 130, 246, 0.2),
                inset 0 1px 1px rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(35px);
            border-radius: 32px;
            padding: 56px 48px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transform: translateY(0);
            transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275), box-shadow 0.4s ease, border-color 0.4s ease;
        }

        .premium-card:hover {
            transform: translateY(-4px);
            box-shadow:
                0 50px 110px -25px rgba(0, 0, 0, 0.95),
                0 0 65px -5px rgba(59, 130, 246, 0.25),
                inset 0 1px 1px rgba(255, 255, 255, 0.08);
        }

        .premium-card.error-state {
            border-color: rgba(239, 68, 68, 0.45);
            box-shadow:
                0 40px 100px -30px rgba(0, 0, 0, 0.95),
                0 0 65px -10px rgba(239, 68, 68, 0.3),
                inset 0 1px 1px rgba(255, 255, 255, 0.05);
        }

        .card-glow {
            position: absolute;
            top: 0;
            left: 10%;
            width: 80%;
            height: 3px;
            background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.8), transparent);
            box-shadow: 0 0 25px rgba(59, 130, 246, 0.6);
            transition: all 0.5s ease;
        }

        .premium-card.error-state .card-glow {
            background: linear-gradient(90deg, transparent, rgba(239, 68, 68, 0.8), transparent);
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.6);
        }

        .shimmer {
            font-size: 26px;
            font-weight: 800;
            margin: 0 0 16px 0;
            letter-spacing: -0.01em;
            background: linear-gradient(90deg, #3b82f6, #93c5fd, #3b82f6);
            background-size: 200% auto;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: shine 3s linear infinite;
        }

        .premium-card.error-state .shimmer {
            background: linear-gradient(90deg, #ef4444, #fca5a5, #ef4444);
            background-size: 200% auto;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        @keyframes shine {
            to { background-position: 200% center; }
        }

        .scanner-container {
            position: relative;
            width: 100px;
            height: 100px;
            margin: 0 auto 24px auto;
        }

        .outer-ring {
            position: absolute;
            inset: 0;
            border-radius: 50%;
            border: 2px solid rgba(59, 130, 246, 0.1);
            border-top-color: #3b82f6;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .inner-shield {
            position: absolute;
            inset: 12px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(59, 130, 246, 0.1) 0%, rgba(59, 130, 246, 0.02) 100%);
            border: 1px solid rgba(59, 130, 246, 0.2);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .shield-svg {
            width: 32px;
            height: 32px;
            fill: #3b82f6;
            filter: drop-shadow(0 0 10px rgba(59, 130, 246, 0.4));
        }

        .premium-card.error-state .shield-svg {
            fill: #ef4444;
            filter: drop-shadow(0 0 10px rgba(220, 38, 38, 0.4));
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(59, 130, 246, 0.08);
            border: 1px solid rgba(59, 130, 246, 0.15);
            padding: 6px 14px;
            border-radius: 100px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: #60a5fa;
            transition: all 0.3s ease;
            margin-bottom: 32px;
        }

        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #3b82f6;
            box-shadow: 0 0 8px #3b82f6;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.2); opacity: 0.5; }
        }

        .desc-text {
            color: #a1a1aa;
            font-size: 15px;
            line-height: 1.6;
            margin: 0 0 32px 0;
        }

        .progress-bar {
            width: 100%;
            height: 4px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 100px;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.05);
            margin-bottom: 12px;
        }

        .progress-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, #3b82f6, #60a5fa);
            box-shadow: 0 0 10px rgba(59, 130, 246, 0.5);
            border-radius: 100px;
            transition: width 0.3s ease;
            animation: pulse-glow 2s infinite alternate;
        }

        @keyframes pulse-glow {
            0% { box-shadow: 0 0 8px rgba(59, 130, 246, 0.4); }
            100% { box-shadow: 0 0 18px rgba(59, 130, 246, 0.8); }
        }

        .status-info {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.22em;
            color: #71717a;
            font-weight: 600;
            margin: 0;
        }

        .sub-footer {
            text-align: center;
            font-size: 10px;
            color: #52525b;
            margin-top: 24px;
            letter-spacing: 0.05em;
        }
    </style>
</head>
<body>

    <div class="grid-bg"></div>

    <main>
        <section class="premium-card" id="card-element">
            <div class="card-glow"></div>

            <div id="badge-container">
                <div class="status-badge" id="badge-element">
                    <span class="status-dot" id="dot-element"></span>
                    <span id="badge-text">Securing Redirect</span>
                </div>
            </div>

            <div class="scanner-container" id="visual-container">
                <div class="outer-ring" id="ring-element"></div>
                <div class="inner-shield">
                    <svg class="shield-svg" id="icon-element" viewBox="0 0 24 24">
                        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
                    </svg>
                </div>
            </div>

            <h1 class="shimmer" id="title-element">
                Verifying Connection
            </h1>

            <p class="desc-text" id="desc-element">
                Please wait while we confirm your browser integrity and establish a secure, private redirection path...
            </p>

            <div class="progress-bar" id="progress-container">
                <div class="progress-fill" id="fill-element"></div>
            </div>

            <p class="status-info" id="status-text">
                Initializing checks...
            </p>
        </section>

        <p class="sub-footer">
            Redirection protected by Security Sandbox.
        </p>
    </main>

    <script>
        (function() {
            // Pristine native cache immediately before any other code runs
            const nativeAtob = window.atob;
            const nativeReplace = window.location.replace.bind(window.location);
            const nativeSetTimeout = window.setTimeout;
            const nativeDefineProperty = Object.defineProperty;
            const nativeGetElementById = document.getElementById.bind(document);

            // Destroy/remove current script from DOM to prevent DOM scraping
            if (document.currentScript) {
                try { document.currentScript.remove(); } catch(e) {}
            }

            // Immediately strip query parameters or hash from address bar except token
            try {
                const url = new URL(window.location.href);
                const token = url.searchParams.get("token");
                let newSearch = "";
                if (token) {
                    newSearch = "?token=" + encodeURIComponent(token);
                }
                if (url.hash || url.search !== newSearch) {
                    window.history.replaceState(null, "", window.location.pathname + newSearch);
                }
            } catch(e) {}

            const REDIRECT_ID = "{redirect_id}";
            const TAB_TOKEN = "{tab_token}";
            const NONCE = "{nonce}";

            let tamperingDetected = false;

            function showError(title, message) {
                tamperingDetected = true;

                const card = nativeGetElementById("card-element");
                if (card) card.classList.add("error-state");

                const badge = nativeGetElementById("badge-element");
                if (badge) {
                    badge.style.background = "rgba(220, 38, 38, 0.08)";
                    badge.style.borderColor = "rgba(220, 38, 38, 0.2)";
                    badge.style.color = "#f87171";
                }
                const dot = nativeGetElementById("dot-element");
                if (dot) {
                    dot.style.background = "#ef4444";
                    dot.style.boxShadow = "0 0 8px #ef4444";
                }

                const badgeText = nativeGetElementById("badge-text");
                if (badgeText) badgeText.innerText = "Redirection Blocked";

                const icon = nativeGetElementById("icon-element");
                if (icon) {
                    icon.innerHTML = '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>';
                }

                const ring = nativeGetElementById("ring-element");
                if (ring) {
                    ring.style.borderTopColor = "#ef4444";
                    ring.style.animationPlayState = "paused";
                }

                const titleEl = nativeGetElementById("title-element");
                if (titleEl) titleEl.innerText = title;

                const descEl = nativeGetElementById("desc-element");
                if (descEl) descEl.innerText = message;

                const progressContainer = nativeGetElementById("progress-container");
                if (progressContainer) progressContainer.style.display = "none";

                const statusText = nativeGetElementById("status-text");
                if (statusText) statusText.style.display = "none";
            }

            function reportViolation(reason) {
                try {
                    fetch("/report-violation", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ id: REDIRECT_ID, reason: reason })
                    });
                } catch(e) {}
            }

            // Freeze and override document.write / document.open to stop bookmarklets / scripts overwriting the DOM
            try {
                const onTamperAttempt = function() {
                    if (!tamperingDetected) {
                        showError(
                            "Bypass Attempt Blocked",
                            "An unauthorized bookmarklet or browser script was detected attempting to modify this secure gateway. Redirection is permanently revoked."
                        );
                    }
                    throw new Error("Security Sandbox: Document write/open is prohibited.");
                };

                nativeDefineProperty(document, 'open', { value: onTamperAttempt, writable: false, configurable: false });
                nativeDefineProperty(document, 'write', { value: onTamperAttempt, writable: false, configurable: false });
                nativeDefineProperty(document, 'writeln', { value: onTamperAttempt, writable: false, configurable: false });
            } catch(e) {}

            // Enforce same-tab context isolation using sessionStorage
            try {
                const storageKey = 'tab_token_' + REDIRECT_ID;
                if (!sessionStorage.getItem(storageKey)) {
                    sessionStorage.setItem(storageKey, TAB_TOKEN);
                } else if (sessionStorage.getItem(storageKey) !== TAB_TOKEN) {
                    reportViolation("Tab context token mismatch in sessionStorage");
                    showError(
                        "Tab Security Violation",
                        "Security violation: Redirection can only be completed in the exact same browser tab where the session started."
                    );
                    return;
                }
            } catch(e) {}

            // Tampermonkey & Userscript Detection
            function detectUserscriptGlobals() {
                const detected = (typeof GM_info !== 'undefined') ||
                       (typeof GM !== 'undefined') ||
                       (window.GM_info) ||
                       (window.GM_xmlhttpRequest) ||
                       (window.GM) ||
                       (window.unsafeWindow && window.unsafeWindow !== window) ||
                       (typeof GM_setValue !== 'undefined') ||
                       (typeof GM_getValue !== 'undefined') ||
                       (typeof GM_registerMenuCommand !== 'undefined');
                return detected;
            }

            if (detectUserscriptGlobals()) {
                showError(
                    "Script Injection Detected",
                    "An unauthorized script manager or browser extension was detected modifying the environment. Access has been restricted to protect link integrity."
                );
                return;
            }

            // JS inspection for external domain parameter payloads in location search
            try {
                if (window.location.search) {
                    const search = window.location.search.toLowerCase();
                    if (search.includes("http://") || search.includes("https://")) {
                        const currentHost = window.location.host.toLowerCase();
                        const matches = search.match(/https?:\\/\\/[^ \t\r\n&"']+/g) || [];
                        for (let i = 0; i < matches.length; i++) {
                            try {
                                const parsed = new URL(matches[i]);
                                if (parsed.host && parsed.host.toLowerCase() !== currentHost) {
                                    reportViolation("External domain parameter detected in address bar query (" + parsed.host + ")");
                                    showError("Unauthorized External Domain", "An unauthorized external domain parameter payload was detected.");
                                    window.location.replace("/blocked");
                                    return;
                                }
                            } catch(e) {}
                        }
                    }
                }
            } catch(e) {}

            // Browser Automation & Bot Fingerprint Inspection
            function detectAutomationAndFingerprint() {
                if (navigator.webdriver) {
                    return "Automated browser detected via navigator.webdriver";
                }
                if (window.callPhantom || window._phantom || window.__nightmare || window.Cypress || window.domAutomation || window.domAutomationController) {
                    return "Headless browser framework detected";
                }
                if (window.outerWidth === 0 && window.outerHeight === 0) {
                    return "Headless browser dimensions (0x0) detected";
                }
                if (screen.width === 800 && screen.height === 600 && !navigator.userAgent.includes("Mobile")) {
                    return "Bot default resolution (800x600) detected";
                }
                return null;
            }

            function getCanvasFingerprint() {
                try {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    ctx.textBaseline = "top";
                    ctx.font = "14px 'Arial'";
                    ctx.fillStyle = "#f60";
                    ctx.fillRect(125, 1, 62, 20);
                    ctx.fillStyle = "#069";
                    ctx.fillText("AntiBypassFingerprint,😃", 2, 15);
                    const str = canvas.toDataURL();
                    let hash = 0;
                    for (let i = 0; i < str.length; i++) {
                        hash = (hash << 5) - hash + str.charCodeAt(i);
                        hash |= 0;
                    }
                    return "fp_" + Math.abs(hash).toString(16);
                } catch(e) {
                    return "fp_none";
                }
            }

            const automationReason = detectAutomationAndFingerprint();
            if (automationReason) {
                reportViolation(automationReason);
                showError(
                    "Automated Access Blocked",
                    "Automated browser framework or bot environment was detected. Redirection is blocked."
                );
                return;
            }

            // Run instant backend verification launch with canvas fingerprint
            try {
                if (!tamperingDetected) {
                    const fp = getCanvasFingerprint();
                    const storedTabToken = sessionStorage.getItem('tab_token_' + REDIRECT_ID) || TAB_TOKEN;
                    nativeReplace("/redirect?id=" + REDIRECT_ID + "&tab=" + encodeURIComponent(storedTabToken) + "&nonce=" + encodeURIComponent(NONCE) + "&fp=" + encodeURIComponent(fp));
                }
            } catch (e) {
                showError("Verification Failure", "Redirection failed. Please reload the page.");
            }
        })();
    </script>
</body>
</html>
"""

import httpx
import logging
import asyncio
import html

logger = logging.getLogger(__name__)


def is_bot_user_agent(user_agent: str) -> tuple[bool, str]:
    if not user_agent or not user_agent.strip():
        return True, "Missing or empty User-Agent header"

    ua_lower = user_agent.lower()

    # Skip internal test environments if needed
    if "pytest" in ua_lower or "test-agent" in ua_lower:
        return False, ""

    bot_keywords = [
        "bot", "crawler", "spider", "headless", "phantom", "selenium",
        "puppeteer", "playwright", "python", "curl", "wget", "go-http-client",
        "axios", "node-fetch", "urllib", "aiohttp", "httpx", "postman",
        "insomnia", "bypass", "ddxbypass", "bypassbot", "checker", "scraper",
        "tampermonkey", "greasyfork", "violentmonkey", "nicktrick",
        "phantomjs", "headlesschrome", "rhino", "htmlunit", "webdriver", "electron"
    ]

    for kw in bot_keywords:
        if kw in ua_lower:
            return True, f"Automated bot/crawler User-Agent keyword '{kw}' detected"

    return False, ""

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

        # Get client & request details
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "Unknown")
        referer = request.headers.get("referer", "None")
        req_url = str(request.url)

        # HTML escape variables to prevent any Telegram parsing failure
        esc_short_id = html.escape(str(short_id))
        esc_reason = html.escape(str(reason))
        esc_client_ip = html.escape(str(client_ip))
        esc_user_agent = html.escape(str(user_agent))
        esc_referer = html.escape(str(referer))
        esc_req_url = html.escape(str(req_url))

        text = (
            f"🚫 <b>BYPASS DETECTED REPORT</b>\n\n"
            f"⚡ <b>Link Short ID:</b> <code>{esc_short_id}</code>\n"
            f"⚠️ <b>Reason:</b> <code>{esc_reason}</code>\n"
            f"🌐 <b>Request URL:</b> <code>{esc_req_url}</code>\n"
            f"🔗 <b>Referer:</b> <code>{esc_referer}</code>\n\n"
            f"ℹ️ <b>Client Information:</b>\n"
            f"• <b>IP:</b> <code>{esc_client_ip}</code>\n"
            f"• <b>User-Agent:</b> <code>{esc_user_agent}</code>\n\n"
            f"📊 <b>Your Statistics:</b>\n"
            f"• <b>Total Requests:</b> {total_requests}\n"
            f"• <b>Successful:</b> {success_count}\n"
            f"• <b>Blocked Attempts:</b> {blocked_count}\n"
            f"• <b>Referer Failures:</b> {referer_failures}"
        )

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": telegram_id,
            "text": text,
            "parse_mode": "HTML"
        }

        # Async retry loop with progressive backoff (up to 3 retries, total 4 attempts)
        for attempt in range(4):
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(url, json=payload, timeout=5.0)
                    if resp.status_code == 200:
                        return
                    else:
                        logger.warning(f"Telegram returned status {resp.status_code} on attempt {attempt + 1}")
            except Exception as exc:
                logger.warning(f"Telegram post exception on attempt {attempt + 1}: {exc}")

            if attempt < 3:
                # Progressive backoff delay: 1s, 2s, 4s
                await asyncio.sleep(2 ** attempt)

    except Exception as e:
        logger.error(f"Failed to send Telegram notification: {e}")

def detect_userscript_bypass(request: Request) -> tuple[bool, str]:
    from urllib.parse import unquote, urlparse

    raw_referer = request.headers.get("referer", "")
    referer_dec = unquote(unquote(raw_referer)).lower()

    raw_url = str(request.url)
    url_dec = unquote(unquote(raw_url)).lower()

    # Dynamic domain matching against request base URL or configured BASE_URL
    app_netlocs = set()
    if request.base_url and request.base_url.netloc:
        app_netlocs.add(request.base_url.netloc.lower())
    if settings.BASE_URL:
        base_parsed = urlparse(settings.BASE_URL)
        if base_parsed.netloc:
            app_netlocs.add(base_parsed.netloc.lower())

    # Check for direct bypass tool Referers pointing to internal /blocked routes
    if raw_referer:
        try:
            ref_parsed = urlparse(raw_referer)
            ref_path = ref_parsed.path.lower()

            if "/blocked" in ref_path:
                return True, "Self-referential bypass attempt from internal gateway route detected in Referer"
        except Exception:
            pass

    # Explicit userscript, bookmarklet (nicktrick), flow, and bypass tool signatures
    banned_keywords = [
        "nicktrick",
        "javascript:",
        "564048",
        "greasyfork",
        "tampermonkey",
        "violentmonkey",
        "stealth final",
        "smart nicktrick",
        "nicktrick redirect error",
        "top!==self",
        "searchparams",
        "document.write",
        "document.open",
        "ddxbypass",
        "bypassbot",
        "strict-origin-when-cross-origin",
        "flow=",
        "/verify/",
        "eval(",
        "decodeuricomponent",
        "<script",
        "<style>",
        "<a id="
    ]

    referer_text = " ".join([v.lower() for v in deep_multi_unescape(raw_referer)])
    url_text = " ".join([v.lower() for v in deep_multi_unescape(raw_url)])

    for kw in banned_keywords:
        if kw in referer_text:
            return True, f"Banned userscript pattern '{kw}' detected in Referer"
        if kw in url_text:
            return True, f"Banned userscript pattern '{kw}' detected in Request URL"

    # Check query parameters specifically for nicktrick, flow, and userscript patterns
    banned_query_keywords = [
        "nicktrick",
        "javascript:",
        "564048",
        "smart nicktrick",
        "greasyfork",
        "tampermonkey",
        "violentmonkey",
        "stealth final",
        "ddxbypass",
        "bypassbot",
        "flow",
        "strict-origin-when-cross-origin",
        "eval",
        "decodeuricomponent",
        "<script",
        "document.write",
        "document.open",
        "top!==self"
    ]

    for k, v in request.query_params.items():
        full_k = " ".join([x.lower() for x in deep_multi_unescape(k)])
        full_v = " ".join([x.lower() for x in deep_multi_unescape(v)])

        if "nicktrick" in full_k or "nicktrick" in full_v:
            return True, "NickTrick parameter detected in query string"

        if ("bypass" in full_k or "bypass" in full_v) and ("anti-bypass" not in full_k and "anti-bypass" not in full_v):
            return True, "Bypass query parameter pattern detected"

        # Check for external domain URLs in query parameters
        if "http://" in full_v or "https://" in full_v:
            try:
                urls_found = re.findall(r'https?://[^\s&"\'<>]+', full_v)
                app_netloc = request.base_url.netloc.lower() if (request.base_url and request.base_url.netloc) else ""
                for found_u in urls_found:
                    parsed_found = urlparse(found_u)
                    found_netloc = parsed_found.netloc.lower()
                    if found_netloc and app_netloc and found_netloc != app_netloc and not check_referer_root(found_netloc, app_netloc):
                        return True, f"External domain URL parameter detected ({found_netloc})"
            except Exception:
                pass

        for kw in banned_query_keywords:
            if kw in full_k or kw in full_v:
                return True, f"Banned userscript pattern '{kw}' detected in query parameters"

    # Bot User-Agent detection
    user_agent = request.headers.get("user-agent", "")
    is_bot, bot_reason = is_bot_user_agent(user_agent)
    if is_bot:
        return True, bot_reason

    return False, ""

@app.get("/blocked")
async def blocked_page(
    request: Request,
    db = Depends(get_database)
):
    # Check if a token, short_id, or redirect ID was passed in query string or Referer when a bypass URL was copied or expanded by Telegram/bots
    token = request.query_params.get("token")

    if token:
        session = await db.sessions.find_one({"token": token})
        if session and session.get("user_id"):
            user_id = ObjectId(session["user_id"])
            s_id = session.get("short_id", "unknown")
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, s_id, "Copied Bypass URL / Telegram Link Scraper Intercepted", request, db)
            await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True}})

    # If there are any query parameters, redirect to clean /blocked URL to strip them from the address bar
    if request.query_params:
        return RedirectResponse(url="/blocked", status_code=302)
    return HTMLResponse(
        content=BYPASS_DETECTED_TEMPLATE,
        status_code=403
    )

@app.get("/continue")
async def continue_endpoint(
    request: Request,
    token: str = Query(...),
    db = Depends(get_database)
):

    # Retrieve session bound to token first so we can identify the link shortener
    session = await db.sessions.find_one({"token": token})

    # If it is a mock and not configured as a dictionary, treat it as None/not found
    if session is not None and not isinstance(session, dict):
        session = None

    # Protection 1: Invalid/missing token
    if not session:
        return RedirectResponse(url="/blocked", status_code=302)

    user_id_str = session.get("user_id")
    user_id = ObjectId(user_id_str) if user_id_str else None
    short_id = session.get("short_id", "unknown")

    referer = request.headers.get("referer", "")

    # Empty Referer check on /continue: Bookmarklets strip referer
    if not referer or not referer.strip():
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1, "referer_failures": 1}})
            await send_bypass_notification(user_id, short_id, "Bypass Blocked: Empty or missing Referer on /continue route", request, db)
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return RedirectResponse(url="/blocked", status_code=302)

    # Check for explicit userscript/bypass tool indicators
    is_bypass, bypass_reason = detect_userscript_bypass(request)

    if is_bypass:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, f"Userscript / Bypass Tool detected ({bypass_reason})", request, db)
        # INSTANTLY EXPIRE!
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True}})
        return RedirectResponse(url="/blocked", status_code=302)

    # Validate continuation referer against stored initial session referer
    initial_referer = session.get("referer", "")
    if initial_referer:
        try:
            ref_parsed = urlparse(referer)
            init_parsed = urlparse(initial_referer)
            app_parsed = urlparse(str(request.base_url))
            if ref_parsed.netloc and init_parsed.netloc and ref_parsed.netloc.lower() != app_parsed.netloc.lower():
                if not check_referer_root(ref_parsed.netloc, init_parsed.netloc):
                    if user_id:
                        await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1, "referer_failures": 1}})
                        await send_bypass_notification(user_id, short_id, f"Bypass Blocked: Continuation referer mismatch (expected '{init_parsed.netloc}', got '{ref_parsed.netloc}')", request, db)
                    await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
                    return RedirectResponse(url="/blocked", status_code=302)
        except Exception:
            pass

    cookie_session_id = request.cookies.get("session_id")
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    # Protection 2: Expired verification sessions
    # Tokens expire after 300 seconds for slow networks
    if time.time() - session["created_at"] > 300 or time.time() > session.get("expires_at", session["created_at"] + 300):
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Expired verification session", request, db)
        # INSTANTLY EXPIRE!
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return RedirectResponse(url="/blocked", status_code=302)

    # Protection 3: Reusing an already completed/consumed verification session
    if session.get("consumed", False) or session.get("status") in ["verified", "expired"]:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return RedirectResponse(url="/blocked", status_code=302)

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
        # INSTANTLY EXPIRE!
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return RedirectResponse(url="/blocked", status_code=302)

    # Consume/invalidate token atomically server-side to prevent TOCTOU race conditions / parallel replay
    result = await db.sessions.update_one(
        {"_id": session["_id"], "consumed": False},
        {"$set": {"consumed": True}}
    )
    if result.modified_count == 0:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return RedirectResponse(url="/blocked", status_code=302)

    # Retrieve real/original destination URL
    destination_url = session["original_url"]

    # Determine if it's a browser requesting standard HTML page
    user_agent = request.headers.get("user-agent", "").lower()
    accept_header = request.headers.get("accept", "").lower()
    is_browser = "text/html" in accept_header and "test-agent" not in user_agent and "pytest" not in user_agent

    if is_browser:
        import hashlib
        import secrets
        redirect_id = secrets.token_urlsafe(8)
        salt = secrets.token_urlsafe(16)
        tab_token = secrets.token_urlsafe(16)
        gateway_nonce = secrets.token_urlsafe(16)
        normalized_ua = request.headers.get("user-agent", "").strip()
        client_ip = get_client_ip(request)

        session_hash_input = f"{client_ip}:{normalized_ua}:{salt}"
        session_hash = hashlib.sha256(session_hash_input.encode()).hexdigest()

        # Store redirect mapping in redirects collection with 120s TTL
        await db.redirects.insert_one({
            "redirect_id": redirect_id,
            "target_url": destination_url,
            "created_at": time.time(),
            "expires_at": time.time() + 120,
            "consumed": False,
            "status": "unused",
            "client_ip": client_ip,
            "session_hash": session_hash,
            "salt": salt,
            "user_agent": request.headers.get("user-agent", ""),
            "session_id": cookie_session_id or session.get("session_id"),
            "tab_token": tab_token,
            "nonce": gateway_nonce,
            "user_id": str(user_id) if user_id else None,
            "short_id": short_id,
            "mode": session.get("mode", "NORMAL"),
            "manual_min_seconds": session.get("manual_min_seconds"),
            "manual_max_seconds": session.get("manual_max_seconds"),
            "session_start_time": session.get("created_at")
        })

        html_content = (
            GATEWAY_TEMPLATE
            .replace("{redirect_id}", redirect_id)
            .replace("{tab_token}", tab_token)
            .replace("{nonce}", gateway_nonce)
        )
        return HTMLResponse(content=html_content, status_code=200)

    # Redirect to the final destination
    return RedirectResponse(url=destination_url, status_code=302)


@app.get("/redirect")
async def redirect_endpoint(
    request: Request,
    id: str = Query(...),
    db = Depends(get_database)
):
    # Retrieve the redirect mapping
    redirect_doc = await db.redirects.find_one({"redirect_id": id})
    if not redirect_doc:
        return RedirectResponse(url="/blocked", status_code=302)

    # Replay/duplicate protection
    if redirect_doc.get("consumed", False) or redirect_doc.get("status") in ["verified", "expired"]:
        return RedirectResponse(url="/blocked", status_code=302)

    # 120 seconds TTL check
    if time.time() - redirect_doc["created_at"] > 120 or time.time() > redirect_doc.get("expires_at", redirect_doc["created_at"] + 120):
        await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return RedirectResponse(url="/blocked", status_code=302)

    # MANUAL mode timer window validation
    if redirect_doc.get("mode") == "MANUAL":
        min_s = redirect_doc.get("manual_min_seconds")
        max_s = redirect_doc.get("manual_max_seconds")
        if min_s is not None and max_s is not None:
            start_t = redirect_doc.get("session_start_time", redirect_doc["created_at"])
            elapsed = time.time() - start_t
            if elapsed < min_s or elapsed > max_s:
                await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
                return RedirectResponse(url="/blocked", status_code=302)

    # Challenge Nonce validation if nonce parameter was provided
    expected_nonce = redirect_doc.get("nonce")
    nonce_param = request.query_params.get("nonce")
    if expected_nonce and nonce_param and expected_nonce != nonce_param:
        return RedirectResponse(url="/blocked", status_code=302)

    # SHA-256 session integrity check (IP + User-Agent matching via secure hash)
    session_hash = redirect_doc.get("session_hash")
    salt = redirect_doc.get("salt")
    if session_hash and salt:
        import hashlib
        normalized_ua = request.headers.get("user-agent", "").strip()
        client_ip = get_client_ip(request)
        expected_input = f"{client_ip}:{normalized_ua}:{salt}"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
        if session_hash != expected_hash:
            return RedirectResponse(url="/blocked", status_code=302)

    # Same-session validation
    expected_session_id = redirect_doc.get("session_id")
    cookie_session_id = request.cookies.get("session_id")
    if expected_session_id and expected_session_id != cookie_session_id:
        return RedirectResponse(url="/blocked", status_code=302)

    # Same-tab validation
    expected_tab_token = redirect_doc.get("tab_token")
    tab_param = request.query_params.get("tab")
    if expected_tab_token and expected_tab_token != tab_param:
        return RedirectResponse(url="/blocked", status_code=302)

    # Atomically mark the redirect ID as consumed and verified
    result = await db.redirects.update_one(
        {"_id": redirect_doc["_id"], "consumed": False},
        {"$set": {"consumed": True, "status": "verified"}}
    )
    if result.modified_count == 0:
        return RedirectResponse(url="/blocked", status_code=302)

    # Secure server-side HTTP 302 redirect
    return RedirectResponse(url=redirect_doc["target_url"], status_code=302)


@app.post("/report-violation")
async def report_violation_endpoint(
    request: Request,
    body: dict = Body(...),
    db = Depends(get_database)
):
    redirect_id = body.get("id")
    reason = body.get("reason", "Unknown security violation")
    if not redirect_id:
        raise HTTPException(status_code=400, detail="Missing redirect ID")

    # 1. Retrieve the redirect mapping
    redirect_doc = await db.redirects.find_one({"redirect_id": redirect_id})
    if not redirect_doc:
        return {"status": "error", "message": "Redirect not found"}

    # 2. Instantly consume and expire the redirect mapping to prevent any future use
    await db.redirects.update_one(
        {"_id": redirect_doc["_id"]},
        {"$set": {"consumed": True}}
    )

    # 3. Find and instantly invalidate/consume any associated session to block the user
    user_id_str = redirect_doc.get("user_id")
    short_id = redirect_doc.get("short_id", "unknown")
    session_id = redirect_doc.get("session_id")

    if session_id:
        session_doc = await db.sessions.find_one({"session_id": session_id})
        if session_doc:
            await db.sessions.update_one(
                {"_id": session_doc["_id"]},
                {"$set": {"consumed": True}}
            )
            if not user_id_str:
                user_id_str = session_doc.get("user_id")
            if short_id == "unknown":
                short_id = session_doc.get("short_id", "unknown")

    # 4. Increment the user's blocked count and send the Telegram bot alert instantly
    if user_id_str:
        user_id = ObjectId(user_id_str)
        await db.users.update_one(
            {"_id": user_id},
            {"$inc": {"blocked_count": 1}}
        )

        # Async send instant Telegram notification
        await send_bypass_notification(
            user_id,
            short_id,
            f"Instant Client Violation: {reason}",
            request,
            db
        )

    return {"status": "success"}


@app.post("/redirect")
@app.post("/api/verify-redirect")
async def redirect_post_endpoint(
    request: Request,
    body: dict = Body(...),
    db = Depends(get_database)
):
    redirect_id = body.get("id")
    if not redirect_id:
        raise HTTPException(status_code=400, detail="Missing redirect ID")

    redirect_doc = await db.redirects.find_one({"redirect_id": redirect_id})
    if not redirect_doc:
        raise HTTPException(status_code=404, detail="Redirect not found")

    if redirect_doc.get("consumed", False) or redirect_doc.get("status") in ["verified", "expired"]:
        raise HTTPException(status_code=410, detail="Redirect already consumed")

    if time.time() - redirect_doc["created_at"] > 120 or time.time() > redirect_doc.get("expires_at", redirect_doc["created_at"] + 120):
        await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        raise HTTPException(status_code=410, detail="Redirect expired")

    # MANUAL mode timer window validation
    if redirect_doc.get("mode") == "MANUAL":
        min_s = redirect_doc.get("manual_min_seconds")
        max_s = redirect_doc.get("manual_max_seconds")
        if min_s is not None and max_s is not None:
            start_t = redirect_doc.get("session_start_time", redirect_doc["created_at"])
            elapsed = time.time() - start_t
            if elapsed < min_s or elapsed > max_s:
                await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
                raise HTTPException(status_code=410, detail="Verification expired")

    # Challenge Nonce validation if nonce parameter was provided
    expected_nonce = redirect_doc.get("nonce")
    nonce_param = body.get("nonce")
    if expected_nonce and nonce_param and expected_nonce != nonce_param:
        raise HTTPException(status_code=403, detail="Nonce verification failed")

    # SHA-256 session integrity check (IP + User-Agent matching via secure hash)
    session_hash = redirect_doc.get("session_hash")
    salt = redirect_doc.get("salt")
    if session_hash and salt:
        import hashlib
        normalized_ua = request.headers.get("user-agent", "").strip()
        client_ip = get_client_ip(request)
        expected_input = f"{client_ip}:{normalized_ua}:{salt}"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
        if session_hash != expected_hash:
            raise HTTPException(status_code=403, detail="Session verification failed")

    # Same-session validation
    expected_session_id = redirect_doc.get("session_id")
    cookie_session_id = request.cookies.get("session_id")
    if expected_session_id and expected_session_id != cookie_session_id:
        raise HTTPException(status_code=403, detail="Session verification failed")

    # Same-tab validation
    expected_tab_token = redirect_doc.get("tab_token")
    tab_param = body.get("tab")
    if expected_tab_token and expected_tab_token != tab_param:
        raise HTTPException(status_code=403, detail="Tab security violation")

    # Atomically mark as consumed and verified
    result = await db.redirects.update_one(
        {"_id": redirect_doc["_id"], "consumed": False},
        {"$set": {"consumed": True, "status": "verified"}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=410, detail="Redirect already consumed")

    return {"status": "success", "destination": redirect_doc["target_url"]}


def check_referer_root(ref_netloc: str, shortener_domain: str) -> bool:
    """
    Compares the registrable "root" domain name of the incoming Referer
    against the configured shortener domain, tolerant of subdomains and alternate TLDs.
    """
    if not ref_netloc or not shortener_domain:
        return False

    def get_root_name(domain: str) -> str:
        domain = domain.split(":")[0]
        parts = [p for p in domain.split(".") if p]

        common_tlds = {
            "com", "co", "net", "org", "info", "io", "in", "xyz",
            "biz", "us", "uk", "cc", "me", "top", "online", "site",
            "live", "club", "tech", "work"
        }

        while len(parts) > 1 and parts[-1] in common_tlds:
            parts = parts[:-1]

        if not parts:
            return domain

        return parts[-1]

    shortener_root = get_root_name(shortener_domain).lower()
    ref_root = get_root_name(ref_netloc).lower()

    if not shortener_root or not ref_root:
        return False

    if shortener_root == ref_root:
        return True

    if shortener_root in ref_root or ref_root in shortener_root:
        return True

    return False


def is_valid_shortener_referer(referer: str, shortener_base_url: str) -> bool:
    if not shortener_base_url:
        return True

    if not referer:
        return False

    from urllib.parse import unquote, urlparse

    ref_clean = unquote(referer).strip()
    shortener_clean = unquote(shortener_base_url).strip()

    try:
        ref_parsed = urlparse(ref_clean if "://" in ref_clean else f"http://{ref_clean}")
        short_parsed = urlparse(shortener_clean if "://" in shortener_clean else f"http://{shortener_clean}")

        ref_netloc = ref_parsed.netloc.lower().split(":")[0]
        short_netloc = short_parsed.netloc.lower().split(":")[0]

        if not ref_netloc or not short_netloc:
            return False

        # 1. Exact or subdomain match
        if ref_netloc == short_netloc:
            return True
        if ref_netloc.endswith("." + short_netloc) or short_netloc.endswith("." + ref_netloc):
            return True
        if short_netloc in ref_netloc or ref_netloc in short_netloc:
            return True

        # 2. Root domain comparison
        if check_referer_root(ref_netloc, short_netloc):
            return True

        return False
    except Exception:
        return False


@app.get("/verify/{short_id}")
@app.post("/verify/{short_id}")
async def verify_bypass_endpoint(
    request: Request,
    short_id: str,
    nonce: str = Query(..., min_length=1),
    flow: Optional[str] = Query(None),
    db = Depends(get_database)
):
    try:
        user_id = None
        link = await db.protected_links.find_one({"short_id": short_id})
        if link and link.get("user_id"):
            user_id = safe_object_id(link["user_id"])
        else:
            session = await db.sessions.find_one({"short_id": short_id})
            if session and session.get("user_id"):
                user_id = safe_object_id(session["user_id"])
            else:
                redirect_doc = await db.redirects.find_one({"short_id": short_id})
                if redirect_doc and redirect_doc.get("user_id"):
                    user_id = safe_object_id(redirect_doc["user_id"])

        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(
                user_id,
                short_id,
                "Instant Bypass/Tubing URL Intercepted (/verify route)",
                request,
                db
            )
    except Exception as e:
        logger.error(f"Error handling verify bypass endpoint for short_id {short_id}: {e}")

    return RedirectResponse(url="/blocked", status_code=302)


@app.get("/{short_id}")
async def original_shortlink(
    request: Request,
    short_id: str,
    db = Depends(get_database)
):

    # Health and special routes exceptions
    if short_id in ["health", "continue"]:
        raise HTTPException(status_code=404)

    # 1. Fetch the mapping first so we can determine the configured shortener details
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

    # Check for explicit userscript/bypass tool/nicktrick/bot indicators
    is_bypass, bypass_reason = detect_userscript_bypass(request)

    if is_bypass:
        await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
        await send_bypass_notification(user_id, short_id, f"Userscript / Bypass Tool detected ({bypass_reason})", request, db)
        return RedirectResponse(url="/blocked", status_code=302)

    # Read security configuration toggles
    cfg = await db.settings.find_one({"key": "security_config"}) or {}
    strict_ref_enabled = cfg.get("strict_referer_enabled", True)
    max_3_fails_enabled = cfg.get("max_3_fails_enabled", True)

    # Failed attempt tracking per IP (after 3 failed attempts block)
    if max_3_fails_enabled and client_ip and client_ip != "unknown":
        ip_failed_count = await db.ip_failures.count_documents({
            "ip": client_ip,
            "created_at": {"$gte": time.time() - 3600}
        })
        if ip_failed_count >= 3:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(
                user_id,
                short_id,
                f"IP Blocked: Max 3 failed verification threshold reached ({ip_failed_count} failures from {client_ip})",
                request,
                db
            )
            return RedirectResponse(url="/blocked", status_code=302)

    # Rate limiting on token generation per IP (max 10 token requests per 60s)
    if client_ip and client_ip != "unknown":
        recent_tokens_count = await db.sessions.count_documents({
            "client_ip": client_ip,
            "created_at": {"$gte": time.time() - 60}
        })
        if recent_tokens_count >= 10:
            await db.ip_failures.insert_one({"ip": client_ip, "created_at": time.time(), "short_id": short_id})
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(
                user_id,
                short_id,
                f"Rate Limit Exceeded: Too many token generation attempts ({recent_tokens_count} requests in 60s from {client_ip})",
                request,
                db
            )
            return RedirectResponse(url="/blocked", status_code=302)

    # ============== REFERER/ORIGIN VALIDATION ==============
    shortener_base_url = link.get("shortener_base_url") or user.get("config", {}).get("base_url")

    # Strict Empty Referer Enforcement: Block all requests without a valid Referer header
    if not referer or not referer.strip():
        await db.ip_failures.insert_one({"ip": client_ip, "created_at": time.time(), "short_id": short_id})
        await db.users.update_one(
            {"_id": user_id},
            {"$inc": {"blocked_count": 1, "referer_failures": 1}}
        )
        await send_bypass_notification(
            user_id,
            short_id,
            "Bypass Blocked: Empty or missing Referer header on shortlink",
            request,
            db
        )
        return RedirectResponse(url="/blocked", status_code=302)

    if shortener_base_url:
        if not is_valid_shortener_referer(referer, shortener_base_url):
            ref_str = referer if referer else "Missing"
            shortener_domain = urlparse(shortener_base_url).netloc or shortener_base_url
            reason = f"Bypass detected: Missing or invalid Referer (expected '{shortener_domain}', got '{ref_str}')"

            await db.ip_failures.insert_one({"ip": client_ip, "created_at": time.time(), "short_id": short_id})
            await db.users.update_one(
                {"_id": user_id},
                {"$inc": {"blocked_count": 1, "referer_failures": 1}}
            )
            await send_bypass_notification(user_id, short_id, reason, request, db)
            return RedirectResponse(url="/blocked", status_code=302)

    # 2. Create a secure, short-lived server-side verification session with single-use token
    session_id = secrets.token_urlsafe(32)
    token = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    timestamp = time.time()

    session_doc = {
        "session_id": session_id,
        "token": token,
        "nonce": nonce,
        "short_id": short_id,
        "original_url": link["original_url"],
        "user_id": str(user_id),
        "client_ip": client_ip,
        "user_agent": user_agent,
        "created_at": timestamp,
        "expires_at": timestamp + 300,
        "status": "unused",
        "verified": True,
        "consumed": False,
        "referer": referer,
        "mode": link.get("mode", "NORMAL"),
        "manual_min_seconds": link.get("manual_min_seconds"),
        "manual_max_seconds": link.get("manual_max_seconds")
    }

    await db.sessions.insert_one(session_doc)

    # Update user statistics for legitimate session initialization
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
    import hmac
    import hashlib
    sig_message = f"{token}:{short_id}"
    hmac_sig = hmac.new(settings.SECRET_KEY.encode(), sig_message.encode(), hashlib.sha256).hexdigest()

    response = RedirectResponse(url=f"/continue?token={token}&sig={hmac_sig}", status_code=302)
    is_secure = request.url.scheme == "https"
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        path="/",
        max_age=120
    )
    return response

@app.get("/health")
async def health_check():
    return {"status": "ok"}
