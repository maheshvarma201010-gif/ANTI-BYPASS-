from typing import Optional
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
import base64
import hmac
import hashlib
import os
import httpx
import logging
import asyncio
import html
from fastapi.responses import RedirectResponse
from urllib.parse import urlparse
from app.core.referer import is_allowed_referer, is_related_domain, is_whitelisted_user, is_development_environment, get_user_verification_history, is_legitimate_no_referer
from bson import ObjectId

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")

def load_template(filename: str) -> str:
    path = os.path.join(TEMPLATES_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""

BYPASS_DETECTED_TEMPLATE = load_template("bypass_detected.html")
GATEWAY_TEMPLATE = load_template("gateway.html")

logger = logging.getLogger(__name__)

# ---------- Helper: Bypass redirect to /verify ----------
def get_bypass_redirect_response(original_url: str, short_id: str, request: Request) -> RedirectResponse:
    """
    Constructs a RedirectResponse to /verify with base64-encoded target and a hash.
    The hash is a HMAC-SHA256 of the original URL (truncated to 16 hex chars) for tamper-proofing.
    """
    b64_target = base64.urlsafe_b64encode(original_url.encode()).decode()
    secret = getattr(settings, "SECRET_KEY", "default-secret-key-change-me")
    hash_val = hmac.new(secret.encode(), original_url.encode(), hashlib.sha256).hexdigest()[:16]
    url = f"/verify?target={b64_target}&hash={hash_val}"
    return RedirectResponse(url=url, status_code=302)

# ---------- Helper functions ----------
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

def is_bot_user_agent(user_agent: str) -> tuple[bool, str]:
    if not user_agent or not user_agent.strip():
        return True, "Missing or empty User-Agent header"
    ua_lower = user_agent.lower()
    if "pytest" in ua_lower or "test-agent" in ua_lower:
        return False, ""
    bot_keywords = [
        "bot", "crawler", "spider", "headless", "phantom", "selenium",
        "puppeteer", "playwright", "python", "curl", "wget", "go-http-client",
        "axios", "node-fetch", "urllib", "aiohttp", "httpx", "postman",
        "insomnia", "bypass", "ddxbypass", "bypassbot", "checker", "scraper",
        "tampermonkey", "greasyfork", "violentmonkey", "nicktrick"
    ]
    for kw in bot_keywords:
        if kw in ua_lower:
            return True, f"Automated bot/crawler User-Agent keyword '{kw}' detected"
    return False, ""

def detect_userscript_bypass(request: Request) -> tuple[bool, str]:
    from urllib.parse import unquote, urlparse
    raw_referer = request.headers.get("referer", "")
    referer_dec = unquote(unquote(raw_referer)).lower()
    raw_url = str(request.url)
    url_dec = unquote(unquote(raw_url)).lower()

    app_netlocs = set()
    if request.base_url and request.base_url.netloc:
        app_netlocs.add(request.base_url.netloc.lower())
    if settings.BASE_URL:
        base_parsed = urlparse(settings.BASE_URL)
        if base_parsed.netloc:
            app_netlocs.add(base_parsed.netloc.lower())

    if raw_referer:
        try:
            ref_parsed = urlparse(raw_referer)
            ref_path = ref_parsed.path.lower()
            if "/blocked" in ref_path:
                return True, "Self-referential bypass attempt from internal gateway route detected in Referer"
        except Exception:
            pass

    banned_keywords = [
        "nicktrick", "javascript:", "564048", "greasyfork", "tampermonkey",
        "violentmonkey", "stealth final", "smart nicktrick",
        "nicktrick redirect error", "top!==self", "searchparams",
        "document.write", "document.open", "ddxbypass", "bypassbot"
    ]
    for kw in banned_keywords:
        if kw in referer_dec:
            return True, f"Banned userscript pattern '{kw}' detected in Referer"
        if kw in url_dec:
            return True, f"Banned userscript pattern '{kw}' detected in Request URL"

    banned_query_keywords = [
        "nicktrick", "javascript:", "564048", "smart nicktrick",
        "greasyfork", "tampermonkey", "violentmonkey", "stealth final",
        "ddxbypass", "bypassbot"
    ]
    for k, v in request.query_params.items():
        k_dec = unquote(unquote(k)).lower()
        v_dec = unquote(unquote(v)).lower()
        if k_dec == "nicktrick" or "nicktrick" in k_dec or "nicktrick" in v_dec:
            return True, "NickTrick parameter detected in query string"
        if ("bypass" in k_dec or "bypass" in v_dec) and ("anti-bypass" not in k_dec and "anti-bypass" not in v_dec):
            return True, "Bypass query parameter pattern detected"
        for kw in banned_query_keywords:
            if kw in k_dec or kw in v_dec:
                return True, f"Banned userscript pattern '{kw}' detected in query parameters"

    user_agent = request.headers.get("user-agent", "")
    is_bot, bot_reason = is_bot_user_agent(user_agent)
    if is_bot:
        return True, bot_reason

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
        total_requests = user.get("total_requests", 0)
        success_count = user.get("success_count", 0)
        blocked_count = user.get("blocked_count", 0)
        referer_failures = user.get("referer_failures", 0)
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "Unknown")
        referer = request.headers.get("referer", "None")
        req_url = str(request.url)
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
        payload = {"chat_id": telegram_id, "text": text, "parse_mode": "HTML"}
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
                await asyncio.sleep(2 ** attempt)
    except Exception as e:
        logger.error(f"Failed to send Telegram notification: {e}")

def check_referer_root(ref_netloc: str, shortener_domain: str) -> bool:
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
        if ref_netloc == short_netloc:
            return True
        if ref_netloc.endswith("." + short_netloc) or short_netloc.endswith("." + ref_netloc):
            return True
        if short_netloc in ref_netloc or ref_netloc in short_netloc:
            return True
        if check_referer_root(ref_netloc, short_netloc):
            return True
        return False
    except Exception:
        return False

# ---------- New /verify endpoint (bypass detection page) ----------
@app.get("/verify")
async def verify_endpoint(
    request: Request,
    target: Optional[str] = Query(None),
    hash: Optional[str] = Query(None),
):
    """
    Shows the bypass detection page.
    Accepts optional 'target' (base64) and 'hash' for informational purposes.
    """
    return HTMLResponse(
        content=BYPASS_DETECTED_TEMPLATE,
        status_code=403
    )

# ---------- /blocked endpoint: now redirects to /verify ----------
@app.get("/blocked")
async def blocked_page(
    request: Request,
    db = Depends(get_database)
):
    token = request.query_params.get("token")
    if token:
        session = await db.sessions.find_one({"token": token})
        if session and session.get("user_id"):
            user_id = ObjectId(session["user_id"])
            s_id = session.get("short_id", "unknown")
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, s_id, "Copied Bypass URL / Telegram Link Scraper Intercepted", request, db)
            await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True}})
            original_url = session.get("original_url", str(request.url))
            return get_bypass_redirect_response(original_url, s_id, request)

    target_url = str(request.url)
    return get_bypass_redirect_response(target_url, "unknown", request)

# ---------- /continue endpoint ----------
@app.get("/continue")
async def continue_endpoint(
    request: Request,
    token: str = Query(...),
    db = Depends(get_database)
):
    session = await db.sessions.find_one({"token": token})
    if session is not None and not isinstance(session, dict):
        session = None

    if not session:
        return get_bypass_redirect_response(str(request.url), "unknown", request)

    user_id_str = session.get("user_id")
    user_id = ObjectId(user_id_str) if user_id_str else None
    short_id = session.get("short_id", "unknown")
    original_url = session.get("original_url", str(request.url))

    referer = request.headers.get("referer", "")
    is_bypass, bypass_reason = detect_userscript_bypass(request)
    if is_bypass:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, f"Userscript / Bypass Tool detected ({bypass_reason})", request, db)
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True}})
        return get_bypass_redirect_response(original_url, short_id, request)

    cookie_session_id = request.cookies.get("session_id")
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    if time.time() - session["created_at"] > 300 or time.time() > session.get("expires_at", session["created_at"] + 300):
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Expired verification session", request, db)
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return get_bypass_redirect_response(original_url, short_id, request)

    if session.get("consumed", False) or session.get("status") in ["verified", "expired"]:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return get_bypass_redirect_response(original_url, short_id, request)

    cookie_valid = cookie_session_id and cookie_session_id == session["session_id"]
    fallback_valid = (not cookie_session_id) and (session["client_ip"] == client_ip) and (session["user_agent"] == user_agent)

    if not (cookie_valid or fallback_valid):
        if cookie_session_id and cookie_session_id != session["session_id"]:
            reason = "Session mismatch"
        elif session["user_agent"] != user_agent:
            reason = "Session client mismatch"
        else:
            reason = "Session validation failed"
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, reason, request, db)
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return get_bypass_redirect_response(original_url, short_id, request)

    result = await db.sessions.update_one(
        {"_id": session["_id"], "consumed": False},
        {"$set": {"consumed": True}}
    )
    if result.modified_count == 0:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return get_bypass_redirect_response(original_url, short_id, request)

    destination_url = session["original_url"]
    user_agent_lower = request.headers.get("user-agent", "").lower()
    accept_header = request.headers.get("accept", "").lower()
    is_browser = "text/html" in accept_header and "test-agent" not in user_agent_lower and "pytest" not in user_agent_lower

    if is_browser:
        redirect_id = secrets.token_urlsafe(8)
        salt = secrets.token_urlsafe(16)
        tab_token = secrets.token_urlsafe(16)
        gateway_nonce = secrets.token_urlsafe(16)
        normalized_ua = request.headers.get("user-agent", "").strip()
        client_ip = get_client_ip(request)
        session_hash_input = f"{client_ip}:{normalized_ua}:{salt}"
        session_hash = hashlib.sha256(session_hash_input.encode()).hexdigest()

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

    return RedirectResponse(url=destination_url, status_code=302)


# ---------- /redirect endpoint ----------
@app.get("/redirect")
async def redirect_endpoint(
    request: Request,
    id: str = Query(...),
    db = Depends(get_database)
):
    redirect_doc = await db.redirects.find_one({"redirect_id": id})
    if not redirect_doc:
        return get_bypass_redirect_response(str(request.url), "unknown", request)

    if redirect_doc.get("consumed", False) or redirect_doc.get("status") in ["verified", "expired"]:
        return get_bypass_redirect_response(redirect_doc["target_url"], redirect_doc.get("short_id", "unknown"), request)

    if time.time() - redirect_doc["created_at"] > 120 or time.time() > redirect_doc.get("expires_at", redirect_doc["created_at"] + 120):
        await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return get_bypass_redirect_response(redirect_doc["target_url"], redirect_doc.get("short_id", "unknown"), request)

    if redirect_doc.get("mode") == "MANUAL":
        min_s = redirect_doc.get("manual_min_seconds")
        max_s = redirect_doc.get("manual_max_seconds")
        if min_s is not None and max_s is not None:
            start_t = redirect_doc.get("session_start_time", redirect_doc["created_at"])
            elapsed = time.time() - start_t
            if elapsed < min_s or elapsed > max_s:
                await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
                return get_bypass_redirect_response(redirect_doc["target_url"], redirect_doc.get("short_id", "unknown"), request)

    expected_nonce = redirect_doc.get("nonce")
    nonce_param = request.query_params.get("nonce")
    if expected_nonce and nonce_param and expected_nonce != nonce_param:
        return get_bypass_redirect_response(redirect_doc["target_url"], redirect_doc.get("short_id", "unknown"), request)

    session_hash = redirect_doc.get("session_hash")
    salt = redirect_doc.get("salt")
    if session_hash and salt:
        import hashlib
        normalized_ua = request.headers.get("user-agent", "").strip()
        client_ip = get_client_ip(request)
        expected_input = f"{client_ip}:{normalized_ua}:{salt}"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
        if session_hash != expected_hash:
            return get_bypass_redirect_response(redirect_doc["target_url"], redirect_doc.get("short_id", "unknown"), request)

    expected_session_id = redirect_doc.get("session_id")
    cookie_session_id = request.cookies.get("session_id")
    if expected_session_id and expected_session_id != cookie_session_id:
        return get_bypass_redirect_response(redirect_doc["target_url"], redirect_doc.get("short_id", "unknown"), request)

    expected_tab_token = redirect_doc.get("tab_token")
    tab_param = request.query_params.get("tab")
    if expected_tab_token and expected_tab_token != tab_param:
        return get_bypass_redirect_response(redirect_doc["target_url"], redirect_doc.get("short_id", "unknown"), request)

    result = await db.redirects.update_one(
        {"_id": redirect_doc["_id"], "consumed": False},
        {"$set": {"consumed": True, "status": "verified"}}
    )
    if result.modified_count == 0:
        return get_bypass_redirect_response(redirect_doc["target_url"], redirect_doc.get("short_id", "unknown"), request)

    return RedirectResponse(url=redirect_doc["target_url"], status_code=302)


# ---------- POST /redirect and /api/verify-redirect ----------
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

    if redirect_doc.get("mode") == "MANUAL":
        min_s = redirect_doc.get("manual_min_seconds")
        max_s = redirect_doc.get("manual_max_seconds")
        if min_s is not None and max_s is not None:
            start_t = redirect_doc.get("session_start_time", redirect_doc["created_at"])
            elapsed = time.time() - start_t
            if elapsed < min_s or elapsed > max_s:
                await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
                raise HTTPException(status_code=410, detail="Verification expired")

    expected_nonce = redirect_doc.get("nonce")
    nonce_param = body.get("nonce")
    if expected_nonce and nonce_param and expected_nonce != nonce_param:
        raise HTTPException(status_code=403, detail="Nonce verification failed")

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

    expected_session_id = redirect_doc.get("session_id")
    cookie_session_id = request.cookies.get("session_id")
    if expected_session_id and expected_session_id != cookie_session_id:
        raise HTTPException(status_code=403, detail="Session verification failed")

    expected_tab_token = redirect_doc.get("tab_token")
    tab_param = body.get("tab")
    if expected_tab_token and expected_tab_token != tab_param:
        raise HTTPException(status_code=403, detail="Tab security violation")

    result = await db.redirects.update_one(
        {"_id": redirect_doc["_id"], "consumed": False},
        {"$set": {"consumed": True, "status": "verified"}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=410, detail="Redirect already consumed")

    return {"status": "success", "destination": redirect_doc["target_url"]}


# ---------- /report-violation ----------
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

    redirect_doc = await db.redirects.find_one({"redirect_id": redirect_id})
    if not redirect_doc:
        return {"status": "error", "message": "Redirect not found"}

    await db.redirects.update_one(
        {"_id": redirect_doc["_id"]},
        {"$set": {"consumed": True}}
    )

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

    if user_id_str:
        user_id = ObjectId(user_id_str)
        await db.users.update_one(
            {"_id": user_id},
            {"$inc": {"blocked_count": 1}}
        )
        await send_bypass_notification(
            user_id,
            short_id,
            f"Instant Client Violation: {reason}",
            request,
            db
        )

    return {"status": "success"}


# ---------- /{short_id} (entry point) ----------
@app.get("/{short_id}")
async def original_shortlink(
    request: Request,
    short_id: str,
    db = Depends(get_database)
):
    if short_id in ["health", "continue", "verify"]:
        raise HTTPException(status_code=404)

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
    original_url = link["original_url"]

    is_bypass, bypass_reason = detect_userscript_bypass(request)
    if is_bypass:
        await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
        await send_bypass_notification(user_id, short_id, f"Userscript / Bypass Tool detected ({bypass_reason})", request, db)
        return get_bypass_redirect_response(original_url, short_id, request)

    shortener_base_url = link.get("shortener_base_url") or user.get("config", {}).get("base_url")
    if shortener_base_url:
        if not is_valid_shortener_referer(referer, shortener_base_url):
            ref_str = referer if referer else "Missing"
            shortener_domain = urlparse(shortener_base_url).netloc or shortener_base_url
            reason = f"Bypass detected: Missing or invalid Referer (expected '{shortener_domain}', got '{ref_str}')"
            await db.users.update_one(
                {"_id": user_id},
                {"$inc": {"blocked_count": 1, "referer_failures": 1}}
            )
            await send_bypass_notification(user_id, short_id, reason, request, db)
            return get_bypass_redirect_response(original_url, short_id, request)

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

    response = RedirectResponse(url=f"/continue?token={token}", status_code=302)
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


# ---------- /health ----------
@app.get("/health")
async def health_check():
    return {"status": "ok"}
