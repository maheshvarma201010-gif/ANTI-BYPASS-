from typing import Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends, HTTPException, Body, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
import secrets
import time
import base64
import hashlib
import hmac
import logging
import asyncio
import html
import httpx
from urllib.parse import urlparse, quote, unquote
from bson import ObjectId

@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_to_mongo()
    yield
    await close_mongo_connection()

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)
app.include_router(api_router)

# SECRET KEY for HMAC - Must be in environment variables
SECRET_KEY = settings.SECRET_KEY or "change-this-to-a-strong-secret-key-min-32-chars"

DEFAULT_BYPASS_BASE_URL = "https://empty-workers-playground.rolexoriginalstg.workers.dev/verify"
DEFAULT_TARGET_URL = "https://example.com"

logger = logging.getLogger(__name__)

async def get_bypass_url(target_url: str = DEFAULT_TARGET_URL, db = None) -> str:
    """
    Generate bypass URL redirect for security interception.
    Fetches custom redirect URL from database if configured.
    """
    base_url = DEFAULT_BYPASS_BASE_URL
    if db:
        try:
            cfg = await db.settings.find_one({"key": "bypass_redirect_url"})
            if cfg and isinstance(cfg, dict) and cfg.get("url"):
                base_url = cfg["url"]
        except Exception as e:
            logger.warning(f"Failed to fetch custom bypass redirect URL: {e}")

    target_b64 = base64.b64encode(target_url.encode("utf-8")).decode("utf-8")
    target_hash = hashlib.md5(target_url.encode("utf-8")).hexdigest()[:16]
    return f"{base_url}?target={target_b64}&hash={target_hash}"

# =====================================================
# HMAC-MD5 URL Structure Functions
# =====================================================

def generate_hmac_hash(target_url: str, salt: Optional[str] = None) -> tuple[str, str]:
    """
    Generate HMAC-MD5 hash with salt
    Returns: (hash_value, salt)
    """
    if not salt:
        salt = secrets.token_urlsafe(16)  # 16 bytes = 22 characters
    
    # HMAC-MD5: HMAC(secret_key, target_url + ":" + salt)
    message = f"{target_url}:{salt}".encode('utf-8')
    hash_obj = hmac.new(
        SECRET_KEY.encode('utf-8'),
        message,
        hashlib.md5
    )
    return hash_obj.hexdigest(), salt

def verify_hmac_hash(target_url: str, hash_value: str, salt: str) -> bool:
    """
    Verify HMAC-MD5 hash using constant-time comparison
    """
    try:
        expected_hash, _ = generate_hmac_hash(target_url, salt)
        return hmac.compare_digest(expected_hash, hash_value)
    except Exception:
        return False

def create_secure_url(target_url: str, base_url: str = None) -> str:
    """
    Create URL with structure: /verify?target={base64}&hash={hmac}&salt={salt}
    """
    if not base_url:
        base_url = f"{settings.BASE_URL}/verify"
    
    base_url = base_url.split("?")[0].rstrip("/")
    
    # Generate HMAC hash with salt
    hash_value, salt = generate_hmac_hash(target_url)
    
    # Base64URL encode target
    target_b64 = base64.urlsafe_b64encode(target_url.encode('utf-8')).decode('utf-8')
    
    # Build URL with all three parameters
    return f"{base_url}?target={target_b64}&hash={hash_value}&salt={salt}"

def decode_target(encoded_target: str) -> Optional[str]:
    """
    Decode base64url encoded target URL
    """
    try:
        # Add padding if necessary
        padding = 4 - (len(encoded_target) % 4)
        if padding != 4:
            encoded_target += '=' * padding
        
        return base64.urlsafe_b64decode(encoded_target).decode('utf-8')
    except Exception:
        return None

def validate_secure_url(target_b64: str, hash_value: str, salt: str) -> tuple[bool, Optional[str]]:
    """
    Validate complete secure URL structure
    Returns: (is_valid, decoded_target_url)
    """
    # Check if all parameters exist
    if not all([target_b64, hash_value, salt]):
        return False, None
    
    # Decode target
    target_url = decode_target(target_b64)
    if not target_url:
        return False, None
    
    # Verify HMAC hash
    if not verify_hmac_hash(target_url, hash_value, salt):
        return False, None
    
    return True, target_url

# =====================================================
# Helper Functions
# =====================================================

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
    from urllib.parse import unquote
    
    raw_referer = request.headers.get("referer", "")
    referer_dec = unquote(unquote(raw_referer)).lower()
    
    raw_url = str(request.url)
    url_dec = unquote(unquote(raw_url)).lower()
    
    # Banned keywords
    banned_keywords = [
        "nicktrick", "javascript:", "564048", "greasyfork", "tampermonkey",
        "violentmonkey", "stealth final", "smart nicktrick", "ddxbypass", "bypassbot"
    ]
    
    for kw in banned_keywords:
        if kw in referer_dec:
            return True, f"Banned userscript pattern '{kw}' detected in Referer"
        if kw in url_dec:
            return True, f"Banned userscript pattern '{kw}' detected in Request URL"
    
    # Check query parameters
    for k, v in request.query_params.items():
        k_dec = unquote(unquote(k)).lower()
        v_dec = unquote(unquote(v)).lower()
        
        if k_dec == "nicktrick" or "nicktrick" in k_dec or "nicktrick" in v_dec:
            return True, "NickTrick parameter detected in query string"
        
        if ("bypass" in k_dec or "bypass" in v_dec) and ("anti-bypass" not in k_dec and "anti-bypass" not in v_dec):
            return True, "Bypass query parameter pattern detected"
    
    # Bot User-Agent detection
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
        
        text = (
            f"🚫 <b>BYPASS DETECTED REPORT</b>\n\n"
            f"⚡ <b>Link Short ID:</b> <code>{html.escape(str(short_id))}</code>\n"
            f"⚠️ <b>Reason:</b> <code>{html.escape(str(reason))}</code>\n"
            f"🌐 <b>Request URL:</b> <code>{html.escape(str(req_url))}</code>\n"
            f"🔗 <b>Referer:</b> <code>{html.escape(str(referer))}</code>\n\n"
            f"ℹ️ <b>Client Information:</b>\n"
            f"• <b>IP:</b> <code>{html.escape(str(client_ip))}</code>\n"
            f"• <b>User-Agent:</b> <code>{html.escape(str(user_agent))}</code>\n\n"
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
        
        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload, timeout=5.0)
    except Exception as e:
        logger.error(f"Failed to send Telegram notification: {e}")

from app.templates import render_template, load_template

def bypass_detected_response():
    """Return the bypass detected HTML page with 403 status code"""
    content = load_template("bypass_detected.html")
    return HTMLResponse(content=content, status_code=403)


# =====================================================
# Main Endpoints with target/hash/salt URL Structure
# =====================================================

@app.get("/verify")
async def verify_endpoint(
    request: Request,
    target: Optional[str] = Query(None, description="Base64URL encoded target URL"),
    hash: Optional[str] = Query(None, description="HMAC-MD5 hash for verification"),
    salt: Optional[str] = Query(None, description="Salt used for hash generation"),
    db = Depends(get_database)
):
    """
    Main verification endpoint with URL structure:
    /verify?target={base64_url}&hash={hmac_md5}&salt={salt}
    """
    
    # Validate the secure URL
    is_valid, target_url = validate_secure_url(target, hash, salt)
    
    if not is_valid:
        # Invalid URL - show bypass detected page
        return bypass_detected_response()
    
    # Check for bypass tools
    is_bypass, bypass_reason = detect_userscript_bypass(request)
    if is_bypass:
        # Check if this is a valid link from database
        link = await db.protected_links.find_one({"original_url": target_url})
        if link:
            user_id = ObjectId(link['user_id'])
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, link.get("short_id", "unknown"), 
                                          f"Userscript / Bypass Tool detected ({bypass_reason})", request, db)
        return bypass_detected_response()
    
    # Check if target URL exists in database
    link = await db.protected_links.find_one({"original_url": target_url})
    if not link:
        # URL not found in database
        return bypass_detected_response()
    
    # Get user info
    user_id = ObjectId(link['user_id'])
    user = await db.users.find_one({"_id": user_id})
    if not user:
        return bypass_detected_response()
    
    # Create verification session
    session_id = secrets.token_urlsafe(32)
    token = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    timestamp = time.time()
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    referer = request.headers.get("referer", "")
    
    session_doc = {
        "session_id": session_id,
        "token": token,
        "nonce": nonce,
        "short_id": link.get("short_id", "unknown"),
        "original_url": target_url,
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
        "manual_max_seconds": link.get("manual_max_seconds"),
        "target_param": target,
        "hash_param": hash,
        "salt_param": salt
    }
    
    await db.sessions.insert_one(session_doc)
    
    # Update user statistics
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
    
    # Check if browser request
    accept_header = request.headers.get("accept", "").lower()
    user_agent_lower = user_agent.lower()
    is_browser = "text/html" in accept_header and "test-agent" not in user_agent_lower and "pytest" not in user_agent_lower
    
    if is_browser:
        # Create redirect mapping for gateway
        redirect_id = secrets.token_urlsafe(8)
        salt_hash = secrets.token_urlsafe(16)
        tab_token = secrets.token_urlsafe(16)
        gateway_nonce = secrets.token_urlsafe(16)
        
        session_hash_input = f"{client_ip}:{user_agent}:{salt_hash}"
        session_hash = hashlib.sha256(session_hash_input.encode()).hexdigest()
        
        await db.redirects.insert_one({
            "redirect_id": redirect_id,
            "target_url": target_url,
            "created_at": timestamp,
            "expires_at": timestamp + 120,
            "consumed": False,
            "status": "unused",
            "client_ip": client_ip,
            "session_hash": session_hash,
            "salt": salt_hash,
            "user_agent": user_agent,
            "session_id": session_id,
            "tab_token": tab_token,
            "nonce": gateway_nonce,
            "user_id": str(user_id),
            "short_id": link.get("short_id", "unknown"),
            "mode": link.get("mode", "NORMAL"),
            "manual_min_seconds": link.get("manual_min_seconds"),
            "manual_max_seconds": link.get("manual_max_seconds"),
            "session_start_time": timestamp
        })
        
        html_content = render_template(
            "gateway.html",
            redirect_id=redirect_id,
            tab_token=tab_token,
            nonce=gateway_nonce
        )
        return HTMLResponse(content=html_content, status_code=200)
    
    # Redirect to final destination
    return RedirectResponse(url=target_url, status_code=302)

@app.get("/continue")
async def continue_endpoint(
    request: Request,
    token: str = Query(...),
    db = Depends(get_database)
):
    """Continue endpoint for session verification"""
    session = await db.sessions.find_one({"token": token})
    
    if session is not None and not isinstance(session, dict):
        session = None
    
    if not session:
        return bypass_detected_response()
    
    user_id_str = session.get("user_id")
    user_id = ObjectId(user_id_str) if user_id_str else None
    short_id = session.get("short_id", "unknown")
    
    # Check for bypass tools
    is_bypass, bypass_reason = detect_userscript_bypass(request)
    if is_bypass:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, f"Userscript / Bypass Tool detected ({bypass_reason})", request, db)
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True}})
        return bypass_detected_response()
    
    cookie_session_id = request.cookies.get("session_id")
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    
    # Check expiration
    if time.time() - session["created_at"] > 300 or time.time() > session.get("expires_at", session["created_at"] + 300):
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Expired verification session", request, db)
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return bypass_detected_response()
    
    # Check if already consumed
    if session.get("consumed", False) or session.get("status") in ["verified", "expired"]:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return bypass_detected_response()
    
    # Validate session
    cookie_valid = cookie_session_id and cookie_session_id == session["session_id"]
    fallback_valid = (not cookie_session_id) and (session["client_ip"] == client_ip) and (session["user_agent"] == user_agent)
    
    if not (cookie_valid or fallback_valid):
        reason = "Session validation failed"
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, reason, request, db)
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return bypass_detected_response()
    
    # Consume token
    result = await db.sessions.update_one(
        {"_id": session["_id"], "consumed": False},
        {"$set": {"consumed": True}}
    )
    if result.modified_count == 0:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return bypass_detected_response()
    
    destination_url = session["original_url"]
    
    # Check if browser
    accept_header = request.headers.get("accept", "").lower()
    user_agent_lower = user_agent.lower()
    is_browser = "text/html" in accept_header and "test-agent" not in user_agent_lower and "pytest" not in user_agent_lower
    
    if is_browser:
        redirect_id = secrets.token_urlsafe(8)
        salt_hash = secrets.token_urlsafe(16)
        tab_token = secrets.token_urlsafe(16)
        gateway_nonce = secrets.token_urlsafe(16)
        
        session_hash_input = f"{client_ip}:{user_agent}:{salt_hash}"
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
            "salt": salt_hash,
            "user_agent": user_agent,
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
        
        html_content = render_template(
            "gateway.html",
            redirect_id=redirect_id,
            tab_token=tab_token,
            nonce=gateway_nonce
        )
        return HTMLResponse(content=html_content, status_code=200)
    
    return RedirectResponse(url=destination_url, status_code=302)

@app.get("/redirect")
async def redirect_endpoint(
    request: Request,
    id: str = Query(...),
    db = Depends(get_database)
):
    """Final redirect endpoint"""
    redirect_doc = await db.redirects.find_one({"redirect_id": id})
    if not redirect_doc:
        return bypass_detected_response()
    
    target_url = redirect_doc.get("target_url")
    
    if redirect_doc.get("consumed", False) or redirect_doc.get("status") in ["verified", "expired"]:
        return bypass_detected_response()
    
    if time.time() - redirect_doc["created_at"] > 120 or time.time() > redirect_doc.get("expires_at", redirect_doc["created_at"] + 120):
        await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return bypass_detected_response()
    
    # Manual mode timer check
    if redirect_doc.get("mode") == "MANUAL":
        min_s = redirect_doc.get("manual_min_seconds")
        max_s = redirect_doc.get("manual_max_seconds")
        if min_s is not None and max_s is not None:
            start_t = redirect_doc.get("session_start_time", redirect_doc["created_at"])
            elapsed = time.time() - start_t
            if elapsed < min_s or elapsed > max_s:
                await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
                return bypass_detected_response()
    
    # Nonce validation
    expected_nonce = redirect_doc.get("nonce")
    nonce_param = request.query_params.get("nonce")
    if expected_nonce and nonce_param and expected_nonce != nonce_param:
        return bypass_detected_response()
    
    # Session integrity check
    session_hash = redirect_doc.get("session_hash")
    salt = redirect_doc.get("salt")
    if session_hash and salt:
        normalized_ua = request.headers.get("user-agent", "").strip()
        client_ip = get_client_ip(request)
        expected_input = f"{client_ip}:{normalized_ua}:{salt}"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
        if session_hash != expected_hash:
            return bypass_detected_response()
    
    # Same-session validation
    expected_session_id = redirect_doc.get("session_id")
    cookie_session_id = request.cookies.get("session_id")
    if expected_session_id and expected_session_id != cookie_session_id:
        return bypass_detected_response()
    
    # Same-tab validation
    expected_tab_token = redirect_doc.get("tab_token")
    tab_param = request.query_params.get("tab")
    if expected_tab_token and expected_tab_token != tab_param:
        return bypass_detected_response()
    
    # Atomically mark as consumed
    result = await db.redirects.update_one(
        {"_id": redirect_doc["_id"], "consumed": False},
        {"$set": {"consumed": True, "status": "verified"}}
    )
    if result.modified_count == 0:
        return bypass_detected_response()
    
    return RedirectResponse(url=redirect_doc["target_url"], status_code=302)

@app.post("/report-violation")
async def report_violation_endpoint(
    request: Request,
    body: dict = Body(...),
    db = Depends(get_database)
):
    """Report client-side violations"""
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

# =====================================================
# Health Check
# =====================================================

@app.get("/health")
async def health_check():
    return {"status": "ok"}

# =====================================================
# Example: Generate Secure URL (Utility)
# =====================================================

@app.get("/generate")
async def generate_secure_url(
    url: str = Query(..., description="Target URL to encode"),
):
    """Generate a secure URL with target, hash, and salt"""
    secure_url = create_secure_url(url)
    return {
        "secure_url": secure_url,
        "target": base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8'),
        "hash": generate_hmac_hash(url)[0],
        "salt": generate_hmac_hash(url)[1]
}
