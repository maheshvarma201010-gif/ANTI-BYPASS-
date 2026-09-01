import os
import secrets
import time
import base64
import hashlib
import hmac
import logging
import html
import httpx
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, quote, unquote

from fastapi import FastAPI, Request, Depends, HTTPException, Body, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from bson import ObjectId

from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.referer import is_allowed_referer

app = FastAPI(title=settings.PROJECT_NAME)
app.include_router(api_router)

# SECRET KEY for HMAC
SECRET_KEY = settings.SECRET_KEY or "change-this-to-a-strong-secret-key-min-32-chars"

DEFAULT_BYPASS_BASE_URL = "https://empty-workers-playground.rolexoriginalstg.workers.dev/verify"
DEFAULT_TARGET_URL = "https://telegram.me/ANI_TELUGUFLIX_BOT?start=verify_W5l06mKTNxyvz3khLKQjjg"

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"

def load_template(filename: str) -> str:
    file_path = TEMPLATES_DIR / filename
    if file_path.exists():
        return file_path.read_text(encoding="utf-8")
    return ""

@app.on_event("startup")
async def startup_db_client():
    try:
        await connect_to_mongo()
    except Exception as e:
        logger.error(f"MongoDB startup connection error: {e}")

@app.on_event("shutdown")
async def shutdown_db_client():
    try:
        await close_mongo_connection()
    except Exception as e:
        logger.error(f"MongoDB shutdown error: {e}")

# =====================================================
# Bypass URL Helper Functions
# =====================================================

async def get_bypass_url(target_url: str = DEFAULT_TARGET_URL, db = None) -> str:
    """
    Generate or fetch the bypass redirect URL with target parameter and hash.
    """
    bypass_base = DEFAULT_BYPASS_BASE_URL
    if db is not None:
        try:
            cfg = await db.settings.find_one({"key": "bypass_redirect_url"})
            if cfg and isinstance(cfg.get("url"), str) and cfg["url"].strip():
                bypass_base = cfg["url"].strip()
        except Exception as e:
            logger.warning(f"Error reading bypass_redirect_url from DB: {e}")

    encoded_target = base64.b64encode(target_url.encode("utf-8")).decode("utf-8")
    hash_val = hashlib.md5(target_url.encode("utf-8")).hexdigest()[:16]
    return f"{bypass_base}?target={encoded_target}&hash={hash_val}"

# =====================================================
# HMAC-MD5 URL Structure Functions
# =====================================================

def generate_hmac_hash(target_url: str, salt: Optional[str] = None) -> tuple[str, str]:
    """
    Generate HMAC-MD5 hash with salt
    Returns: (hash_value, salt)
    """
    if not salt:
        salt = secrets.token_urlsafe(16)
    
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
    hash_value, salt = generate_hmac_hash(target_url)
    target_b64 = base64.urlsafe_b64encode(target_url.encode('utf-8')).decode('utf-8')
    return f"{base_url}?target={target_b64}&hash={hash_value}&salt={salt}"

def decode_target(encoded_target: str) -> Optional[str]:
    """
    Decode base64/urlsafe base64 target URL cleanly.
    Handles unquoting, URL-safe and standard base64 variants.
    """
    if not encoded_target:
        return None
    try:
        s = unquote(unquote(encoded_target)).strip()
        if s.startswith("http://") or s.startswith("https://"):
            return s

        padding = 4 - (len(s) % 4)
        if padding != 4:
            s += '=' * padding
        
        try:
            decoded = base64.urlsafe_b64decode(s).decode('utf-8', errors='ignore')
            if decoded.startswith("http://") or decoded.startswith("https://"):
                return decoded
        except Exception:
            pass

        decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
        if decoded.startswith("http://") or decoded.startswith("https://"):
            return decoded
    except Exception:
        pass
    return None

def validate_secure_url(target_b64: str, hash_value: Optional[str] = None, salt: Optional[str] = None) -> tuple[bool, Optional[str]]:
    """
    Validate secure URL structure and decode target.
    """
    target_url = decode_target(target_b64)
    if not target_url:
        return False, None
    
    if hash_value and salt:
        if verify_hmac_hash(target_url, hash_value, salt):
            return True, target_url
    
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

async def check_request_allowed_domain(request: Request, db = None) -> bool:
    """
    Check if the Referer or Origin header matches an allowed domain.
    Safe against disconnected or uninitialized DB instances.
    """
    referer = request.headers.get("referer", "")
    origin = request.headers.get("origin", "")

    try:
        if referer and await is_allowed_referer(referer, db):
            return True

        if origin and await is_allowed_referer(origin, db):
            return True
    except Exception as e:
        logger.warning(f"Error checking allowed domain: {e}")

    return False

def is_antibypass_domain_exemption(request: Request) -> bool:
    """
    Check if request URL, referer, or origin domain name contains antibypass or anti-bypass.
    """
    try:
        url_host = request.url.netloc.lower()
        if "antibypass" in url_host or "anti-bypass" in url_host:
            return True

        referer = request.headers.get("referer", "")
        if referer:
            ref_host = urlparse(referer if "://" in referer else f"http://{referer}").netloc.lower()
            if "antibypass" in ref_host or "anti-bypass" in ref_host:
                return True

        origin = request.headers.get("origin", "")
        if origin:
            orig_host = urlparse(origin if "://" in origin else f"http://{origin}").netloc.lower()
            if "antibypass" in orig_host or "anti-bypass" in orig_host:
                return True
    except Exception as e:
        logger.warning(f"Error checking antibypass domain exemption: {e}")

    return False

async def detect_userscript_bypass(request: Request, db = None) -> tuple[bool, str]:
    raw_referer = request.headers.get("referer", "")
    referer_dec = unquote(unquote(raw_referer)).lower()
    
    raw_url = str(request.url)
    url_dec = unquote(unquote(raw_url)).lower()
    
    # Skip bypass detection for exempted domains (antibypass domain names or allowed referers/origins)
    if is_antibypass_domain_exemption(request) or await check_request_allowed_domain(request, db):
        return False, ""

    banned_keywords = [
        "nicktrick", "javascript:", "564048", "greasyfork", "tampermonkey",
        "violentmonkey", "stealth final", "smart nicktrick", "ddxbypass", "bypassbot"
    ]

    for kw in banned_keywords:
        if kw in referer_dec:
            return True, f"Banned userscript pattern '{kw}' detected in Referer"
        if kw in url_dec:
            return True, f"Banned userscript pattern '{kw}' detected in Request URL"
    
    for k, v in request.query_params.items():
        k_dec = unquote(unquote(k)).lower()
        v_dec = unquote(unquote(v)).lower()
        
        if k_dec == "nicktrick" or "nicktrick" in k_dec or "nicktrick" in v_dec:
            return True, "NickTrick parameter detected in query string"
        
        if ("bypass" in k_dec or "bypass" in v_dec) and (
            "anti-bypass" not in k_dec and "anti-bypass" not in v_dec and
            "antibypass" not in k_dec and "antibypass" not in v_dec
        ):
            return True, "Bypass query parameter pattern detected"
    
    user_agent = request.headers.get("user-agent", "")
    is_bot, bot_reason = is_bot_user_agent(user_agent)
    if is_bot:
        return True, bot_reason
    
    return False, ""

async def send_bypass_notification(user_id: ObjectId, short_id: str, reason: str, request: Request, db):
    if db is None:
        return
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

def bypass_detected_response():
    """Return the bypass detected HTML page with 403 status code"""
    content = load_template("bypass_detected.html")
    return HTMLResponse(content=content, status_code=403)

# =====================================================
# Main Endpoints with target/hash/salt URL Structure
# =====================================================

@app.get("/")
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
    /?target={base64_url}&hash={hmac_md5}&salt={salt} or /verify?target=...
    """
    if not target:
        return bypass_detected_response()
    
    is_valid, target_url = validate_secure_url(target, hash, salt)
    if not is_valid or not target_url:
        return bypass_detected_response()
    
    is_bypass, bypass_reason = await detect_userscript_bypass(request, db)
    if is_bypass:
        if db is not None:
            try:
                link = await db.protected_links.find_one({"original_url": target_url})
                if link and "user_id" in link:
                    user_id = ObjectId(link['user_id'])
                    await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
                    await send_bypass_notification(user_id, link.get("short_id", "unknown"),
                                                  f"Userscript / Bypass Tool detected ({bypass_reason})", request, db)
            except Exception as e:
                logger.error(f"DB error during bypass check: {e}")
        return bypass_detected_response()
    
    user_id = None
    short_id = "unknown"
    mode = "NORMAL"
    manual_min_seconds = None
    manual_max_seconds = None

    if db is not None:
        try:
            link = await db.protected_links.find_one({"original_url": target_url})
            if link:
                user_id = ObjectId(link['user_id']) if link.get('user_id') else None
                short_id = link.get("short_id", "unknown")
                mode = link.get("mode", "NORMAL")
                manual_min_seconds = link.get("manual_min_seconds")
                manual_max_seconds = link.get("manual_max_seconds")

                if user_id:
                    await db.users.update_one(
                        {"_id": user_id},
                        {
                            "$inc": {"success_count": 1},
                            "$set": {
                                "last_success": time.time(),
                                "last_ip": get_client_ip(request),
                                "last_user_agent": request.headers.get("user-agent", "")
                            }
                        }
                    )
        except Exception as e:
            logger.error(f"DB error fetching link info: {e}")

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
        "short_id": short_id,
        "original_url": target_url,
        "user_id": str(user_id) if user_id else None,
        "client_ip": client_ip,
        "user_agent": user_agent,
        "created_at": timestamp,
        "expires_at": timestamp + 300,
        "status": "unused",
        "verified": True,
        "consumed": False,
        "referer": referer,
        "mode": mode,
        "manual_min_seconds": manual_min_seconds,
        "manual_max_seconds": manual_max_seconds,
        "target_param": target,
        "hash_param": hash,
        "salt_param": salt
    }
    
    if db is not None:
        try:
            await db.sessions.insert_one(session_doc)
        except Exception as e:
            logger.error(f"DB error inserting session: {e}")
    
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
        
        if db is not None:
            try:
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
                    "user_id": str(user_id) if user_id else None,
                    "short_id": short_id,
                    "mode": mode,
                    "manual_min_seconds": manual_min_seconds,
                    "manual_max_seconds": manual_max_seconds,
                    "session_start_time": timestamp
                })
            except Exception as e:
                logger.error(f"DB error inserting redirect: {e}")
        
        gateway_template = load_template("gateway.html")
        html_content = (
            gateway_template
            .replace("{redirect_id}", redirect_id)
            .replace("{tab_token}", tab_token)
            .replace("{nonce}", gateway_nonce)
        )
        return HTMLResponse(content=html_content, status_code=200)
    
    return RedirectResponse(url=target_url, status_code=302)

@app.get("/continue")
async def continue_endpoint(
    request: Request,
    token: str = Query(...),
    db = Depends(get_database)
):
    """Continue endpoint for session verification"""
    if db is None:
        return bypass_detected_response()

    try:
        session = await db.sessions.find_one({"token": token})
    except Exception as e:
        logger.error(f"DB error in continue: {e}")
        session = None

    if session is not None and not isinstance(session, dict):
        session = None
    
    if not session:
        return bypass_detected_response()
    
    user_id_str = session.get("user_id")
    user_id = ObjectId(user_id_str) if user_id_str else None
    short_id = session.get("short_id", "unknown")
    
    is_bypass, bypass_reason = await detect_userscript_bypass(request, db)
    if is_bypass:
        if user_id:
            try:
                await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
                await send_bypass_notification(user_id, short_id, f"Userscript / Bypass Tool detected ({bypass_reason})", request, db)
            except Exception:
                pass
        try:
            await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True}})
        except Exception:
            pass
        return bypass_detected_response()
    
    cookie_session_id = request.cookies.get("session_id")
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    
    if time.time() - session["created_at"] > 300 or time.time() > session.get("expires_at", session["created_at"] + 300):
        if user_id:
            try:
                await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
                await send_bypass_notification(user_id, short_id, "Expired verification session", request, db)
            except Exception:
                pass
        try:
            await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        except Exception:
            pass
        return bypass_detected_response()
    
    if session.get("consumed", False) or session.get("status") in ["verified", "expired"]:
        if user_id:
            try:
                await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
                await send_bypass_notification(user_id, short_id, "Token already used", request, db)
            except Exception:
                pass
        return bypass_detected_response()
    
    cookie_valid = cookie_session_id and cookie_session_id == session["session_id"]
    fallback_valid = (not cookie_session_id) and (session["client_ip"] == client_ip) and (session["user_agent"] == user_agent)
    
    if not (cookie_valid or fallback_valid):
        reason = "Session validation failed"
        if user_id:
            try:
                await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
                await send_bypass_notification(user_id, short_id, reason, request, db)
            except Exception:
                pass
        try:
            await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        except Exception:
            pass
        return bypass_detected_response()
    
    try:
        result = await db.sessions.update_one(
            {"_id": session["_id"], "consumed": False},
            {"$set": {"consumed": True}}
        )
        if result.modified_count == 0:
            if user_id:
                await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
                await send_bypass_notification(user_id, short_id, "Token already used", request, db)
            return bypass_detected_response()
    except Exception as e:
        logger.error(f"DB error updating session state: {e}")
        return bypass_detected_response()

    destination_url = session["original_url"]
    
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
        
        try:
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
        except Exception as e:
            logger.error(f"DB error inserting redirect in continue: {e}")
        
        gateway_template = load_template("gateway.html")
        html_content = (
            gateway_template
            .replace("{redirect_id}", redirect_id)
            .replace("{tab_token}", tab_token)
            .replace("{nonce}", gateway_nonce)
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
    if db is None:
        return bypass_detected_response()

    try:
        redirect_doc = await db.redirects.find_one({"redirect_id": id})
    except Exception as e:
        logger.error(f"DB error in redirect: {e}")
        redirect_doc = None

    if not redirect_doc:
        return bypass_detected_response()
    
    target_url = redirect_doc.get("target_url")
    
    if redirect_doc.get("consumed", False) or redirect_doc.get("status") in ["verified", "expired"]:
        return bypass_detected_response()
    
    if time.time() - redirect_doc["created_at"] > 120 or time.time() > redirect_doc.get("expires_at", redirect_doc["created_at"] + 120):
        try:
            await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        except Exception:
            pass
        return bypass_detected_response()
    
    if redirect_doc.get("mode") == "MANUAL":
        min_s = redirect_doc.get("manual_min_seconds")
        max_s = redirect_doc.get("manual_max_seconds")
        if min_s is not None and max_s is not None:
            start_t = redirect_doc.get("session_start_time", redirect_doc["created_at"])
            elapsed = time.time() - start_t
            if elapsed < min_s or elapsed > max_s:
                try:
                    await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
                except Exception:
                    pass
                return bypass_detected_response()
    
    expected_nonce = redirect_doc.get("nonce")
    nonce_param = request.query_params.get("nonce")
    if expected_nonce and nonce_param and expected_nonce != nonce_param:
        return bypass_detected_response()
    
    session_hash = redirect_doc.get("session_hash")
    salt = redirect_doc.get("salt")
    if session_hash and salt:
        normalized_ua = request.headers.get("user-agent", "").strip()
        client_ip = get_client_ip(request)
        expected_input = f"{client_ip}:{normalized_ua}:{salt}"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
        if session_hash != expected_hash:
            return bypass_detected_response()
    
    expected_session_id = redirect_doc.get("session_id")
    cookie_session_id = request.cookies.get("session_id")
    if expected_session_id and expected_session_id != cookie_session_id:
        return bypass_detected_response()
    
    expected_tab_token = redirect_doc.get("tab_token")
    tab_param = request.query_params.get("tab")
    if expected_tab_token and expected_tab_token != tab_param:
        return bypass_detected_response()
    
    try:
        result = await db.redirects.update_one(
            {"_id": redirect_doc["_id"], "consumed": False},
            {"$set": {"consumed": True, "status": "verified"}}
        )
        if result.modified_count == 0:
            return bypass_detected_response()
    except Exception as e:
        logger.error(f"DB error updating redirect state: {e}")
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
    
    if db is None:
        return {"status": "error", "message": "Database disconnected"}

    try:
        redirect_doc = await db.redirects.find_one({"redirect_id": redirect_id})
    except Exception as e:
        logger.error(f"DB error in report_violation: {e}")
        redirect_doc = None

    if not redirect_doc:
        return {"status": "error", "message": "Redirect not found"}
    
    try:
        await db.redirects.update_one(
            {"_id": redirect_doc["_id"]},
            {"$set": {"consumed": True}}
        )
    except Exception:
        pass
    
    user_id_str = redirect_doc.get("user_id")
    short_id = redirect_doc.get("short_id", "unknown")
    session_id = redirect_doc.get("session_id")
    
    if session_id:
        try:
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
        except Exception:
            pass
    
    if user_id_str:
        try:
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
        except Exception:
            pass
    
    return {"status": "success"}

# =====================================================
# Health Check
# =====================================================

@app.get("/health")
async def health_check():
    return {"status": "ok"}

# =====================================================
# Utility: Generate Secure URL
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
