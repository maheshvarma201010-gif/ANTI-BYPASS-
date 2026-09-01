import secrets
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from fastapi.responses import JSONResponse
from app.models.database import get_database
from app.core.security import encrypt_url, decrypt_url
from app.core.config import settings
from datetime import datetime
import httpx
from urllib.parse import urlparse
import base64
import hashlib
import hmac
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# SECRET KEY for HMAC - Should be in settings
SECRET_KEY = settings.SECRET_KEY or "change-this-to-a-strong-secret-key-min-32-chars"

# =====================================================
# HMAC-MD5 URL Generation Functions
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

# =====================================================
# API Endpoint
# =====================================================

@router.get("/api")
@router.get("/st")
async def create_protected_link(
    request: Request,
    api: str = Query(...),
    url: str = Query(...),
    db = Depends(get_database)
):
    """
    Create a protected link with HMAC-MD5 verification
    Returns the bridge URL that the shortener will redirect to
    """
    # Multi-shortener daisy-chain lookup
    current_api = api
    final_shortener_config = None
    user = None

    for _ in range(10):
        found_user = await db.users.find_one({
            "$or": [
                {"api_key": current_api},
                {"shorteners.abp_key": current_api},
                {"shorteners.manual_abp_key": current_api}
            ]
        })
        if not found_user:
            break

        user = found_user
        shortener_config = None
        if user.get("api_key") == current_api:
            shortener_config = user.get("config")
        else:
            for s in user.get("shorteners", []):
                if s.get("abp_key") == current_api or s.get("manual_abp_key") == current_api:
                    is_manual = (s.get("manual_abp_key") == current_api)
                    shortener_config = {
                        "base_url": s.get("base_url"),
                        "api_key": s.get("api_key"),
                        "mode": "MANUAL" if is_manual else s.get("mode", "NORMAL"),
                        "manual_min_seconds": s.get("manual_min_seconds"),
                        "manual_max_seconds": s.get("manual_max_seconds")
                    }
                    break

        if not shortener_config:
            break

        # Check if the configured base_url points to our own service
        parsed_request_url = urlparse(str(request.base_url))
        parsed_config_url = urlparse(shortener_config["base_url"])
        parsed_settings_url = urlparse(settings.BASE_URL)

        if parsed_config_url.netloc.lower() in [parsed_settings_url.netloc.lower(), parsed_request_url.netloc.lower()]:
            # It points to us! Extract the next API key in the chain
            try:
                decrypted_next_api = decrypt_url(shortener_config["api_key"])
                current_api = decrypted_next_api
            except Exception:
                current_api = shortener_config["api_key"]
            continue
        else:
            # Found a raw, external shortener!
            final_shortener_config = shortener_config
            break

    # Fallback to direct config
    if not final_shortener_config and user:
        if user.get("api_key") == api:
            final_shortener_config = user.get("config")
        else:
            for s in user.get("shorteners", []):
                if s.get("abp_key") == api or s.get("manual_abp_key") == api:
                    is_manual = (s.get("manual_abp_key") == api)
                    final_shortener_config = {
                        "base_url": s.get("base_url"),
                        "api_key": s.get("api_key"),
                        "mode": "MANUAL" if is_manual else s.get("mode", "NORMAL"),
                        "manual_min_seconds": s.get("manual_min_seconds"),
                        "manual_max_seconds": s.get("manual_max_seconds")
                    }
                    break

    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    if not final_shortener_config:
        raise HTTPException(status_code=400, detail="Shortener not connected")

    shortener_base = final_shortener_config['base_url']
    shortener_api = decrypt_url(final_shortener_config['api_key'])

    # =====================================================
    # GENERATE SECURE URL WITH target/hash/salt
    # =====================================================
    
    # Our bridge URL that the shortener will redirect to
    current_base = str(request.base_url).rstrip('/')
    
    # Generate secure URL with target/hash/salt structure
    # The target is the original URL that the user wants to access
    bridge_url = create_secure_url(url, current_base)
    
    logger.info(f"Generated secure URL: {bridge_url}")

    # Save the mapping (keeping short_id for backward compatibility)
    short_id = secrets.token_urlsafe(8)
    protected_link = {
        "user_id": str(user['_id']),
        "short_id": short_id,
        "original_url": url,
        "secure_url": bridge_url,  # Store the full secure URL
        "shortener_base_url": shortener_base,
        "created_at": datetime.utcnow(),
        "mode": final_shortener_config.get("mode", "NORMAL"),
        "manual_min_seconds": final_shortener_config.get("manual_min_seconds"),
        "manual_max_seconds": final_shortener_config.get("manual_max_seconds"),
        # Store hash components for verification
        "target": base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8'),
        "hash": generate_hmac_hash(url)[0],
        "salt": generate_hmac_hash(url)[1]
    }
    await db.protected_links.insert_one(protected_link)

    # Update total requests
    await db.users.update_one({"_id": user['_id']}, {"$inc": {"total_requests": 1}})

    # Send the secure URL to the shortener API
    api_url = f"{shortener_base}/api"
    params = {
        "api": shortener_api,
        "url": bridge_url  # Now this is the secure URL with target/hash/salt
    }

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(api_url, params=params, timeout=10.0)
            if resp.status_code in [200, 301, 302, 307, 308]:
                try:
                    result = resp.json()
                    # Add the secure URL to the response for debugging
                    if isinstance(result, dict):
                        result["secure_url"] = bridge_url
                    return result
                except Exception:
                    # If flat-text shortener, return it directly
                    return {
                        "status": "success", 
                        "short_url": resp.text.strip(),
                        "secure_url": bridge_url
                    }
            else:
                return JSONResponse(
                    content={
                        "status": "error", 
                        "message": "Shortener API returned an error",
                        "secure_url": bridge_url  # Still return the URL even on error
                    },
                    status_code=resp.status_code
                )
    except Exception as e:
        return JSONResponse(
            content={
                "status": "error", 
                "message": f"Connection to shortener failed: {str(e)}",
                "secure_url": bridge_url
            },
            status_code=500
        )

# =====================================================
# Utility endpoint to generate secure URL directly
# =====================================================

@router.get("/generate-secure-url")
async def generate_secure_url_endpoint(
    url: str = Query(..., description="Target URL to encode"),
    request: Request = None
):
    """
    Generate a secure URL with target, hash, and salt parameters
    Useful for testing and debugging
    """
    current_base = str(request.base_url).rstrip('/') if request else settings.BASE_URL
    secure_url = create_secure_url(url, current_base)
    
    hash_value, salt = generate_hmac_hash(url)
    target_b64 = base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8')
    
    return {
        "secure_url": secure_url,
        "target": target_b64,
        "hash": hash_value,
        "salt": salt,
        "original_url": url
    }

@router.get("/health")
async def health_check():
    return {"status": "ok"}
