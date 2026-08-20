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

router = APIRouter()

@router.get("/api")
@router.get("/st")
async def create_protected_link(
    request: Request,
    api: str = Query(...),
    url: str = Query(...),
    db = Depends(get_database)
):
    # Multi-shortener daisy-chain lookup to resolve the original raw external shortener config
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
            # It points to us! Let's extract the next API key in the chain and resolve again
            try:
                decrypted_next_api = decrypt_url(shortener_config["api_key"])
                current_api = decrypted_next_api
            except Exception:
                current_api = shortener_config["api_key"]
            continue
        else:
            # We found a raw, external shortener!
            final_shortener_config = shortener_config
            break

    # Fallback to the direct config if daisy-chain didn't find any external shortener
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

    short_id = secrets.token_urlsafe(8)

    # 1. Save the mapping
    protected_link = {
        "user_id": str(user['_id']),
        "short_id": short_id,
        "original_url": url,
        "shortener_base_url": shortener_base,
        "created_at": datetime.utcnow(),
        "mode": final_shortener_config.get("mode", "NORMAL"),
        "manual_min_seconds": final_shortener_config.get("manual_min_seconds"),
        "manual_max_seconds": final_shortener_config.get("manual_max_seconds")
    }
    await db.protected_links.insert_one(protected_link)

    # Update total requests
    await db.users.update_one({"_id": user['_id']}, {"$inc": {"total_requests": 1}})

    # Our bridge URL that the shortener will redirect to
    current_base = str(request.base_url).rstrip('/')
    bridge_url = f"{current_base}/{short_id}"

    api_url = f"{shortener_base}/api"
    params = {
        "api": shortener_api,
        "url": bridge_url
    }

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(api_url, params=params, timeout=10.0)
            if resp.status_code in [200, 301, 302, 307, 308]:
                try:
                    result = resp.json()
                    return result
                except Exception:
                    # If flat-text shortener, return it directly in JSON form
                    return {"status": "success", "short_url": resp.text.strip()}
            else:
                return JSONResponse(
                    content={"status": "error", "message": "Shortener API returned an error"},
                    status_code=resp.status_code
                )
    except Exception as e:
        return JSONResponse(
            content={"status": "error", "message": f"Connection to shortener failed: {str(e)}"},
            status_code=500
        )

@router.get("/api/verify-status")
@router.get("/api/check-verification")
@router.get("/api/verifybot/status")
@router.post("/api/verifybot/verify")
async def verify_status_endpoint(
    request: Request,
    api_key: Optional[str] = Query(None),
    telegram_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    db = Depends(get_database)
):
    # Extract API key from query params or Authorization header
    key = api_key
    if not key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            key = auth_header.split(" ", 1)[1].strip()

    # Verify key against FILESTORE_APIKEY or user api_key
    is_valid_key = False
    if settings.FILESTORE_APIKEY and key == settings.FILESTORE_APIKEY:
        is_valid_key = True
    elif key:
        found = await db.users.find_one({"$or": [{"api_key": key}, {"shorteners.abp_key": key}, {"shorteners.manual_abp_key": key}]})
        if found:
            is_valid_key = True

    if key and not is_valid_key:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    query_id = str(telegram_id) if telegram_id else (str(user_id) if user_id else None)
    if not query_id:
        return JSONResponse(content={"status": "error", "message": "Missing telegram_id or user_id parameter"})

    verification = await db.user_verifications.find_one({
        "$or": [{"telegram_id": query_id}, {"user_id": query_id}]
    })

    if verification and verification.get("verified", False):
        return {
            "status": "success",
            "verified": True,
            "telegram_id": verification.get("telegram_id"),
            "verified_at": verification.get("verified_at"),
            "bot_username": verification.get("bot_username")
        }

    return {
        "status": "success",
        "verified": False,
        "message": "User not verified"
    }

@router.get("/health")
async def health_check():
    return {"status": "ok"}
