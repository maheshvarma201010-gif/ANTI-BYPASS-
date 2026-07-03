from fastapi import FastAPI, Request, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.security import decrypt_url
import httpx
from datetime import datetime
from bson import ObjectId
import secrets
from typing import Optional
from urllib.parse import urlparse

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(api_router)

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

@app.get("/{short_id}")
async def direct_redirect(
    request: Request,
    short_id: str,
    sig: Optional[str] = Query(None),
    db = Depends(get_database)
):
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    user_id = link['user_id']
    user = await db.users.find_one({"_id": ObjectId(user_id)}) if isinstance(user_id, str) else await db.users.find_one({"_id": user_id})

    if not user or not user.get('config'):
        return RedirectResponse(url=link['original_url'])

    shortener_base = user['config']['base_url']
    ip = request.client.host

    # 1. Initial Hit (no token)
    if not sig:
        # Bot handling: Allow bots to use 302 or 200 ok redirects
        ua = request.headers.get("user-agent", "").lower()
        is_bot = any(bot_name in ua for bot_name in ["telegram", "discord", "whatsapp", "bot", "crawler", "spider"])

        if is_bot:
            return RedirectResponse(url=link['original_url'])

        # Check if already blocked
        blocked = await db.verifications.find_one({"ip": ip, "short_id": short_id, "status": "blocked"})
        if blocked:
            return HTMLResponse(content="<h1>⚠️ Bypass Detected</h1>", status_code=403)

        # Check if already verified (Requirement 7: redirect only once)
        # If they already have a successful verification, we can let them through
        success = await db.verifications.find_one({"ip": ip, "short_id": short_id, "status": "success"})
        if success:
            return RedirectResponse(url=link['original_url'])

        # Generate one-time token
        token = secrets.token_urlsafe(16)
        await db.verifications.insert_one({
            "token": token,
            "short_id": short_id,
            "ip": ip,
            "status": "pending",
            "created_at": datetime.utcnow(),
            "server_verified": False
        })

        # Determine current base URL dynamically
        current_base = str(request.base_url).rstrip('/')
        callback_url = f"{current_base}/{short_id}?sig={token}"

        encrypted_api = user['config']['api_key']
        shortener_api = decrypt_url(encrypted_api)

        if not shortener_api:
            return HTMLResponse(content="<h1>⚠️ Configuration Error</h1>", status_code=500)

        api_url = f"{shortener_base}/api"
        params = {
            "api": shortener_api,
            "url": callback_url
        }

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(api_url, params=params, timeout=10.0)
                if resp.status_code == 200:
                    result = resp.json()
                    # Support various shortener API response formats
                    short_url = (
                        result.get("short_url") or
                        result.get("shortenedUrl") or
                        result.get("url") or
                        result.get("link") or
                        result.get("short")
                    )
                    if short_url:
                        return RedirectResponse(url=short_url)
        except Exception:
            pass

        # Requirement 10: minimize exposure and prevent direct access.
        # Falling back to original_url on API failure is a security hole.
        return HTMLResponse(content="<h1>⚠️ Service Temporarily Unavailable</h1>", status_code=503)

    # 2. Return from shortener
    verification = await db.verifications.find_one({"token": sig, "short_id": short_id, "ip": ip})
    if not verification:
        return HTMLResponse(content="<h1>⚠️ Bypass Detected</h1>", status_code=403)

    if verification['status'] != 'pending':
        return HTMLResponse(content="<h1>⚠️ Bypass Detected</h1>", status_code=403)

    shortener_domain = urlparse(shortener_base).netloc
    referer = request.headers.get("referer", "")
    referer_host = urlparse(referer).netloc

    # Stricter hostname-based check
    if referer_host and (referer_host == shortener_domain or referer_host.endswith("." + shortener_domain)):
        # Referer valid - Grant access
        await db.verifications.update_one(
            {"token": sig},
            {"$set": {"status": "success", "validated_at": datetime.utcnow()}}
        )
        return RedirectResponse(url=link['original_url'])
    else:
        # Referer missing or invalid - Block access
        await db.verifications.update_one(
            {"token": sig},
            {"$set": {"status": "blocked", "blocked_at": datetime.utcnow()}}
        )
        return HTMLResponse(content="<h1>⚠️ Bypass Detected</h1>", status_code=403)

@app.get("/health")
async def health_check():
    return {"status": "ok"}
