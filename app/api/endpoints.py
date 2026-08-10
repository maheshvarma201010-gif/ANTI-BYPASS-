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
    # Find user by global api_key or by matching shorteners abp_key
    user = await db.users.find_one({
        "$or": [
            {"api_key": api},
            {"shorteners.abp_key": api}
        ]
    })
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    # 1. Determine the specific shortener config
    shortener_config = None
    if user.get("api_key") == api:
        shortener_config = user.get("config")
    else:
        for s in user.get("shorteners", []):
            if s.get("abp_key") == api:
                shortener_config = {
                    "base_url": s.get("base_url"),
                    "api_key": s.get("api_key")
                }
                break

    if not shortener_config:
        raise HTTPException(status_code=400, detail="Shortener not connected")

    shortener_base = shortener_config['base_url']
    shortener_api = decrypt_url(shortener_config['api_key'])

    short_id = secrets.token_urlsafe(8)

    # 2. Save the mapping with the specific shortener base URL
    protected_link = {
        "user_id": str(user['_id']),
        "short_id": short_id,
        "original_url": url,
        "shortener_base_url": shortener_base,
        "created_at": datetime.utcnow()
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
        async with httpx.AsyncClient() as client:
            resp = await client.get(api_url, params=params, timeout=10.0)
            if resp.status_code == 200:
                result = resp.json()
                # We return the exact same original shortener link
                return result
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

@router.get("/health")
async def health_check():
    return {"status": "ok"}
