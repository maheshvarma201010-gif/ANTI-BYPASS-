import secrets
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from app.models.database import get_database
from app.core.security import generate_challenge_token, verify_challenge_token, encrypt_url, decrypt_url
from app.core.config import settings
from datetime import datetime
import httpx

router = APIRouter()

@router.get("/api")
async def create_protected_link(
    request: Request,
    api: str = Query(...),
    url: str = Query(...),
    db = Depends(get_database)
):
    user = await db.users.find_one({"api_key": api})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    short_id = secrets.token_urlsafe(6)

    protected_link = {
        "user_id": str(user['_id']),
        "short_id": short_id,
        "original_url": url,
        "created_at": datetime.utcnow()
    }

    await db.protected_links.insert_one(protected_link)

    # Determine current base URL dynamically
    current_base = str(request.base_url).rstrip('/')
    protected_url = f"{current_base}/{short_id}"

    # Notify via Telegram
    try:
        from app.bot.bot import bot
        await bot.send_message(user['telegram_id'], f"✅ Link Protected: {url}\nProtected URL: {protected_url}")
    except Exception:
        pass

    return {
        "status": "success",
        "protected_url": protected_url,
        "short_id": short_id
    }

@router.get("/health")
async def health_check():
    return {"status": "ok"}
