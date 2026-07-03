from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.security import decrypt_url
import httpx
from datetime import datetime
from bson import ObjectId

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(api_router)

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

@app.get("/{short_id}")
async def direct_redirect(request: Request, short_id: str, db = Depends(get_database)):
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    user_id = link['user_id']
    user = await db.users.find_one({"_id": ObjectId(user_id)}) if isinstance(user_id, str) else await db.users.find_one({"_id": user_id})

    if not user or not user.get('config'):
        return RedirectResponse(url=link['original_url'])

    # Log visit
    await db.request_logs.insert_one({
        "short_id": short_id,
        "timestamp": datetime.utcnow(),
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent"),
        "referer": request.headers.get("referer"),
        "status": "success",
        "type": "direct_redirect"
    })

    # Call user's shortener API to get the final destination shortlink
    shortener_base = user['config']['base_url']
    encrypted_api = user['config']['api_key']
    shortener_api = decrypt_url(encrypted_api)
    dest_url = link['original_url']

    api_url = f"{shortener_base}/api?api={shortener_api}&url={dest_url}"

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(api_url, timeout=10.0)
            if resp.status_code == 200:
                result = resp.json()
                short_url = result.get("short_url") or result.get("shortenedUrl")
                if short_url:
                    return RedirectResponse(url=short_url)
    except Exception:
        pass

    # Fallback to original URL if shortener fails
    return RedirectResponse(url=dest_url)

@app.get("/health")
async def health_check():
    return {"status": "ok"}
