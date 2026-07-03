from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
import httpx
from datetime import datetime
from bson import ObjectId

app = FastAPI(title=settings.PROJECT_NAME)
templates = Jinja2Templates(directory="app/templates")

app.include_router(api_router)

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

@app.get("/{short_id}")
async def referer_redirect(request: Request, short_id: str, db = Depends(get_database)):
    referer = request.headers.get("referer")

    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    # Block if no referer
    if not referer:
        await db.request_logs.insert_one({
            "short_id": short_id,
            "timestamp": datetime.utcnow(),
            "ip": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "referer": referer,
            "status": "blocked",
            "reason": "referer_empty"
        })
        return templates.TemplateResponse("bypass_detected.html", {"request": request})

    user_id = link['user_id']
    user = await db.users.find_one({"_id": ObjectId(user_id)}) if isinstance(user_id, str) else await db.users.find_one({"_id": user_id})

    if not user or not user.get('config'):
        return RedirectResponse(url=link['original_url'])

    # Log success
    await db.request_logs.insert_one({
        "short_id": short_id,
        "timestamp": datetime.utcnow(),
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent"),
        "referer": referer,
        "status": "success"
    })

    # Call user's shortener API
    shortener_base = user['config']['base_url']
    shortener_api = user['config']['api_key']
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

    return RedirectResponse(url=dest_url)

@app.get("/health")
async def health_check():
    return {"status": "ok"}
