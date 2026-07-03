from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.security import generate_challenge_token, verify_challenge_token, decrypt_url
import httpx
from datetime import datetime
from bson import ObjectId
from urllib.parse import urlparse

app = FastAPI(title=settings.PROJECT_NAME)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

app.include_router(api_router)

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

@app.get("/{short_id}", response_class=HTMLResponse)
async def serve_challenge(request: Request, short_id: str, db = Depends(get_database)):
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    challenge_token = generate_challenge_token(short_id)
    return templates.TemplateResponse("challenge.html", {
        "request": request,
        "short_id": short_id,
        "challenge_token": challenge_token
    })

@app.post("/verify")
async def verify_challenge(request: Request, db = Depends(get_database)):
    data = await request.json()
    short_id = data.get("short_id")
    token = data.get("token")
    js_referer = data.get("referer") # Captured via document.referrer in JS

    if not verify_challenge_token(token, short_id):
        await db.request_logs.insert_one({
            "short_id": short_id,
            "timestamp": datetime.utcnow(),
            "ip": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "referer": js_referer,
            "status": "blocked",
            "reason": "invalid_token"
        })
        return JSONResponse(status_code=400, content={"status": "fail", "reason": "invalid_token"})

    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
         return JSONResponse(status_code=404, content={"status": "fail", "reason": "not_found"})

    user_id = link['user_id']
    user = await db.users.find_one({"_id": ObjectId(user_id)}) if isinstance(user_id, str) else await db.users.find_one({"_id": user_id})

    if not user or not user.get('config'):
        return JSONResponse(status_code=400, content={"status": "fail", "reason": "misconfigured"})

    # Referrer Validation (Server-side)
    allowed_url = user['config']['base_url']
    allowed_domain = urlparse(allowed_url).netloc.lower()
    referer_domain = urlparse(js_referer).netloc.lower() if js_referer else ""

    is_valid_referer = True
    if not js_referer or not referer_domain:
        is_valid_referer = False
    elif allowed_domain:
        if allowed_domain not in referer_domain and not referer_domain.endswith(allowed_domain):
            is_valid_referer = False

    if not is_valid_referer:
        await db.request_logs.insert_one({
            "short_id": short_id,
            "timestamp": datetime.utcnow(),
            "ip": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "referer": js_referer,
            "status": "blocked",
            "reason": "referer_failed"
        })
        return JSONResponse(status_code=403, content={"status": "fail", "reason": "bypass_detected"})

    # Log success
    await db.request_logs.insert_one({
        "short_id": short_id,
        "timestamp": datetime.utcnow(),
        "ip": request.client.host,
        "user_agent": request.headers.get("user-agent"),
        "referer": js_referer,
        "status": "success"
    })

    # Call user's shortener API
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
                    return {"status": "success", "redirect": short_url}
    except Exception:
        pass

    return {"status": "success", "redirect": dest_url}

@app.get("/health")
async def health_check():
    return {"status": "ok"}
