from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.security import generate_challenge_token, verify_challenge_token
import httpx
from datetime import datetime
from bson import ObjectId

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
    referer = data.get("referer")

    # Collect fingerprint data as requested (but simplified validation for now)
    fingerprint = {
        "user_agent": request.headers.get("user-agent"),
        "language": data.get("language"),
        "screen_size": data.get("screen_size"),
        "timezone": data.get("timezone")
    }

    if not verify_challenge_token(token, short_id):
        return JSONResponse(status_code=400, content={"status": "fail", "reason": "invalid_token"})

    # Referer Validation
    if not referer or referer == "null" or referer == "undefined":
        # Log failure
        await db.request_logs.insert_one({
            "short_id": short_id,
            "timestamp": datetime.utcnow(),
            "ip": request.client.host,
            "user_agent": fingerprint["user_agent"],
            "referer": referer,
            "fingerprint": fingerprint,
            "status": "blocked",
            "reason": "referer_empty"
        })
        return JSONResponse(status_code=403, content={"status": "fail", "reason": "bypass_detected"})

    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
         return JSONResponse(status_code=404, content={"status": "fail", "reason": "not_found"})

    user_id = link['user_id']
    user = await db.users.find_one({"_id": ObjectId(user_id)}) if isinstance(user_id, str) else await db.users.find_one({"_id": user_id})

    if not user or not user.get('config'):
        return JSONResponse(status_code=400, content={"status": "fail", "reason": "misconfigured"})

    # Log success
    await db.request_logs.insert_one({
        "short_id": short_id,
        "timestamp": datetime.utcnow(),
        "ip": request.client.host,
        "user_agent": fingerprint["user_agent"],
        "referer": referer,
        "fingerprint": fingerprint,
        "status": "success"
    })

    # Redirect to user's shortener
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
                    return {"status": "success", "redirect": short_url}
    except Exception:
        pass

    return {"status": "success", "redirect": dest_url}
