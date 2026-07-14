from fastapi import FastAPI, Request, Depends, HTTPException, Body
from fastapi.responses import HTMLResponse, RedirectResponse
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.referer import get_bridge_page_html, handle_validation, get_blocked_page_html
from urllib.parse import urlparse
from bson import ObjectId
from datetime import datetime

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(api_router)

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

@app.get("/{short_id}")
async def bridge_page(
    request: Request,
    short_id: str,
    db = Depends(get_database)
):
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    referer = request.headers.get("referer", "").strip()
    user_id = link.get("user_id")
    user = None
    if user_id:
        try:
            user = await db.users.find_one({"_id": ObjectId(user_id)})
        except Exception:
            pass

    if referer:
        # Strict server-side referer validation when referer is present
        is_valid = False
        try:
            parsed_ref = urlparse(referer)
            ref_host = (parsed_ref.netloc or parsed_ref.path).lower().strip()
            if ":" in ref_host:
                ref_host = ref_host.split(":")[0]

            # 1. Check dynamically whitelisted domains
            from app.core.referer import get_allowed_domains
            allowed_domains = await get_allowed_domains(db)
            for domain in allowed_domains:
                if ref_host == domain or ref_host.endswith(f".{domain}"):
                    is_valid = True
                    break

            # 2. Check user's connected shortener domain
            if not is_valid and user and "config" in user and "base_url" in user["config"]:
                shortener_base = user["config"]["base_url"]
                parsed_short = urlparse(shortener_base)
                short_host = (parsed_short.netloc or parsed_short.path).lower().strip()
                if ":" in short_host:
                    short_host = short_host.split(":")[0]
                if ref_host == short_host or ref_host.endswith(f".{short_host}"):
                    is_valid = True
        except Exception:
            pass

        if is_valid:
            # Skip verification and immediately redirect to final destination
            if user:
                await db.users.update_one(
                    {"_id": user["_id"]},
                    {
                        "$inc": {"success_count": 1},
                        "$set": {
                            "last_success": datetime.utcnow(),
                            "last_ip": request.client.host if request.client else "unknown",
                            "last_user_agent": request.headers.get("user-agent", "")
                        }
                    }
                )
            return RedirectResponse(url=link['original_url'], status_code=307)
        else:
            # Block the request immediately
            client_ip = request.client.host if request.client else "unknown"
            user_agent = request.headers.get("user-agent", "")
            requested_url = str(request.url)

            log_entry = {
                "timestamp": datetime.utcnow(),
                "ip": client_ip,
                "user_agent": user_agent,
                "referer": referer,
                "requested_url": requested_url,
                "reason": "Invalid Referer",
                "short_id": short_id,
                "status": "blocked"
            }
            await db.request_logs.insert_one(log_entry)

            if user:
                await db.users.update_one(
                    {"_id": user["_id"]},
                    {"$inc": {"blocked_count": 1, "referer_failures": 1}}
                )

            return HTMLResponse(content=get_blocked_page_html(), status_code=403)

    # If referer is missing, serve the bridge page to allow client-side JS / referrer check
    return HTMLResponse(content=get_bridge_page_html(short_id))

@app.post("/validate/{short_id}")
async def validate_js(
    request: Request,
    short_id: str,
    payload: dict = Body(...),
    db = Depends(get_database)
):
    return await handle_validation(request, short_id, payload, db)

@app.get("/health")
async def health_check():
    return {"status": "ok"}
