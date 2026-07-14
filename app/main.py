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
            from app.core.referer import extract_domain, get_allowed_domains
            ref_host = extract_domain(referer)

            # 1. Check dynamically whitelisted domains
            allowed_domains = await get_allowed_domains(db)
            for domain in allowed_domains:
                allowed_host = extract_domain(domain)
                if ref_host == allowed_host or ref_host.endswith(f".{allowed_host}"):
                    is_valid = True
                    break

            # 2. Check user's connected shortener domain
            if not is_valid and user and "config" in user and "base_url" in user["config"]:
                shortener_base = user["config"]["base_url"]
                short_host = extract_domain(shortener_base)
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
async def health_check(db = Depends(get_database)):
    try:
        # Perform a fast ping command to verify database connectivity
        await db.command("ping")
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "details": str(e)
        }
