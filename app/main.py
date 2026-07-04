from fastapi import FastAPI, Request, Depends, HTTPException, Query, Body
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.security import decrypt_url, verify_challenge_token, generate_challenge_token
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
async def bridge_page(
    request: Request,
    short_id: str,
    db = Depends(get_database)
):
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    # Serve the JS challenge as per requirements
    token = generate_challenge_token(short_id)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <script>
            window.onload = function() {{
                const payload = {{
                    referrer: document.referrer,
                    userAgent: navigator.userAgent,
                    hostname: window.location.hostname,
                    timestamp: Math.floor(Date.now() / 1000),
                    token: "{token}"
                }};

                fetch("/validate/{short_id}", {{
                    method: "POST",
                    headers: {{ "Content-Type": "application/json" }},
                    body: JSON.stringify(payload)
                }})
                .then(r => r.json())
                .then(data => {{
                    if (data.status === "success") {{
                        window.location.href = data.destination;
                    }} else {{
                        document.body.innerHTML = "<h1>⚠️ Bypass Detected</h1>";
                    }}
                }})
                .catch(() => {{
                    document.body.innerHTML = "<h1>⚠️ Bypass Detected</h1>";
                }});
            }};
        </script>
    </head>
    <body></body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/validate/{short_id}")
async def validate_js(
    short_id: str,
    payload: dict = Body(...),
    db = Depends(get_database)
):
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        return JSONResponse(content={"status": "error", "message": "Invalid link"}, status_code=400)

    user_id = ObjectId(link['user_id'])

    # 1. Was JS executed? (implied by the call)
    # 2. Token validation (token + expired)
    token = payload.get("token")
    if not verify_challenge_token(token, short_id):
        await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
        return JSONResponse(content={"status": "error", "message": "Invalid or expired token"}, status_code=403)

    # 3. Referer check
    referer = payload.get("referrer")
    user = await db.users.find_one({"_id": user_id})
    shortener_domain = urlparse(user['config']['base_url']).netloc

    # "Treat an empty document.referrer as suspicious"
    if not referer or shortener_domain not in referer:
        await db.users.update_one({"_id": user_id}, {"$inc": {"referer_failures": 1, "blocked_count": 1}})
        return JSONResponse(content={"status": "error", "message": "Invalid referer"}, status_code=403)

    # 4. Success
    await db.users.update_one({"_id": user_id}, {"$inc": {"success_count": 1}})
    return {"status": "success", "destination": link['original_url']}

@app.get("/health")
async def health_check():
    return {"status": "ok"}
