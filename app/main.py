from fastapi import FastAPI, Request, Depends, HTTPException, Body, Query
from fastapi.responses import HTMLResponse
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.referer import get_bridge_page_html, handle_validation

app = FastAPI(title=settings.PROJECT_NAME)

app.include_router(api_router)

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

import secrets
import time
from fastapi.responses import RedirectResponse
from urllib.parse import urlparse
from app.core.referer import is_allowed_referer, is_related_domain, is_whitelisted_user, is_development_environment, get_user_verification_history, is_legitimate_no_referer
from bson import ObjectId

BYPASS_DETECTED_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bypass Detected</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: #f7fafc;
            color: #2d3748;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.05);
            max-width: 500px;
            width: 100%;
            text-align: center;
            border: 2px solid #e2e8f0;
        }
        h1 {
            color: #e53e3e;
            font-size: 24px;
            margin-top: 0;
            margin-bottom: 20px;
        }
        p {
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .reason {
            background-color: #fffaf0;
            border: 1px solid #feebc8;
            color: #dd6b20;
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 14px;
            margin-bottom: 24px;
            word-break: break-all;
        }
        .footer {
            color: #718096;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚫 BYPASS DETECTED</h1>
        <p>Your request could not be verified due to a security violation.</p>
        <div class="reason">Reason: {detected_reason}</div>
        <p class="footer">Please start again from the original shortlink.</p>
    </div>
</body>
</html>
"""

@app.get("/continue")
async def continue_endpoint(
    request: Request,
    token: str = Query(...),
    db = Depends(get_database)
):
    cookie_session_id = request.cookies.get("session_id")
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    referer = request.headers.get("referer", "")

    # Retrieve session bound to token
    session = await db.sessions.find_one({"token": token})

    # Protection 1: Invalid/missing token
    if not session:
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE.replace("{detected_reason}", "Invalid token"),
            status_code=403
        )

    # Protection 2: Expired verification sessions
    # Tokens expire after 60 seconds
    if time.time() - session["created_at"] > 60:
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE.replace("{detected_reason}", "Expired verification session"),
            status_code=403
        )

    # Protection 3: Reusing an already completed/consumed verification session
    if session.get("consumed", False):
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE.replace("{detected_reason}", "Token already used"),
            status_code=403
        )

    # Protection 4: Session mismatch (anti-paste/direct access/share check)
    if not cookie_session_id or cookie_session_id != session["session_id"]:
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE.replace("{detected_reason}", "Session mismatch"),
            status_code=403
        )

    # Protection 5: Client consistency mismatch (User-Agent changed)
    # We relax strict IP checks to support shifting IP mobile users, but User-Agent is validated.
    if session["user_agent"] != user_agent:
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE.replace("{detected_reason}", "Session client mismatch"),
            status_code=403
        )

    # Protection 6: Invalid Referer signal (Referer check as an additional signal, don't rely only on it)
    # If a Referer is present, it shouldn't be completely mismatched from the expected flow
    if referer:
        parsed_referer = urlparse(referer)
        parsed_request = urlparse(str(request.base_url))
        if parsed_referer.netloc != parsed_request.netloc:
            return HTMLResponse(
                content=BYPASS_DETECTED_TEMPLATE.replace("{detected_reason}", "Invalid referer signal"),
                status_code=403
            )

    # Consume/invalidate token atomically server-side to prevent TOCTOU race conditions / parallel replay
    result = await db.sessions.update_one(
        {"_id": session["_id"], "consumed": False},
        {"$set": {"consumed": True}}
    )
    if result.modified_count == 0:
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE.replace("{detected_reason}", "Token already used"),
            status_code=403
        )

    # Retrieve real/original destination URL
    destination_url = session["original_url"]

    # Redirect to the final destination
    return RedirectResponse(url=destination_url, status_code=303)

@app.get("/{short_id}")
async def original_shortlink(
    request: Request,
    short_id: str,
    db = Depends(get_database)
):
    # Health and special routes exceptions
    if short_id in ["health", "continue"]:
        raise HTTPException(status_code=404)

    # 1. Fetch the mapping
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    user_id = ObjectId(link['user_id'])
    user = await db.users.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    referer = request.headers.get("referer", "")

    # ============== REFERER VALIDATION ==============
    shortener_domain = urlparse(user['config']['base_url']).netloc
    referer_valid = False
    referer_reason = ""

    # Direct match
    if shortener_domain in referer:
        referer_valid = True
    else:
        # Check if referer is a known allowed source
        if await is_allowed_referer(referer, db):
            referer_valid = True
            referer_reason = "allowed_referer"
        # Check if legitimate missing
        elif not referer:
            user_history = await get_user_verification_history(user_id, db)
            if await is_legitimate_no_referer(client_ip, user_agent, user_id, db):
                referer_valid = True
                referer_reason = "legitimate_missing"
            elif user_history.get("success_rate", 0) > 0.9:
                referer_valid = True
                referer_reason = "trusted_user"
        # Check if subdomain or related domain
        if not referer_valid and referer:
            if await is_related_domain(referer, shortener_domain, db):
                referer_valid = True
                referer_reason = "related_domain"

    if not referer_valid:
        if await is_whitelisted_user(user_id, db):
            referer_valid = True
            referer_reason = "whitelisted"
        elif await is_development_environment(client_ip, user_agent):
            referer_valid = True
            referer_reason = "development"

    if not referer_valid:
        # Update user's blocked/referer failures count
        await db.users.update_one(
            {"_id": user_id},
            {"$inc": {"referer_failures": 1, "blocked_count": 1}}
        )
        # Return bypass detected page for invalid referer
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE.replace("{detected_reason}", "Invalid referer"),
            status_code=403
        )

    # 2. Referer validated! Create a secure, short-lived server-side session.
    session_id = secrets.token_urlsafe(32)
    token = secrets.token_urlsafe(32)
    timestamp = time.time()

    session_doc = {
        "session_id": session_id,
        "token": token,
        "short_id": short_id,
        "original_url": link["original_url"],
        "user_id": str(user_id),
        "client_ip": client_ip,
        "user_agent": user_agent,
        "created_at": timestamp,
        "verified": True,  # Already verified backend referer check
        "consumed": False
    }

    await db.sessions.insert_one(session_doc)

    # Increment success count on referer validation
    await db.users.update_one(
        {"_id": user_id},
        {
            "$inc": {"success_count": 1},
            "$set": {
                "last_success": timestamp,
                "last_ip": client_ip,
                "last_user_agent": user_agent
            }
        }
    )

    # 3. Set the session ID cookie and redirect to continuation endpoint
    response = RedirectResponse(url=f"/continue?token={token}", status_code=303)
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=60  # 60 seconds TTL
    )
    return response

@app.get("/health")
async def health_check():
    return {"status": "ok"}
