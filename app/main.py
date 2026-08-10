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
    <title>Bypass Detected - Security Violation</title>
    <!-- Include Tailwind CSS via CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap');
        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background: radial-gradient(circle at top right, #fff5f5, #ffffff);
        }
        .glass-panel {
            background: rgba(255, 255, 255, 0.85);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(229, 62, 62, 0.15);
        }
        .animate-bounce-slow {
            animation: bounce 2s infinite;
        }
        @keyframes bounce {
            0%, 100% {
                transform: translateY(-5%);
                animation-timing-function: cubic-bezier(0.8,0,1,1);
            }
            50% {
                transform: none;
                animation-timing-function: cubic-bezier(0,0,0.2,1);
            }
        }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4 bg-slate-50">
    <div class="w-full max-w-lg glass-panel rounded-3xl shadow-2xl overflow-hidden p-8 md:p-10 text-center relative border border-rose-100">
        <!-- Top Decorative Gradient Bar -->
        <div class="absolute top-0 left-0 right-0 h-2 bg-gradient-to-r from-red-500 via-rose-500 to-orange-500"></div>

        <!-- Shield / Warning Icon -->
        <div class="mx-auto w-24 h-24 mb-6 bg-rose-50 rounded-full flex items-center justify-center border-4 border-rose-100 animate-bounce-slow shadow-sm">
            <span class="text-rose-500 text-4xl"><i class="fa-solid fa-shield-halved"></i></span>
        </div>

        <!-- Heading -->
        <h1 class="text-3xl font-extrabold text-slate-800 tracking-tight mb-3">
            🚫 BYPASS DETECTED
        </h1>
        <p class="text-slate-500 text-md leading-relaxed mb-6">
            Our multi-layer security system has intercepted an abnormal request that violates session validation policies.
        </p>

        <!-- Reason Card -->
        <div class="bg-rose-50/70 border border-rose-100 rounded-2xl p-5 mb-8 text-left relative overflow-hidden">
            <div class="absolute top-0 right-0 p-3 text-rose-200 text-5xl font-bold select-none pointer-events-none">
                <i class="fa-solid fa-ban"></i>
            </div>
            <span class="text-xs font-bold uppercase tracking-wider text-rose-500 block mb-1">Security Reason</span>
            <div class="text-slate-800 font-mono text-sm break-all font-semibold leading-relaxed">
                {detected_reason}
            </div>
        </div>

        <!-- Action Guide -->
        <div class="text-left mb-8 space-y-3 bg-slate-50 border border-slate-100 rounded-2xl p-5">
            <span class="text-xs font-bold uppercase tracking-wider text-slate-400 block mb-2">How to continue safely</span>
            <div class="flex items-start gap-3 text-sm text-slate-600">
                <span class="text-emerald-500 mt-0.5"><i class="fa-solid fa-circle-check"></i></span>
                <p>Go back to the <strong>original source</strong> where the link was shared.</p>
            </div>
            <div class="flex items-start gap-3 text-sm text-slate-600">
                <span class="text-emerald-500 mt-0.5"><i class="fa-solid fa-circle-check"></i></span>
                <p>Click the <strong>original shortlink</strong> directly to initialize a secure session.</p>
            </div>
            <div class="flex items-start gap-3 text-sm text-slate-600">
                <span class="text-emerald-500 mt-0.5"><i class="fa-solid fa-circle-check"></i></span>
                <p>Do not share, bookmark, or directly copy the continuation URL.</p>
            </div>
        </div>

        <!-- Footer / Action Button -->
        <div class="border-t border-slate-100 pt-6">
            <p class="text-sm font-medium text-slate-500 mb-4">Please start again from the original shortlink.</p>
            <button onclick="window.history.back()" class="w-full py-3.5 px-6 rounded-2xl font-semibold bg-gradient-to-r from-red-500 to-rose-600 text-white hover:from-red-600 hover:to-rose-700 active:scale-[0.98] transition shadow-lg shadow-rose-500/20 focus:outline-none focus:ring-2 focus:ring-rose-500 focus:ring-offset-2">
                <i class="fa-solid fa-arrow-left mr-2"></i> Try Again / Go Back
            </button>
        </div>
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
    # Tokens expire after 120 seconds for slower networks
    if time.time() - session["created_at"] > 120:
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
        ref_netloc = parsed_referer.netloc.lower()
        base_netloc = parsed_request.netloc.lower()

        # Retrieve shortener domain to allow redirects retaining the shortener Referer
        shortener_domain = ""
        try:
            user_id = ObjectId(session["user_id"])
            user = await db.users.find_one({"_id": user_id})
            if user:
                shortener_domain = urlparse(user['config']['base_url']).netloc.lower()
        except Exception:
            pass

        if base_netloc not in ref_netloc and ref_netloc not in base_netloc:
            # Also allow shortener_domain if present
            if not shortener_domain or (shortener_domain not in ref_netloc and ref_netloc not in shortener_domain):
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
    return RedirectResponse(url=destination_url, status_code=302)

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
    # We do not block empty Referer because legitimate clicks from chat apps or browsers stripping Referer
    # must not be falsely flagged as bypasses. Referer is only verified if it is present.
    shortener_domain = urlparse(user['config']['base_url']).netloc.lower()
    parsed_base = urlparse(str(request.base_url))
    base_netloc = parsed_base.netloc.lower()

    referer_valid = False
    referer_reason = ""

    if not referer:
        referer_valid = True
        referer_reason = "missing_referer_allowed"
    else:
        ref_netloc = urlparse(referer).netloc.lower()
        if shortener_domain and (shortener_domain in ref_netloc or ref_netloc in shortener_domain):
            referer_valid = True
            referer_reason = "shortener_match"
        elif base_netloc and (base_netloc in ref_netloc or ref_netloc in base_netloc):
            referer_valid = True
            referer_reason = "base_match"
        elif await is_allowed_referer(referer, db):
            referer_valid = True
            referer_reason = "allowed_referer"
        elif await is_related_domain(referer, shortener_domain, db):
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
    response = RedirectResponse(url=f"/continue?token={token}", status_code=302)
    is_secure = request.url.scheme == "https"
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        path="/",
        max_age=120  # 120 seconds TTL
    )
    return response

@app.get("/health")
async def health_check():
    return {"status": "ok"}
