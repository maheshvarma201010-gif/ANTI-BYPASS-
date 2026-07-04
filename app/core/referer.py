from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
from datetime import datetime, timezone
from bson import ObjectId
from urllib.parse import urlparse
from app.core.security import generate_challenge_token, verify_challenge_token

def get_bridge_page_html(short_id: str) -> str:
    token = generate_challenge_token(short_id)
    return f"""
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
                    }} else if (data.status === "blocked" && data.reason === "Missing JavaScript Referer") {{
                        document.body.innerHTML = `
                            <h1>❌ Bypass Detected page</h1>
                            <p>No valid JavaScript Referer was found.</p>
                            <p>Access has been denied.</p>
                            <p>Do not redirect to the destination.</p>
                            <p>Do not generate or return the short link.</p>
                            <p>Do not retry automatically.</p>
                            <p>Do not continue any additional verification.</p>
                        `;
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
    <body>
        <div id="verification-status">
            <h1>❌ JavaScript verification failed.</h1>
            <p>Possible bypass attempt detected.</p>
            <p>Do not redirect.</p>
        </div>
    </body>
    </html>
    """

async def handle_validation(
    request: Request,
    short_id: str,
    payload: dict,
    db
) -> JSONResponse:
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        return JSONResponse(content={"status": "error", "message": "Invalid link"}, status_code=400)

    user_id = ObjectId(link['user_id'])
    user = await db.users.find_one({"_id": user_id})
    if not user:
        return JSONResponse(content={"status": "error", "message": "User not found"}, status_code=404)

    referer = payload.get("referrer")

    # Rule 3: Missing JavaScript Referer
    if not referer:
        # Log the event
        log_entry = {
            "short_id": short_id,
            "timestamp": datetime.now(timezone.utc),
            "ip": request.client.host if request.client else "unknown",
            "user_agent": request.headers.get("user-agent", ""),
            "api_key": user.get("api_key", "N/A"),
            "requested_url": str(request.url),
            "reason": "Missing JavaScript Referer",
            "status": "blocked"
        }
        await db.request_logs.insert_one(log_entry)
        await db.users.update_one({"_id": user_id}, {"$inc": {"referer_failures": 1, "blocked_count": 1}})

        return JSONResponse(
            status_code=403,
            content={
                "status": "blocked",
                "reason": "Missing JavaScript Referer",
                "message": "Bypass detected."
            }
        )

    # 1. Was JS executed? (implied by the call)
    # 2. Token validation (token + expired)
    token = payload.get("token")
    if not verify_challenge_token(token, short_id):
        await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
        return JSONResponse(content={"status": "error", "message": "Invalid or expired token"}, status_code=403)

    # 3. Referer check
    shortener_domain = urlparse(user['config']['base_url']).netloc

    if shortener_domain not in referer:
        await db.users.update_one({"_id": user_id}, {"$inc": {"referer_failures": 1, "blocked_count": 1}})
        return JSONResponse(content={"status": "error", "message": "Invalid referer"}, status_code=403)

    # 4. Success
    await db.users.update_one({"_id": user_id}, {"$inc": {"success_count": 1}})
    return JSONResponse(content={"status": "success", "destination": link['original_url']})
