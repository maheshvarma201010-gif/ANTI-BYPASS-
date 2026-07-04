from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from urllib.parse import urlparse
from app.core.security import generate_challenge_token, verify_challenge_token
import logging
import asyncio
import hashlib
import re

logger = logging.getLogger(__name__)

def get_bridge_page_html(short_id: str) -> str:
    token = generate_challenge_token(short_id)
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="referrer" content="origin">
        <title>Verifying...</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                background: #f5f7fa;
                padding: 20px;
            }}
            .container {{
                background: white;
                border-radius: 12px;
                box-shadow: 0 4px 24px rgba(0,0,0,0.08);
                padding: 40px;
                max-width: 500px;
                width: 100%;
                text-align: center;
            }}
            .spinner {{
                display: inline-block;
                width: 40px;
                height: 40px;
                border: 4px solid #e2e8f0;
                border-top-color: #3b82f6;
                border-radius: 50%;
                animation: spin 0.8s linear infinite;
                margin-bottom: 20px;
            }}
            @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
            h1 {{ font-size: 24px; color: #1a202c; margin-bottom: 12px; }}
            p {{ color: #4a5568; line-height: 1.6; margin-bottom: 16px; }}
            .error-icon {{ font-size: 48px; margin-bottom: 16px; }}
            .btn {{
                display: inline-block;
                padding: 10px 24px;
                background: #3b82f6;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 16px;
                cursor: pointer;
                transition: background 0.2s;
                margin: 4px;
            }}
            .btn:hover {{ background: #2563eb; }}
            .btn-secondary {{ background: #e2e8f0; color: #1a202c; }}
            .btn-secondary:hover {{ background: #cbd5e0; }}
            .progress-bar {{
                width: 100%;
                height: 4px;
                background: #e2e8f0;
                border-radius: 2px;
                overflow: hidden;
                margin: 16px 0;
            }}
            .progress-bar .fill {{
                height: 100%;
                background: #3b82f6;
                transition: width 0.3s ease;
                width: 0%;
            }}
            ul {{ text-align: left; padding-left: 20px; margin: 12px 0; color: #4a5568; }}
            li {{ margin: 6px 0; }}
        </style>
    </head>
    <body>
        <div class="container" id="verification-container">
            <div class="spinner"></div>
            <h1>Verifying your request...</h1>
            <p>Please wait while we verify your browser environment.</p>
            <div class="progress-bar">
                <div class="fill" id="progress-fill"></div>
            </div>
            <p style="font-size: 14px; color: #a0aec0;">Attempt 1 of 3</p>
        </div>

        <script>
            let retryCount = 0;
            const maxRetries = 3;
            const container = document.getElementById('verification-container');
            const progressFill = document.getElementById('progress-fill');

            function updateProgress(attempt) {{
                const percentage = (attempt / maxRetries) * 100;
                progressFill.style.width = percentage + '%';
                document.querySelector('p:last-child').textContent = `Attempt ${{attempt + 1}} of ${{maxRetries}}`;
            }}

            async function verifyWithRetry() {{
                const payload = {{
                    referrer: document.referrer || '',
                    userAgent: navigator.userAgent,
                    hostname: window.location.hostname,
                    timestamp: Math.floor(Date.now() / 1000),
                    token: "{token}",
                    screenWidth: window.screen.width,
                    screenHeight: window.screen.height,
                    language: navigator.language || '',
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
                    retryCount: retryCount
                }};

                try {{
                    updateProgress(retryCount);
                    
                    const response = await fetch("/validate/{short_id}", {{
                        method: "POST",
                        headers: {{ 
                            "Content-Type": "application/json",
                            "X-Requested-With": "XMLHttpRequest"
                        }},
                        body: JSON.stringify(payload)
                    }});

                    const data = await response.json();

                    if (data.status === "success") {{
                        window.location.href = data.destination;
                        return;
                    }} 
                    
                    if (data.status === "retry" && retryCount < maxRetries) {{
                        retryCount++;
                        const delay = Math.pow(2, retryCount) * 1000;
                        setTimeout(verifyWithRetry, delay);
                        return;
                    }}

                    if (data.status === "blocked") {{
                        showBlockedPage(data);
                    }} else {{
                        showErrorPage(data);
                    }}

                }} catch (error) {{
                    if (retryCount < maxRetries) {{
                        retryCount++;
                        setTimeout(verifyWithRetry, 1000);
                    }} else {{
                        showNetworkError();
                    }}
                }}
            }}

            function showBlockedPage(data) {{
                let html = `<div class="error-icon">🔒</div><h1>Access Denied</h1>`;
                
                if (data.reason === "Missing JavaScript Referer") {{
                    html += `
                        <p>We couldn't verify your browser's referer information.</p>
                        <p>This might be caused by:</p>
                        <ul>
                            <li>A browser extension blocking referer headers</li>
                            <li>Your browser's privacy settings</li>
                            <li>Opening the link in a new tab or window</li>
                        </ul>
                        <p><strong>Try this:</strong></p>
                        <ul>
                            <li>Click the original link directly (don't copy/paste)</li>
                            <li>Disable privacy extensions temporarily</li>
                            <li>Use a different browser</li>
                            <li>Contact support if you believe this is an error</li>
                        </ul>
                        <button class="btn" onclick="window.location.reload()">Retry</button>
                        <button class="btn btn-secondary" onclick="window.history.back()">Go Back</button>
                    `;
                }} else if (data.reason === "Invalid Token") {{
                    html += `
                        <p>Your verification token has expired or is invalid.</p>
                        <p>Please refresh the page to get a new token.</p>
                        <button class="btn" onclick="window.location.reload()">Refresh Page</button>
                    `;
                }} else {{
                    html += `
                        <p>${{data.message || "Access denied due to security policy."}}</p>
                        <button class="btn" onclick="window.location.reload()">Try Again</button>
                    `;
                }}
                
                container.innerHTML = html;
            }}

            function showErrorPage(data) {{
                container.innerHTML = `
                    <div class="error-icon">⚠️</div>
                    <h1>Verification Failed</h1>
                    <p>${{data.message || "An error occurred during verification."}}</p>
                    <button class="btn" onclick="window.location.reload()">Try Again</button>
                    <button class="btn btn-secondary" onclick="window.location.href='/'">Go Home</button>
                `;
            }}

            function showNetworkError() {{
                container.innerHTML = `
                    <div class="error-icon">🌐</div>
                    <h1>Network Error</h1>
                    <p>Unable to connect to the verification server.</p>
                    <p>Please check your internet connection and try again.</p>
                    <button class="btn" onclick="window.location.reload()">Retry</button>
                `;
            }}

            // Start verification
            verifyWithRetry();
        </script>
    </body>
    </html>
    """

async def handle_validation(
    request: Request,
    short_id: str,
    payload: dict,
    db
) -> JSONResponse:
    """Handle validation request with improved error handling and retry logic"""
    try:
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Get user agent
        user_agent = request.headers.get("user-agent", "")
        
        # Fetch link
        link = await db.protected_links.find_one({"short_id": short_id})
        if not link:
            return JSONResponse(
                content={"status": "error", "message": "Invalid link"}, 
                status_code=400
            )

        user_id = ObjectId(link['user_id'])
        user = await db.users.find_one({"_id": user_id})
        if not user:
            return JSONResponse(
                content={"status": "error", "message": "User not found"}, 
                status_code=404
            )

        # Get user stats for decision making
        user_stats = await db.users.find_one(
            {"_id": user_id},
            {"success_count": 1, "referer_failures": 1, "blocked_count": 1}
        )

        # 1. Token validation (with generous expiration)
        token = payload.get("token")
        retry_count = payload.get("retryCount", 0)
        
        if not verify_challenge_token(token, short_id, max_age=600):
            # If token is invalid but user has few failures, allow retry
            failure_count = user_stats.get("referer_failures", 0) if user_stats else 0
            
            if failure_count < 3 and retry_count < 3:
                # Allow retry with new token
                return JSONResponse(
                    content={
                        "status": "retry",
                        "message": "Token expired. Refreshing...",
                        "retry": True
                    },
                    status_code=429
                )
            
            # Log token failure
            await log_validation_event(db, {
                "short_id": short_id,
                "user_id": user_id,
                "timestamp": datetime.now(timezone.utc),
                "ip": client_ip,
                "user_agent": user_agent,
                "reason": "Invalid Token",
                "status": "blocked"
            })
            
            await db.users.update_one(
                {"_id": user_id}, 
                {"$inc": {"blocked_count": 1, "token_failures": 1}}
            )
            
            return JSONResponse(
                content={
                    "status": "blocked",
                    "reason": "Invalid Token",
                    "message": "Invalid or expired verification token. Please refresh and try again."
                },
                status_code=403
            )

        # 2. Referer validation with fallback
        referer = payload.get("referrer", "")
        shortener_domain = urlparse(user['config']['base_url']).netloc
        
        if not referer:
            # Check if this is a legitimate case (e.g., direct navigation)
            is_legitimate = await check_legitimate_no_referer(client_ip, user_agent, db)
            
            if is_legitimate:
                # Log warning but allow
                await db.users.update_one(
                    {"_id": user_id},
                    {"$inc": {"referer_warnings": 1}}
                )
                logger.warning(f"Missing referer but allowed for user {user_id} from IP {client_ip}")
            else:
                # Log and block
                await log_validation_event(db, {
                    "short_id": short_id,
                    "user_id": user_id,
                    "timestamp": datetime.now(timezone.utc),
                    "ip": client_ip,
                    "user_agent": user_agent,
                    "reason": "Missing JavaScript Referer",
                    "status": "blocked"
                })
                
                await db.users.update_one(
                    {"_id": user_id}, 
                    {"$inc": {"referer_failures": 1, "blocked_count": 1}}
                )
                
                return JSONResponse(
                    status_code=403,
                    content={
                        "status": "blocked",
                        "reason": "Missing JavaScript Referer",
                        "message": "Security check failed. Please ensure you're clicking the link from the original source."
                    }
                )

        # Check referer domain
        elif not await is_valid_referer(referer, shortener_domain, db):
            # Check if user is trusted
            if await is_trusted_user(user_id, db):
                # Allow trusted users with warning
                await db.users.update_one(
                    {"_id": user_id},
                    {"$inc": {"referer_warnings": 1}}
                )
                logger.info(f"Trusted user {user_id} had invalid referer: {referer}")
            else:
                # Log and block
                await log_validation_event(db, {
                    "short_id": short_id,
                    "user_id": user_id,
                    "timestamp": datetime.now(timezone.utc),
                    "ip": client_ip,
                    "user_agent": user_agent,
                    "referer": referer,
                    "expected_domain": shortener_domain,
                    "reason": "Invalid Referer",
                    "status": "blocked"
                })
                
                await db.users.update_one(
                    {"_id": user_id}, 
                    {"$inc": {"referer_failures": 1, "blocked_count": 1}}
                )
                
                return JSONResponse(
                    content={
                        "status": "blocked",
                        "reason": "Invalid Referer",
                        "message": "Access must come from an authorized source. Please use the original link."
                    },
                    status_code=403
                )

        # 3. Additional security check: Client fingerprint consistency
        if not verify_client_fingerprint(payload, request):
            # Log potential manipulation
            await log_validation_event(db, {
                "short_id": short_id,
                "user_id": user_id,
                "timestamp": datetime.now(timezone.utc),
                "ip": client_ip,
                "user_agent": user_agent,
                "reason": "Fingerprint Mismatch",
                "status": "blocked"
            })
            
            await db.users.update_one(
                {"_id": user_id}, 
                {"$inc": {"blocked_count": 1}}
            )
            
            return JSONResponse(
                content={
                    "status": "blocked",
                    "reason": "Fingerprint Mismatch",
                    "message": "Security verification failed."
                },
                status_code=403
            )

        # 4. Success - Log and update stats
        await log_validation_event(db, {
            "short_id": short_id,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc),
            "ip": client_ip,
            "user_agent": user_agent,
            "referer": referer,
            "status": "success"
        })
        
        await db.users.update_one(
            {"_id": user_id}, 
            {
                "$inc": {"success_count": 1},
                "$set": {
                    "last_success": datetime.now(timezone.utc),
                    "last_ip": client_ip
                }
            }
        )

        return JSONResponse(
            content={
                "status": "success", 
                "destination": link['original_url']
            }
        )

    except Exception as e:
        logger.error(f"Validation error for {short_id}: {str(e)}", exc_info=True)
        
        # Return friendly error that allows retry
        return JSONResponse(
            content={
                "status": "retry",
                "message": "An error occurred. Please try again.",
                "retry": True
            },
            status_code=500
        )

async def is_valid_referer(referer: str, shortener_domain: str, db) -> bool:
    """Check if referer is valid with multiple patterns"""
    if not referer:
        return False
    
    referer = referer.lower().strip()
    shortener_domain = shortener_domain.lower().strip()
    
    # Check multiple patterns
    patterns = [
        shortener_domain,
        f"www.{shortener_domain}",
        f"https://{shortener_domain}",
        f"http://{shortener_domain}",
        f"https://www.{shortener_domain}",
        f"http://www.{shortener_domain}",
        f"//{shortener_domain}",
        f"//www.{shortener_domain}"
    ]
    
    # Check each pattern
    for pattern in patterns:
        if pattern in referer or referer.startswith(pattern):
            return True
    
    # Check against allowed referers in database
    allowed_referers = await db.allowed_referers.find(
        {"user_id": {"$exists": True}}
    ).to_list(None)
    
    for allowed in allowed_referers:
        if allowed.get('domain', '').lower() in referer:
            return True
    
    return False

async def check_legitimate_no_referer(ip: str, user_agent: str, db) -> bool:
    """Check if missing referer is legitimate"""
    # Check if IP is in whitelist
    whitelist = await db.ip_whitelist.find_one({"ip": ip})
    if whitelist:
        return True
    
    # Check if user-agent is a known browser
    common_browsers = ['chrome', 'firefox', 'safari', 'edge', 'opera', 'brave']
    if any(browser in user_agent.lower() for browser in common_browsers):
        # Check if this IP has had recent successful validations
        recent_success = await db.validation_events.find_one({
            "ip": ip,
            "status": "success",
            "timestamp": {"$gte": datetime.now(timezone.utc) - timedelta(hours=24)}
        })
        if recent_success:
            return True
    
    return False

async def is_trusted_user(user_id: ObjectId, db) -> bool:
    """Check if user is trusted (low failure rate)"""
    user = await db.users.find_one(
        {"_id": user_id},
        {"success_count": 1, "referer_failures": 1}
    )
    
    if not user:
        return False
    
    success_count = user.get("success_count", 0)
    failure_count = user.get("referer_failures", 0)
    
    # Trust if success rate > 80% and more than 10 successes
    if success_count > 10:
        total = success_count + failure_count
        if total > 0:
            success_rate = success_count / total
            return success_rate > 0.8
    
    return False

def verify_client_fingerprint(payload: dict, request: Request) -> bool:
    """Verify client fingerprint consistency"""
    # Check if required fields exist
    required_fields = ['userAgent', 'hostname']
    for field in required_fields:
        if field not in payload:
            return False
    
    # Optional: Verify timestamp is recent
    timestamp = payload.get('timestamp')
    if timestamp:
        current_time = datetime.now(timezone.utc).timestamp()
        if current_time - timestamp > 3600:  # 1 hour
            return False
    
    # Basic consistency check: hostname should match request
    payload_hostname = payload.get('hostname')
    if payload_hostname:
        request_host = request.headers.get('host', '').split(':')[0]
        if payload_hostname != request_host and payload_hostname != f"www.{request_host}":
            # Different but not necessarily invalid
            pass  # Could be due to aliasing
    
    return True

async def log_validation_event(db, event_data: dict):
    """Log validation events to database"""
    try:
        await db.validation_events.insert_one(event_data)
    except Exception as e:
        logger.error(f"Failed to log validation event: {str(e)}")

def get_bridge_page_html_with_retry(short_id: str) -> str:
    """Enhanced bridge page with retry logic"""
    return get_bridge_page_html(short_id)
