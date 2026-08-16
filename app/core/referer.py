from fastapi import Request
from fastapi.responses import JSONResponse
from datetime import datetime, timezone, timedelta
from bson import ObjectId
from urllib.parse import urlparse
from app.core.security import generate_challenge_token, verify_challenge_token
import logging
import hashlib
import re
import json
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

def get_bridge_page_html(short_id: str) -> str:
    """Generate bridge page with comprehensive verification"""
    token = generate_challenge_token(short_id)
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="referrer" content="origin">
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
        <meta http-equiv="Pragma" content="no-cache">
        <meta http-equiv="Expires" content="0">
        <title>Verifying...</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                background: #f7fafc;
                padding: 20px;
                margin: 0;
            }}
            .container {{
                background: white;
                border-radius: 16px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.08);
                padding: 48px;
                max-width: 540px;
                width: 100%;
                text-align: center;
                transition: all 0.3s ease;
            }}
            .spinner {{
                width: 48px;
                height: 48px;
                border: 4px solid #e2e8f0;
                border-top-color: #4299e1;
                border-radius: 50%;
                animation: spin 0.8s cubic-bezier(0.6, 0, 0.4, 1) infinite;
                margin: 0 auto 24px;
            }}
            @keyframes spin {{
                to {{ transform: rotate(360deg); }}
            }}
            h1 {{
                font-size: 22px;
                color: #2d3748;
                margin-bottom: 8px;
                font-weight: 600;
            }}
            .subtitle {{
                color: #718096;
                font-size: 16px;
                margin-bottom: 20px;
            }}
            .progress-container {{
                width: 100%;
                height: 6px;
                background: #edf2f7;
                border-radius: 3px;
                overflow: hidden;
                margin: 20px 0;
            }}
            .progress-fill {{
                height: 100%;
                background: linear-gradient(90deg, #4299e1, #48bb78);
                width: 0%;
                transition: width 0.5s ease;
                border-radius: 3px;
            }}
            .status-text {{
                font-size: 14px;
                color: #a0aec0;
                margin-top: 8px;
            }}
            .error-icon {{ font-size: 56px; margin-bottom: 16px; display: block; }}
            .success-icon {{ font-size: 56px; margin-bottom: 16px; display: block; }}
            .btn-group {{
                display: flex;
                gap: 8px;
                justify-content: center;
                flex-wrap: wrap;
                margin-top: 16px;
            }}
            .btn {{
                padding: 10px 24px;
                border: none;
                border-radius: 8px;
                font-size: 15px;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s;
                text-decoration: none;
                display: inline-block;
            }}
            .btn-primary {{
                background: #4299e1;
                color: white;
            }}
            .btn-primary:hover {{
                background: #3182ce;
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(66, 153, 225, 0.3);
            }}
            .btn-secondary {{
                background: #edf2f7;
                color: #2d3748;
            }}
            .btn-secondary:hover {{
                background: #e2e8f0;
            }}
            .btn-success {{
                background: #48bb78;
                color: white;
            }}
            .btn-success:hover {{
                background: #38a169;
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(72, 187, 120, 0.3);
            }}
            .message-box {{
                background: #f7fafc;
                border-radius: 8px;
                padding: 16px;
                margin: 16px 0;
                text-align: left;
            }}
            .message-box ul {{
                padding-left: 20px;
                margin: 8px 0;
            }}
            .message-box li {{
                margin: 4px 0;
                color: #4a5568;
                font-size: 14px;
            }}
            .hidden {{ display: none; }}
            .fade-in {{
                animation: fadeIn 0.5s ease;
            }}
            @keyframes fadeIn {{
                from {{ opacity: 0; transform: translateY(10px); }}
                to {{ opacity: 1; transform: translateY(0); }}
            }}
        </style>
    </head>
    <body>
        <div class="container" id="app">
            <div id="loading-state">
                <div class="spinner"></div>
                <h1>Verifying Your Request</h1>
                <p class="subtitle">Please wait while we confirm your browser environment</p>
                <div class="progress-container">
                    <div class="progress-fill" id="progressFill"></div>
                </div>
                <p class="status-text" id="statusText">Attempt 1 of 3</p>
            </div>
        </div>

        <script>
            const MAX_RETRIES = 3;
            let retryCount = 0;
            let verificationAttempts = 0;
            const app = document.getElementById('app');
            const progressFill = document.getElementById('progressFill');

            function updateProgress(attempt) {{
                const percentage = Math.min((attempt / MAX_RETRIES) * 100, 100);
                progressFill.style.width = percentage + '%';
                document.getElementById('statusText').textContent = `Attempt ${{attempt + 1}} of ${{MAX_RETRIES}}`;
            }}

            function getClientFingerprint() {{
                const canvas = document.createElement('canvas');
                canvas.width = 256;
                canvas.height = 256;
                const ctx = canvas.getContext('2d');
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillStyle = '#f60';
                ctx.fillRect(100, 100, 50, 50);
                ctx.fillStyle = '#069';
                ctx.fillText('Cwm fjordbank glyphs vext quiz, 😃', 2, 15);
                const canvasFingerprint = canvas.toDataURL();
                
                return {{
                    canvas: canvasFingerprint,
                    screenResolution: `${{window.screen.width}}x${{window.screen.height}}`,
                    screenColorDepth: window.screen.colorDepth,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                    language: navigator.language,
                    platform: navigator.platform,
                    hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                    deviceMemory: navigator.deviceMemory || 'unknown'
                }};
            }}

            async function performVerification(retryAttempt = 0) {{
                verificationAttempts++;
                updateProgress(verificationAttempts - 1);
                
                const fingerprint = getClientFingerprint();
                
                const payload = {{
                    referrer: document.referrer || '',
                    userAgent: navigator.userAgent,
                    hostname: window.location.hostname,
                    timestamp: Math.floor(Date.now() / 1000),
                    token: "{token}",
                    retryCount: retryAttempt,
                    verificationId: `${{Date.now()}}-${{Math.random().toString(36).substr(2, 9)}}`,
                    fingerprint: fingerprint,
                    referrerPolicy: document.referrerPolicy || 'default',
                    connectionType: navigator.connection ? navigator.connection.effectiveType : 'unknown',
                    isSecure: window.isSecureContext || false
                }};

                try {{
                    const response = await fetch("/validate/{short_id}", {{
                        method: "POST",
                        headers: {{ 
                            "Content-Type": "application/json",
                            "X-Requested-With": "XMLHttpRequest",
                            "X-Verification-ID": payload.verificationId
                        }},
                        body: JSON.stringify(payload)
                    }});

                    const data = await response.json();

                    if (data.status === "success") {{
                        showSuccess(data);
                        return;
                    }} 
                    
                    if (data.status === "retry" && retryAttempt < MAX_RETRIES) {{
                        const delay = Math.min(Math.pow(2, retryAttempt) * 1000, 5000);
                        document.getElementById('statusText').textContent = `Retrying in ${{Math.round(delay/1000)}}s...`;
                        setTimeout(() => performVerification(retryAttempt + 1), delay);
                        return;
                    }}

                    if (data.status === "blocked") {{
                        showBlocked(data);
                    }} else {{
                        showError(data);
                    }}

                }} catch (error) {{
                    if (retryAttempt < MAX_RETRIES) {{
                        setTimeout(() => performVerification(retryAttempt + 1), 1500);
                    }} else {{
                        showNetworkError();
                    }}
                }}
            }}

            function showSuccess(data) {{
                app.innerHTML = `
                    <div class="fade-in">
                        <span class="success-icon">✅</span>
                        <h1>Verification Successful!</h1>
                        <p class="subtitle">Redirecting you to your destination...</p>
                        <div class="progress-container">
                            <div class="progress-fill" style="width: 100%; background: #48bb78;"></div>
                        </div>
                        <button class="btn btn-success" onclick="window.location.href='${{data.destination}}'">
                            Click here if not redirected
                        </button>
                    </div>
                `;
                
                setTimeout(() => {{
                    window.location.href = data.destination;
                }}, 1500);
            }}

            function showBlocked(data) {{
                let html = `<div class="fade-in"><span class="error-icon">🔒</span><h1>Access Denied</h1>`;
                
                if (data.reason === "Missing JavaScript Referer") {{
                    html += `
                        <p class="subtitle">We couldn't verify your browser's referer information.</p>
                        <div class="message-box">
                            <p><strong>Common causes:</strong></p>
                            <ul>
                                <li>🔒 Browser extensions blocking referer headers</li>
                                <li>🛡️ Privacy settings (Safari, Firefox Enhanced Tracking)</li>
                                <li>📋 Opening link in a new tab/window</li>
                                <li>🔄 Using a bookmark or direct URL</li>
                            </ul>
                            <p style="margin-top: 8px;"><strong>Solutions:</strong></p>
                            <ul>
                                <li>✅ Click the original link directly</li>
                                <li>✅ Disable privacy extensions temporarily</li>
                                <li>✅ Try a different browser</li>
                                <li>✅ Use Incognito/Private mode</li>
                            </ul>
                        </div>
                        <div class="btn-group">
                            <button class="btn btn-primary" onclick="location.reload()">🔄 Retry</button>
                            <button class="btn btn-secondary" onclick="window.history.back()">← Go Back</button>
                        </div>
                    `;
                }} else if (data.reason === "Invalid Token") {{
                    html += `
                        <p class="subtitle">Your verification token has expired.</p>
                        <div class="message-box">
                            <p>Tokens expire after 10 minutes for security.</p>
                            <p>Please refresh the page to get a new token.</p>
                        </div>
                        <div class="btn-group">
                            <button class="btn btn-primary" onclick="location.reload()">🔄 Refresh</button>
                        </div>
                    `;
                }} else if (data.reason === "Invalid Referer") {{
                    html += `
                        <p class="subtitle">Invalid referer detected.</p>
                        <div class="message-box">
                            <p>You must access this link from the original source.</p>
                            <p><strong>Please use the original short link provided.</strong></p>
                        </div>
                        <div class="btn-group">
                            <button class="btn btn-secondary" onclick="window.history.back()">← Go Back</button>
                        </div>
                    `;
                }} else {{
                    html += `
                        <p class="subtitle">${{data.message || "Access denied due to security policy."}}</p>
                        <div class="btn-group">
                            <button class="btn btn-primary" onclick="location.reload()">🔄 Try Again</button>
                        </div>
                    `;
                }}
                
                html += `</div>`;
                app.innerHTML = html;
            }}

            function showError(data) {{
                app.innerHTML = `
                    <div class="fade-in">
                        <span class="error-icon">⚠️</span>
                        <h1>Verification Error</h1>
                        <p class="subtitle">${{data.message || "An unexpected error occurred."}}</p>
                        <div class="btn-group">
                            <button class="btn btn-primary" onclick="location.reload()">🔄 Retry</button>
                            <button class="btn btn-secondary" onclick="window.location.href='/'">🏠 Home</button>
                        </div>
                    </div>
                `;
            }}

            function showNetworkError() {{
                app.innerHTML = `
                    <div class="fade-in">
                        <span class="error-icon">🌐</span>
                        <h1>Network Error</h1>
                        <p class="subtitle">Unable to connect to the verification server.</p>
                        <div class="message-box">
                            <p>Please check:</p>
                            <ul>
                                <li>Your internet connection</li>
                                <li>Firewall or VPN settings</li>
                                <li>Ad blockers that might interfere</li>
                            </ul>
                        </div>
                        <div class="btn-group">
                            <button class="btn btn-primary" onclick="location.reload()">🔄 Retry</button>
                        </div>
                    </div>
                `;
            }}

            // Start verification with a small delay to ensure page is ready
            setTimeout(() => performVerification(0), 300);
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
    """
    Enhanced validation with multiple fallback mechanisms
    to prevent false positives for legitimate users
    """
    try:
        # Extract request data
        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        verification_id = request.headers.get("X-Verification-ID", "unknown")
        
        # Get the link
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

        # Get user's verification history
        user_history = await get_user_verification_history(user_id, db)
        
        # ============== STEP 1: TOKEN VALIDATION ==============
        token = payload.get("token")
        retry_count = payload.get("retryCount", 0)
        
        # First check: Is this a genuine user with good history?
        is_genuine_user = user_history.get("success_rate", 0) > 0.7 and user_history.get("total_attempts", 0) > 5
        
        # Validate token with flexible expiration for genuine users
        token_valid = verify_challenge_token(token, short_id, max_age=600 if is_genuine_user else 300)
        
        if not token_valid:
            # Allow retry for genuine users with good history
            if is_genuine_user and retry_count < 2:
                return JSONResponse(
                    content={
                        "status": "retry",
                        "message": "Refreshing verification...",
                        "retry": True
                    },
                    status_code=429
                )
            
            # Check if this might be a caching issue
            if await check_caching_issue(short_id, client_ip, db):
                return JSONResponse(
                    content={
                        "status": "retry",
                        "message": "Token refresh required",
                        "retry": True
                    },
                    status_code=429
                )
            
            # Block only after multiple failures
            await log_validation_event(db, {
                "short_id": short_id,
                "user_id": user_id,
                "timestamp": datetime.now(timezone.utc),
                "ip": client_ip,
                "user_agent": user_agent,
                "reason": "Invalid Token",
                "status": "blocked",
                "verification_id": verification_id
            })
            
            await db.users.update_one(
                {"_id": user_id},
                {"$inc": {"token_failures": 1, "blocked_count": 1}}
            )
            
            return JSONResponse(
                content={
                    "status": "blocked",
                    "reason": "Invalid Token",
                    "message": "Verification token expired. Please refresh the page and try again."
                },
                status_code=403
            )

        # ============== STEP 2: REFERER VALIDATION ==============
        referer = payload.get("referrer", "")
        shortener_base = user['config'].get('base_url', '') if user.get('config') else ''
        shortener_domain = urlparse(shortener_base).netloc if shortener_base else ''
        
        # Multiple referer validation approaches
        referer_valid = False
        referer_reason = ""
        
        # Approach 1: Direct match
        if shortener_domain and shortener_domain in referer:
            referer_valid = True
        else:
            # Approach 2: Check if referer is a known allowed source
            referer_valid = await is_allowed_referer(referer, db)
            if referer_valid:
                referer_reason = "allowed_referer"
            
            # Approach 3: Check if this is a legitimate missing referer
            if not referer:
                if await is_legitimate_no_referer(client_ip, user_agent, user_id, db):
                    referer_valid = True
                    referer_reason = "legitimate_missing"
                elif user_history.get("success_rate", 0) > 0.9:
                    # Trusted users with high success rate
                    referer_valid = True
                    referer_reason = "trusted_user"
            
            # Approach 4: Check if referer is a subdomain or related domain
            if not referer_valid and referer and shortener_domain:
                if await is_related_domain(referer, shortener_domain, db):
                    referer_valid = True
                    referer_reason = "related_domain"
        
        if not referer_valid:
            # Check if user is in whitelist
            if await is_whitelisted_user(user_id, db):
                referer_valid = True
                referer_reason = "whitelisted"
            
            # Check if this is a test/development environment
            if await is_development_environment(client_ip, user_agent):
                referer_valid = True
                referer_reason = "development"
        
        # Log referer validation result
        await db.users.update_one(
            {"_id": user_id},
            {"$push": {
                "referer_validation_history": {
                    "timestamp": datetime.now(timezone.utc),
                    "referer": referer[:100],  # Truncate for storage
                    "valid": referer_valid,
                    "reason": referer_reason
                }
            }}
        )
        
        if not referer_valid:
            await log_validation_event(db, {
                "short_id": short_id,
                "user_id": user_id,
                "timestamp": datetime.now(timezone.utc),
                "ip": client_ip,
                "user_agent": user_agent,
                "referer": referer,
                "expected_domain": shortener_domain,
                "reason": "Invalid Referer",
                "status": "blocked",
                "verification_id": verification_id
            })
            
            await db.users.update_one(
                {"_id": user_id},
                {"$inc": {"referer_failures": 1, "blocked_count": 1}}
            )
            
            return JSONResponse(
                content={
                    "status": "blocked",
                    "reason": "Invalid Referer",
                    "message": "Security verification failed. Please use the original short link."
                },
                status_code=403
            )

        # ============== STEP 3: FINGERPRINT VALIDATION ==============
        fingerprint = payload.get("fingerprint", {})
        if not await validate_fingerprint(fingerprint, user_id, db):
            # Log but don't block immediately - could be false positive
            await db.users.update_one(
                {"_id": user_id},
                {"$inc": {"fingerprint_warnings": 1}}
            )
            
            # Only block if repeated fingerprint issues
            if user_history.get("fingerprint_warnings", 0) > 3:
                await log_validation_event(db, {
                    "short_id": short_id,
                    "user_id": user_id,
                    "timestamp": datetime.now(timezone.utc),
                    "ip": client_ip,
                    "reason": "Fingerprint Mismatch",
                    "status": "blocked"
                })
                
                return JSONResponse(
                    content={
                        "status": "blocked",
                        "reason": "Fingerprint Mismatch",
                        "message": "Security verification failed."
                    },
                    status_code=403
                )

        # ============== STEP 4: SUCCESS ==============
        # Increment success count
        await db.users.update_one(
            {"_id": user_id},
            {
                "$inc": {"success_count": 1},
                "$set": {
                    "last_success": datetime.now(timezone.utc),
                    "last_ip": client_ip,
                    "last_user_agent": user_agent
                }
            }
        )

        # Log success
        await log_validation_event(db, {
            "short_id": short_id,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc),
            "ip": client_ip,
            "user_agent": user_agent,
            "referer": referer,
            "status": "success",
            "verification_id": verification_id,
            "referer_reason": referer_reason
        })

        return JSONResponse(
            content={
                "status": "success",
                "destination": link['original_url']
            }
        )

    except Exception as e:
        logger.error(f"Validation error: {str(e)}", exc_info=True)
        
        # Return a retry response instead of error to minimize user impact
        return JSONResponse(
            content={
                "status": "retry",
                "message": "System busy. Please try again.",
                "retry": True
            },
            status_code=500
        )

# ============== HELPER FUNCTIONS ==============

async def get_user_verification_history(user_id: ObjectId, db) -> Dict[str, Any]:
    """Get user's verification statistics"""
    user = await db.users.find_one(
        {"_id": user_id},
        {
            "success_count": 1,
            "referer_failures": 1,
            "blocked_count": 1,
            "token_failures": 1,
            "fingerprint_warnings": 1
        }
    )
    
    if not user:
        return {
            "success_rate": 0,
            "total_attempts": 0,
            "fingerprint_warnings": 0
        }
    
    success_count = user.get("success_count", 0)
    failure_count = user.get("referer_failures", 0) + user.get("token_failures", 0)
    total_attempts = success_count + failure_count
    
    return {
        "success_rate": success_count / total_attempts if total_attempts > 0 else 0,
        "total_attempts": total_attempts,
        "success_count": success_count,
        "failure_count": failure_count,
        "fingerprint_warnings": user.get("fingerprint_warnings", 0),
        "blocked_count": user.get("blocked_count", 0)
    }

async def is_allowed_referer(referer: str, db) -> bool:
    """Check if referer is in allowed list"""
    if not referer:
        return False
    
    allowed = await db.allowed_referers.find_one({
        "domain": {"$regex": re.escape(referer), "$options": "i"}
    })
    
    return allowed is not None

async def is_legitimate_no_referer(ip: str, user_agent: str, user_id: ObjectId, db) -> bool:
    """Check if missing referer is legitimate"""
    # Check IP whitelist
    whitelist = await db.ip_whitelist.find_one({"ip": ip})
    if whitelist:
        return True
    
    # Check if user has successfully verified before
    recent_success = await db.validation_events.find_one({
        "user_id": user_id,
        "status": "success",
        "timestamp": {"$gte": datetime.now(timezone.utc) - timedelta(hours=1)}
    })
    
    if recent_success:
        return True
    
    # Check if user agent is from a known browser
    known_browsers = ['chrome', 'firefox', 'safari', 'edge', 'opera', 'brave', 'mobile']
    if any(browser in user_agent.lower() for browser in known_browsers):
        # Check if this IP has had success before
        ip_success = await db.validation_events.find_one({
            "ip": ip,
            "status": "success",
            "timestamp": {"$gte": datetime.now(timezone.utc) - timedelta(hours=24)}
        })
        if ip_success:
            return True
    
    return False

async def is_related_domain(referer: str, shortener_domain: str, db) -> bool:
    """Check if referer is a related domain"""
    if not referer or not shortener_domain:
        return False
    
    try:
        parsed = urlparse(referer)
        referer_domain = parsed.netloc or parsed.path
        
        # Check if it's a subdomain
        if referer_domain.endswith(f".{shortener_domain}"):
            return True
        
        # Check if it's in the related domains list
        related = await db.related_domains.find_one({
            "domain": referer_domain
        })
        
        return related is not None
    except:
        return False

async def is_whitelisted_user(user_id: ObjectId, db) -> bool:
    """Check if user is whitelisted"""
    user = await db.users.find_one({
        "_id": user_id,
        "whitelisted": True
    })
    return user is not None

async def is_development_environment(ip: str, user_agent: str) -> bool:
    """Check if this is a development environment"""
    dev_ips = ['127.0.0.1', 'localhost', '::1']
    if ip in dev_ips:
        return True
    
    dev_agents = ['curl', 'wget', 'python-requests', 'postman', 'insomnia']
    if any(agent in user_agent.lower() for agent in dev_agents):
        return True
    
    return False

async def check_caching_issue(short_id: str, ip: str, db) -> bool:
    """Check if token failure might be due to caching"""
    recent_attempts = await db.validation_events.count_documents({
        "short_id": short_id,
        "ip": ip,
        "timestamp": {"$gte": datetime.now(timezone.utc) - timedelta(seconds=30)}
    })
    
    return recent_attempts > 0

async def validate_fingerprint(fingerprint: dict, user_id: ObjectId, db) -> bool:
    """Validate client fingerprint"""
    if not fingerprint:
        return True  # Don't block on missing fingerprint
    
    # Basic validation - check if required fields exist
    required_fields = ['screenResolution', 'timezone', 'language']
    for field in required_fields:
        if field not in fingerprint:
            return False
    
    # Check if fingerprint matches previous successful attempts
    previous = await db.validation_events.find_one({
        "user_id": user_id,
        "status": "success",
        "timestamp": {"$gte": datetime.now(timezone.utc) - timedelta(hours=24)}
    })
    
    if previous:
        prev_fingerprint = previous.get("fingerprint", {})
        # Compare major fingerprint components
        if prev_fingerprint:
            if prev_fingerprint.get('screenResolution') != fingerprint.get('screenResolution'):
                return False
            if prev_fingerprint.get('timezone') != fingerprint.get('timezone'):
                return False
    
    return True

async def log_validation_event(db, event_data: dict):
    """Log validation events"""
    try:
        # Ensure ObjectId is properly handled
        if 'user_id' in event_data and not isinstance(event_data['user_id'], ObjectId):
            event_data['user_id'] = ObjectId(event_data['user_id'])
        
        await db.validation_events.insert_one(event_data)
    except Exception as e:
        logger.error(f"Failed to log validation event: {str(e)}")
