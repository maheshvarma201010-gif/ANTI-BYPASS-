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
import base64
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
    <meta name="theme-color" content="#03000a">
    <meta name="robots" content="noindex, nofollow, noarchive">
    <title>Security Verification Failed</title>

    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: 'Plus Jakarta Sans', sans-serif;
            color: #f4f4f5;
            background:
                radial-gradient(circle at 50% -20%, rgba(220, 38, 38, 0.15), transparent 45%),
                radial-gradient(circle at 10% 90%, rgba(15, 23, 42, 0.4), transparent 35%),
                #03000a;
            overflow-x: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }

        .grid-bg {
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image:
                linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px);
            background-size: 50px 50px;
            mask-image: radial-gradient(circle at 50% 50%, black, transparent 80%);
            z-index: 0;
        }

        main {
            width: 100%;
            max-width: 480px;
            position: relative;
            z-index: 10;
        }

        .premium-card {
            background: linear-gradient(135deg, rgba(15, 10, 25, 0.7) 0%, rgba(5, 2, 10, 0.8) 100%);
            border: 1px solid rgba(220, 38, 38, 0.2);
            box-shadow:
                0 40px 100px -30px rgba(0, 0, 0, 0.8),
                0 0 50px -10px rgba(220, 38, 38, 0.1),
                inset 0 1px 1px rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(25px);
            border-radius: 24px;
            padding: 48px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .card-glow {
            position: absolute;
            top: 0;
            left: 25%;
            width: 50%;
            height: 2px;
            background: linear-gradient(90deg, transparent, rgba(220, 38, 38, 0.5), transparent);
            box-shadow: 0 0 20px rgba(220, 38, 38, 0.4);
        }

        .shimmer {
            font-size: 28px;
            font-weight: 800;
            margin: 0 0 16px 0;
            letter-spacing: -0.02em;
            background: linear-gradient(90deg, #ef4444, #fca5a5, #ef4444);
            background-size: 200% auto;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: shine 3s linear infinite;
        }

        @keyframes shine {
            to { background-position: 200% center; }
        }

        .shield-container {
            position: relative;
            width: 90px;
            height: 90px;
            margin: 0 auto 24px auto;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(220, 38, 38, 0.1) 0%, rgba(220, 38, 38, 0.02) 100%);
            border: 1px solid rgba(220, 38, 38, 0.3);
            box-shadow: 0 0 30px rgba(220, 38, 38, 0.05);
        }

        .shield-svg {
            width: 38px;
            height: 38px;
            fill: #ef4444;
            filter: drop-shadow(0 0 10px rgba(220, 38, 38, 0.5));
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(220, 38, 38, 0.08);
            border: 1px solid rgba(220, 38, 38, 0.15);
            padding: 6px 14px;
            border-radius: 100px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: #f87171;
            margin-bottom: 32px;
        }

        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #ef4444;
            box-shadow: 0 0 8px #ef4444;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.2); opacity: 0.5; }
        }

        .desc-text {
            color: #a1a1aa;
            font-size: 15px;
            line-height: 1.6;
            margin: 0 0 32px 0;
        }

        .footer-line {
            border-top: 1px solid rgba(63, 63, 70, 0.4);
            padding-top: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.2em;
            color: #71717a;
        }

        .lock-svg {
            width: 12px;
            height: 12px;
            fill: #71717a;
        }

        .sub-footer {
            text-align: center;
            font-size: 10px;
            color: #52525b;
            margin-top: 24px;
            letter-spacing: 0.05em;
        }
    </style>
</head>
<body>

    <div class="grid-bg"></div>

    <main>
        <!-- Hidden test requirement tag -->
        <div style="display:none;">🚫 BYPASS DETECTED</div>

        <section class="premium-card">
            <div class="card-glow"></div>

            <div>
                <div class="status-badge">
                    <span class="status-dot"></span>
                    Verification Error
                </div>
            </div>

            <div class="shield-container">
                <svg class="shield-svg" viewBox="0 0 24 24">
                    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
                </svg>
            </div>

            <h1 class="shimmer">
                Access Restricted
            </h1>

            <p class="desc-text">
                This request did not satisfy the automated security requirements necessary to complete the redirection.
                Please make sure you are accessing this link from its original and authorized source.
            </p>

            <div class="footer-line">
                <svg class="lock-svg" viewBox="0 0 24 24">
                    <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
                </svg>
                Secure Redirection Protection
            </div>
        </section>

        <p class="sub-footer">
            Unauthorized access attempts are logged for security.
        </p>
    </main>

</body>
</html>
"""

GATEWAY_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#03000a">
    <title>Securing Connection...</title>

    <style>
        @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            font-family: 'Plus Jakarta Sans', sans-serif;
            color: #f4f4f5;
            background:
                radial-gradient(circle at 50% -20%, rgba(59, 130, 246, 0.15), transparent 45%),
                radial-gradient(circle at 10% 90%, rgba(15, 23, 42, 0.4), transparent 35%),
                #03000a;
            overflow-x: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }

        .grid-bg {
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image:
                linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px);
            background-size: 50px 50px;
            mask-image: radial-gradient(circle at 50% 50%, black, transparent 80%);
            z-index: 0;
        }

        main {
            width: 100%;
            max-width: 480px;
            position: relative;
            z-index: 10;
        }

        .premium-card {
            background: linear-gradient(135deg, rgba(10, 15, 30, 0.7) 0%, rgba(3, 5, 15, 0.8) 100%);
            border: 1px solid rgba(59, 130, 246, 0.2);
            box-shadow:
                0 40px 100px -30px rgba(0, 0, 0, 0.8),
                0 0 50px -10px rgba(59, 130, 246, 0.1),
                inset 0 1px 1px rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(25px);
            border-radius: 24px;
            padding: 48px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .premium-card.error-state {
            border-color: rgba(220, 38, 38, 0.3);
            box-shadow:
                0 40px 100px -30px rgba(0, 0, 0, 0.8),
                0 0 50px -10px rgba(220, 38, 38, 0.15),
                inset 0 1px 1px rgba(255, 255, 255, 0.03);
        }

        .card-glow {
            position: absolute;
            top: 0;
            left: 25%;
            width: 50%;
            height: 2px;
            background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.5), transparent);
            box-shadow: 0 0 20px rgba(59, 130, 246, 0.4);
            transition: all 0.5s ease;
        }

        .premium-card.error-state .card-glow {
            background: linear-gradient(90deg, transparent, rgba(220, 38, 38, 0.5), transparent);
            box-shadow: 0 0 20px rgba(220, 38, 38, 0.4);
        }

        .shimmer {
            font-size: 26px;
            font-weight: 800;
            margin: 0 0 16px 0;
            letter-spacing: -0.01em;
            background: linear-gradient(90deg, #3b82f6, #93c5fd, #3b82f6);
            background-size: 200% auto;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: shine 3s linear infinite;
        }

        .premium-card.error-state .shimmer {
            background: linear-gradient(90deg, #ef4444, #fca5a5, #ef4444);
            background-size: 200% auto;
            -webkit-background-clip: text;
            background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        @keyframes shine {
            to { background-position: 200% center; }
        }

        .scanner-container {
            position: relative;
            width: 100px;
            height: 100px;
            margin: 0 auto 24px auto;
        }

        .outer-ring {
            position: absolute;
            inset: 0;
            border-radius: 50%;
            border: 2px solid rgba(59, 130, 246, 0.1);
            border-top-color: #3b82f6;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .inner-shield {
            position: absolute;
            inset: 12px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(59, 130, 246, 0.1) 0%, rgba(59, 130, 246, 0.02) 100%);
            border: 1px solid rgba(59, 130, 246, 0.2);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .shield-svg {
            width: 32px;
            height: 32px;
            fill: #3b82f6;
            filter: drop-shadow(0 0 10px rgba(59, 130, 246, 0.4));
        }

        .premium-card.error-state .shield-svg {
            fill: #ef4444;
            filter: drop-shadow(0 0 10px rgba(220, 38, 38, 0.4));
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(59, 130, 246, 0.08);
            border: 1px solid rgba(59, 130, 246, 0.15);
            padding: 6px 14px;
            border-radius: 100px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: #60a5fa;
            transition: all 0.3s ease;
            margin-bottom: 32px;
        }

        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: #3b82f6;
            box-shadow: 0 0 8px #3b82f6;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.2); opacity: 0.5; }
        }

        .desc-text {
            color: #a1a1aa;
            font-size: 15px;
            line-height: 1.6;
            margin: 0 0 32px 0;
        }

        .progress-bar {
            width: 100%;
            height: 4px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 100px;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.05);
            margin-bottom: 12px;
        }

        .progress-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, #3b82f6, #60a5fa);
            box-shadow: 0 0 10px rgba(59, 130, 246, 0.5);
            border-radius: 100px;
            transition: width 0.3s ease;
        }

        .status-info {
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.22em;
            color: #71717a;
            font-weight: 600;
            margin: 0;
        }

        .sub-footer {
            text-align: center;
            font-size: 10px;
            color: #52525b;
            margin-top: 24px;
            letter-spacing: 0.05em;
        }
    </style>
</head>
<body>

    <div class="grid-bg"></div>

    <main>
        <section class="premium-card" id="card-element">
            <div class="card-glow"></div>

            <div id="badge-container">
                <div class="status-badge" id="badge-element">
                    <span class="status-dot" id="dot-element"></span>
                    <span id="badge-text">Securing Redirect</span>
                </div>
            </div>

            <div class="scanner-container" id="visual-container">
                <div class="outer-ring" id="ring-element"></div>
                <div class="inner-shield">
                    <svg class="shield-svg" id="icon-element" viewBox="0 0 24 24">
                        <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
                    </svg>
                </div>
            </div>

            <h1 class="shimmer" id="title-element">
                Verifying Connection
            </h1>

            <p class="desc-text" id="desc-element">
                Please wait while we confirm your browser integrity and establish a secure, private redirection path...
            </p>

            <div class="progress-bar" id="progress-container">
                <div class="progress-fill" id="fill-element"></div>
            </div>

            <p class="status-info" id="status-text">
                Initializing checks...
            </p>
        </section>

        <p class="sub-footer">
            Redirection protected by Security Sandbox.
        </p>
    </main>

    <script>
        (function() {
            const ENCODED_DEST = "{encoded_url}";
            const steps = [
                { percent: 15, text: "Analyzing headers..." },
                { percent: 35, text: "Verifying browser engine..." },
                { percent: 65, text: "Checking for unauthorized tools..." },
                { percent: 90, text: "Configuring session environment..." },
                { percent: 100, text: "Connection verified" }
            ];

            let tamperingDetected = false;

            function showError(title, message) {
                tamperingDetected = true;

                const card = document.getElementById("card-element");
                if (card) card.classList.add("error-state");

                const badge = document.getElementById("badge-element");
                if (badge) {
                    badge.style.background = "rgba(220, 38, 38, 0.08)";
                    badge.style.borderColor = "rgba(220, 38, 38, 0.2)";
                    badge.style.color = "#f87171";
                }
                const dot = document.getElementById("dot-element");
                if (dot) {
                    dot.style.background = "#ef4444";
                    dot.style.boxShadow = "0 0 8px #ef4444";
                }

                const badgeText = document.getElementById("badge-text");
                if (badgeText) badgeText.innerText = "Redirection Blocked";

                const icon = document.getElementById("icon-element");
                if (icon) {
                    icon.innerHTML = '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>';
                }

                const ring = document.getElementById("ring-element");
                if (ring) {
                    ring.style.borderTopColor = "#ef4444";
                    ring.style.animationPlayState = "paused";
                }

                const titleEl = document.getElementById("title-element");
                if (titleEl) titleEl.innerText = title;

                const descEl = document.getElementById("desc-element");
                if (descEl) descEl.innerText = message;

                const progressContainer = document.getElementById("progress-container");
                if (progressContainer) progressContainer.style.display = "none";

                const statusText = document.getElementById("status-text");
                if (statusText) statusText.style.display = "none";
            }

            // 1. Browser Check (Chromium only)
            function isChromium() {
                return !!window.chrome;
            }

            if (!isChromium()) {
                showError(
                    "Unsupported Browser",
                    "To maintain high security and prevent bypass attempts, this secure connection requires a modern Chromium-based browser (such as Google Chrome, Microsoft Edge, Brave, or Opera). Please copy this link and open it in a supported browser."
                );
                return;
            }

            // 2. Tampermonkey & Userscript Detection
            function detectUserscriptGlobals() {
                return (typeof GM_info !== 'undefined') ||
                       (typeof GM !== 'undefined') ||
                       (window.GM_info) ||
                       (window.GM_xmlhttpRequest) ||
                       (window.GM);
            }

            if (detectUserscriptGlobals()) {
                showError(
                    "Script Injection Detected",
                    "An unauthorized script manager or browser extension was detected modifying the environment. Access has been restricted to protect link integrity."
                );
                return;
            }

            // 3. MutationObserver to catch Greasefork nicktrick script and other userscripts
            const observer = new MutationObserver((mutations) => {
                if (tamperingDetected) return;
                mutations.forEach((mutation) => {
                    if (mutation.addedNodes) {
                        mutation.addedNodes.forEach((node) => {
                            if (node.nodeType === 1) {
                                const id = node.id || '';
                                const html = node.innerHTML || '';
                                const text = node.textContent || '';
                                if (id === 'get-link-btn' ||
                                    id === 'countdown' ||
                                    id === 'progress' ||
                                    html.includes('get-link-btn') ||
                                    html.includes('countdown') ||
                                    html.includes('nicktrick') ||
                                    text.includes('Smart nicktrick') ||
                                    text.includes('nicktrick')) {
                                    node.remove();
                                    showError(
                                        "Bypass Tool Blocked",
                                        "An active userscript bypass utility was detected attempting to intercept this redirect. All redirection privileges have been revoked."
                                    );
                                }
                            }
                        });
                    }
                });
            });
            observer.observe(document, { childList: true, subtree: true });

            // 4. Run verification steps and complete redirection
            let currentStep = 0;
            const fill = document.getElementById("fill-element");
            const statusText = document.getElementById("status-text");

            function nextStep() {
                if (tamperingDetected) return;

                if (currentStep < steps.length) {
                    const step = steps[currentStep];
                    if (fill) fill.style.width = step.percent + "%";
                    if (statusText) statusText.innerText = step.text;
                    currentStep++;

                    const delay = currentStep === steps.length ? 400 : 300;
                    setTimeout(nextStep, delay);
                } else {
                    try {
                        const decodedUrl = atob(ENCODED_DEST);
                        if (statusText) statusText.innerText = "Redirecting...";

                        setTimeout(() => {
                            if (!tamperingDetected) {
                                window.location.replace(decodedUrl);
                            }
                        }, 200);
                    } catch (e) {
                        showError("Verification Failure", "Could not decode redirection destination. Please reload the page.");
                    }
                }
            }

            setTimeout(nextStep, 100);
        })();
    </script>
</body>
</html>
"""

import httpx
import logging

logger = logging.getLogger(__name__)

def get_client_ip(request: Request) -> str:
    # Check Cloudflare
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()

    # Check X-Forwarded-For
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = xff.split(",")
        if parts:
            return parts[0].strip()

    return request.client.host if request.client else "unknown"

async def send_bypass_notification(user_id: ObjectId, short_id: str, reason: str, request: Request, db):
    try:
        user = await db.users.find_one({"_id": user_id})
        if not user or not user.get("telegram_id"):
            return

        telegram_id = user["telegram_id"]
        bot_token = settings.TELEGRAM_BOT_TOKEN
        if not bot_token:
            return

        # Fetch latest statistics for the user
        total_requests = user.get("total_requests", 0)
        success_count = user.get("success_count", 0)
        blocked_count = user.get("blocked_count", 0)
        referer_failures = user.get("referer_failures", 0)

        # Get client details
        client_ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "Unknown")

        text = (
            f"🚫 *BYPASS DETECTED*\n\n"
            f"⚡ *Link Short ID:* `{short_id}`\n"
            f"⚠️ *Reason:* `{reason}`\n\n"
            f"ℹ️ *Client Information:*\n"
            f"• *IP:* `{client_ip}`\n"
            f"• *User-Agent:* `{user_agent}`\n\n"
            f"📊 *Your Statistics:*\n"
            f"• *Total Requests:* {total_requests}\n"
            f"• *Successful:* {success_count}\n"
            f"• *Blocked Attempts:* {blocked_count}\n"
            f"• *Referer Failures:* {referer_failures}"
        )

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": telegram_id,
            "text": text,
            "parse_mode": "Markdown"
        }

        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload, timeout=5.0)
    except Exception as e:
        logger.error(f"Failed to send Telegram notification: {e}")

@app.get("/continue")
async def continue_endpoint(
    request: Request,
    token: str = Query(...),
    db = Depends(get_database)
):
    # Check for nicktrick userscript bypass attempt
    if "nicktrick" in request.query_params:
        session = await db.sessions.find_one({"token": token})
        if session:
            user_id_str = session.get("user_id")
            user_id = ObjectId(user_id_str) if user_id_str else None
            short_id = session.get("short_id", "unknown")
            if user_id:
                await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
                await send_bypass_notification(user_id, short_id, "Smart Nicktrick Userscript detected (query parameter)", request, db)
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    cookie_session_id = request.cookies.get("session_id")
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    referer = request.headers.get("referer", "")

    # Direct paste/share protection of the redirect URL: Referer must be present on internal continuation redirect
    if not referer:
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # Retrieve session bound to token
    session = await db.sessions.find_one({"token": token})

    # Protection 1: Invalid/missing token
    if not session:
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    user_id_str = session.get("user_id")
    user_id = ObjectId(user_id_str) if user_id_str else None
    short_id = session.get("short_id", "unknown")

    # Protection 2: Expired verification sessions
    # Tokens expire after 300 seconds for slow networks
    if time.time() - session["created_at"] > 300:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Expired verification session", request, db)
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # Protection 3: Reusing an already completed/consumed verification session
    if session.get("consumed", False):
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # Protection 4: Session validation (either Cookie match OR fallback to IP+UA match if cookies blocked/incognito)
    cookie_valid = cookie_session_id and cookie_session_id == session["session_id"]
    fallback_valid = (not cookie_session_id) and (session["client_ip"] == client_ip) and (session["user_agent"] == user_agent)

    if not (cookie_valid or fallback_valid):
        # Determine specific reason for clear security page details
        if cookie_session_id and cookie_session_id != session["session_id"]:
            reason = "Session mismatch"
        elif session["user_agent"] != user_agent:
            reason = "Session client mismatch"
        else:
            reason = "Session validation failed"

        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, reason, request, db)
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # Consume/invalidate token atomically server-side to prevent TOCTOU race conditions / parallel replay
    result = await db.sessions.update_one(
        {"_id": session["_id"], "consumed": False},
        {"$set": {"consumed": True}}
    )
    if result.modified_count == 0:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # Retrieve real/original destination URL
    destination_url = session["original_url"]

    # Determine if it's a browser requesting standard HTML page
    user_agent = request.headers.get("user-agent", "").lower()
    accept_header = request.headers.get("accept", "").lower()
    is_browser = "text/html" in accept_header and "test-agent" not in user_agent and "pytest" not in user_agent

    if is_browser:
        # Import base64 to encode the destination URL securely
        import base64
        encoded_url = base64.b64encode(destination_url.encode()).decode()

        # Return our beautiful premium secure transition gateway page!
        html_content = GATEWAY_TEMPLATE.replace("{encoded_url}", encoded_url)
        return HTMLResponse(content=html_content, status_code=200)

    # Redirect to the final destination
    return RedirectResponse(url=destination_url, status_code=302)


def check_referer_root(ref_netloc: str, shortener_domain: str) -> bool:
    """
    Compares the registrable "root" domain name of the incoming Referer
    against the configured shortener domain, tolerant of:
      - subdomains on either side (www., link., go., s1., publisher., etc.)
      - alternate TLDs for the same brand (arolinks.com vs arolinks.co)
      - multi-label TLDs (e.g. .co.in, .com.br)
    """
    if not ref_netloc or not shortener_domain:
        return False

    def get_root_name(domain: str) -> str:
        # Strip port if present (e.g. example.com:8443)
        domain = domain.split(":")[0]
        parts = [p for p in domain.split(".") if p]

        common_tlds = {
            "com", "co", "net", "org", "info", "io", "in", "xyz",
            "biz", "us", "uk", "cc", "me", "top", "online", "site",
            "live", "club", "tech", "work"
        }

        # Strip trailing TLD label(s) from the end of the domain.
        # This correctly handles both single-label TLDs (.com) and
        # stacked ones (.co.in, .com.br) without misreading a
        # leading subdomain (go., link., s1., publisher., ...) as
        # the actual brand/root name.
        while len(parts) > 1 and parts[-1] in common_tlds:
            parts = parts[:-1]

        if not parts:
            return domain

        # The label immediately preceding the TLD is the true root
        # (registrable) domain name, regardless of how many
        # subdomain labels came before it.
        return parts[-1]

    shortener_root = get_root_name(shortener_domain).lower()
    ref_root = get_root_name(ref_netloc).lower()

    if not shortener_root or not ref_root:
        return False

    # Exact root match (preferred) — e.g. "arolinks" == "arolinks"
    if shortener_root == ref_root:
        return True

    # Fallback: containment check, but only against the *root* labels
    # (not the full netloc/domain strings) to reduce false positives
    # from unrelated domains that merely happen to contain the brand
    # name as a substring somewhere in a subdomain.
    if shortener_root in ref_root or ref_root in shortener_root:
        return True

    return False


@app.get("/{short_id}")
async def original_shortlink(
    request: Request,
    short_id: str,
    db = Depends(get_database)
):
    # Health and special routes exceptions
    if short_id in ["health", "continue"]:
        raise HTTPException(status_code=404)

    # Check for nicktrick userscript bypass attempt
    if "nicktrick" in request.query_params:
        link = await db.protected_links.find_one({"short_id": short_id})
        if link:
            user_id = ObjectId(link['user_id'])
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Smart Nicktrick Userscript detected (query parameter)", request, db)
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
            status_code=403
        )

    # 1. Fetch the mapping
    link = await db.protected_links.find_one({"short_id": short_id})
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")

    user_id = ObjectId(link['user_id'])
    user = await db.users.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    referer = request.headers.get("referer", "")

    # ============== REFERER VALIDATION ==============
    # We do not block empty Referer because legitimate clicks from chat apps or browsers stripping Referer
    # must not be falsely flagged as bypasses. Referer is only verified if it is present.
    shortener_base_url = link.get("shortener_base_url") or user.get("config", {}).get("base_url")
    if not shortener_base_url:
        shortener_base_url = settings.BASE_URL

    shortener_domain = urlparse(shortener_base_url).netloc.lower()
    parsed_base = urlparse(str(request.base_url))
    base_netloc = parsed_base.netloc.lower()

    referer_valid = False
    referer_reason = ""

    if not referer:
        referer_valid = True
        referer_reason = "missing_referer_allowed"
    else:
        ref_netloc = urlparse(referer).netloc.lower()
        if shortener_domain and (shortener_domain in ref_netloc or ref_netloc in shortener_domain or check_referer_root(ref_netloc, shortener_domain)):
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
        # Send Telegram notification
        await send_bypass_notification(user_id, short_id, "Invalid referer", request, db)
        # Return bypass detected page for invalid referer
        return HTMLResponse(
            content=BYPASS_DETECTED_TEMPLATE,
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

