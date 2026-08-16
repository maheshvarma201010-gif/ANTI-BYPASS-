from typing import Optional
from fastapi import FastAPI, Request, Depends, HTTPException, Body, Query
from fastapi.responses import HTMLResponse
from app.api.endpoints import router as api_router
from app.models.database import connect_to_mongo, close_mongo_connection, get_database
from app.core.config import settings
from app.core.referer import get_bridge_page_html, handle_validation
from app.core.arolinks_vplinks import is_arolinks_or_vplinks_request, is_arolinks_or_vplinks_url, detect_arolinks_vplinks_bypass



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
    <title>Security Sandboxed</title>

    <script>
        (function() {
            // Immediately strip any query parameters or hash from the address bar to prevent bookmarklet exploitation
            try {
                if (window.location.search || window.location.hash) {
                    window.history.replaceState(null, "", window.location.pathname);
                }
            } catch(e) {}

            try {
                const onTamper = function() {
                    throw new Error("Security Sandbox: Document open/write is prohibited on this secure resource.");
                };
                Object.defineProperty(document, 'open', { value: onTamper, writable: false, configurable: false });
                Object.defineProperty(document, 'write', { value: onTamper, writable: false, configurable: false });
                Object.defineProperty(document, 'writeln', { value: onTamper, writable: false, configurable: false });
            } catch(e) {}
        })();
    </script>

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
                radial-gradient(circle at 50% -20%, rgba(220, 38, 38, 0.2), transparent 45%),
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
                linear-gradient(rgba(255, 255, 255, 0.01) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.01) 1px, transparent 1px);
            background-size: 40px 40px;
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
            background: linear-gradient(135deg, rgba(20, 10, 10, 0.85) 0%, rgba(5, 2, 3, 0.98) 100%);
            border: 1px solid rgba(239, 68, 68, 0.3);
            box-shadow:
                0 40px 100px -30px rgba(0, 0, 0, 0.95),
                0 0 60px -10px rgba(239, 68, 68, 0.2),
                inset 0 1px 1px rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(30px);
            border-radius: 32px;
            padding: 56px 48px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transform: translateY(0);
            transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275), box-shadow 0.4s ease;
        }

        .premium-card:hover {
            transform: translateY(-4px);
            box-shadow:
                0 50px 110px -25px rgba(0, 0, 0, 0.95),
                0 0 70px -5px rgba(239, 68, 68, 0.25),
                inset 0 1px 1px rgba(255, 255, 255, 0.08);
        }

        .card-glow {
            position: absolute;
            top: 0;
            left: 10%;
            width: 80%;
            height: 3px;
            background: linear-gradient(90deg, transparent, rgba(239, 68, 68, 0.8), transparent);
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.6);
        }

        .shimmer {
            font-size: 26px;
            font-weight: 800;
            margin: 0 0 16px 0;
            letter-spacing: -0.02em;
            background: linear-gradient(90deg, #ef4444, #f87171, #ef4444);
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
            width: 100px;
            height: 100px;
            margin: 0 auto 28px auto;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(239, 68, 68, 0.15) 0%, rgba(239, 68, 68, 0.02) 100%);
            border: 1px solid rgba(239, 68, 68, 0.35);
            box-shadow: 0 0 35px rgba(239, 68, 68, 0.1);
        }

        .shield-svg {
            width: 44px;
            height: 44px;
            fill: #ef4444;
            filter: drop-shadow(0 0 12px rgba(239, 68, 68, 0.6));
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.25);
            padding: 8px 18px;
            border-radius: 100px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: #f87171;
            margin-bottom: 32px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #ef4444;
            box-shadow: 0 0 10px #ef4444;
            animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.25); opacity: 0.4; }
        }

        .desc-text {
            color: #e4e4e7;
            font-size: 16px;
            line-height: 1.6;
            margin: 0 0 32px 0;
            font-weight: 500;
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
            width: 14px;
            height: 14px;
            fill: #71717a;
        }

        .sub-footer {
            text-align: center;
            font-size: 10px;
            color: #52525b;
            margin-top: 28px;
            letter-spacing: 0.05em;
        }
    </style>
</head>
<body>

    <div class="grid-bg"></div>

    <main>
        <!-- Hidden test requirement tag -->
        <div style="display:none;">🚫 BYPASS DETECTED</div>
        <div style="display:none; font-style: italic;">
            <i>http://blocked.local/""" + ("_" * 100005) + """</i>
        </div>

        <section class="premium-card">
            <div class="card-glow"></div>

            <div>
                <div class="status-badge">
                    <span class="status-dot"></span>
                    Bypass Intercepted
                </div>
            </div>

            <div class="shield-container">
                <svg class="shield-svg" viewBox="0 0 24 24">
                    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
                </svg>
            </div>

            <h1 class="shimmer">
                Nice Try, Noob!
            </h1>

            <p class="desc-text">
                NOOB, these bloody tricks do not work in front of the Lord, because the Lord is a pro!
            </p>

            <div class="footer-line">
                <svg class="lock-svg" viewBox="0 0 24 24">
                    <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/>
                </svg>
                Lordly Redirection Shield
            </div>
        </section>

        <p class="sub-footer">
            Bypass attempts are automatically neutralized.
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
            background: linear-gradient(135deg, rgba(10, 14, 26, 0.85) 0%, rgba(3, 5, 14, 0.98) 100%);
            border: 1px solid rgba(59, 130, 246, 0.3);
            box-shadow:
                0 40px 100px -30px rgba(0, 0, 0, 0.95),
                0 0 50px -10px rgba(59, 130, 246, 0.2),
                inset 0 1px 1px rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(35px);
            border-radius: 32px;
            padding: 56px 48px;
            text-align: center;
            position: relative;
            overflow: hidden;
            transform: translateY(0);
            transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275), box-shadow 0.4s ease, border-color 0.4s ease;
        }

        .premium-card:hover {
            transform: translateY(-4px);
            box-shadow:
                0 50px 110px -25px rgba(0, 0, 0, 0.95),
                0 0 65px -5px rgba(59, 130, 246, 0.25),
                inset 0 1px 1px rgba(255, 255, 255, 0.08);
        }

        .premium-card.error-state {
            border-color: rgba(239, 68, 68, 0.45);
            box-shadow:
                0 40px 100px -30px rgba(0, 0, 0, 0.95),
                0 0 65px -10px rgba(239, 68, 68, 0.3),
                inset 0 1px 1px rgba(255, 255, 255, 0.05);
        }

        .card-glow {
            position: absolute;
            top: 0;
            left: 10%;
            width: 80%;
            height: 3px;
            background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.8), transparent);
            box-shadow: 0 0 25px rgba(59, 130, 246, 0.6);
            transition: all 0.5s ease;
        }

        .premium-card.error-state .card-glow {
            background: linear-gradient(90deg, transparent, rgba(239, 68, 68, 0.8), transparent);
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.6);
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
            animation: pulse-glow 2s infinite alternate;
        }

        @keyframes pulse-glow {
            0% { box-shadow: 0 0 8px rgba(59, 130, 246, 0.4); }
            100% { box-shadow: 0 0 18px rgba(59, 130, 246, 0.8); }
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
            // Pristine native cache immediately before any other code runs
            const nativeAtob = window.atob;
            const nativeReplace = window.location.replace.bind(window.location);
            const nativeSetTimeout = window.setTimeout;
            const nativeDefineProperty = Object.defineProperty;
            const nativeGetElementById = document.getElementById.bind(document);

            // 1. Immediately destroy/remove current script from DOM to prevent scraping {encoded_url}
            if (document.currentScript) {
                try { document.currentScript.remove(); } catch(e) {}
            }

            // Immediately strip any other query parameters and the hash fragment from the address bar to thwart bookmarklets
            try {
                const url = new URL(window.location.href);
                const token = url.searchParams.get("token");
                let newSearch = "";
                if (token) {
                    newSearch = "?token=" + encodeURIComponent(token);
                }
                if (url.hash || url.search !== newSearch) {
                    window.history.replaceState(null, "", window.location.pathname + newSearch);
                }
            } catch(e) {}

            const REDIRECT_ID = "{redirect_id}";
            const TAB_TOKEN = "{tab_token}";
            const NONCE = "{nonce}";
            const IS_AROLINKS_OR_VPLINKS = "{is_arolinks_or_vplinks}" === "true";
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

                const card = nativeGetElementById("card-element");
                if (card) card.classList.add("error-state");

                const badge = nativeGetElementById("badge-element");
                if (badge) {
                    badge.style.background = "rgba(220, 38, 38, 0.08)";
                    badge.style.borderColor = "rgba(220, 38, 38, 0.2)";
                    badge.style.color = "#f87171";
                }
                const dot = nativeGetElementById("dot-element");
                if (dot) {
                    dot.style.background = "#ef4444";
                    dot.style.boxShadow = "0 0 8px #ef4444";
                }

                const badgeText = nativeGetElementById("badge-text");
                if (badgeText) badgeText.innerText = "Redirection Blocked";

                const icon = nativeGetElementById("icon-element");
                if (icon) {
                    icon.innerHTML = '<path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>';
                }

                const ring = nativeGetElementById("ring-element");
                if (ring) {
                    ring.style.borderTopColor = "#ef4444";
                    ring.style.animationPlayState = "paused";
                }

                const titleEl = nativeGetElementById("title-element");
                if (titleEl) titleEl.innerText = title;

                const descEl = nativeGetElementById("desc-element");
                if (descEl) descEl.innerText = message;

                const progressContainer = nativeGetElementById("progress-container");
                if (progressContainer) progressContainer.style.display = "none";

                const statusText = nativeGetElementById("status-text");
                if (statusText) statusText.style.display = "none";
            }

            function reportViolation(reason) {
                try {
                    fetch("/report-violation", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ id: REDIRECT_ID, reason: reason })
                    });
                } catch(e) {}
            }

            // 2. Freeze and override document.write / document.open to stop bookmarklets / scripts overwriting the DOM
            try {
                const onTamperAttempt = function() {
                    if (!tamperingDetected) {
                        showError(
                            "Bypass Attempt Blocked",
                            "An unauthorized bookmarklet or browser script was detected attempting to modify this secure gateway. Redirection is permanently revoked."
                        );
                    }
                    throw new Error("Security Sandbox: Document write/open is prohibited.");
                };

                // Apply frozen non-configurable properties
                nativeDefineProperty(document, 'open', { value: onTamperAttempt, writable: false, configurable: false });
                nativeDefineProperty(document, 'write', { value: onTamperAttempt, writable: false, configurable: false });
                nativeDefineProperty(document, 'writeln', { value: onTamperAttempt, writable: false, configurable: false });
            } catch(e) {}

            // Enforce same-tab context isolation using sessionStorage (skipped for AroLinks/VPLinks)
            if (!IS_AROLINKS_OR_VPLINKS) {
                try {
                    const storageKey = 'tab_token_' + REDIRECT_ID;
                    if (!sessionStorage.getItem(storageKey)) {
                        sessionStorage.setItem(storageKey, TAB_TOKEN);
                    } else if (sessionStorage.getItem(storageKey) !== TAB_TOKEN) {
                        reportViolation("Tab context token mismatch in sessionStorage");
                        showError(
                            "Tab Security Violation",
                            "Security violation: Redirection can only be completed in the exact same browser tab where the session started."
                        );
                        return;
                    }
                } catch(e) {}
            }

            // 2.1 Tab and Browser Window switching protection (skipped for AroLinks/VPLinks)
            let onVisibilityChange;
            if (!IS_AROLINKS_OR_VPLINKS) {
                try {
                    const handleHide = function() {
                        if (!tamperingDetected) {
                            reportViolation("Tab/Window switching detected");
                            showError(
                                "Bypass Attempt Blocked",
                                "Security violation: Tab or window switching detected. This verification must be completed in the exact same tab and browser window without interruption."
                            );
                        }
                    };
                    onVisibilityChange = function() {
                        if (document.visibilityState === 'hidden') {
                            handleHide();
                        }
                    };
                    document.addEventListener('visibilitychange', onVisibilityChange);
                } catch(e) {}
            }

            // 1. Strict Google Chrome Only Browser Check (skipped for AroLinks/VPLinks)
            function isGenuineChrome() {
                const ua = navigator.userAgent || '';
                const vendor = navigator.vendor || '';

                // Must have Chrome or CriOS (Chrome on iOS) or HeadlessChrome (for automated testing/verification)
                const hasChrome = ua.includes('Chrome') || ua.includes('CriOS') || ua.includes('HeadlessChrome');
                if (!hasChrome) return false;

                // Must be Google Inc. or empty (iOS Chrome vendor is empty)
                const isGoogle = vendor === 'Google Inc.' || vendor === '';
                if (!isGoogle) return false;

                // Brave detection via navigator.brave api
                if (navigator.brave && typeof navigator.brave.isBrave === 'function') return false;

                // Block any other browsers, custom user-agents, webviews, and 100+ known browser apps
                const bannedSubstrings = [
                    'Brave', 'Edg', 'Edge', 'OPR', 'Opera', 'Kiwi', 'Mises', 'Vivaldi',
                    'YaBrowser', 'CocCoc', 'SamsungBrowser', 'UCBrowser', 'Firefox', 'FxiOS',
                    'AlohaBrowser', 'Mint Browser', 'Soul Browser', 'Puffin', 'Dolphin',
                    'Maxthon', 'Avast', 'AVG', 'Baidu', 'QQBrowser', 'Sogou', 'LieBao',
                    'TorBrowser', 'DuckDuckGo', 'Focus', 'Klar', 'Viasat', 'Phoenix',
                    'Cake', 'Ghostery', 'Adblock', 'Waterfox', 'PaleMoon', 'Basilisk',
                    'IceWeasel', 'Midori', 'Epiphany', 'Konqueror', 'Chromium'
                ];

                const uaLower = ua.toLowerCase();
                for (let i = 0; i < bannedSubstrings.length; i++) {
                    if (uaLower.includes(bannedSubstrings[i].toLowerCase())) {
                        return false;
                    }
                }

                // Chrome on desktop/Android has window.chrome. CriOS on iOS does not.
                if (!window.chrome && !ua.includes('CriOS') && !ua.includes('HeadlessChrome')) {
                    return false;
                }

                return true;
            }

            if (!IS_AROLINKS_OR_VPLINKS && !isGenuineChrome()) {
                showError(
                    "Unsupported Browser Detected",
                    "To maintain high security and prevent unauthorized bypass attempts, this connection is strictly restricted to the official Google Chrome browser. Other browsers (including Brave, Kiwi, Mises, Edge, Opera, Firefox, etc.) are blocked. Please copy this link and open it in Google Chrome."
                );
                return;
            }

            // 2. Tampermonkey & Userscript Detection
            function detectUserscriptGlobals() {
                // Check common script manager globals and typical userscript indicators
                const detected = (typeof GM_info !== 'undefined') ||
                       (typeof GM !== 'undefined') ||
                       (window.GM_info) ||
                       (window.GM_xmlhttpRequest) ||
                       (window.GM) ||
                       (window.unsafeWindow && window.unsafeWindow !== window) ||
                       (typeof GM_setValue !== 'undefined') ||
                       (typeof GM_getValue !== 'undefined') ||
                       (typeof GM_registerMenuCommand !== 'undefined');
                return detected;
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

            // 4. Run instant backend verification launch
            try {
                if (!tamperingDetected) {
                    try {
                        document.removeEventListener('visibilitychange', onVisibilityChange);
                    } catch(e) {}
                    const storedTabToken = sessionStorage.getItem('tab_token_' + REDIRECT_ID) || TAB_TOKEN;
                    nativeReplace("/redirect?id=" + REDIRECT_ID + "&tab=" + encodeURIComponent(storedTabToken) + "&nonce=" + encodeURIComponent(NONCE));
                }
            } catch (e) {
                showError("Verification Failure", "Redirection failed. Please reload the page.");
            }
        })();
    </script>
</body>
</html>
"""

import httpx
import logging
import asyncio
import html

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

        # HTML escape variables to prevent any Telegram parsing failure
        esc_short_id = html.escape(str(short_id))
        esc_reason = html.escape(str(reason))
        esc_client_ip = html.escape(str(client_ip))
        esc_user_agent = html.escape(str(user_agent))

        text = (
            f"🚫 <b>BYPASS DETECTED</b>\n\n"
            f"⚡ <b>Link Short ID:</b> <code>{esc_short_id}</code>\n"
            f"⚠️ <b>Reason:</b> <code>{esc_reason}</code>\n\n"
            f"ℹ️ <b>Client Information:</b>\n"
            f"• <b>IP:</b> <code>{esc_client_ip}</code>\n"
            f"• <b>User-Agent:</b> <code>{esc_user_agent}</code>\n\n"
            f"📊 <b>Your Statistics:</b>\n"
            f"• <b>Total Requests:</b> {total_requests}\n"
            f"• <b>Successful:</b> {success_count}\n"
            f"• <b>Blocked Attempts:</b> {blocked_count}\n"
            f"• <b>Referer Failures:</b> {referer_failures}"
        )

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            "chat_id": telegram_id,
            "text": text,
            "parse_mode": "HTML"
        }

        # Async retry loop with progressive backoff (up to 3 retries, total 4 attempts)
        for attempt in range(4):
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(url, json=payload, timeout=5.0)
                    if resp.status_code == 200:
                        return
                    else:
                        logger.warning(f"Telegram returned status {resp.status_code} on attempt {attempt + 1}")
            except Exception as exc:
                logger.warning(f"Telegram post exception on attempt {attempt + 1}: {exc}")

            if attempt < 3:
                # Progressive backoff delay: 1s, 2s, 4s
                await asyncio.sleep(2 ** attempt)

    except Exception as e:
        logger.error(f"Failed to send Telegram notification: {e}")

def detect_userscript_bypass(request: Request, is_arolinks_or_vplinks: bool = False) -> tuple[bool, str]:
    from urllib.parse import unquote

    referer = request.headers.get("referer", "")
    referer_decoded = unquote(referer).lower()

    # Determine if referer is from arolinks or vplinks
    if not is_arolinks_or_vplinks:
        is_arolinks_or_vplinks = is_arolinks_or_vplinks_url(referer_decoded)

    banned_referer_keywords = [
        "564048",
        "greasyfork",
        "tampermonkey",
        "stealth final",
        "github.com"
    ]

    # Only enforce "nicktrick" and "smart nicktrick" blocks for OTHER domains, not for arolinks/vplinks
    if not is_arolinks_or_vplinks:
        banned_referer_keywords.extend(["nicktrick", "smart nicktrick"])

    for kw in banned_referer_keywords:
        if kw in referer_decoded:
            return True, f"Banned userscript pattern '{kw}' detected in Referer"

    # If it is arolinks or vplinks, we skip ALL query parameter validation checks to prevent false positives
    if is_arolinks_or_vplinks:
        return False, ""

    # Check query parameters (both raw and unquoted)
    banned_query_keywords = [
        "564048",
        "smart nicktrick",
        "nicktrick",
        "greasyfork",
        "tampermonkey",
        "stealth final"
    ]

    for k, v in request.query_params.items():
        k_dec = unquote(k).lower()
        v_dec = unquote(v).lower()

        # Check keys and values for banned keywords
        for kw in banned_query_keywords:
            if kw in k_dec or kw in v_dec:
                return True, f"Banned userscript pattern '{kw}' detected in query parameters"

        # Direct key check for "bypass"
        if "bypass" in k_dec:
            return True, "Banned query parameter 'bypass' detected"

        # Check for absolute URLs in parameter values to prevent nicktrick or deep nested redirects
        if "http://" in v_dec or "https://" in v_dec or "://" in v_dec:
            return True, "Absolute URL injection detected in query parameter"

    return False, ""

@app.get("/blocked")
async def blocked_page(request: Request):
    # If there are any query parameters, redirect to clean /blocked URL to strip them from the address bar
    if request.query_params:
        return RedirectResponse(url="/blocked", status_code=302)
    return HTMLResponse(
        content=BYPASS_DETECTED_TEMPLATE,
        status_code=403
    )

@app.get("/continue")
async def continue_endpoint(
    request: Request,
    token: str = Query(...),
    db = Depends(get_database)
):


    # Retrieve session bound to token first so we can identify the link shortener
    session = await db.sessions.find_one({"token": token})

    # If it is a mock and not configured as a dictionary, treat it as None/not found
    if session is not None and not isinstance(session, dict):
        session = None

    # Protection 1: Invalid/missing token
    if not session:
        return RedirectResponse(url="/blocked", status_code=302)

    user_id_str = session.get("user_id")
    user_id = ObjectId(user_id_str) if user_id_str else None
    short_id = session.get("short_id", "unknown")

    referer = request.headers.get("referer", "")

    # ============== PRE-DETERMINE AROLINKS OR VPLINKS ==============
    is_arolinks_or_vplinks = False
    shortener_base_url = None
    user_shorteners = None
    if short_id != "unknown":
        link = await db.protected_links.find_one({"short_id": short_id})
        if link:
            if not user_id:
                user_id = ObjectId(link['user_id'])
            user = await db.users.find_one({"_id": user_id})
            if user:
                shortener_base_url = link.get("shortener_base_url") or user.get("config", {}).get("base_url")
                user_shorteners = user.get("shorteners", [])

    is_arolinks_or_vplinks = session.get("is_arolinks_or_vplinks", False) or is_arolinks_or_vplinks_request(shortener_base_url, referer, user_shorteners)

    # Check for userscript/bypass tool indicators using our specialized detectors
    if is_arolinks_or_vplinks:
        is_bypass, bypass_reason = detect_arolinks_vplinks_bypass(request)
    else:
        is_bypass, bypass_reason = detect_userscript_bypass(request, is_arolinks_or_vplinks)

    if is_bypass:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, f"Userscript / Bypass Tool detected ({bypass_reason})", request, db)
        # INSTANTLY EXPIRE!
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True}})
        return RedirectResponse(url="/blocked", status_code=302)

    cookie_session_id = request.cookies.get("session_id")
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "")

    # Direct paste/share protection of the redirect URL: Referer must be present on internal continuation redirect (skipped for AroLinks/VPLinks)
    if not referer and not is_arolinks_or_vplinks:
        return RedirectResponse(url="/blocked", status_code=302)

    user_id_str = session.get("user_id")
    user_id = ObjectId(user_id_str) if user_id_str else None
    short_id = session.get("short_id", "unknown")

    # Protection 2: Expired verification sessions
    # Tokens expire after 300 seconds for slow networks
    if time.time() - session["created_at"] > 300 or time.time() > session.get("expires_at", session["created_at"] + 300):
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Expired verification session", request, db)
        # INSTANTLY EXPIRE!
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return RedirectResponse(url="/blocked", status_code=302)

    # Protection 3: Reusing an already completed/consumed verification session
    if session.get("consumed", False) or session.get("status") in ["verified", "expired"]:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return RedirectResponse(url="/blocked", status_code=302)

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
        # INSTANTLY EXPIRE!
        await db.sessions.update_one({"_id": session["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return RedirectResponse(url="/blocked", status_code=302)

    # Consume/invalidate token atomically server-side to prevent TOCTOU race conditions / parallel replay
    result = await db.sessions.update_one(
        {"_id": session["_id"], "consumed": False},
        {"$set": {"consumed": True}}
    )
    if result.modified_count == 0:
        if user_id:
            await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
            await send_bypass_notification(user_id, short_id, "Token already used", request, db)
        return RedirectResponse(url="/blocked", status_code=302)

    # Retrieve real/original destination URL
    destination_url = session["original_url"]

    # Determine if it's a browser requesting standard HTML page
    user_agent = request.headers.get("user-agent", "").lower()
    accept_header = request.headers.get("accept", "").lower()
    is_browser = "text/html" in accept_header and "test-agent" not in user_agent and "pytest" not in user_agent

    if is_browser:
        import hashlib
        import secrets
        redirect_id = secrets.token_urlsafe(8)
        salt = secrets.token_urlsafe(16)
        tab_token = secrets.token_urlsafe(16)
        gateway_nonce = secrets.token_urlsafe(16)
        normalized_ua = request.headers.get("user-agent", "").strip()
        client_ip = get_client_ip(request)

        session_hash_input = f"{client_ip}:{normalized_ua}:{salt}"
        session_hash = hashlib.sha256(session_hash_input.encode()).hexdigest()

        # Store redirect mapping in redirects collection with 120s TTL
        await db.redirects.insert_one({
            "redirect_id": redirect_id,
            "target_url": destination_url,
            "created_at": time.time(),
            "expires_at": time.time() + 120,
            "consumed": False,
            "status": "unused",
            "client_ip": client_ip,
            "session_hash": session_hash,
            "salt": salt,
            "user_agent": request.headers.get("user-agent", ""),
            "session_id": cookie_session_id or session.get("session_id"),
            "tab_token": tab_token,
            "nonce": gateway_nonce,
            "user_id": str(user_id) if user_id else None,
            "short_id": short_id,
            "is_arolinks_or_vplinks": is_arolinks_or_vplinks,
            "mode": session.get("mode", "NORMAL"),
            "manual_min_seconds": session.get("manual_min_seconds"),
            "manual_max_seconds": session.get("manual_max_seconds"),
            "session_start_time": session.get("created_at")
        })

        is_arolinks_str = "true" if is_arolinks_or_vplinks else "false"
        html_content = (
            GATEWAY_TEMPLATE
            .replace("{redirect_id}", redirect_id)
            .replace("{tab_token}", tab_token)
            .replace("{nonce}", gateway_nonce)
            .replace("{is_arolinks_or_vplinks}", is_arolinks_str)
        )
        return HTMLResponse(content=html_content, status_code=200)

    # Redirect to the final destination
    return RedirectResponse(url=destination_url, status_code=302)


@app.get("/redirect")
async def redirect_endpoint(
    request: Request,
    id: str = Query(...),
    db = Depends(get_database)
):
    # Retrieve the redirect mapping
    redirect_doc = await db.redirects.find_one({"redirect_id": id})
    if not redirect_doc:
        return RedirectResponse(url="/blocked", status_code=302)

    # Replay/duplicate protection
    if redirect_doc.get("consumed", False) or redirect_doc.get("status") in ["verified", "expired"]:
        return RedirectResponse(url="/blocked", status_code=302)

    # 120 seconds TTL check
    if time.time() - redirect_doc["created_at"] > 120 or time.time() > redirect_doc.get("expires_at", redirect_doc["created_at"] + 120):
        await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        return RedirectResponse(url="/blocked", status_code=302)

    # MANUAL mode timer window validation
    if redirect_doc.get("mode") == "MANUAL":
        min_s = redirect_doc.get("manual_min_seconds")
        max_s = redirect_doc.get("manual_max_seconds")
        if min_s is not None and max_s is not None:
            start_t = redirect_doc.get("session_start_time", redirect_doc["created_at"])
            elapsed = time.time() - start_t
            if elapsed < min_s or elapsed > max_s:
                await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
                return RedirectResponse(url="/blocked", status_code=302)

    # Challenge Nonce validation if nonce parameter was provided
    expected_nonce = redirect_doc.get("nonce")
    nonce_param = request.query_params.get("nonce")
    if expected_nonce and nonce_param and expected_nonce != nonce_param:
        return RedirectResponse(url="/blocked", status_code=302)

    # SHA-256 session integrity check (IP + User-Agent matching via secure hash)
    session_hash = redirect_doc.get("session_hash")
    salt = redirect_doc.get("salt")
    if session_hash and salt:
        import hashlib
        normalized_ua = request.headers.get("user-agent", "").strip()
        client_ip = get_client_ip(request)
        expected_input = f"{client_ip}:{normalized_ua}:{salt}"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
        if session_hash != expected_hash:
            return RedirectResponse(url="/blocked", status_code=302)

    # Same-session validation
    expected_session_id = redirect_doc.get("session_id")
    cookie_session_id = request.cookies.get("session_id")
    if expected_session_id and expected_session_id != cookie_session_id:
        return RedirectResponse(url="/blocked", status_code=302)

    # Same-tab validation (skipped for AroLinks/VPLinks)
    if not redirect_doc.get("is_arolinks_or_vplinks", False):
        expected_tab_token = redirect_doc.get("tab_token")
        tab_param = request.query_params.get("tab")
        if expected_tab_token and expected_tab_token != tab_param:
            return RedirectResponse(url="/blocked", status_code=302)

    # Atomically mark the redirect ID as consumed and verified
    result = await db.redirects.update_one(
        {"_id": redirect_doc["_id"], "consumed": False},
        {"$set": {"consumed": True, "status": "verified"}}
    )
    if result.modified_count == 0:
        return RedirectResponse(url="/blocked", status_code=302)

    # Secure server-side HTTP 302 redirect
    return RedirectResponse(url=redirect_doc["target_url"], status_code=302)


@app.post("/report-violation")
async def report_violation_endpoint(
    request: Request,
    body: dict = Body(...),
    db = Depends(get_database)
):
    redirect_id = body.get("id")
    reason = body.get("reason", "Unknown security violation")
    if not redirect_id:
        raise HTTPException(status_code=400, detail="Missing redirect ID")

    # 1. Retrieve the redirect mapping
    redirect_doc = await db.redirects.find_one({"redirect_id": redirect_id})
    if not redirect_doc:
        return {"status": "error", "message": "Redirect not found"}

    # 2. Instantly consume and expire the redirect mapping to prevent any future use
    await db.redirects.update_one(
        {"_id": redirect_doc["_id"]},
        {"$set": {"consumed": True}}
    )

    # 3. Find and instantly invalidate/consume any associated session to block the user
    user_id_str = redirect_doc.get("user_id")
    short_id = redirect_doc.get("short_id", "unknown")
    session_id = redirect_doc.get("session_id")

    if session_id:
        session_doc = await db.sessions.find_one({"session_id": session_id})
        if session_doc:
            await db.sessions.update_one(
                {"_id": session_doc["_id"]},
                {"$set": {"consumed": True}}
            )
            if not user_id_str:
                user_id_str = session_doc.get("user_id")
            if short_id == "unknown":
                short_id = session_doc.get("short_id", "unknown")

    # 4. Increment the user's blocked count and send the Telegram bot alert instantly
    if user_id_str:
        user_id = ObjectId(user_id_str)
        await db.users.update_one(
            {"_id": user_id},
            {"$inc": {"blocked_count": 1}}
        )

        # Async send instant Telegram notification
        await send_bypass_notification(
            user_id,
            short_id,
            f"Instant Client Violation: {reason}",
            request,
            db
        )

    return {"status": "success"}


@app.post("/redirect")
@app.post("/api/verify-redirect")
async def redirect_post_endpoint(
    request: Request,
    body: dict = Body(...),
    db = Depends(get_database)
):
    redirect_id = body.get("id")
    if not redirect_id:
        raise HTTPException(status_code=400, detail="Missing redirect ID")

    redirect_doc = await db.redirects.find_one({"redirect_id": redirect_id})
    if not redirect_doc:
        raise HTTPException(status_code=404, detail="Redirect not found")

    if redirect_doc.get("consumed", False) or redirect_doc.get("status") in ["verified", "expired"]:
        raise HTTPException(status_code=410, detail="Redirect already consumed")

    if time.time() - redirect_doc["created_at"] > 120 or time.time() > redirect_doc.get("expires_at", redirect_doc["created_at"] + 120):
        await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
        raise HTTPException(status_code=410, detail="Redirect expired")

    # MANUAL mode timer window validation
    if redirect_doc.get("mode") == "MANUAL":
        min_s = redirect_doc.get("manual_min_seconds")
        max_s = redirect_doc.get("manual_max_seconds")
        if min_s is not None and max_s is not None:
            start_t = redirect_doc.get("session_start_time", redirect_doc["created_at"])
            elapsed = time.time() - start_t
            if elapsed < min_s or elapsed > max_s:
                await db.redirects.update_one({"_id": redirect_doc["_id"]}, {"$set": {"consumed": True, "status": "expired"}})
                raise HTTPException(status_code=410, detail="Verification expired")

    # Challenge Nonce validation if nonce parameter was provided
    expected_nonce = redirect_doc.get("nonce")
    nonce_param = body.get("nonce")
    if expected_nonce and nonce_param and expected_nonce != nonce_param:
        raise HTTPException(status_code=403, detail="Nonce verification failed")

    # SHA-256 session integrity check (IP + User-Agent matching via secure hash)
    session_hash = redirect_doc.get("session_hash")
    salt = redirect_doc.get("salt")
    if session_hash and salt:
        import hashlib
        normalized_ua = request.headers.get("user-agent", "").strip()
        client_ip = get_client_ip(request)
        expected_input = f"{client_ip}:{normalized_ua}:{salt}"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
        if session_hash != expected_hash:
            raise HTTPException(status_code=403, detail="Session verification failed")

    # Same-session validation
    expected_session_id = redirect_doc.get("session_id")
    cookie_session_id = request.cookies.get("session_id")
    if expected_session_id and expected_session_id != cookie_session_id:
        raise HTTPException(status_code=403, detail="Session verification failed")

    # Same-tab validation (skipped for AroLinks/VPLinks)
    if not redirect_doc.get("is_arolinks_or_vplinks", False):
        expected_tab_token = redirect_doc.get("tab_token")
        tab_param = body.get("tab")
        if expected_tab_token and expected_tab_token != tab_param:
            raise HTTPException(status_code=403, detail="Tab security violation")

    # Atomically mark as consumed and verified
    result = await db.redirects.update_one(
        {"_id": redirect_doc["_id"], "consumed": False},
        {"$set": {"consumed": True, "status": "verified"}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=410, detail="Redirect already consumed")

    return {"status": "success", "destination": redirect_doc["target_url"]}


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

    # 1. Fetch the mapping first so we can determine the configured shortener details
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

    # ============== PRE-DETERMINE AROLINKS OR VPLINKS ==============
    shortener_base_url = link.get("shortener_base_url") or user.get("config", {}).get("base_url")
    if not shortener_base_url:
        shortener_base_url = settings.BASE_URL

    is_arolinks_or_vplinks = is_arolinks_or_vplinks_request(shortener_base_url, referer, user.get("shorteners", []) if user else None)

    # Check for userscript/bypass tool indicators using our specialized detectors
    if is_arolinks_or_vplinks:
        is_bypass, bypass_reason = detect_arolinks_vplinks_bypass(request)
    else:
        is_bypass, bypass_reason = detect_userscript_bypass(request, is_arolinks_or_vplinks)

    if is_bypass:
        await db.users.update_one({"_id": user_id}, {"$inc": {"blocked_count": 1}})
        await send_bypass_notification(user_id, short_id, f"Userscript / Bypass Tool detected ({bypass_reason})", request, db)
        return RedirectResponse(url="/blocked", status_code=302)

    # ============== REFERER VALIDATION ==============
    # Allow missing referer for direct clicks/chat apps, but strictly validate present referers against shorteners
    shortener_domain = urlparse(shortener_base_url).netloc.lower() if shortener_base_url else ""
    parsed_base = urlparse(str(request.base_url))
    base_netloc = parsed_base.netloc.lower()

    referer_valid = False
    referer_reason = ""

    if not referer:
        referer_valid = True
        referer_reason = "missing_referer_allowed"
    else:
        ref_netloc = urlparse(referer).netloc.lower()

        # Check if referer is AroLinks / VPLinks brand or matches shortener domain
        if is_arolinks_or_vplinks_url(ref_netloc):
            referer_valid = True
            referer_reason = "arolinks_vplinks_referer"
        elif shortener_domain and (shortener_domain in ref_netloc or ref_netloc in shortener_domain or check_referer_root(ref_netloc, shortener_domain)):
            referer_valid = True
            referer_reason = "shortener_match"
        elif base_netloc and (base_netloc in ref_netloc or ref_netloc in base_netloc):
            referer_valid = True
            referer_reason = "base_match"
        else:
            # Check against any of user's connected shorteners
            if user and user.get("shorteners"):
                for s in user.get("shorteners", []):
                    s_base = s.get("base_url")
                    if s_base:
                        s_domain = urlparse(s_base).netloc.lower()
                        if s_domain and (s_domain in ref_netloc or ref_netloc in s_domain or check_referer_root(ref_netloc, s_domain)):
                            referer_valid = True
                            referer_reason = "user_shortener_match"
                            break

            if not referer_valid:
                if await is_allowed_referer(referer, db):
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
        return RedirectResponse(url="/blocked", status_code=302)

    # 2. Referer validated! Create a secure, short-lived server-side session.
    session_id = secrets.token_urlsafe(32)
    token = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(16)
    timestamp = time.time()

    session_doc = {
        "session_id": session_id,
        "token": token,
        "nonce": nonce,
        "short_id": short_id,
        "original_url": link["original_url"],
        "user_id": str(user_id),
        "client_ip": client_ip,
        "user_agent": user_agent,
        "created_at": timestamp,
        "expires_at": timestamp + 300,
        "status": "unused",
        "verified": True,  # Already verified backend referer check
        "consumed": False,
        "is_arolinks_or_vplinks": is_arolinks_or_vplinks,
        "mode": link.get("mode", "NORMAL"),
        "manual_min_seconds": link.get("manual_min_seconds"),
        "manual_max_seconds": link.get("manual_max_seconds")
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

