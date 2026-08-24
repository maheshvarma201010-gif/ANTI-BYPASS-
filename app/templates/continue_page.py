CONTINUE_PAGE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Continue Verification</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
            background: #f5f5f5;
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
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            max-width: 500px;
            width: 100%;
            text-align: center;
        }
        .emoji { font-size: 64px; display: block; margin-bottom: 20px; }
        h1 { font-size: 24px; margin-bottom: 15px; }
        .error h1 { color: #dc3545; }
        .success h1 { color: #28a745; }
        .message { color: #666; font-size: 16px; line-height: 1.6; margin-bottom: 20px; }
        .url-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            text-align: left;
            word-break: break-all;
        }
        .url-box label { font-weight: 600; color: #333; display: block; margin-bottom: 5px; }
        .url-box code { color: #495057; font-size: 13px; background: transparent; }
        .btn {
            padding: 12px 30px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            transition: background 0.3s;
            text-decoration: none;
            display: inline-block;
            margin: 5px;
        }
        .btn-primary { background: #007bff; color: white; }
        .btn-primary:hover { background: #0056b3; }
        .btn-success { background: #28a745; color: white; }
        .btn-success:hover { background: #1e7e34; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #5a6268; }
        .hidden { display: none; }
        .spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #007bff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- COPY PASTE DETECTED NOTICE -->
        <div id="pasteNotice" class="hidden" style="background: #fff3cd; border: 1px solid #ffeeba; border-radius: 8px; padding: 10px; margin-bottom: 15px; color: #856404; font-size: 14px; font-weight: 600;">
            📋 Copy Paste / Direct Link Entry Detected!
        </div>

        <!-- ERROR STATE -->
        <div id="errorState">
            <span class="emoji">⚠️</span>
            <h1 style="color: #dc3545;">Missing Verification Parameters</h1>
            <div class="message">
                The continuation link is incomplete or invalid.<br>
                Please ensure you have <strong>target</strong>, <strong>hash</strong>, and <strong>nonce</strong> parameters.
            </div>
            <div class="url-box">
                <label>📋 Current URL:</label>
                <code id="currentUrl">Loading...</code>
            </div>
            <div class="url-box">
                <label>✅ Required Format:</label>
                <code style="color: #28a745;">
                    /continue?target=ENCODED_TARGET&hash=YOUR_HASH&nonce=NONCE
                </code>
            </div>
            <div id="referrerFix" class="hidden" style="margin: 15px 0;">
                <div class="url-box" style="background: #d4edda; border: 1px solid #c3e6cb;">
                    <label>🔍 Found Parameters in Referrer:</label>
                    <button class="btn btn-success" id="fixLinkBtn">🔧 Fix Link Automatically</button>
                </div>
            </div>
            <div style="margin-top: 20px;">
                <button class="btn btn-primary" onclick="location.reload()">🔄 Retry</button>
                <button class="btn btn-secondary" onclick="window.history.back()">⬅ Go Back</button>
            </div>
        </div>

        <!-- SUCCESS STATE -->
        <div id="successState" class="hidden">
            <span class="emoji">✅</span>
            <h1 style="color: #28a745;">Verification Successful!</h1>
            <div class="message" id="successMessage">Processing...</div>
            <div class="spinner"></div>
        </div>
    </div>

    <script>
        (function() {
            const errorState = document.getElementById('errorState');
            const successState = document.getElementById('successState');
            const currentUrlElement = document.getElementById('currentUrl');
            const pasteNotice = document.getElementById('pasteNotice');

            currentUrlElement.textContent = window.location.href;

            try {
                const nav = performance.getEntriesByType("navigation")[0];
                if (!document.referrer || (nav && nav.type === "navigate")) {
                    pasteNotice.classList.remove('hidden');
                }
            } catch(e) {}

            const urlParams = new URLSearchParams(window.location.search);
            const target = urlParams.get('target');
            const hash = urlParams.get('hash');
            const nonce = urlParams.get('nonce');

            if (!target || !hash) {
                errorState.classList.remove('hidden');
                successState.classList.add('hidden');
                errorState.style.display = 'block';
                successState.style.display = 'none';

                const referrer = document.referrer;
                if (referrer) {
                    try {
                        const refUrl = new URL(referrer);
                        const refTarget = refUrl.searchParams.get('target');
                        const refHash = refUrl.searchParams.get('hash');
                        const refNonce = refUrl.searchParams.get('nonce') || '8ad6e37025674688';

                        if (refTarget && refHash) {
                            const fixDiv = document.getElementById('referrerFix');
                            fixDiv.classList.remove('hidden');

                            const correctUrl = window.location.origin +
                                             window.location.pathname +
                                             '?target=' + encodeURIComponent(refTarget) +
                                             '&hash=' + encodeURIComponent(refHash) +
                                             '&nonce=' + encodeURIComponent(refNonce);

                            document.getElementById('fixLinkBtn').onclick = function() {
                                window.location.href = correctUrl;
                            };

                            const fixDivContent = fixDiv.querySelector('.url-box');
                            fixDivContent.innerHTML = `
                                <label>🔧 Correct URL:</label>
                                <code style="color: #155724; font-size: 12px; word-break: break-all;">${correctUrl}</code>
                                <br><br>
                                <button class="btn btn-success" onclick="window.location.href='${correctUrl}'">
                                    🔧 Click to Fix
                                </button>
                            `;
                        }
                    } catch (e) {}
                }
                return;
            }

            errorState.classList.add('hidden');
            successState.classList.remove('hidden');
            errorState.style.display = 'none';
            successState.style.display = 'block';

            try {
                const decodedTarget = atob(decodeURIComponent(target));
                const expectedHash = '8ad6e37025674688';

                if (hash === expectedHash) {
                    document.getElementById('successMessage').textContent =
                        `Redirecting to: ${decodedTarget}`;

                    setTimeout(() => {
                        window.location.href = decodedTarget;
                    }, 2000);
                } else {
                    document.querySelector('#successState .emoji').textContent = '❌';
                    document.querySelector('#successState h1').style.color = '#dc3545';
                    document.querySelector('#successState h1').textContent = 'Invalid Hash';
                    document.getElementById('successMessage').textContent =
                        'Verification hash does not match. Please check your link.';
                }
            } catch (error) {
                document.querySelector('#successState .emoji').textContent = '❌';
                document.querySelector('#successState h1').style.color = '#dc3545';
                document.querySelector('#successState h1').textContent = 'Verification Failed';
                document.getElementById('successMessage').textContent =
                    'Failed to process verification. Invalid target format.';
            }
        })();
    </script>
</body>
</html>
"""
