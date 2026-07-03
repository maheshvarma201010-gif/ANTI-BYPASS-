async function runChallenge(shortId, token) {
    const referer = document.referrer;
    const container = document.getElementById('main-container');

    try {
        const response = await fetch('/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                short_id: shortId,
                token: token,
                referer: referer
            })
        });

        if (response.status === 403) {
            // Referrer validation failed
            const result = await response.json();
            showBypassDetected();
            return;
        }

        const result = await response.json();
        if (result.status === 'success') {
            window.location.href = result.redirect;
        } else {
            showError(result.reason || 'Validation failed');
        }
    } catch (error) {
        showError('An error occurred. Please refresh the page.');
    }
}

function showBypassDetected() {
    document.body.innerHTML = `
        <div style="font-family: -apple-system, system-ui, sans-serif; background-color: #f7f9fc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0;">
            <div style="text-align: center; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); max-width: 500px; width: 100%;">
                <h1 style="font-size: 1.8rem; color: #e74c3c;">⚠️ Bypass Detected</h1>
                <p style="color: #666; line-height: 1.5; margin-top: 1rem;">
                    Access has been denied because the required referrer verification failed. This request appears to have bypassed the intended shortener flow.
                </p>
            </div>
        </div>
    `;
}

function showError(msg) {
    const container = document.getElementById('main-container');
    container.innerHTML = `<h1 style="color: #e74c3c;">Error</h1><p style="color: #666;">${msg}</p>`;
}
