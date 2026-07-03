async function runChallenge(shortId, token) {
    const referer = document.referrer;
    const errorMessage = document.getElementById('error-message');

    // Collect fingerprinting data
    const fingerprint = {
        short_id: shortId,
        token: token,
        referer: referer,
        language: navigator.language,
        screen_size: `${window.screen.width}x${window.screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    };

    try {
        const response = await fetch('/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(fingerprint)
        });

        const result = await response.json();

        if (result.status === 'success') {
            window.location.href = result.redirect;
        } else {
            document.querySelector('.spinner').style.display = 'none';
            document.querySelector('h1').textContent = 'Access Blocked';
            document.querySelector('p').textContent = '';
            errorMessage.textContent = result.reason === 'bypass_detected' ? 'Bypass Detected! Please use a valid link.' : 'Validation failed: ' + result.reason;
            errorMessage.style.display = 'block';
        }
    } catch (error) {
        errorMessage.textContent = 'An error occurred. Please refresh the page.';
        errorMessage.style.display = 'block';
    }
}
