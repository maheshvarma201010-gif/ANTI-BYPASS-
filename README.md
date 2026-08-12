# 🛡️ Premium URL Shortener Anti-Bypass Protection System

A state-of-the-art, high-performance, and extremely secure backend verification system designed to protect URL shortener redirects from bypass attempts.

---

## ⚡ Redirection Redesign Model

The system operates entirely on the server-side to guarantee that no client-side script or browser storage can be manipulated or bypassed.

```
Original Shortlink (e.g. https://arolinks.com/links?nicktrick=...)
      ↓
Backend Verification (Check Referer & config on GET /{short_id})
      ↓
Verification successful
      ↓
Create Secure Server-side Session & Cryptographic Continuation Token
      ↓
Redirect to /continue?token=RANDOM_TOKEN (with secure cookie set)
      ↓
Anti-bypass/session validation (Cookie, same-tab Storage matching & referer presence check)
      ↓
Redirection Handled strictly on Server Side (GET /redirect?id=RED_ID) (HTTP 302)
```

---

## 🔒 Advanced Security & Anti-Bypass Protections

The backend implements comprehensive, industry-leading defenses against direct pasting, parameter sharing, and replay attacks:

### 1. 🍪 Secure Server-Side Sessions & Cookies
- When a user opens the original shortlink, the backend validates their entry and creates a temporary server-side session in MongoDB with a cryptographically secure, random 256-bit `session_id`.
- The `session_id` is set as an `HttpOnly`, `SameSite=Lax` cookie on the client's browser, restricted to `path="/"`.
- This cookie is dynamically configured with the `secure` flag based on the incoming request scheme (True for HTTPS, False for HTTP).

### 2. 🎟️ One-Time Continuation Tokens (Replay Protection)
- Together with the session, a cryptographically secure random one-time `token` is generated and bound to the session.
- When the client requests the `/continue` endpoint, the server atomically retrieves and invalidates the session in a single database transaction (`update_one` with `"consumed": False` filter). This completely eliminates any **Time-of-Check to Time-of-Use (TOCTOU)** race conditions and parallel request replays.

### 3. ⏱️ Short-Lived Expiration (Session TTL)
- Continuation sessions are valid for a maximum of **300 seconds (5 minutes)**, and redirection tokens expire in **120 seconds**. Any requests made after expiration are securely rejected.

### 4. 🔒 Server-Side ID Redirection Mapping (Hidden URLs)
- Target destination URLs are kept **100% hidden** on the client side. No base64-encoded strings or URL references are ever embedded in the gateway template.
- REDIRECT is executed entirely on the server-side via `GET /redirect` using a unique, random redirection ID mapped in the server MongoDB collection, which redirects with an HTTP 302 response on verification success.

### 5. 📑 Same-Tab Isolation via sessionStorage & SHA-256 Hashing
- Enforces strict same-tab, same-browser, and same-session execution using:
  - Cryptographically secure `tab_token` matched inside `sessionStorage` (preventing tab duplication or URL sharing).
  - SHA-256 session integrity checks hashing the client's IP and User-Agent with a secure server-side salt.
  - Active tab visibility tracking via the `visibilitychange` API. If tab switching, minimized browser window, or focus loss is detected, it instantly posts to `/report-violation` to permanently consume/expire the session and trigger Telegram alerts.

### 6. 🔗 Tailored Referer Integrity Check for Arolinks and Vplinks
- Only permits manual solving from legitimate sources. Extends bypass keyword matching globally for third-party domains, but provides precise, custom-tailored exceptions specifically for **Arolinks** and **Vplinks** referers, completely eliminating false positives for legitimate users solving shorteners manually.

---

## 🤖 Telegram Bot Control Features

Our anti-bypass bot allows creators to manage their shortener configurations easily with interactive menus:

1. **Unlimited Shorteners:** Add and manage unlimited shortener configurations per user concurrently.
2. **Interactive Callback Controls:** Beautiful Inline Keyboard buttons for:
   - `➕ Connect / Reconnect`
   - `👁️ View`
   - `❌ Delete`
3. **No Overwrites/Conflicts:** Features a unique suffix-matching system to handle duplicate name registrations (e.g., `Arolinks`, `Arolinks 2`) without overwriting previous configs.
4. **Bypass Security Notifications:** Whenever a bypass attempt is intercepted, the bot asynchronously sends a rich private security alert to the creator's Telegram ID containing the exact reason, client info (IP, User-Agent), and their current link statistics.

---

## 🧪 Testing

Execute the comprehensive test suite with:
```bash
pip install -r requirements.txt
python -m pytest
```
