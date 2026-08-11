# 🛡️ Premium URL Shortener Anti-Bypass Protection System

A state-of-the-art, high-performance, and extremely secure backend verification system designed to protect URL shortener redirects from bypass attempts.

---

## ⚡ Architecture Flow

The system operates entirely on the server-side to guarantee that no client-side script or browser storage (like localStorage) can be manipulated or bypassed.

```
Original Shortlink (e.g. https://shortener.com/abc)
      ↓
Backend Verification (Check Referer & config on GET /{short_id})
      ↓
Verification successful
      ↓
Create Secure Server-side Session & Cryptographic Continuation Token
      ↓
Redirect to /continue?token=RANDOM_TOKEN (with secure cookie set)
      ↓
Anti-bypass/session validation (Cookie & referer presence check)
      ↓
Final Destination URL Redirect (HTTP 302)
```

---

## 🔒 Security & Anti-Bypass Protections

The backend implements comprehensive defenses against direct pasting, parameter sharing, and replay attacks:

### 1. 🍪 Secure Server-Side Sessions & Cookies
- When a user opens the original shortlink, the backend validates their entry and creates a temporary server-side session in MongoDB with a cryptographically secure, random 256-bit `session_id`.
- The `session_id` is set as an `HttpOnly`, `SameSite=Lax` cookie on the client's browser, restricted to `path="/"`.
- This cookie is dynamically configured with the `secure` flag based on the incoming request scheme (True for HTTPS, False for HTTP) to prevent local and CI test environments from discarding cookies.

### 2. 🎟️ One-Time Continuation Tokens (Replay Protection)
- Together with the session, a cryptographically secure random one-time `token` is generated and bound to the session.
- When the client requests the `/continue` endpoint, the server atomically retrieves and invalidates the session in a single database transaction (`update_one` with `"consumed": False` filter). This completely eliminates any **Time-of-Check to Time-of-Use (TOCTOU)** race conditions and parallel request replays.

### 3. ⏱️ Short-Lived Expiration (Session TTL)
- Continuation sessions are valid for a maximum of **300 seconds (5 minutes)**. Any requests made after expiration are securely rejected.

### 4. 🔗 Adaptive Referer Validation
- Referers are fully verified at the entrypoint (`/{short_id}`). To accommodate browsers, private tabs, or chat applications (like Telegram, Discord) that strip the Referer header, empty/missing Referers are safely allowed.
- If a Referer is present, the system runs an **Adaptive Root Domain Substring Match** (`check_referer_root`). This extracts core domain names (e.g., `"arolinks"` or `"vplinks"`) by discarding common TLDs and subdomains. Legitimate redirects from alternative shortener domains (like `arolinks.co` instead of `arolinks.com`) are fully validated without false positives.

### 5. 📋 Direct Paste/Share Protection
- The continuation URL `/continue?token=...` alone is not sufficient for access. If pasted directly into another browser or shared:
  - The request will fail because the required `session_id` cookie is missing ("Session mismatch").
  - The request will fail because the browser sends an empty Referer header when pasting links directly into the address bar. The `/continue` route strictly enforces that the **Referer header must be present** on the redirect, completely stopping copy-pasted redirects.

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

## 🛠️ Setup & Environment Configuration

### Prerequisites
- Python 3.12+
- MongoDB instance

### Environment Variables
Configure the following in a `.env` file:
```env
PROJECT_NAME="Anti-Bypass Protection"
SECRET_KEY="your-secret-key-here"
ENCRYPTION_KEY="32-byte-long-secret-key-for-aes-!!"
MONGODB_URL="mongodb://localhost:27017"
DATABASE_NAME="antibypass"
TELEGRAM_BOT_TOKEN="your_bot_token"
BASE_URL="https://yourdomain.com"
```

---

## 🧪 Testing

Execute the comprehensive test suite with:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest
```
