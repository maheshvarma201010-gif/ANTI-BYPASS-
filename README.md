# Anti-Bypass Protection Service

A robust, enterprise-grade anti-bypass URL protection system built with **FastAPI**, **MongoDB**, and **aiogram**. This service acts as a secure intermediary layer for URL shorteners, protecting shortlinks against automated bypass bots, scripts (e.g. Tampermonkey/Greasefork), bookmarklets, and unauthorized link scrapers.

---

## 🌟 Core Features & Security Architecture

### 🛡️ Multi-Layer Anti-Bypass Suite
1. **Strict Referer & Origin Detection:** Validates that incoming clicks originate directly from configured shortener domains or user shorteners, blocking direct paste/share bypass attempts.
2. **Userscript & Extension Detection:** Blocks known bypass script patterns (such as Tampermonkey, Greasefork, nicktrick, stealth scripts) in query parameters and HTTP Referers.
3. **Official Google Chrome Browser Enforcement:** Restricts gateway access exclusively to genuine Google Chrome browsers, neutralizing automated headless scrapers and unofficial client tools.
4. **Context & Tab Isolation:** Uses dynamic single-use `sessionStorage` tokens tied to redirect IDs to prevent cross-tab or out-of-context link sharing.
5. **Tab & Window Focus Protection:** Detects tab switching or browser window hiding during redirection, invalidating suspicious sessions immediately.
6. **DOM Sandboxing:** Freezes `document.open`, `document.write`, and `document.writeln` using immutable property definitions (`Object.defineProperty`), preventing bookmarklets or injected scripts from overwriting page content.
7. **Address Bar Sanitization:** Instantly scrubs tracking parameters, hash fragments, and active payload parameters using `window.history.replaceState`.
8. **Server-Side Token State & Single-Use TTL:** Sessions and redirect tokens expire quickly (120s TTL) and transition atomically (`unused` → `consumed`) to prevent TOCTOU race conditions and replay attacks.
9. **Instant Bot Violation Notifications:** Dispatches real-time, HTML-formatted Telegram alerts to the link owner whenever a bypass attempt is intercepted.

---

## 🤖 Telegram Bot Integration

The integrated Telegram bot (`aiogram 3.x`) allows users to manage their shorteners and monitor real-time protection statistics.

### Bot Commands
- `/start` - Launch the bot and view main menu options.
- `/connect` - Connect or manage URL shorteners.
- `/api` - View connected shortener details and generated Anti-Bypass (ABP) API keys.
- `/stats` - View total, successful, blocked, and referer failure request statistics.
- `/delete` - Delete account and remove stored shorteners.

### Verification Modes
1. **NORMAL Mode:** Standard real-time browser integrity verification.
2. **MANUAL Mode:** Timer-based verification window where verification is only allowed within a user-defined start and end time window in seconds.

---

## 🚀 Quick Start & Deployment

### Prerequisites
- Python 3.11+
- MongoDB
- Telegram Bot Token (from [@BotFather](https://t.me/BotFather))

### Environment Variables
Create a `.env` file in the root directory:

```env
PROJECT_NAME="Anti-Bypass Protection"
MONGODB_URL="mongodb://localhost:27017"
DATABASE_NAME="anti_bypass_db"
SECRET_KEY="your-super-secret-key"
TELEGRAM_BOT_TOKEN="your-telegram-bot-token"
BASE_URL="https://your-domain.com"
```

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Start application server and Telegram bot
bash start.sh
```

---

## 🔌 API Endpoints

- `GET /{short_id}` - Entry shortlink endpoint with referer validation and session creation.
- `GET /continue` - Serves secure JavaScript gateway template and session validation.
- `GET /redirect` / `POST /redirect` - Secure HTTP 302 redirection endpoint.
- `POST /report-violation` - Triggered on client-side security tampering to instantly invalidate sessions.
- `POST /api/shorten` - Generate protected shortlinks programmatically.
- `GET /health` - Health check status endpoint.
