# Anti-Bypass Protection Service

A high-performance, enterprise-grade anti-bypass URL protection system built with **FastAPI**, **MongoDB**, and **aiogram**. This service acts as a secure intermediary layer for URL shorteners, protecting shortlinks against automated bypass bots, scripts (e.g. NickTrick, Tampermonkey, Greasefork), bookmarklets, and unauthorized link scrapers.

---

## 🌟 Core Features & Security Architecture

### 🛡️ Multi-Layer Anti-Bypass Suite
1. **Strict Referer & Origin Detection:** Validates that incoming clicks originate directly from configured shortener domains, blocking direct paste/share bypass attempts and self-referential gateway links.
2. **Userscript & Bookmarklet Detection:** Instantly blocks known bypass script patterns (such as NickTrick, Tampermonkey, Greasefork, stealth scripts, `top!==self`, `document.write`) in query parameters, HTTP Referers, and request URLs.
3. **Environment & Render Configuration Fallback:** Loads configuration seamlessly from environment variables (e.g., Render, Koyeb, Docker) or defaults defined in `app/core/config.py`.
4. **Context & Tab Isolation:** Uses dynamic single-use `sessionStorage` tokens tied to redirect IDs to prevent cross-tab or out-of-context link sharing.
5. **DOM Sandboxing:** Freezes `document.open`, `document.write`, and `document.writeln` using immutable property definitions (`Object.defineProperty`), preventing bookmarklets or injected scripts from overwriting page content.
6. **Address Bar Sanitization:** Instantly scrubs tracking parameters, hash fragments, and active payload parameters using `window.history.replaceState`.
7. **Server-Side Token State & Single-Use TTL:** Sessions and redirect tokens expire quickly (120s TTL) and transition atomically (`unused` → `consumed`) to prevent TOCTOU race conditions and replay attacks.
8. **Instant Bot Violation Notifications:** Dispatches real-time, HTML-formatted Telegram alerts to the link owner whenever a bypass attempt is intercepted.

---

## 🤖 Telegram Bot & Admin Panel

The integrated Telegram bot (`aiogram 3.x`) provides an intuitive dashboard with premium UI styling, clean blockquotes, and vibrant emojis.

### 🚀 Commands Guide
- `/start` - Access the main menu dashboard.
- `/connect` - Connect, view, or manage URL shorteners.
- `/api` - View connected shortener details and generated Anti-Bypass (ABP) API keys.
- `/stats` - View real-time request traffic, successful verifications, and blocked bypass metrics.
- `/panel` - **Admin Panel** to view, add bulk image banner URLs (100+ in a single message), or clear banners.
- `/help` - View complete bot usage guide and documentation.
- `/delete` - Remove account and all connected shortener configurations.

### 🖼️ Banner Image Management
- Admins can configure banner image URLs via the `/panel` command or environment variables (`IMAGE_URLS`).
- When banner image URLs are added, the bot randomly attaches a banner image to every message reply.
- If zero URLs are configured, the bot operates seamlessly in text-only mode without throwing errors.

### ⚙️ Verification Modes
1. **NORMAL Mode:** Standard real-time browser integrity verification.
2. **MANUAL Mode:** Timer-based verification window where verification is only allowed within a user-defined start and end time window in seconds.

---

## 🚀 Environment Variables

Configure environment variables in Render, Koyeb, or your local `.env` file:

```env
PROJECT_NAME="Anti-Bypass Protection"
MONGODB_URL="mongodb://localhost:27017"
DATABASE_NAME="antibypass"
SECRET_KEY="your-super-secret-key"
ENCRYPTION_KEY="32-byte-long-secret-key-for-aes-!!"
TELEGRAM_BOT_TOKEN="your-telegram-bot-token"
BASE_URL="https://your-domain.com"

# Admin & Banner Image Configuration
ADMIN_IDS="123456789,987654321"
IMAGE_URLS="https://example.com/banner1.jpg,https://example.com/banner2.jpg"
```

---

## 🔌 API Integration

To protect links programmatically, send a request to the API endpoint with your generated **ABP API Key**:

```http
GET /api?api=YOUR_ABP_KEY&url=https://target-destination.com
```

Response format:
```json
{
  "status": "success",
  "short_url": "https://example.com/xyz123"
}
```
