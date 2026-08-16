# 🛡️ Premium URL Shortener Anti-Bypass Protection System

A state-of-the-art, high-performance, and extremely secure backend verification gateway designed to protect URL shortener redirects from bypass attempts. Built with **FastAPI**, **MongoDB (Motor)**, and **aiogram**, this system provides robust, industry-grade security while delivering a beautiful, seamless, and premium user experience.

---

## ⚡ Redirection Redesign Model

The system operates entirely on the server-side to guarantee that no client-side script, browser extension, or storage manipulation can bypass target redirects.

```
Original Shortlink (e.g., https://myshortener.com/...)
      ↓
Backend Verification (Checks config & verifies referer domain on GET /{short_id})
      ↓
Verification successful
      ↓
Create Secure Server-side Session & Cryptographic Continuation Token
      ↓
Redirect to /continue?token=RANDOM_TOKEN (with secure HttpOnly cookie set)
      ↓
Anti-bypass & session validation (Cookie, IP/UA matching & referer presence check)
      ↓
Redirection Handled strictly on Server Side (GET /redirect?id=RED_ID) (HTTP 302)
```

---

## 🔒 Advanced Security & Multi-Layered Algorithms

The backend implements comprehensive defenses against direct pasting, parameter sharing, bookmarklets, and replay attacks:

### 1. 🛡️ Session Integrity & Token Binding
- Generates a unique verification session (`session_id`), bound to client attributes (IP and User-Agent), and stores session state in MongoDB.
- Tokens are bound to their specific session to prevent token reuse across different browser contexts or sessions.

### 2. ⏱️ Short-Lived Expiration & Timestamp Verification
- Verification sessions and tokens have short expiration windows (5-minute session TTL, 120-second redirect TTL).
- Expired tokens or requests made outside allowed timeframes are immediately rejected and marked as expired.

### 3. 🎯 Single-Use Sessions & Replay Detection
- Every session and redirect token is usable only once (`consumed: False` $\rightarrow$ `consumed: True` via atomic MongoDB `update_one` transactions).
- Replaying previously used links or tokens triggers an immediate block and notifies the creator via Telegram.

### 4. ⚙️ NORMAL & MANUAL Verification Modes
- **NORMAL Mode:** Standard automated verification with strict referer and browser checks.
- **MANUAL Mode:** Timer-based verification window. Creators can configure a custom start time $T_1$ and end time $T_2$ in seconds via the Telegram bot. Verification only succeeds if completed within the valid $[T_1, T_2]$ second window.

### 5. 🎟️ Server-Side Token State & Challenge Nonces
- Tracks token state explicitly on the backend (`unused` $\rightarrow$ `processing` $\rightarrow$ `verified` / `expired`).
- Requires fresh server-generated challenge nonces before verification can complete.

### 6. 🚫 Immediate Bookmarklet & Userscript Neutralization
- Attempts to use bookmarklets (such as `nicktrick`) or injected scripts instantly trigger a 302 redirect to the blocked page.
- The `/blocked` page implements DOM sandboxing by freezing `document.open`, `document.write`, and `document.writeln` using `Object.defineProperty`.

---

## 🤖 Telegram Bot Control Features

Our anti-bypass bot allows creators to manage their shortener configurations easily with interactive menus:

1. **Shortener Mode Selection:**
   - Choose between **1. NORMAL** and **2. MANUAL** modes.
   - For MANUAL mode, set custom start and end duration windows (e.g., 200s to 220s).
2. **Dedicated API Keys:**
   - Issues distinct MANUAL mode ABP API keys (`manual_abp_key`) for timer-based links.
3. **Interactive Callback Controls:**
   - Buttons for `➕ Connect / Reconnect`, `👁️ View`, `❌ Delete Account`.
4. **Bypass Security Notifications:**
   - Sends real-time Telegram alerts whenever a bypass attempt or invalid referer is intercepted.

---

## 🚀 Running the Server

Start the FastAPI application with Uvicorn:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```
