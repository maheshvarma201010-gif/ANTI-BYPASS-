# Anti-Bypass Protection Service

A real-time Anti-Bypass Protection (ABP) API and Telegram Bot service to protect shortlinks and redirection endpoints against scrapers, automated scripts, and bypass tools.

## 🚀 Local Development & Setup Commands

### Installation
```bash
pip install -r requirements.txt
```

### Running Locally
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## ⚡ Vercel Deployment Settings

When deploying this project to **Vercel**, use the following configuration settings:

- **Framework Preset**: Other
- **Install Command**: `pip install -r requirements.txt --break-system-packages`
- **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port 8000`
- **Output Directory**: `.`

---

## 🔧 Environment Variables

Create a `.env` file based on `.env.example`:

```env
PROJECT_NAME="Anti-Bypass Protection"
BASE_URL="https://your-domain.com"
MONGODB_URL="mongodb://localhost:27017"
DATABASE_NAME="antibypass"
TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN"
```
