#!/bin/bash

# Start the Telegram Bot in the background
python -m app.bot.bot_runner &

# Start the FastAPI app using Gunicorn with Uvicorn workers, binding dynamically to the PORT environment variable if available
gunicorn app.main:app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:${PORT:-8000} \
    --access-logfile - \
    --error-logfile -
