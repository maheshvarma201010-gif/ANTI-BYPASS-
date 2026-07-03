#!/bin/bash

# Start the Telegram Bot in the background
python -m app.bot.bot_runner &

# Start the FastAPI app using Gunicorn with Uvicorn workers
gunicorn app.main:app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --access-log- - \
    --error-log- -
