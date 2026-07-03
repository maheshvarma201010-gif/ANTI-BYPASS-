from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "Anti-Bypass Protection"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = "your-secret-key-here"  # Change in production
    ENCRYPTION_KEY: str = "32-byte-long-secret-key-for-aes-!!" # 32 bytes for AES-256

    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "antibypass"

    TELEGRAM_BOT_TOKEN: str = ""
    BASE_URL: str = "https://antibypass.koyeb.app"

    # Challenge settings
    CHALLENGE_EXPIRY_SECONDS: int = 60
    TOKEN_EXPIRY_SECONDS: int = 300

    class Config:
        env_file = ".env"

settings = Settings()
