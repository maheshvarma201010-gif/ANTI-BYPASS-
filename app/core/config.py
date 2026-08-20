import os
from pydantic_settings import BaseSettings
from typing import Optional, List

class Settings(BaseSettings):
    PROJECT_NAME: str = "Anti-Bypass Protection"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = "your-secret-key-here"  # Change in production
    ENCRYPTION_KEY: str = "32-byte-long-secret-key-for-aes-!!" # 32 bytes for AES-256

    MONGODB_URL: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "antibypass"

    TELEGRAM_BOT_TOKEN: str = ""
    BASE_URL: str = "https://antibypass-31lh.onrender.com"

    # Admin IDs and Banner Images configuration from env or defaults
    ADMIN_IDS: str = ""
    IMAGE_URLS: str = ""

    # Challenge settings
    CHALLENGE_EXPIRY_SECONDS: int = 60
    TOKEN_EXPIRY_SECONDS: int = 300

    class Config:
        env_file = ".env"
        extra = "ignore"

    def get_admin_ids(self) -> List[str]:
        raw = os.getenv("ADMIN_IDS", self.ADMIN_IDS)
        if not raw:
            return []
        return [x.strip() for x in raw.replace(",", " ").split() if x.strip()]

    def get_image_urls(self) -> List[str]:
        raw = os.getenv("IMAGE_URLS", self.IMAGE_URLS)
        if not raw:
            return []
        return [x.strip() for x in raw.replace(",", " ").split() if x.strip() and x.strip().startswith("http")]

settings = Settings()
