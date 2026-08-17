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
    BASE_URL: str = "https://antibypass.koyeb.app"

    # Admin IDs and Banner Images configuration from env or defaults
    ADMIN_IDS: str = "8912467729"
    IMAGE_URLS: str = "https://files.catbox.moe/2hc6j, https://files.catbox.moe/v16uq, https://files.catbox.moe/hpzl8, https://files.catbox.moe/qqrak, https://files.catbox.moe/47qut, https://files.catbox.moe/tywna, https://files.catbox.moe/hirxb, https://files.catbox.moe/01qpj, https://files.catbox.moe/tw7tn, https://files.catbox.moe/8orn2, https://files.catbox.moe/pid4n, https://files.catbox.moe/n5hpi, https://files.catbox.moe/o5hb1, https://files.catbox.moe/ptudv, https://files.catbox.moe/lalrd, https://files.catbox.moe/9aeh5"

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
