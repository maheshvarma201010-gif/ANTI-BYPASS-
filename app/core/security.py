import secrets
import hmac
import hashlib
import time
import base64
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from app.core.config import settings

def generate_api_key() -> str:
    return f"abp_{secrets.token_hex(16)}"

def generate_challenge_token(short_id: str) -> str:
    """Generates a signed token for the JS challenge."""
    timestamp = int(time.time())
    message = f"{short_id}:{timestamp}"
    signature = hmac.new(
        settings.SECRET_KEY.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{message}:{signature}"

def verify_challenge_token(token: str, short_id: str, max_age: Optional[int] = None) -> bool:
    """Verifies the challenge token."""
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return False

        t_short_id, timestamp, signature = parts
        if t_short_id != short_id:
            return False

        # Check expiry
        expiry = max_age if max_age is not None else settings.CHALLENGE_EXPIRY_SECONDS
        if int(time.time()) - int(timestamp) > expiry:
            return False

        # Verify signature
        message = f"{t_short_id}:{timestamp}"
        expected_signature = hmac.new(
            settings.SECRET_KEY.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected_signature)
    except Exception:
        return False

def encrypt_url(url: str) -> str:
    """Encrypts a URL using AES-256-CBC."""
    key = settings.ENCRYPTION_KEY.encode()[:32]
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(url.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return f"{iv}:{ct}"

def decrypt_url(encrypted_url: str) -> Optional[str]:
    """Decrypts a URL using AES-256-CBC."""
    try:
        key = settings.ENCRYPTION_KEY.encode()[:32]
        iv_b64, ct_b64 = encrypted_url.split(":")
        iv = base64.b64decode(iv_b64)
        ct = base64.b64decode(ct_b64)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception:
        return None
