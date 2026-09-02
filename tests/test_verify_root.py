import pytest
import base64
from fastapi.testclient import TestClient
from app.main import app, decode_target, validate_secure_url

client = TestClient(app)

def test_decode_target_user_url():
    target_b64 = "aHR0cHM6Ly90ZWxlZ3JhbS5tZS9BTklfVEVMVUdVRkxJWF9CT1Q_c3RhcnQ9dmVyaWZ5X1c1bDA2bUtUTnh5dnoza2hMS1Fqamc="
    decoded = decode_target(target_b64)
    assert decoded == "https://telegram.me/ANI_TELUGUFLIX_BOT?start=verify_W5l06mKTNxyvz3khLKQjjg"

def test_root_endpoint_verification():
    target_b64 = "aHR0cHM6Ly90ZWxlZ3JhbS5tZS9BTklfVEVMVUdVRkxJWF9CT1Q_c3RhcnQ9dmVyaWZ5X1c1bDA2bUtUTnh5dnoza2hMS1Fqamc="
    hash_val = "38043e8e818e3df3bf646b7a2fbcf520"
    salt_val = "peq-9RxQJxoyzn7Lzw3vHA"

    response = client.get(
        "/",
        params={"target": target_b64, "hash": hash_val, "salt": salt_val},
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept": "text/html"}
    )
    assert response.status_code == 200
    assert "Verifying Connection" in response.text
    assert "session_id" in response.cookies

def test_urllinkshort_referer_no_false_bypass():
    target_b64 = "aHR0cHM6Ly90ZWxlZ3JhbS5tZS9BTklfVEVMVUdVRkxJWF9CT1Q_c3RhcnQ9dmVyaWZ5X1c1bDA2bUtUTnh5dnoza2hMS1Fqamc="
    hash_val = "38043e8e818e3df3bf646b7a2fbcf520"
    salt_val = "peq-9RxQJxoyzn7Lzw3vHA"

    response = client.get(
        "/verify",
        params={"target": target_b64, "hash": hash_val, "salt": salt_val},
        headers={
            "User-Agent": "Mozilla/5.0 (Linux; Android 11; CUBOT KINGKONG 5) AppleWebKit/537.36",
            "Referer": "https://web.urllinkshort.in/TcMOX",
            "Accept": "text/html"
        }
    )
    assert response.status_code == 200
    assert "Verifying Connection" in response.text
    assert "session_id" in response.cookies
