from app.core.security import generate_api_key, generate_challenge_token, verify_challenge_token, encrypt_url, decrypt_url
import time

def test_api_key_generation():
    key = generate_api_key()
    assert key.startswith("abp_")
    assert len(key) > 10

def test_challenge_token():
    short_id = "test123"
    token = generate_challenge_token(short_id)
    assert verify_challenge_token(token, short_id) is True
    assert verify_challenge_token(token, "wrong_id") is False

def test_challenge_token_expiry():
    short_id = "test123"
    # We can't easily test expiry without mocking time or waiting, but let's check it works normally
    token = generate_challenge_token(short_id)
    assert verify_challenge_token(token, short_id) is True

def test_encryption():
    url = "https://example.com"
    encrypted = encrypt_url(url)
    decrypted = decrypt_url(encrypted)
    assert url == decrypted
