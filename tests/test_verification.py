import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock
from bson import ObjectId
from app.main import app
from app.models.database import get_database

client = TestClient(app)

def test_verify_bypass_endpoint():
    target = "aHR0cHM6Ly9maWxlc3RvcmVwcm9ieS05cW00Lm9ucmVuZGVyLmNvbS90cmFjay9mZjd0Nl85Mmt0MF8xM25hX2JtZg=="
    hash_val = "6a374c77521189c"
    response = client.get(f"/verify?target={target}&hash={hash_val}")
    assert response.status_code == 403
    assert "BYPASS DETECTED" in response.text
    assert "Bypass Intercepted" in response.text

def test_human_verification_endpoint_not_found():
    mock_db = MagicMock()
    mock_db.protected_links.find_one = AsyncMock(return_value=None)
    app.dependency_overrides[get_database] = lambda: mock_db
    try:
        response = client.get("/s9DB-brJsD0")
        assert response.status_code == 404
    finally:
        app.dependency_overrides.clear()

def test_human_verification_flow_success():
    mock_db = MagicMock()
    user_id = ObjectId()
    fake_link = {
        "_id": ObjectId(),
        "short_id": "s9DB-brJsD0",
        "original_url": "https://example.com/file",
        "user_id": str(user_id),
        "shortener_base_url": "https://example-shortener.com"
    }
    fake_user = {
        "_id": user_id,
        "telegram_id": "12345678",
        "config": {"base_url": "https://example-shortener.com"}
    }

    mock_db.protected_links.find_one = AsyncMock(return_value=fake_link)
    mock_db.users.find_one = AsyncMock(return_value=fake_user)
    mock_db.users.update_one = AsyncMock(return_value=None)
    mock_db.sessions.insert_one = AsyncMock(return_value=None)

    app.dependency_overrides[get_database] = lambda: mock_db

    try:
        response = client.get(
            "/s9DB-brJsD0",
            headers={"referer": "https://example-shortener.com/s9DB-brJsD0", "user-agent": "Mozilla/5.0"},
            follow_redirects=False
        )
        assert response.status_code == 302
        assert "/continue?token=" in response.headers["location"]
        assert "session_id" in response.cookies
    finally:
        app.dependency_overrides.clear()
