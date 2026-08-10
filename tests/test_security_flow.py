import pytest
import time
from fastapi import Request
from unittest.mock import AsyncMock, MagicMock
from bson import ObjectId
from app.main import original_shortlink, continue_endpoint, BYPASS_DETECTED_TEMPLATE
import json

@pytest.mark.asyncio
async def test_normal_verification_and_redirect():
    # Setup database mocks
    db = MagicMock()
    db.protected_links = AsyncMock()
    db.users = AsyncMock()
    db.sessions = AsyncMock()
    db.allowed_referers = AsyncMock()
    db.validation_events = AsyncMock()
    db.ip_whitelist = AsyncMock()
    db.sessions = AsyncMock()

    user_id = ObjectId()
    short_id = "test_short"
    original_url = "https://target-destination.com"

    db.protected_links.find_one.return_value = {
        "user_id": str(user_id),
        "short_id": short_id,
        "original_url": original_url
    }
    db.users.find_one.return_value = {
        "_id": user_id,
        "config": {"base_url": "https://myshortener.com"},
        "success_count": 0
    }

    # Mock original shortlink request with valid referrer
    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {
        "user-agent": "test-agent",
        "referer": "https://myshortener.com/abc"
    }

    response = await original_shortlink(request, short_id, db)

    # Verify that redirection happened to continue endpoint
    assert response.status_code == 303
    assert response.headers["location"].startswith("/continue?token=")

    # Retrieve cookie and token
    cookie_header = response.headers.get("set-cookie", "")
    assert "session_id=" in cookie_header
    session_id_part = [p for p in cookie_header.split(";") if "session_id=" in p][0]
    cookie_session_id = session_id_part.split("=")[1]

    token = response.headers["location"].split("=")[1]

    # Verify database insert of session
    db.sessions.insert_one.assert_called_once()
    session_data = db.sessions.insert_one.call_args[0][0]
    assert session_data["session_id"] == cookie_session_id
    assert session_data["token"] == token
    assert session_data["original_url"] == original_url

    # Mock continue request
    continue_request = MagicMock(spec=Request)
    continue_request.client = MagicMock()
    continue_request.client.host = "1.2.3.4"
    continue_request.headers = {
        "user-agent": "test-agent",
        "referer": "https://my-app.com/continue"
    }
    continue_request.cookies = {"session_id": cookie_session_id}
    continue_request.base_url = "https://my-app.com"

    db.sessions.find_one.return_value = session_doc = {
        "_id": ObjectId(),
        "session_id": cookie_session_id,
        "token": token,
        "short_id": short_id,
        "original_url": original_url,
        "client_ip": "1.2.3.4",
        "user_agent": "test-agent",
        "created_at": time.time(),
        "consumed": False
    }

    final_resp = await continue_endpoint(continue_request, token, db)

    # Successful final redirect checks
    assert final_resp.status_code == 303
    assert final_resp.headers["location"] == original_url
    db.sessions.update_one.assert_called_once_with(
        {"_id": session_doc["_id"], "consumed": False},
        {"$set": {"consumed": True}}
    )


@pytest.mark.asyncio
async def test_session_mismatch():
    db = MagicMock()
    db.sessions = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {"user-agent": "test-agent"}
    request.cookies = {"session_id": "mismatched_cookie"}

    db.sessions.find_one.return_value = {
        "_id": ObjectId(),
        "session_id": "correct_cookie_id",
        "token": "valid_token",
        "client_ip": "1.2.3.4",
        "user_agent": "test-agent",
        "created_at": time.time(),
        "consumed": False
    }

    response = await continue_endpoint(request, "valid_token", db)
    assert response.status_code == 403
    assert "Session mismatch" in response.body.decode()


@pytest.mark.asyncio
async def test_expired_session():
    db = MagicMock()
    db.sessions = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {"user-agent": "test-agent"}
    request.cookies = {"session_id": "cookie_id"}

    db.sessions.find_one.return_value = {
        "_id": ObjectId(),
        "session_id": "cookie_id",
        "token": "valid_token",
        "client_ip": "1.2.3.4",
        "user_agent": "test-agent",
        "created_at": time.time() - 121, # More than 120 seconds ago
        "consumed": False
    }

    response = await continue_endpoint(request, "valid_token", db)
    assert response.status_code == 403
    assert "Expired verification session" in response.body.decode()


@pytest.mark.asyncio
async def test_empty_referer_from_shortlink_allowed():
    db = MagicMock()
    db.protected_links = AsyncMock()
    db.users = AsyncMock()
    db.allowed_referers = MagicMock()
    db.allowed_referers.find_one = AsyncMock(return_value=None)
    db.validation_events = MagicMock()
    db.validation_events.find_one = AsyncMock(return_value=None)
    db.ip_whitelist = MagicMock()
    db.ip_whitelist.find_one = AsyncMock(return_value=None)
    db.sessions = AsyncMock()

    user_id = ObjectId()
    short_id = "test_short"

    db.protected_links.find_one.return_value = {
        "user_id": str(user_id),
        "short_id": short_id,
        "original_url": "https://example.com"
    }

    async def mock_find_one(query, *args, **kwargs):
        if query and "whitelisted" in query:
            return None
        return {
            "_id": user_id,
            "config": {"base_url": "https://myshortener.com"}
        }
    db.users.find_one = mock_find_one

    # Referer is empty
    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "8.8.8.8"
    request.headers = {
        "user-agent": "test-agent",
        "referer": ""
    }

    response = await original_shortlink(request, short_id, db)
    # Empty referer must NOT be blocked, it should proceed to set cookie and redirect
    assert response.status_code == 303
    assert response.headers["location"].startswith("/continue?token=")


@pytest.mark.asyncio
async def test_invalid_token_direct_continuation():
    db = MagicMock()
    db.sessions = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {"user-agent": "test-agent"}
    request.cookies = {}

    db.sessions.find_one.return_value = None

    response = await continue_endpoint(request, "non_existent_token", db)
    assert response.status_code == 403
    assert "Invalid token" in response.body.decode()


@pytest.mark.asyncio
async def test_reused_token():
    db = MagicMock()
    db.sessions = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {"user-agent": "test-agent"}
    request.cookies = {"session_id": "cookie_id"}

    db.sessions.find_one.return_value = {
        "_id": ObjectId(),
        "session_id": "cookie_id",
        "token": "valid_token",
        "client_ip": "1.2.3.4",
        "user_agent": "test-agent",
        "created_at": time.time(),
        "consumed": True # Token already used/consumed
    }

    response = await continue_endpoint(request, "valid_token", db)
    assert response.status_code == 403
    assert "Token already used" in response.body.decode()


@pytest.mark.asyncio
async def test_invalid_referer():
    # Setup database mocks
    db = MagicMock()
    db.protected_links = AsyncMock()
    db.users = AsyncMock()
    db.allowed_referers = MagicMock()
    db.allowed_referers.find_one = AsyncMock(return_value=None)
    db.validation_events = MagicMock()
    db.validation_events.find_one = AsyncMock(return_value=None)
    db.ip_whitelist = MagicMock()
    db.ip_whitelist.find_one = AsyncMock(return_value=None)
    db.sessions = AsyncMock()

    user_id = ObjectId()
    short_id = "test_short"

    db.protected_links.find_one.return_value = {
        "user_id": str(user_id),
        "short_id": short_id,
        "original_url": "https://example.com"
    }

    async def mock_find_one(query, *args, **kwargs):
        if query and "whitelisted" in query:
            return None
        return {
            "_id": user_id,
            "config": {"base_url": "https://myshortener.com"}
        }
    db.users.find_one = mock_find_one

    # Mock original shortlink request with an invalid/mismatched referer and not in dev/whitelist
    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "8.8.8.8"  # Non-local IP to bypass is_development_environment
    request.headers = {
        "user-agent": "test-agent",
        "referer": "https://someinvalidbypasssite.com"
    }
    request.base_url = "https://my-app.com"

    response = await original_shortlink(request, short_id, db)
    assert response.status_code == 403
    assert "Invalid referer" in response.body.decode()
