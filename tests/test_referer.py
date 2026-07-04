import pytest
from fastapi import Request
from app.core.referer import handle_validation
from unittest.mock import AsyncMock, MagicMock
from bson import ObjectId
import json

@pytest.mark.asyncio
async def test_handle_validation_missing_referer():
    # Mocking the request
    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "127.0.0.1"
    request.headers = {"user-agent": "test-agent"}
    request.url = "http://testserver/validate/short123"

    # Mocking the database
    db = MagicMock()
    db.protected_links = AsyncMock()
    db.request_logs = AsyncMock()
    db.users = AsyncMock()

    user_id = str(ObjectId())
    db.protected_links.find_one.return_value = {"user_id": user_id, "original_url": "https://example.com"}
    db.users.find_one.return_value = {"_id": ObjectId(user_id), "api_key": "test_api_key"}

    # Payload with missing referrer
    payload = {"referrer": "", "token": "valid:token"}

    response = await handle_validation(request, "short123", payload, db)

    assert response is not None
    assert response.status_code == 403
    assert json.loads(response.body.decode()) == {
        "status": "blocked",
        "reason": "Missing JavaScript Referer",
        "message": "Bypass detected."
    }

    # Verify logging
    db.request_logs.insert_one.assert_called_once()
    args, _ = db.request_logs.insert_one.call_args
    assert args[0]["reason"] == "Missing JavaScript Referer"
    assert args[0]["status"] == "blocked"

@pytest.mark.asyncio
async def test_handle_validation_valid_referer():
    # Mocking the request
    request = MagicMock(spec=Request)

    # Mocking the database
    db = MagicMock()
    db.protected_links = AsyncMock()
    db.users = AsyncMock()

    user_id = str(ObjectId())
    db.protected_links.find_one.return_value = {"user_id": user_id, "original_url": "https://example.com"}
    db.users.find_one.return_value = {
        "_id": ObjectId(user_id),
        "api_key": "test_api_key",
        "config": {"base_url": "https://shortener.com"}
    }

    # Payload with valid referrer
    payload = {
        "referrer": "https://shortener.com/some-page",
        "token": "short123:1234567890:sig"
    }

    # We need to mock verify_challenge_token to return True
    with MagicMock() as mock_verify:
        import app.core.referer
        app.core.referer.verify_challenge_token = MagicMock(return_value=True)

        response = await handle_validation(request, "short123", payload, db)

        assert response.status_code == 200
        assert json.loads(response.body.decode())["status"] == "success"
