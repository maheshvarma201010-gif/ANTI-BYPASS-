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
    request.client.host = "8.8.8.8"
    request.headers = {"user-agent": "test-agent"}
    request.url = "http://testserver/validate/short123"

    # Mocking the database
    db = MagicMock()
    db.protected_links = AsyncMock()
    db.request_logs = AsyncMock()
    db.validation_events = AsyncMock()
    db.users = AsyncMock()

    user_id = str(ObjectId())
    db.protected_links.find_one.return_value = {"user_id": user_id, "original_url": "https://example.com"}
    db.users.find_one.return_value = {
        "_id": ObjectId(user_id),
        "api_key": "test_api_key",
        "config": {"base_url": "https://shortener.com"}
    }
    db.validation_events.count_documents = AsyncMock(return_value=0)
    db.validation_events.insert_one = AsyncMock()
    db.ip_whitelist.find_one = AsyncMock(return_value=None)
    db.validation_events.find_one = AsyncMock(return_value=None)
    db.allowed_referers.find_one = AsyncMock(return_value=None)

    # Payload with missing referrer, but first let's mock verify_challenge_token to return True so we bypass the Token validation and reach the Referer validation
    with MagicMock() as mock_verify:
        import app.core.referer
        app.core.referer.verify_challenge_token = MagicMock(return_value=True)

        db.users.find_one.side_effect = [
            db.users.find_one.return_value, # First find_one in handle_validation
            {"_id": ObjectId(user_id)}, # Second find_one in get_user_verification_history
            None # Third find_one in is_whitelisted_user
        ]

        payload = {"referrer": "", "token": "valid:token"}

        response = await handle_validation(request, "short123", payload, db)

        assert response is not None
        assert response.status_code == 403

        # Verify logging
        db.validation_events.insert_one.assert_called_once()
        args, _ = db.validation_events.insert_one.call_args
        assert args[0]["reason"] == "Invalid Referer"
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

        db.users.find_one.side_effect = [
            db.users.find_one.return_value, # First find_one in handle_validation
            {"_id": ObjectId(user_id)}, # Second find_one in get_user_verification_history
            None # Third find_one in is_whitelisted_user
        ]

        response = await handle_validation(request, "short123", payload, db)

        assert response.status_code == 200
        assert json.loads(response.body.decode())["status"] == "success"
