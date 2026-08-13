from fastapi import BackgroundTasks
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
        "config": {"base_url": "https://arolinks.com"},
        "success_count": 0
    }

    # Mock original shortlink request with valid referrer
    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {
        "user-agent": "test-agent",
        "referer": "https://arolinks.com/abc"
    }

    response = await original_shortlink(request, short_id, BackgroundTasks(), db)

    # Verify that redirection happened to continue endpoint
    assert response.status_code == 302
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

    final_resp = await continue_endpoint(continue_request, BackgroundTasks(), token, db)

    # Successful final redirect checks
    assert final_resp.status_code == 302
    assert final_resp.headers["location"] == original_url
    db.sessions.update_one.assert_called_once_with(
        {"_id": session_doc["_id"], "consumed": False},
        {"$set": {"consumed": True}}
    )


@pytest.mark.asyncio
async def test_session_mismatch():
    db = MagicMock()
    db.sessions = AsyncMock()
    db.users = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {"user-agent": "test-agent", "referer": "https://my-app.com"}
    request.cookies = {"session_id": "mismatched_cookie"}

    db.sessions.find_one.return_value = {
        "_id": ObjectId(),
        "session_id": "correct_cookie_id",
        "token": "valid_token",
        "user_id": str(ObjectId()),
        "client_ip": "1.2.3.4",
        "user_agent": "test-agent",
        "created_at": time.time(),
        "consumed": False
    }

    response = await continue_endpoint(request, BackgroundTasks(), "valid_token", db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_expired_session():
    db = MagicMock()
    db.sessions = AsyncMock()
    db.users = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {"user-agent": "test-agent", "referer": "https://my-app.com"}
    request.cookies = {"session_id": "cookie_id"}

    db.sessions.find_one.return_value = {
        "_id": ObjectId(),
        "session_id": "cookie_id",
        "token": "valid_token",
        "user_id": str(ObjectId()),
        "client_ip": "1.2.3.4",
        "user_agent": "test-agent",
        "created_at": time.time() - 301, # More than 300 seconds ago
        "consumed": False
    }

    response = await continue_endpoint(request, BackgroundTasks(), "valid_token", db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


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
        "original_url": "https://example.com",
        "shortener_base_url": "https://arolinks.com"
    }

    async def mock_find_one(query, *args, **kwargs):
        if query and "whitelisted" in query:
            return None
        return {
            "_id": user_id,
            "config": {"base_url": "https://arolinks.com"}
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

    response = await original_shortlink(request, short_id, BackgroundTasks(), db)
    # Empty referer must NOT be blocked, it should proceed to set cookie and redirect
    assert response.status_code == 302
    assert response.headers["location"].startswith("/continue?token=")


@pytest.mark.asyncio
async def test_invalid_token_direct_continuation():
    db = MagicMock()
    db.sessions = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {"user-agent": "test-agent", "referer": "https://my-app.com"}
    request.cookies = {}

    db.sessions.find_one.return_value = None

    response = await continue_endpoint(request, BackgroundTasks(), "non_existent_token", db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_continue_endpoint_empty_referer_blocked_direct_paste():
    db = MagicMock()
    db.sessions = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {"user-agent": "test-agent", "referer": ""} # Empty Referer
    request.cookies = {"session_id": "cookie_id"}

    response = await continue_endpoint(request, BackgroundTasks(), "valid_token", db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_reused_token():
    db = MagicMock()
    db.sessions = AsyncMock()
    db.users = AsyncMock()
    db.redirects = AsyncMock()
    db.redirects.insert_one = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {"user-agent": "test-agent", "referer": "https://my-app.com"}
    request.cookies = {"session_id": "cookie_id"}

    db.sessions.find_one.return_value = {
        "_id": ObjectId(),
        "session_id": "cookie_id",
        "token": "valid_token",
        "user_id": str(ObjectId()),
        "client_ip": "1.2.3.4",
        "user_agent": "test-agent",
        "created_at": time.time(),
        "consumed": True # Token already used/consumed
    }

    response = await continue_endpoint(request, BackgroundTasks(), "valid_token", db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


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
        "original_url": "https://example.com",
        "shortener_base_url": "https://arolinks.com"
    }

    async def mock_find_one(query, *args, **kwargs):
        if query and "whitelisted" in query:
            return None
        return {
            "_id": user_id,
            "config": {"base_url": "https://arolinks.com"}
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

    response = await original_shortlink(request, short_id, BackgroundTasks(), db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_absolute_url_query_parameter_injection_blocked():
    db = MagicMock()
    db.protected_links = AsyncMock()
    db.users = AsyncMock()

    short_id = "test_short"
    db.protected_links.find_one.return_value = {
        "user_id": str(ObjectId()),
        "short_id": short_id,
        "original_url": "https://example.com",
        "shortener_base_url": "https://arolinks.com"
    }
    db.users.find_one.return_value = {
        "_id": ObjectId(),
        "telegram_id": "12345"
    }

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    # Query parameters contain an absolute URL
    request.query_params = {"any_key": "https://target-payload.com"}

    response = await original_shortlink(request, short_id, BackgroundTasks(), db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_blocked_greasyfork_userscript_urls():
    db = MagicMock()
    db.protected_links = AsyncMock()
    db.users = AsyncMock()

    short_id = "test_short"
    db.protected_links.find_one.return_value = {
        "user_id": str(ObjectId()),
        "short_id": short_id,
        "original_url": "https://example.com",
        "shortener_base_url": "https://arolinks.com"
    }
    db.users.find_one.return_value = {
        "_id": ObjectId(),
        "telegram_id": "12345"
    }

    # Test 1: Banned userscript URL in Referer
    request1 = MagicMock(spec=Request)
    request1.client = MagicMock()
    request1.client.host = "1.2.3.4"
    request1.query_params = {}
    request1.headers = {
        "referer": "https://update.greasyfork.org/scripts/564048/Smart%20nicktrick%20Redirect%20%28Stealth%20Final%29.user.js"
    }

    response1 = await original_shortlink(request1, short_id, BackgroundTasks(), db)
    assert response1.status_code == 302
    assert response1.headers["location"] == "/blocked"

    # Test 2: Banned userscript URL with spaces in Referer
    request2 = MagicMock(spec=Request)
    request2.client = MagicMock()
    request2.client.host = "1.2.3.4"
    request2.query_params = {}
    request2.headers = {
        "referer": "https://update.greasyfork.org/scripts/564048/Smart nicktrick Redirect %28Stealth%20Final%29.user.js"
    }

    response2 = await original_shortlink(request2, short_id, BackgroundTasks(), db)
    assert response2.status_code == 302
    assert response2.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_continue_endpoint_browser_html():
    db = MagicMock()
    db.sessions = AsyncMock()
    db.users = AsyncMock()
    db.redirects = AsyncMock()
    db.redirects.insert_one = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {
        "user-agent": "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 safari/537.36",
        "referer": "https://my-app.com",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp"
    }
    request.cookies = {"session_id": "cookie_id"}

    db.sessions.find_one.return_value = {
        "_id": ObjectId(),
        "session_id": "cookie_id",
        "token": "valid_token",
        "user_id": str(ObjectId()),
        "client_ip": "1.2.3.4",
        "user_agent": "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 safari/537.36",
        "created_at": time.time(),
        "consumed": False,
        "original_url": "https://destination-url.com"
    }

    response = await continue_endpoint(request, BackgroundTasks(), "valid_token", db)
    assert response.status_code == 200
    body_decoded = response.body.decode()
    assert "Securing Connection..." in body_decoded
    assert "isGenuineChrome" in body_decoded
    assert "detectUserscriptGlobals" in body_decoded


@pytest.mark.asyncio
async def test_original_shortlink_nicktrick_blocked():
    db = MagicMock()
    db.protected_links = AsyncMock()
    db.users = AsyncMock()

    short_id = "test_short"
    db.protected_links.find_one.return_value = {
        "user_id": str(ObjectId()),
        "short_id": short_id,
        "original_url": "https://example.com",
        "shortener_base_url": "https://arolinks.com"
    }
    db.users.find_one.return_value = {
        "_id": ObjectId(),
        "telegram_id": "12345"
    }

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    # Query parameters contain "nicktrick"
    request.query_params = {"nicktrick": "some_payload"}

    response = await original_shortlink(request, short_id, BackgroundTasks(), db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_blocked_page_serves_html():
    from app.main import blocked_page
    request = MagicMock(spec=Request)
    request.query_params = {}
    response = await blocked_page(request)
    assert response.status_code == 403
    body = response.body.decode()
    assert "🚫 BYPASS DETECTED" in body
    # Confirm our frozen tamper script protections are injected
    assert "onTamper" in body
    assert "Object.defineProperty" in body


@pytest.mark.asyncio
async def test_blocked_page_redirects_if_query_params_present():
    from app.main import blocked_page
    request = MagicMock(spec=Request)
    request.query_params = {"nicktrick": "https://payload.com"}
    response = await blocked_page(request)
    # It must return a 302 redirect to /blocked without query parameters
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_redirect_endpoint_success():
    from app.main import redirect_endpoint
    db = MagicMock()
    db.redirects = AsyncMock()

    redirect_id = "test_redir_id"
    target_url = "https://example.com/target"

    db.redirects.find_one.return_value = {
        "_id": ObjectId(),
        "redirect_id": redirect_id,
        "target_url": target_url,
        "created_at": time.time(),
        "consumed": False
    }

    # Simulate successful atomic update (modified_count == 1)
    update_result = MagicMock()
    update_result.modified_count = 1
    db.redirects.update_one.return_value = update_result

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {}

    response = await redirect_endpoint(request, redirect_id, db)
    assert response.status_code == 302
    assert response.headers["location"] == target_url


@pytest.mark.asyncio
async def test_redirect_endpoint_invalid_id():
    from app.main import redirect_endpoint
    db = MagicMock()
    db.redirects = AsyncMock()

    db.redirects.find_one.return_value = None

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {}

    response = await redirect_endpoint(request, "invalid_id", db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_redirect_endpoint_already_consumed():
    from app.main import redirect_endpoint
    db = MagicMock()
    db.redirects = AsyncMock()

    redirect_id = "test_redir_id"
    db.redirects.find_one.return_value = {
        "_id": ObjectId(),
        "redirect_id": redirect_id,
        "target_url": "https://example.com",
        "created_at": time.time(),
        "consumed": True
    }

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {}

    response = await redirect_endpoint(request, redirect_id, db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_redirect_endpoint_expired():
    from app.main import redirect_endpoint
    db = MagicMock()
    db.redirects = AsyncMock()

    redirect_id = "test_redir_id"
    db.redirects.find_one.return_value = {
        "_id": ObjectId(),
        "redirect_id": redirect_id,
        "target_url": "https://example.com",
        "created_at": time.time() - 121,  # Older than 120 seconds
        "consumed": False
    }

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {}

    response = await redirect_endpoint(request, redirect_id, db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_redirect_post_endpoint_success():
    from app.main import redirect_post_endpoint
    db = MagicMock()
    db.redirects = AsyncMock()

    redirect_id = "test_redir_id"
    target_url = "https://example.com/target"

    db.redirects.find_one.return_value = {
        "_id": ObjectId(),
        "redirect_id": redirect_id,
        "target_url": target_url,
        "created_at": time.time(),
        "consumed": False
    }

    # Simulate successful atomic update (modified_count == 1)
    update_result = MagicMock()
    update_result.modified_count = 1
    db.redirects.update_one.return_value = update_result

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {}

    body = {"id": redirect_id}
    response = await redirect_post_endpoint(request, body, db)
    assert response["status"] == "success"
    assert response["destination"] == target_url


@pytest.mark.asyncio
async def test_redirect_post_endpoint_consumed_or_expired():
    from app.main import redirect_post_endpoint
    from fastapi import HTTPException
    db = MagicMock()
    db.redirects = AsyncMock()

    redirect_id = "test_redir_id"

    # Test already consumed
    db.redirects.find_one.return_value = {
        "_id": ObjectId(),
        "redirect_id": redirect_id,
        "target_url": "https://example.com",
        "created_at": time.time(),
        "consumed": True
    }

    request = MagicMock(spec=Request)
    body = {"id": redirect_id}

    with pytest.raises(HTTPException) as exc_info:
        await redirect_post_endpoint(request, body, db)
    assert exc_info.value.status_code == 410
    assert "already consumed" in exc_info.value.detail


@pytest.mark.asyncio
async def test_redirect_endpoint_sha256_success():
    from app.main import redirect_endpoint
    import hashlib
    db = MagicMock()
    db.redirects = AsyncMock()

    redirect_id = 'test_redir_id'
    target_url = 'https://example.com/target'
    salt = 'secure_salt_123'
    client_ip = '1.2.3.4'
    user_agent = 'test-agent'

    expected_input = f'{client_ip}:{user_agent}:{salt}'
    session_hash = hashlib.sha256(expected_input.encode()).hexdigest()

    db.redirects.find_one.return_value = {
        '_id': ObjectId(),
        'redirect_id': redirect_id,
        'target_url': target_url,
        'created_at': time.time(),
        'consumed': False,
        'session_hash': session_hash,
        'salt': salt
    }

    update_result = MagicMock()
    update_result.modified_count = 1
    db.redirects.update_one.return_value = update_result

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = client_ip
    request.headers = {'user-agent': user_agent}

    response = await redirect_endpoint(request, redirect_id, db)
    assert response.status_code == 302
    assert response.headers['location'] == target_url


@pytest.mark.asyncio
async def test_redirect_endpoint_sha256_mismatch_blocked():
    from app.main import redirect_endpoint
    db = MagicMock()
    db.redirects = AsyncMock()

    redirect_id = 'test_redir_id'
    target_url = 'https://example.com/target'

    db.redirects.find_one.return_value = {
        '_id': ObjectId(),
        'redirect_id': redirect_id,
        'target_url': target_url,
        'created_at': time.time(),
        'consumed': False,
        'session_hash': 'some_other_hash',
        'salt': 'some_salt'
    }

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = '1.2.3.4'
    request.headers = {'user-agent': 'different-agent'}

    response = await redirect_endpoint(request, redirect_id, db)
    assert response.status_code == 302
    assert response.headers['location'] == '/blocked'


@pytest.mark.asyncio
async def test_redirect_endpoint_tab_success():
    from app.main import redirect_endpoint
    db = MagicMock()
    db.redirects = AsyncMock()

    redirect_id = 'test_redir_id'
    target_url = 'https://example.com/target'
    session_id = 'valid_session_id_123'
    tab_token = 'valid_tab_token_456'

    db.redirects.find_one.return_value = {
        '_id': ObjectId(),
        'redirect_id': redirect_id,
        'target_url': target_url,
        'created_at': time.time(),
        'consumed': False,
        'session_id': session_id,
        'tab_token': tab_token
    }

    update_result = MagicMock()
    update_result.modified_count = 1
    db.redirects.update_one.return_value = update_result

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = '1.2.3.4'
    request.headers = {}
    request.cookies = {'session_id': session_id}
    request.query_params = {'tab': tab_token}

    response = await redirect_endpoint(request, redirect_id, db)
    assert response.status_code == 302
    assert response.headers['location'] == target_url


@pytest.mark.asyncio
async def test_redirect_endpoint_tab_mismatch_blocked():
    from app.main import redirect_endpoint
    db = MagicMock()
    db.redirects = AsyncMock()

    redirect_id = 'test_redir_id'
    target_url = 'https://example.com/target'
    session_id = 'valid_session_id_123'
    tab_token = 'valid_tab_token_456'

    db.redirects.find_one.return_value = {
        '_id': ObjectId(),
        'redirect_id': redirect_id,
        'target_url': target_url,
        'created_at': time.time(),
        'consumed': False,
        'session_id': session_id,
        'tab_token': tab_token
    }

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = '1.2.3.4'
    request.headers = {}
    request.cookies = {'session_id': session_id}
    request.query_params = {'tab': 'wrong_tab_token'}

    response = await redirect_endpoint(request, redirect_id, db)
    assert response.status_code == 302
    assert response.headers['location'] == '/blocked'


@pytest.mark.asyncio
async def test_redirect_endpoint_session_mismatch_blocked():
    from app.main import redirect_endpoint
    db = MagicMock()
    db.redirects = AsyncMock()

    redirect_id = 'test_redir_id'
    target_url = 'https://example.com/target'
    session_id = 'valid_session_id_123'
    tab_token = 'valid_tab_token_456'

    db.redirects.find_one.return_value = {
        '_id': ObjectId(),
        'redirect_id': redirect_id,
        'target_url': target_url,
        'created_at': time.time(),
        'consumed': False,
        'session_id': session_id,
        'tab_token': tab_token
    }

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = '1.2.3.4'
    request.headers = {}
    request.cookies = {'session_id': 'different_session'}
    request.query_params = {'tab': tab_token}

    response = await redirect_endpoint(request, redirect_id, db)
    assert response.status_code == 302
    assert response.headers['location'] == '/blocked'


@pytest.mark.asyncio
async def test_report_violation_endpoint_success():
    from app.main import report_violation_endpoint
    db = MagicMock()
    db.redirects = AsyncMock()
    db.sessions = AsyncMock()
    db.users = AsyncMock()

    redirect_id = 'test_redir_id'
    user_id = ObjectId()
    session_id = 'session_id_123'

    db.redirects.find_one.return_value = {
        '_id': ObjectId(),
        'redirect_id': redirect_id,
        'target_url': 'https://example.com',
        'created_at': time.time(),
        'consumed': False,
        'session_id': session_id,
        'user_id': str(user_id),
        'short_id': 'test_short'
    }

    db.sessions.find_one.return_value = {
        '_id': ObjectId(),
        'session_id': session_id,
        'consumed': False,
        'user_id': str(user_id),
        'short_id': 'test_short'
    }

    db.users.find_one.return_value = {
        '_id': user_id,
        'telegram_id': '12345'
    }

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = '1.2.3.4'
    request.headers = {}

    body = {'id': redirect_id, 'reason': 'Tab switching detected'}
    response = await report_violation_endpoint(request, BackgroundTasks(), body, db)
    assert response['status'] == 'success'

    db.redirects.update_one.assert_called()
    db.sessions.update_one.assert_called()
    db.users.update_one.assert_called_with(
        {'_id': user_id},
        {'$inc': {'blocked_count': 1}}
    )


@pytest.mark.asyncio
async def test_continue_endpoint_any_param_extraction_blocked():
    db = MagicMock()
    db.sessions = AsyncMock()
    db.sessions.find_one.return_value = None
    db.users = AsyncMock()
    token = "test_token"
    request = MagicMock(spec=Request)
    # Using a totally arbitrary query parameter containing an absolute URL
    request.query_params = {"any_random_param": "https://example.com/dest_url"}

    response = await continue_endpoint(request, BackgroundTasks(), token, db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"


@pytest.mark.asyncio
async def test_original_shortlink_non_arolinks_vplinks_bypass_success():
    db = MagicMock()
    db.protected_links = AsyncMock()
    db.users = AsyncMock()

    short_id = "test_short"
    original_url = "https://legit-target.com/file"

    db.protected_links.find_one.return_value = {
        "user_id": str(ObjectId()),
        "short_id": short_id,
        "original_url": original_url,
        "shortener_base_url": "https://some-unrelated-shortener.com"
    }
    db.users.find_one.return_value = {
        "_id": ObjectId(),
        "config": {"base_url": "https://some-unrelated-shortener.com"}
    }

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {}

    response = await original_shortlink(request, short_id, BackgroundTasks(), db)
    # Since it is NOT Arolinks or Vplinks, it must immediately redirect to the target URL!
    assert response.status_code == 302
    assert response.headers["location"] == original_url


@pytest.mark.asyncio
async def test_background_tasks_offloads_notification():
    db = MagicMock()
    db.sessions = AsyncMock()
    db.users = AsyncMock()

    request = MagicMock(spec=Request)
    request.client = MagicMock()
    request.client.host = "1.2.3.4"
    request.headers = {"user-agent": "test-agent", "referer": "https://some-referer.com"}
    request.cookies = {"session_id": "cookie_id"}

    db.sessions.find_one.return_value = {
        "_id": ObjectId(),
        "session_id": "cookie_id",
        "token": "valid_token",
        "user_id": str(ObjectId()),
        "client_ip": "1.2.3.4",
        "user_agent": "test-agent",
        "created_at": time.time() - 301, # Expired session
        "consumed": False
    }

    background_tasks = BackgroundTasks()
    # We will verify that background tasks are added successfully
    response = await continue_endpoint(request, background_tasks, "valid_token", db)
    assert response.status_code == 302
    assert response.headers["location"] == "/blocked"
    # Should have scheduled a background task
    assert len(background_tasks.tasks) > 0
