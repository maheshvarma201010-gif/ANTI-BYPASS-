import pytest
from starlette.datastructures import Headers, URL, QueryParams
from app.core.referer import check_referer_root, is_valid_shortener_referer
from app.main import detect_userscript_bypass

class DummyRequest:
    def __init__(self, headers=None, url="https://antibypass.org/verify?target=abc", query_params=None):
        self.headers = Headers(headers or {})
        self.url = URL(url)
        self.query_params = QueryParams(query_params or {})

class ErrorDB:
    @property
    def allowed_referers(self):
        class BrokenColl:
            def find(self, query):
                raise RuntimeError("DB Disconnected")
        return BrokenColl()

def test_check_referer_root():
    assert check_referer_root("shortener.com", "https://shortener.com/link") is True
    assert check_referer_root("shortener.com", "https://sub.shortener.com/link") is True
    assert check_referer_root("sub.shortener.com", "https://shortener.com/link") is True
    assert check_referer_root("a.shortener.com", "https://b.shortener.com/link") is True
    assert check_referer_root("shortener.com", "https://otherdomain.com/link") is False
    assert check_referer_root("", "https://shortener.com") is False
    assert check_referer_root("shortener.com", "") is False

@pytest.mark.asyncio
async def test_is_valid_shortener_referer():
    # Matching shortener domain root without DB
    assert await is_valid_shortener_referer("shortener.com", "https://sub.shortener.com/page", db=None) is True
    assert await is_valid_shortener_referer("shortener.com", "https://other.com/page", db=None) is False

    # Safe against disconnected DB
    assert await is_valid_shortener_referer("shortener.com", "https://other.com/page", db=ErrorDB()) is False

@pytest.mark.asyncio
async def test_detect_userscript_bypass_antibypass_exemption():
    # URL containing antibypass domain name
    req_url_exemption = DummyRequest(
        headers={"user-agent": "Mozilla/5.0"},
        url="https://antibypass.app/verify?target=123&nicktrick=true"
    )
    is_bypass, _ = await detect_userscript_bypass(req_url_exemption, db=None)
    assert is_bypass is False

    # Referer containing antibypass domain name
    req_ref_exemption = DummyRequest(
        headers={"referer": "https://my-antibypass.com/page", "user-agent": "Mozilla/5.0"},
        url="https://example.com/verify?target=123"
    )
    is_bypass, _ = await detect_userscript_bypass(req_ref_exemption, db=None)
    assert is_bypass is False

    # Query params containing antibypass / anti-bypass parameter
    req_param_exemption = DummyRequest(
        headers={"user-agent": "Mozilla/5.0"},
        url="https://example.com/verify",
        query_params={"antibypass_token": "xyz123", "anti-bypass": "true"}
    )
    is_bypass, _ = await detect_userscript_bypass(req_param_exemption, db=None)
    assert is_bypass is False

    # Banned keyword should still be detected if domain is not exempted
    req_banned = DummyRequest(
        headers={"referer": "https://greasyfork.org/scripts/123", "user-agent": "Mozilla/5.0"},
        url="https://example.com/verify"
    )
    is_bypass, reason = await detect_userscript_bypass(req_banned, db=None)
    assert is_bypass is True
    assert "greasyfork" in reason

    # Safe against disconnected DB
    req_db_err = DummyRequest(
        headers={"user-agent": "Mozilla/5.0"},
        url="https://example.com/verify"
    )
    is_bypass, _ = await detect_userscript_bypass(req_db_err, db=ErrorDB())
    assert is_bypass is False
