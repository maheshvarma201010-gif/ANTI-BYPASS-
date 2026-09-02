import pytest
from fastapi.testclient import TestClient
from app.main import app, detect_userscript_bypass

client = TestClient(app)

class FakeAllowedCursor:
    def __init__(self, docs):
        self.docs = docs
        self._iter = iter(docs)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration

class FakeAllowedDB:
    def __init__(self, domains):
        self.domains = [{"domain": d} for d in domains]

    @property
    def allowed_referers(self):
        class Coll:
            def __init__(self, docs):
                self.docs = docs

            def find(self, query):
                return FakeAllowedCursor(self.docs)

        return Coll(self.domains)

@pytest.mark.asyncio
async def test_allowed_origin_or_referer_bypass_check():
    db = FakeAllowedDB(["telegram.me", "allowed-shortener.com"])

    class DummyRequest:
        def __init__(self, headers, url="https://antibypass.app/?target=123"):
            self.headers = headers
            self.url = url
            self.query_params = {}

    req_with_allowed_referer = DummyRequest({"referer": "https://telegram.me/some_channel", "user-agent": "Mozilla/5.0"})
    is_bypass, _ = await detect_userscript_bypass(req_with_allowed_referer, db)
    assert is_bypass is False

    req_with_allowed_origin = DummyRequest({"origin": "https://allowed-shortener.com", "user-agent": "Mozilla/5.0"})
    is_bypass_origin, _ = await detect_userscript_bypass(req_with_allowed_origin, db)
    assert is_bypass_origin is False
