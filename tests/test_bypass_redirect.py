import pytest
import base64
import hashlib
from app.main import get_bypass_url, DEFAULT_BYPASS_BASE_URL, DEFAULT_TARGET_URL
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.storage.base import StorageKey
from app.bot.handlers import cmd_redirecttobp, process_bypass_url, ConnectStates

class FakeDBSetting:
    def __init__(self, data=None):
        self.data = data if data is not None else {}

    async def find_one(self, query):
        if query.get("key") == "bypass_redirect_url":
            return self.data.get("bypass_redirect_url")
        return None

    async def update_one(self, filter_q, update_q, upsert=False):
        key = filter_q.get("key")
        if key == "bypass_redirect_url":
            if "$set" in update_q:
                self.data["bypass_redirect_url"] = update_q["$set"]

class FakeDB:
    def __init__(self, data=None):
        self.settings = FakeDBSetting(data)

@pytest.mark.asyncio
async def test_get_bypass_url_default():
    target = "https://example.com/testlink"
    url = await get_bypass_url(target_url=target, db=None)

    expected_b64 = base64.b64encode(target.encode("utf-8")).decode("utf-8")
    expected_hash = hashlib.md5(target.encode("utf-8")).hexdigest()[:16]
    expected = f"{DEFAULT_BYPASS_BASE_URL}?target={expected_b64}&hash={expected_hash}"
    assert url == expected

@pytest.mark.asyncio
async def test_get_bypass_url_custom_db():
    custom_worker = "https://custom-worker.example.workers.dev/verify"
    db = FakeDB({"bypass_redirect_url": {"url": custom_worker}})
    target = "https://example.com/my-protected-file"

    url = await get_bypass_url(target_url=target, db=db)
    expected_b64 = base64.b64encode(target.encode("utf-8")).decode("utf-8")
    expected_hash = hashlib.md5(target.encode("utf-8")).hexdigest()[:16]
    expected = f"{custom_worker}?target={expected_b64}&hash={expected_hash}"
    assert url == expected

class FakeUser:
    def __init__(self, user_id=12345):
        self.id = user_id
        self.username = "admin_user"

class FakeMessage:
    def __init__(self, text, user_id=12345):
        self.text = text
        self.from_user = FakeUser(user_id)
        self.answers = []

    async def answer(self, text, parse_mode=None, reply_markup=None):
        self.answers.append(text)
        return self

@pytest.mark.asyncio
async def test_bot_redirecttobp_flow(monkeypatch):
    data_store = {}
    fake_db = FakeDB(data_store)

    # Patch get_database and is_admin
    monkeypatch.setattr("app.bot.handlers.get_database", lambda: fake_db)
    monkeypatch.setattr("app.bot.handlers.is_admin", lambda uid: True)
    monkeypatch.setattr("app.bot.handlers.send_bot_msg", lambda target, text, reply_markup=None, parse_mode="HTML": target.answer(text))

    storage = MemoryStorage()
    key = StorageKey(bot_id=1, chat_id=12345, user_id=12345)
    state = FSMContext(storage=storage, key=key)

    msg1 = FakeMessage("/redirecttobp")
    await cmd_redirecttobp(msg1, state)

    current_state = await state.get_state()
    assert current_state == ConnectStates.waiting_for_bypass_url.state

    new_url = "https://new-worker.mydomain.workers.dev/verify"
    msg2 = FakeMessage(new_url)
    await process_bypass_url(msg2, state)

    current_state_after = await state.get_state()
    assert current_state_after is None

    saved_doc = fake_db.settings.data.get("bypass_redirect_url")
    assert saved_doc is not None
    assert saved_doc.get("url") == new_url
