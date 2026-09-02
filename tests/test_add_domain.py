import pytest
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.storage.base import StorageKey

from app.bot.handlers import (
    cmd_add_domain,
    cb_add_allowed_domain,
    process_allowed_domain,
    cb_view_allowed_domains,
    cb_delete_allowed_domain,
    ConnectStates
)
from app.core.referer import is_allowed_referer

class FakeAllowedReferers:
    def __init__(self, data=None):
        self.docs = data if data is not None else []

    async def update_one(self, filter_q, update_q, upsert=False):
        domain = filter_q.get("domain")
        for doc in self.docs:
            if doc.get("domain") == domain:
                if "$set" in update_q:
                    doc.update(update_q["$set"])
                return
        if "$set" in update_q:
            self.docs.append(update_q["$set"])

    def find(self, query):
        class AsyncCursor:
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

        return AsyncCursor(self.docs)

    async def delete_one(self, filter_q):
        domain = filter_q.get("domain")
        self.docs = [d for d in self.docs if d.get("domain") != domain]

class FakeBotDB:
    def __init__(self, data=None):
        self.allowed_referers = FakeAllowedReferers(data)

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

class FakeCallbackQuery:
    def __init__(self, data, user_id=12345):
        self.data = data
        self.from_user = FakeUser(user_id)
        self.message = FakeMessage("")
        self.answered = False

    async def answer(self, *args, **kwargs):
        self.answered = True

@pytest.mark.asyncio
async def test_add_domain_flow(monkeypatch):
    data_store = []
    fake_db = FakeBotDB(data_store)

    monkeypatch.setattr("app.bot.handlers.get_database", lambda: fake_db)
    monkeypatch.setattr("app.bot.handlers.is_admin", lambda uid: True)
    monkeypatch.setattr("app.bot.handlers.send_bot_msg", lambda target, text, reply_markup=None, parse_mode="HTML": target.answer(text))

    storage = MemoryStorage()
    key = StorageKey(bot_id=1, chat_id=12345, user_id=12345)
    state = FSMContext(storage=storage, key=key)

    msg1 = FakeMessage("/add")
    await cmd_add_domain(msg1)
    assert len(msg1.answers) == 1

    cb1 = FakeCallbackQuery("add_allowed_domain")
    await cb_add_allowed_domain(cb1, state)
    assert await state.get_state() == ConnectStates.waiting_for_allowed_domain.state

    msg2 = FakeMessage("example.com")
    await process_allowed_domain(msg2, state)
    assert await state.get_state() is None

    assert any(doc.get("domain") == "example.com" for doc in fake_db.allowed_referers.docs)

    is_allowed = await is_allowed_referer("https://sub.example.com/page", fake_db)
    assert is_allowed is True

    cb_del = FakeCallbackQuery("del_domain:example.com")
    await cb_delete_allowed_domain(cb_del)
    assert not any(doc.get("domain") == "example.com" for doc in fake_db.allowed_referers.docs)
