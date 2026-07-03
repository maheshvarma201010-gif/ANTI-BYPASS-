from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class ShortenerConfig(BaseModel):
    base_url: str
    api_key: str

class UserBase(BaseModel):
    telegram_id: str
    username: Optional[str] = None

class UserCreate(UserBase):
    pass

class UserUpdate(BaseModel):
    api_key: Optional[str] = None
    is_active: Optional[bool] = None

class User(UserBase):
    api_key: str
    config: Optional[ShortenerConfig] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True

class ProtectedLinkBase(BaseModel):
    original_url: str

class ProtectedLinkCreate(ProtectedLinkBase):
    user_id: str
    short_id: str

class ProtectedLink(ProtectedLinkBase):
    user_id: str
    short_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class RequestLog(BaseModel):
    short_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    ip: str
    user_agent: Optional[str] = None
    referer: Optional[str] = None
    status: str  # 'success', 'blocked'
    reason: Optional[str] = None
