"""Tracks user sessions passing through the gateway."""
from datetime import datetime
from typing import Optional
from beanie import Document
from pydantic import Field


class UserSession(Document):
    session_id: str
    user_id: str
    user_role: str = "user"
    ip_address: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    is_active: bool = True
    last_seen: Optional[datetime] = None

    class Settings:
        name = "user_sessions"
