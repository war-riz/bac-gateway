from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class NotificationOut(BaseModel):
    id: str
    type: str
    severity: str
    title: str
    message: str
    is_read: bool
    related_event_id: Optional[str]
    related_ip: Optional[str]
    created_at: datetime


class NotificationListOut(BaseModel):
    items: list[NotificationOut]
    unread_count: int


class MarkReadRequest(BaseModel):
    notification_id: Optional[str] = None   # None = mark all read
