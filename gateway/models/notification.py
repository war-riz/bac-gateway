"""
gateway/models/notification.py
────────────────────────────────
Admin notifications — stored in MongoDB.
Created automatically when:
  - A new attack type is detected for the first time today
  - Detection accuracy drops below threshold
  - A module is disabled
  - 10+ attacks from the same IP in 5 minutes
  - Gateway latency exceeds 50ms threshold
"""
from datetime import datetime
from typing import Optional
from beanie import Document
from pydantic import Field
from enum import Enum


class NotificationType(str, Enum):
    ATTACK_DETECTED    = "ATTACK_DETECTED"
    HIGH_FREQUENCY_IP  = "HIGH_FREQUENCY_IP"
    MODULE_DISABLED    = "MODULE_DISABLED"
    LATENCY_EXCEEDED   = "LATENCY_EXCEEDED"
    ACCURACY_DROP      = "ACCURACY_DROP"
    NEW_ATTACK_PATTERN = "NEW_ATTACK_PATTERN"


class NotificationSeverity(str, Enum):
    INFO     = "INFO"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"


class Notification(Document):
    type: NotificationType
    severity: NotificationSeverity
    title: str
    message: str
    is_read: bool = False
    related_event_id: Optional[str] = None    # links to SecurityEvent
    related_ip: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "notifications"
