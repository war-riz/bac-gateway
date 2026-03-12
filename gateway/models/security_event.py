"""
Every detected attack is saved as a SecurityEvent.
This is the core audit log — powers the dashboard event table.
"""
from datetime import datetime
from typing import Optional
from beanie import Document
from pydantic import Field
from enum import Enum


class AttackType(str, Enum):
    IDOR = "IDOR"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    FORCEFUL_BROWSING = "FORCEFUL_BROWSING"
    INADEQUATE_AUTHORIZATION = "INADEQUATE_AUTHORIZATION"
    PARAMETER_TAMPERING = "PARAMETER_TAMPERING"


class ActionTaken(str, Enum):
    BLOCKED = "BLOCKED"
    FORWARDED = "FORWARDED"


class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


def derive_severity(confidence: float) -> Severity:
    if confidence >= 0.9: return Severity.CRITICAL
    if confidence >= 0.7: return Severity.HIGH
    if confidence >= 0.4: return Severity.MEDIUM
    return Severity.LOW


class SecurityEvent(Document):
    attack_type: AttackType
    action_taken: ActionTaken = ActionTaken.BLOCKED
    detection_module: str
    confidence_score: float = 1.0
    severity: Severity = Severity.HIGH
    source_ip: str
    target_url: str
    http_method: str
    user_agent: Optional[str] = None
    session_token_hash: Optional[str] = None
    rule_triggered: str
    request_payload_summary: Optional[str] = None
    processing_time_ms: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "security_events"