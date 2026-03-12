from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class SecurityEventOut(BaseModel):
    id: str
    attack_type: str
    severity: str                    
    action_taken: str
    detection_module: str
    confidence_score: float
    source_ip: str
    target_url: str
    http_method: str
    user_agent: Optional[str]
    rule_triggered: str
    details: Optional[str]
    processing_time_ms: float
    timestamp: datetime


class PaginatedEvents(BaseModel):
    items: list[SecurityEventOut]
    total: int
    page: int
    page_size: int


class AttackTypeCount(BaseModel):
    _id: str
    count: int


class SeverityCount(BaseModel):
    _id: str
    count: int


class TopIP(BaseModel):
    _id: str
    count: int


class TopURL(BaseModel):
    _id: str
    count: int


class HourlyCount(BaseModel):
    hour: str
    blocked: int = 0
    total: int = 0


class EventStatsOut(BaseModel):
    by_attack_type: list[AttackTypeCount]
    by_severity: list[SeverityCount]
    top_source_ips: list[TopIP]
    top_target_urls: list[TopURL]
    hourly_counts: list[HourlyCount]