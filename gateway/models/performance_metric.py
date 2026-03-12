"""Latency/throughput snapshot saved periodically — used in dashboard charts."""
from datetime import datetime
from beanie import Document
from pydantic import Field


class PerformanceMetric(Document):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    total_requests: int = 0
    blocked_requests: int = 0
    forwarded_requests: int = 0
    idor_count: int = 0
    privilege_escalation_count: int = 0
    forceful_browsing_count: int = 0
    inadequate_auth_count: int = 0
    parameter_tampering_count: int = 0

    class Settings:
        name = "performance_metrics"
