from datetime import datetime
from pydantic import BaseModel


class MetricSnapshotOut(BaseModel):
    timestamp: datetime
    avg_latency_ms: float
    p95_latency_ms: float
    total_requests: int
    blocked_requests: int
    forwarded_requests: int
    idor_count: int
    privilege_escalation_count: int
    forceful_browsing_count: int
    inadequate_auth_count: int
    parameter_tampering_count: int


class MetricsHistoryOut(BaseModel):
    snapshots: list[MetricSnapshotOut]
    period_hours: int
    overall_avg_latency_ms: float
    peak_latency_ms: float
    total_requests_in_period: int
