from pydantic import BaseModel


class AttackTypeSummary(BaseModel):
    attack_type: str
    count: int


class DashboardSummary(BaseModel):
    total_events_today: int
    total_events_all_time: int
    blocked_today: int
    forwarded_today: int
    avg_latency_ms: float
    detection_accuracy: float
    false_positive_rate: float
    attack_breakdown: list[AttackTypeSummary]
    modules_status: dict[str, bool]
    last_7_days_total: int
    trend: str                           # "up" | "down"
