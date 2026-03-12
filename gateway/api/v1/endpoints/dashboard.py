"""
GET /api/v1/dashboard/summary  — Main stats card data
"""
from typing import Annotated
from fastapi import APIRouter, Depends
from gateway.core.dependencies import get_current_admin
from gateway.models.user import User
from gateway.schemas.dashboard import DashboardSummary, AttackTypeSummary
from gateway.services.event_service import get_dashboard_stats
from gateway.services.config_service import get_all_configs

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
async def summary(admin: Annotated[User, Depends(get_current_admin)]):
    stats = await get_dashboard_stats()
    configs = await get_all_configs()

    total = max(stats["total_events_today"], 1)
    tp = stats["blocked_today"]
    fp_estimate = max(0, stats["forwarded_today"] - tp)

    return DashboardSummary(
        total_events_today=stats["total_events_today"],
        total_events_all_time=stats["total_events_all_time"],
        blocked_today=tp,
        forwarded_today=stats["forwarded_today"],
        avg_latency_ms=stats["avg_latency_ms"],
        detection_accuracy=round(tp / total, 4),
        false_positive_rate=round(fp_estimate / total, 4),
        attack_breakdown=[AttackTypeSummary(**x) for x in stats["attack_breakdown"]],
        modules_status={c.module_name: c.is_enabled for c in configs},
        last_7_days_total=stats["last_7_days_total"],
        trend=stats["trend"],
    )
