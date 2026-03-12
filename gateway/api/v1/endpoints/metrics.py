"""
GET /api/v1/metrics          — Historical latency/throughput snapshots
GET /api/v1/metrics/current  — Latest single snapshot (polling fallback)
"""
from typing import Annotated
from fastapi import APIRouter, Depends, Query
from gateway.core.dependencies import get_current_admin
from gateway.models.user import User
from gateway.schemas.metrics import MetricSnapshotOut, MetricsHistoryOut
from gateway.services.metrics_service import get_metrics_history

router = APIRouter(prefix="/metrics", tags=["Performance Metrics"])


@router.get("", response_model=MetricsHistoryOut)
async def metrics_history(
    admin: Annotated[User, Depends(get_current_admin)],
    hours: int = Query(1, ge=1, le=24, description="How many hours of history to return"),
):
    """
    Returns latency + throughput snapshots for the past N hours.
    Each snapshot is a 30-second window.
    Use this to render the latency line chart on the dashboard.
    """
    snapshots = await get_metrics_history(hours)

    if not snapshots:
        return MetricsHistoryOut(
            snapshots=[], period_hours=hours,
            overall_avg_latency_ms=0.0, peak_latency_ms=0.0,
            total_requests_in_period=0,
        )

    all_latencies = [s.avg_latency_ms for s in snapshots]
    return MetricsHistoryOut(
        snapshots=[
            MetricSnapshotOut(
                timestamp=s.timestamp,
                avg_latency_ms=s.avg_latency_ms,
                p95_latency_ms=s.p95_latency_ms,
                total_requests=s.total_requests,
                blocked_requests=s.blocked_requests,
                forwarded_requests=s.forwarded_requests,
                idor_count=s.idor_count,
                privilege_escalation_count=s.privilege_escalation_count,
                forceful_browsing_count=s.forceful_browsing_count,
                inadequate_auth_count=s.inadequate_auth_count,
                parameter_tampering_count=s.parameter_tampering_count,
            )
            for s in snapshots
        ],
        period_hours=hours,
        overall_avg_latency_ms=round(sum(all_latencies) / len(all_latencies), 2),
        peak_latency_ms=round(max(all_latencies), 2),
        total_requests_in_period=sum(s.total_requests for s in snapshots),
    )


@router.get("/current", response_model=MetricSnapshotOut | None)
async def current_metrics(admin: Annotated[User, Depends(get_current_admin)]):
    """Latest single snapshot — useful as a polling fallback if WebSocket is unavailable."""
    snapshots = await get_metrics_history(hours=1)
    if not snapshots:
        return None
    latest = sorted(snapshots, key=lambda s: s.timestamp, reverse=True)[0]
    return MetricSnapshotOut(
        timestamp=latest.timestamp,
        avg_latency_ms=latest.avg_latency_ms,
        p95_latency_ms=latest.p95_latency_ms,
        total_requests=latest.total_requests,
        blocked_requests=latest.blocked_requests,
        forwarded_requests=latest.forwarded_requests,
        idor_count=latest.idor_count,
        privilege_escalation_count=latest.privilege_escalation_count,
        forceful_browsing_count=latest.forceful_browsing_count,
        inadequate_auth_count=latest.inadequate_auth_count,
        parameter_tampering_count=latest.parameter_tampering_count,
    )
