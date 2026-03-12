"""
GET  /api/v1/events              — Paginated event list (filterable)
GET  /api/v1/events/stats        — Attack counts + hourly breakdown for charts
GET  /api/v1/events/{id}         — Single event detail
"""
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from gateway.core.dependencies import get_current_admin
from gateway.models.security_event import AttackType
from gateway.models.user import User
from gateway.schemas.event import (
    PaginatedEvents, SecurityEventOut, EventStatsOut,
    AttackTypeCount, SeverityCount, TopIP, TopURL, HourlyCount,
)
from gateway.services.event_service import (
    get_recent_events, get_event_by_id, get_attack_stats,
)

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.get("/stats", response_model=EventStatsOut)
async def event_stats(
    admin: Annotated[User, Depends(get_current_admin)],
    hours: int = Query(24, ge=1, le=168, description="Look-back window in hours (max 7 days)"),
):
    """Attack counts, hourly breakdown, top IPs and URLs — for dashboard charts."""
    data = await get_attack_stats(hours)
    return EventStatsOut(
        by_attack_type=[
            AttackTypeCount(_id=x["attack_type"], count=x["count"])
            for x in data["counts_by_type"]
        ],
        by_severity=[
            SeverityCount(**x) for x in data["severity_counts"]
        ],
        top_source_ips=[
            TopIP(_id=x["ip"], count=x["count"])
            for x in data["top_source_ips"]
        ],
        top_target_urls=[
            TopURL(_id=x["url"], count=x["count"])
            for x in data["top_targeted_urls"]
        ],
        hourly_counts=[
            HourlyCount(
                hour=x["hour"],
                blocked=sum(x.get(t.value, 0) for t in AttackType),
                total=sum(x.get(t.value, 0) for t in AttackType),
            )
            for x in data["hourly_breakdown"]
        ],
    )


@router.get("", response_model=PaginatedEvents)
async def list_events(
    admin: Annotated[User, Depends(get_current_admin)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    attack_type: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
):
    """Paginated event log. Filter by attack_type or source_ip."""
    items, total = await get_recent_events(page, page_size, attack_type, source_ip)
    return PaginatedEvents(
        items=[_to_out(e) for e in items],
        total=total, page=page, page_size=page_size,
    )


@router.get("/{event_id}", response_model=SecurityEventOut)
async def get_event(
    event_id: str,
    admin: Annotated[User, Depends(get_current_admin)],
):
    """Full detail for a single security event — used in event detail drawer."""
    event = await get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return _to_out(event)


def _to_out(e) -> SecurityEventOut:
    return SecurityEventOut(
        id=str(e.id),
        attack_type=e.attack_type,
        severity=e.severity, 
        action_taken=e.action_taken,
        detection_module=e.detection_module,
        confidence_score=e.confidence_score,
        source_ip=e.source_ip,
        target_url=e.target_url,
        http_method=e.http_method,
        user_agent=e.user_agent,
        rule_triggered=e.rule_triggered,
        details=e.request_payload_summary,
        processing_time_ms=e.processing_time_ms,
        timestamp=e.timestamp,
    )