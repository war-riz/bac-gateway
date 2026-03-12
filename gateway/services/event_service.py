"""
gateway/services/event_service.py  [UPDATED]
──────────────────────────────────────────────
Now includes: single event lookup, stats by attack type, time-series data.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
from beanie import SortDirection
from gateway.models.security_event import SecurityEvent, AttackType, Severity
from gateway.services.metrics_service import _blocked_hourly, _forwarded_hourly

async def get_recent_events(
    page: int = 1,
    page_size: int = 20,
    attack_type: Optional[str] = None,
    source_ip: Optional[str] = None,
):
    query = SecurityEvent.find()
    if attack_type:
        query = SecurityEvent.find(SecurityEvent.attack_type == AttackType(attack_type))
    if source_ip:
        query = SecurityEvent.find(SecurityEvent.source_ip == source_ip)

    total = await query.count()
    items = await (query.sort([("timestamp", SortDirection.DESCENDING)])
                        .skip((page - 1) * page_size)
                        .limit(page_size)
                        .to_list())
    return items, total


async def get_event_by_id(event_id: str) -> Optional[SecurityEvent]:
    """Fetch a single event by its MongoDB ObjectId string."""
    return await SecurityEvent.get(event_id)


async def get_attack_stats(hours: int = 24) -> dict:
    """
    Returns per-attack-type counts for the past N hours.
    Used to render the bar/pie chart on the dashboard.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    events = await SecurityEvent.find(SecurityEvent.timestamp >= cutoff).to_list()

    counts: dict[str, int] = {t.value: 0 for t in AttackType}
    severity_counts: dict[str, int] = {s.value: 0 for s in Severity}
    hourly: dict[str, dict] = {}
    total_confidence = 0.0
    all_hours = sorted(set(list(hourly.keys()) + list(_blocked_hourly.keys()) + list(_forwarded_hourly.keys())))

    for e in events:
        counts[e.attack_type] += 1
        severity_counts[e.severity] += 1                             
        total_confidence += e.confidence_score

        # Build hourly breakdown for time-series chart
        hour_label = e.timestamp.strftime("%H:00")
        if hour_label not in hourly:
            hourly[hour_label] = {t.value: 0 for t in AttackType}
        hourly[hour_label][e.attack_type] += 1

    return {
        "period_hours": hours,
        "total_attacks": len(events),
        "counts_by_type": [{"attack_type": k, "count": v} for k, v in counts.items()],
        "severity_counts": [{"_id": k, "count": v} for k, v in severity_counts.items()],
        "hourly_breakdown": [
            {
                "hour":    h,
                "blocked": _blocked_hourly.get(h, sum(hourly.get(h, {}).values())),
                "total":   _blocked_hourly.get(h, 0) + _forwarded_hourly.get(h, 0)
                           or sum(hourly.get(h, {}).values()),
                **hourly.get(h, {t.value: 0 for t in AttackType}),
            }
            for h in all_hours
        ],
        "avg_confidence": round(total_confidence / len(events), 4) if events else 0.0,
        "top_source_ips": _top_ips(events, n=10),
        "top_targeted_urls": _top_urls(events, n=10),
    }


async def get_dashboard_stats() -> dict:
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    total_all = await SecurityEvent.count()
    today = await SecurityEvent.find(SecurityEvent.timestamp >= today_start).to_list()

    blocked = sum(1 for e in today if e.action_taken == "BLOCKED")
    latencies = [e.processing_time_ms for e in today if e.processing_time_ms > 0]
    breakdown: dict = {}
    for e in today:
        breakdown[str(e.attack_type)] = breakdown.get(str(e.attack_type), 0) + 1

    # Week-over-week comparison
    week_ago = now - timedelta(days=7)
    last_week_count = await SecurityEvent.find(
        SecurityEvent.timestamp >= week_ago,
        SecurityEvent.timestamp < today_start,
    ).count()

    return {
        "total_events_today": len(today),
        "total_events_all_time": total_all,
        "blocked_today": blocked,
        "forwarded_today": len(today) - blocked,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0.0,
        "attack_breakdown": [{"attack_type": k, "count": v} for k, v in breakdown.items()],
        "last_7_days_total": last_week_count,
        "trend": "up" if len(today) > (last_week_count / 7) else "down",
    }


def _top_ips(events: list, n: int = 10) -> list[dict]:
    counts: dict[str, int] = {}
    for e in events:
        counts[e.source_ip] = counts.get(e.source_ip, 0) + 1
    return [{"ip": ip, "count": c}
            for ip, c in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]]


def _top_urls(events: list, n: int = 10) -> list[dict]:
    counts: dict[str, int] = {}
    for e in events:
        counts[e.target_url] = counts.get(e.target_url, 0) + 1
    return [{"url": url, "count": c}
            for url, c in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]]
