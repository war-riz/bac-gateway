"""
gateway/services/metrics_service.py
──────────────────────────────────────
Saves rolling performance snapshots to MongoDB every 30 seconds.
Provides historical data for the latency/throughput line charts.

A background task started in main.py calls record_snapshot() on a timer.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from gateway.models.performance_metric import PerformanceMetric
from gateway.models.security_event import SecurityEvent, AttackType

logger = logging.getLogger(__name__)

# In-memory buffer: collects latency readings between snapshots
_latency_buffer: list[float] = []
_request_count: int = 0
_blocked_count: int = 0
_forwarded_hourly: dict[str, int] = {}   # hour_label → forwarded count
_blocked_hourly:   dict[str, int] = {}   # hour_label → blocked count     


def record_request(latency_ms: float, was_blocked: bool) -> None:
    """
    Called by gateway_middleware on EVERY request (not just attacks).
    Cheap in-memory operation — no DB write here.
    """
    global _request_count, _blocked_count
    _latency_buffer.append(latency_ms)
    _request_count += 1
    if was_blocked:
        _blocked_count += 1

    # Track hourly blocked/forwarded for the chart
    from datetime import datetime
    hour_label = datetime.utcnow().strftime("%H:00")
    if was_blocked:
        _blocked_hourly[hour_label]   = _blocked_hourly.get(hour_label, 0) + 1
    else:
        _forwarded_hourly[hour_label] = _forwarded_hourly.get(hour_label, 0) + 1


async def record_snapshot() -> None:
    """
    Flushes the in-memory buffer to MongoDB as a PerformanceMetric document.
    Called every 30 seconds by the background task.
    """
    global _latency_buffer, _request_count, _blocked_count

    if not _latency_buffer:
        return  # Nothing to record in this window

    latencies = sorted(_latency_buffer)
    avg_ms = sum(latencies) / len(latencies)
    p95_idx = int(len(latencies) * 0.95)
    p95_ms = latencies[min(p95_idx, len(latencies) - 1)]

    # Per-attack-type counts in this window (from DB for accuracy)
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=30)
    recent = await SecurityEvent.find(
        SecurityEvent.timestamp >= window_start
    ).to_list()

    counts = {t.value: 0 for t in AttackType}
    for e in recent:
        counts[e.attack_type] += 1

    metric = PerformanceMetric(
        avg_latency_ms=round(avg_ms, 2),
        p95_latency_ms=round(p95_ms, 2),
        total_requests=_request_count,
        blocked_requests=_blocked_count,
        forwarded_requests=_request_count - _blocked_count,
        idor_count=counts.get("IDOR", 0),
        privilege_escalation_count=counts.get("PRIVILEGE_ESCALATION", 0),
        forceful_browsing_count=counts.get("FORCEFUL_BROWSING", 0),
        inadequate_auth_count=counts.get("INADEQUATE_AUTHORIZATION", 0),
        parameter_tampering_count=counts.get("PARAMETER_TAMPERING", 0),
    )
    await metric.insert()

    # Broadcast to dashboard
    from gateway.services.websocket_service import broadcast_metric_update
    await broadcast_metric_update({
        "avg_latency_ms": metric.avg_latency_ms,
        "p95_latency_ms": metric.p95_latency_ms,
        "total_requests": metric.total_requests,
        "blocked_requests": metric.blocked_requests,
        "timestamp": metric.timestamp.isoformat(),
    })

    # Reset buffer
    _latency_buffer = []
    _request_count = 0
    _blocked_count = 0
    logger.debug(f"Metrics snapshot saved: avg={avg_ms:.1f}ms, requests={metric.total_requests}")


async def get_metrics_history(hours: int = 1) -> list[PerformanceMetric]:
    """Returns metric snapshots for the past N hours — used for line charts."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    return await (PerformanceMetric.find(PerformanceMetric.timestamp >= cutoff)
                  .sort([("timestamp", 1)])
                  .to_list())


async def metrics_background_task() -> None:
    """
    Infinite loop — runs as an asyncio background task.
    Every 30 seconds: save snapshot + push to WebSocket clients.
    """
    logger.info("Metrics background task started (30s interval)")
    while True:
        await asyncio.sleep(30)
        try:
            await record_snapshot()
        except Exception as e:
            logger.error(f"Metrics snapshot failed: {e}")
