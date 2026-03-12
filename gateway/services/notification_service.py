"""
gateway/services/notification_service.py
──────────────────────────────────────────
Creates and manages admin notifications.
Called by the gateway middleware after every blocked event.
Also runs threshold checks (high-freq IP, latency spike, accuracy drop).
"""
import logging
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import Optional

from gateway.models.notification import Notification, NotificationType, NotificationSeverity
from gateway.models.security_event import SecurityEvent
from gateway.config.settings import get_settings

logger = logging.getLogger(__name__)

# In-memory cache: IP → list of recent attack timestamps
# Resets on process restart — fine for a research prototype
_ip_attack_log: dict[str, list[datetime]] = defaultdict(list)


async def create_attack_notification(
    event_id: str,
    attack_type: str,
    source_ip: str,
    rule_triggered: str,
    latency_ms: float,
) -> Notification:
    """
    Called after every blocked attack. Creates notification and
    runs all threshold checks in one place.
    """
    settings = get_settings()
    severity = _severity_for_attack(attack_type)

    notif = Notification(
        type=NotificationType.ATTACK_DETECTED,
        severity=severity,
        title=f"{attack_type.replace('_', ' ').title()} Attack Blocked",
        message=f"Rule '{rule_triggered}' triggered from IP {source_ip}",
        related_event_id=event_id,
        related_ip=source_ip,
    )
    await notif.insert()

    # Broadcast to WebSocket clients
    from gateway.services.websocket_service import broadcast_notification
    await broadcast_notification(notif)

    # ── Threshold checks ─────────────────────────────────────────
    await _check_high_frequency_ip(source_ip)

    if latency_ms > settings.max_latency_ms:
        await _create_latency_notification(latency_ms, settings.max_latency_ms)

    return notif


async def _check_high_frequency_ip(ip: str) -> None:
    """Alert if same IP causes 10+ attacks within 5 minutes."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=5)

    # Clean old entries
    _ip_attack_log[ip] = [t for t in _ip_attack_log[ip] if t > cutoff]
    _ip_attack_log[ip].append(now)

    if len(_ip_attack_log[ip]) >= 10:
        # Only create one notification per burst (not one per attack)
        if len(_ip_attack_log[ip]) == 10:
            notif = Notification(
                type=NotificationType.HIGH_FREQUENCY_IP,
                severity=NotificationSeverity.CRITICAL,
                title="High-Frequency Attack Detected",
                message=f"IP {ip} triggered 10+ attacks in the last 5 minutes. Possible automated scan.",
                related_ip=ip,
            )
            await notif.insert()
            from gateway.services.websocket_service import broadcast_notification
            await broadcast_notification(notif)
            logger.warning(f"HIGH FREQUENCY ATTACK from {ip}")


async def _create_latency_notification(actual_ms: float, threshold_ms: int) -> None:
    """Alert when processing latency exceeds the 50ms research target."""
    # Deduplicate: don't spam if already have an unread latency alert
    existing = await Notification.find(
        Notification.type == NotificationType.LATENCY_EXCEEDED,
        Notification.is_read == False,
    ).count()
    if existing == 0:
        notif = Notification(
            type=NotificationType.LATENCY_EXCEEDED,
            severity=NotificationSeverity.WARNING,
            title="Latency Threshold Exceeded",
            message=(
                f"Detection processing took {actual_ms:.1f}ms "
                f"(target: <{threshold_ms}ms). Performance may be degraded."
            ),
        )
        await notif.insert()
        from gateway.services.websocket_service import broadcast_notification
        await broadcast_notification(notif)


async def create_module_disabled_notification(
    module_name: str, admin_username: str
) -> Notification:
    notif = Notification(
        type=NotificationType.MODULE_DISABLED,
        severity=NotificationSeverity.WARNING,
        title=f"Detection Module Disabled",
        message=f"Module '{module_name}' was disabled by admin '{admin_username}'. "
                f"Attacks of this type will no longer be blocked.",
    )
    await notif.insert()
    from gateway.services.websocket_service import broadcast_notification
    await broadcast_notification(notif)
    return notif


def _severity_for_attack(attack_type: str) -> NotificationSeverity:
    critical_types = {"PRIVILEGE_ESCALATION", "PARAMETER_TAMPERING"}
    return (NotificationSeverity.CRITICAL if attack_type in critical_types
            else NotificationSeverity.WARNING)


async def get_notifications(unread_only: bool = False, limit: int = 50) -> list[Notification]:
    query = (Notification.find(Notification.is_read == False) if unread_only
             else Notification.find())
    return await (query.sort([("created_at", -1)]).limit(limit).to_list())


async def mark_all_read() -> int:
    """Mark all unread notifications as read. Returns count updated."""
    unread = await Notification.find(Notification.is_read == False).to_list()
    for n in unread:
        n.is_read = True
        await n.save()
    return len(unread)


async def mark_one_read(notification_id: str) -> Optional[Notification]:
    n = await Notification.get(notification_id)
    if n:
        n.is_read = True
        await n.save()
    return n


async def get_unread_count() -> int:
    return await Notification.find(Notification.is_read == False).count()
