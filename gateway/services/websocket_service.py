"""
gateway/services/websocket_service.py
───────────────────────────────────────
Manages all active WebSocket connections.
Any part of the app can call broadcast_event() or broadcast_notification()
to push real-time data to the dashboard without polling.

Connection registry is in-memory — fine for a single-process deployment.
"""
import json
import logging
from datetime import datetime
from typing import Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Holds all active WebSocket connections and broadcasts to them."""

    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        logger.info(f"WS client connected. Total: {len(self._connections)}")

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._connections:
            self._connections.remove(ws)
        logger.info(f"WS client disconnected. Total: {len(self._connections)}")

    async def broadcast(self, data: dict) -> None:
        """Send JSON to all connected clients. Silently drop dead connections."""
        dead = []
        for ws in self._connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    @property
    def connection_count(self) -> int:
        return len(self._connections)


# ── Singleton — imported everywhere ──────────────────────────────
manager = ConnectionManager()


async def broadcast_event(event_doc) -> None:
    """
    Called by gateway_middleware after every blocked attack.
    Pushes the event to the dashboard live feed instantly.
    """
    await manager.broadcast({
        "type": "SECURITY_EVENT",
        "payload": {
            "id": str(event_doc.id),
            "attack_type": event_doc.attack_type,
            "action_taken": event_doc.action_taken,
            "source_ip": event_doc.source_ip,
            "target_url": event_doc.target_url,
            "http_method": event_doc.http_method,
            "rule_triggered": event_doc.rule_triggered,
            "confidence_score": event_doc.confidence_score,
            "processing_time_ms": event_doc.processing_time_ms,
            "timestamp": event_doc.timestamp.isoformat(),
        },
    })


async def broadcast_notification(notif_doc) -> None:
    """Push a new notification badge + toast to the dashboard."""
    await manager.broadcast({
        "type": "NOTIFICATION",
        "payload": {
            "id": str(notif_doc.id),
            "notification_type": notif_doc.type,
            "severity": notif_doc.severity,
            "title": notif_doc.title,
            "message": notif_doc.message,
            "created_at": notif_doc.created_at.isoformat(),
        },
    })


async def broadcast_metric_update(metrics: dict) -> None:
    """Push a latency/throughput snapshot every 30 seconds."""
    await manager.broadcast({
        "type": "METRIC_UPDATE",
        "payload": metrics,
    })


async def broadcast_module_toggle(module_name: str, is_enabled: bool, by: str) -> None:
    """Inform all dashboard tabs when a module is toggled."""
    await manager.broadcast({
        "type": "MODULE_TOGGLE",
        "payload": {
            "module_name": module_name,
            "is_enabled": is_enabled,
            "changed_by": by,
            "timestamp": datetime.utcnow().isoformat(),
        },
    })
