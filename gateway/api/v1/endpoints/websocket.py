"""
WebSocket /ws/events
─────────────────────
Real-time feed to the dashboard. Any client connecting here will receive:

  { "type": "SECURITY_EVENT",   "payload": {...} }   — every blocked attack
  { "type": "NOTIFICATION",     "payload": {...} }   — new admin alerts
  { "type": "METRIC_UPDATE",    "payload": {...} }   — every 30s perf snapshot
  { "type": "MODULE_TOGGLE",    "payload": {...} }   — when admin toggles a module
  { "type": "PING",             "payload": {} }      — keepalive every 30s

Authentication: pass the JWT as a query parameter ?token=<jwt>
  e.g. ws://localhost:8000/ws/events?token=eyJ...
"""
import asyncio
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from gateway.utils.security import decode_access_token
from gateway.services.websocket_service import manager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/events")
async def websocket_events(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token"),
):
    # ── Auth check before accepting ──────────────────────────────
    payload = decode_access_token(token)
    if not payload or payload.get("role") != "admin":
        await websocket.close(code=4001, reason="Unauthorized")
        return

    await manager.connect(websocket)

    # Send welcome message with current stats
    from gateway.services.event_service import get_dashboard_stats
    try:
        stats = await get_dashboard_stats()
        await websocket.send_json({
            "type": "CONNECTED",
            "payload": {
                "message": "Connected to BAC Gateway real-time feed",
                "active_connections": manager.connection_count,
                "current_stats": stats,
            },
        })
    except Exception:
        pass

    # ── Keep connection alive + handle client messages ────────────
    try:
        while True:
            # Wait for a ping or any message from client
            # If client disconnects, this raises WebSocketDisconnect
            data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)

            if data == "ping":
                await websocket.send_json({"type": "PONG", "payload": {}})

    except asyncio.TimeoutError:
        # Send server-side keepalive ping
        try:
            await websocket.send_json({"type": "PING", "payload": {}})
        except Exception:
            manager.disconnect(websocket)
            return

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("WebSocket client disconnected cleanly")

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
