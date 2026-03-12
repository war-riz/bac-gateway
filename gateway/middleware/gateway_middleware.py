"""
gateway/middleware/gateway_middleware.py  [UPDATED]
────────────────────────────────────────────────────
Now integrates:
  - metrics_service.record_request() on every request
  - notification_service.create_attack_notification() on every block
  - websocket_service.broadcast_event() for real-time dashboard feed
"""
import asyncio
import logging
import time
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
import httpx

from gateway.config.settings import get_settings
from gateway.detection.engine import DetectionEngine
from gateway.models.security_event import SecurityEvent, AttackType, ActionTaken, derive_severity
from gateway.utils.security import hash_token

logger = logging.getLogger(__name__)

GATEWAY_OWNED = ["/api/v1", "/docs", "/openapi.json", "/redoc", "/ws"]


class GatewayProxyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, engine: DetectionEngine):
        super().__init__(app)
        self.engine = engine
        self.settings = get_settings()

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Gateway's own routes — pass straight through
        if any(path.startswith(g) for g in GATEWAY_OWNED):
            return await call_next(request)

        # Run all 5 detection modules
        attack, elapsed_ms = await self.engine.analyse(request)

        # Record latency for metrics (every request)
        from gateway.services.metrics_service import record_request
        record_request(elapsed_ms, was_blocked=bool(attack))

        if attack and attack.should_block:
            # Save event + notify + broadcast — all async, non-blocking
            asyncio.create_task(self._handle_blocked(request, attack, elapsed_ms))

            logger.warning(
                f"BLOCKED | {attack.attack_type} | {attack.rule_triggered} "
                f"| {path} | {elapsed_ms:.1f}ms"
            )
            return JSONResponse(
                status_code=403,
                content={
                    "blocked": True,
                    "attack_type": attack.attack_type,
                    "message": "Request blocked by BAC Security Gateway",
                    "rule": attack.rule_triggered,
                    "reference": f"BAC-{int(time.time())}",
                },
            )

        return await self._proxy(request, elapsed_ms)

    async def _handle_blocked(self, request: Request, attack, ms: float) -> None:
        """Save event to DB, create notification, broadcast to WebSocket clients."""
        try:
            raw_token = (
                request.cookies.get("access_token")
                or request.headers.get("Authorization", "").replace("Bearer ", "")
            )
            event = SecurityEvent(
                attack_type=AttackType(attack.attack_type),
                action_taken=ActionTaken.BLOCKED,
                detection_module=attack.attack_type,
                confidence_score=attack.confidence,
                severity=derive_severity(attack.confidence),
                source_ip=request.client.host if request.client else "unknown",
                target_url=str(request.url),
                http_method=request.method,
                user_agent=request.headers.get("user-agent"),
                session_token_hash=hash_token(raw_token) if raw_token else None,
                rule_triggered=attack.rule_triggered,
                request_payload_summary=attack.details[:500],
                processing_time_ms=ms,
            )
            await event.insert()

            # Push to dashboard live feed
            from gateway.services.websocket_service import broadcast_event
            await broadcast_event(event)

            # Create notification (also broadcasts via WebSocket internally)
            from gateway.services.notification_service import create_attack_notification
            await create_attack_notification(
                event_id=str(event.id),
                attack_type=attack.attack_type,
                source_ip=event.source_ip,
                rule_triggered=attack.rule_triggered,
                latency_ms=ms,
            )

        except Exception as e:
            logger.error(f"Failed to handle blocked request: {e}")

    async def _proxy(self, request: Request, detection_ms: float) -> Response:
        url = (
            self.settings.protected_app_url + request.url.path
            + (f"?{request.url.query}" if request.url.query else "")
        )
        headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
        headers["X-Forwarded-For"] = request.client.host if request.client else "unknown"
        headers["X-Gateway-Detection-Ms"] = f"{detection_ms:.2f}"
        body = getattr(request.state, "cached_body", None) or await request.body()

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.request(
                    request.method, url, headers=headers, content=body
                )
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                )
        except httpx.ConnectError:
            return JSONResponse(status_code=502, content={"error": "Demo site unreachable"})
