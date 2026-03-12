"""
MODULE 3 — Forceful Browsing Detection (URL Authentication)
Rule: protected URLs require a valid session. No session = blocked.
Reads protected/public prefixes live from GatewayConfig so admin changes take effect.
"""
import logging
from fastapi import Request
from .base import BaseDetector, DetectionResult

logger = logging.getLogger(__name__)

# Fallback defaults used only if DB config is unavailable
_DEFAULT_PROTECTED = ["/admin", "/dashboard", "/api/v1/admin", "/api/v1/users",
                      "/api/v1/submissions", "/api/v1/documents", "/api/v1/configs",
                      "/profile", "/settings", "/checkout", "/orders"]
_DEFAULT_PUBLIC    = ["/api/v1/auth", "/api/v1/health", "/docs", "/openapi.json",
                      "/redoc", "/static", "/favicon.ico"]


async def _get_prefixes() -> tuple[list[str], list[str]]:
    try:
        from gateway.models.gateway_config import GatewayConfig
        cfg = await GatewayConfig.find_one(GatewayConfig.module_name == "URLAuthenticationModule")
        if cfg and cfg.config:
            return cfg.config.get("protected_prefixes", _DEFAULT_PROTECTED), \
                   cfg.config.get("public_prefixes", _DEFAULT_PUBLIC)
    except Exception:
        pass
    return _DEFAULT_PROTECTED, _DEFAULT_PUBLIC


class ForcefulBrowsingDetector(BaseDetector):
    name = "URLAuthenticationModule"
    attack_type = "FORCEFUL_BROWSING"

    async def detect(self, request: Request) -> DetectionResult:
        path = request.url.path
        protected, public = await _get_prefixes()

        if any(path.startswith(p) for p in public):
            return self._clean()

        if any(path.startswith(p) for p in protected):
            if not getattr(request.state, "is_authenticated", False):
                logger.warning(f"Forceful browsing | unauthenticated → {path}")
                return DetectionResult(
                    detected=True, attack_type=self.attack_type,
                    rule_triggered="protected_url_no_session", confidence=0.97,
                    details=f"Unauthenticated request to protected URL: '{path}'",
                )
        return self._clean()