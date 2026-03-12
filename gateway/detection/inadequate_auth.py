"""
MODULE 4 — Inadequate Authorization Detection (Token Validation)
Reads scope_requirements live from GatewayConfig.
"""
import logging
from fastapi import Request
from .base import BaseDetector, DetectionResult
from gateway.utils.security import decode_access_token

logger = logging.getLogger(__name__)

_DEFAULT_SCOPE_MAP = {
    "/api/v1/admin":              ["admin"],
    "/api/v1/configs":            ["admin"],
    "/api/v1/documents/download": ["read:documents"],
}
PUBLIC = ["/api/v1/auth", "/api/v1/health", "/docs", "/openapi.json", "/static"]


async def _get_scope_map() -> dict[str, list[str]]:
    try:
        from gateway.models.gateway_config import GatewayConfig
        cfg = await GatewayConfig.find_one(GatewayConfig.module_name == "SessionTokenValidationModule")
        if cfg and cfg.config:
            return cfg.config.get("scope_requirements", _DEFAULT_SCOPE_MAP)
    except Exception:
        pass
    return _DEFAULT_SCOPE_MAP


class InadequateAuthDetector(BaseDetector):
    name = "SessionTokenValidationModule"
    attack_type = "INADEQUATE_AUTHORIZATION"

    async def detect(self, request: Request) -> DetectionResult:
        path = request.url.path
        if any(path.startswith(p) for p in PUBLIC):
            return self._clean()

        token    = _get_token(request)
        scope_map = await _get_scope_map()

        if not token:
            if any(path.startswith(ep) for ep in scope_map):
                return DetectionResult(
                    detected=True, attack_type=self.attack_type,
                    rule_triggered="missing_auth_token", confidence=0.95,
                    details=f"No token for protected endpoint: '{path}'",
                )
            return self._clean()

        payload = decode_access_token(token)
        if payload is None:
            return DetectionResult(
                detected=True, attack_type=self.attack_type,
                rule_triggered="invalid_or_expired_token", confidence=0.98,
                details="Token is invalid or expired",
            )

        role   = payload.get("role", "user")
        scopes = payload.get("scopes", [])
        for prefix, required_scopes in scope_map.items():
            if path.startswith(prefix) and role != "admin":
                for req in required_scopes:
                    if req not in scopes:
                        return DetectionResult(
                            detected=True, attack_type=self.attack_type,
                            rule_triggered="insufficient_token_scope", confidence=0.96,
                            details=f"Missing scope '{req}' for '{path}'",
                        )
        return self._clean()


def _get_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("access_token")