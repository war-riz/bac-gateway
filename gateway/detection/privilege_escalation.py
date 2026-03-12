"""
MODULE 2 — Privilege Escalation Detection (Role Verification)
Reads admin_endpoints and moderator_endpoints live from GatewayConfig.
"""
import re
import logging
from fastapi import Request
from .base import BaseDetector, DetectionResult

logger = logging.getLogger(__name__)

_DEFAULT_ADMIN = ["/admin", "/api/v1/admin", "/api/v1/users/manage", "/api/v1/configs"]
ROLE_INJECT = re.compile(
    r"(?:role|user_role|is_admin|privilege|access_level)\s*=\s*(?:admin|superuser|root|1|true)",
    re.IGNORECASE,
)


async def _get_admin_endpoints() -> list[str]:
    try:
        from gateway.models.gateway_config import GatewayConfig
        cfg = await GatewayConfig.find_one(GatewayConfig.module_name == "RoleVerificationModule")
        if cfg and cfg.config:
            return cfg.config.get("admin_endpoints", _DEFAULT_ADMIN)
    except Exception:
        pass
    return _DEFAULT_ADMIN


class PrivilegeEscalationDetector(BaseDetector):
    name = "RoleVerificationModule"
    attack_type = "PRIVILEGE_ESCALATION"

    async def detect(self, request: Request) -> DetectionResult:
        path  = request.url.path
        role  = getattr(request.state, "user_role", "guest")
        admin_endpoints = await _get_admin_endpoints()

        if any(path.startswith(ep) for ep in admin_endpoints) and role != "admin":
            logger.warning(f"Privilege escalation | role='{role}' → {path}")
            return DetectionResult(
                detected=True, attack_type=self.attack_type,
                rule_triggered="admin_endpoint_unauthorized_role", confidence=0.98,
                details=f"Role '{role}' attempted admin endpoint '{path}'",
            )

        url  = str(request.url)
        body = getattr(request.state, "cached_body", b"").decode("utf-8", errors="ignore")
        if ROLE_INJECT.search(url) or ROLE_INJECT.search(body):
            return DetectionResult(
                detected=True, attack_type=self.attack_type,
                rule_triggered="role_parameter_injection", confidence=0.99,
                details="Role manipulation detected in request",
            )
        return self._clean()