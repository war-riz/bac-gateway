"""
MODULE 5 — Parameter Tampering Detection (Parameter Integrity)
Reads sensitive_params and forbidden_fields live from GatewayConfig.
"""
import json
import re
import logging
from fastapi import Request
from .base import BaseDetector, DetectionResult
from gateway.utils.security import compute_hmac
from gateway.config.settings import get_settings

logger = logging.getLogger(__name__)

_DEFAULT_SENSITIVE = {"price", "amount", "total", "user_id", "account_id", "discount"}
_DEFAULT_FORBIDDEN = ["is_admin", "is_superuser", "role", "privilege", "verified", "approved"]


async def _get_config() -> tuple[set[str], re.Pattern]:
    try:
        from gateway.models.gateway_config import GatewayConfig
        cfg = await GatewayConfig.find_one(GatewayConfig.module_name == "ParameterIntegrityModule")
        if cfg and cfg.config:
            sensitive = set(cfg.config.get("sensitive_params", list(_DEFAULT_SENSITIVE)))
            forbidden = cfg.config.get("forbidden_fields", _DEFAULT_FORBIDDEN)
            pattern   = re.compile(r"\b(" + "|".join(re.escape(f) for f in forbidden) + r")\b", re.IGNORECASE)
            return sensitive, pattern
    except Exception:
        pass
    return _DEFAULT_SENSITIVE, re.compile(
        r"\b(is_admin|is_superuser|role|privilege|verified|approved)\b", re.IGNORECASE
    )


class ParameterTamperingDetector(BaseDetector):
    name = "ParameterIntegrityModule"
    attack_type = "PARAMETER_TAMPERING"

    async def detect(self, request: Request) -> DetectionResult:
        settings  = get_settings()
        params    = dict(request.query_params)
        sig       = params.pop("_param_sig", None)
        sensitive, forbidden_re = await _get_config()

        if sig:
            canonical = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
            if sig != compute_hmac(canonical, settings.secret_key):
                return DetectionResult(
                    detected=True, attack_type=self.attack_type,
                    rule_triggered="hmac_signature_mismatch", confidence=0.99,
                    details="Parameter HMAC signature failed verification",
                )

        for k, v in params.items():
            if k in sensitive:
                try:
                    if float(v) <= 0:
                        return DetectionResult(
                            detected=True, attack_type=self.attack_type,
                            rule_triggered="suspicious_sensitive_param_value", confidence=0.90,
                            details=f"Suspicious value '{v}' for parameter '{k}'",
                        )
                except ValueError:
                    pass

        body = getattr(request.state, "cached_body", b"").decode("utf-8", errors="ignore")
        if body:
            if request.headers.get("content-type", "").startswith("application/json"):
                try:
                    for key in json.loads(body):
                        if forbidden_re.match(key):
                            return DetectionResult(
                                detected=True, attack_type=self.attack_type,
                                rule_triggered="mass_assignment_attempt", confidence=0.97,
                                details=f"Forbidden field '{key}' in request body",
                            )
                except json.JSONDecodeError:
                    pass
            elif forbidden_re.search(body):
                return DetectionResult(
                    detected=True, attack_type=self.attack_type,
                    rule_triggered="mass_assignment_form", confidence=0.96,
                    details="Forbidden privilege field in form body",
                )

        return self._clean()