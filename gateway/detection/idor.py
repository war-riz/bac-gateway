"""
MODULE 1 — IDOR Detection (Session-Resource Validation)
Rule: session user ID must match the resource ID in the URL.
Reads protected_resource_paths and id_query_params live from GatewayConfig.
"""
import re
import logging
from fastapi import Request
from .base import BaseDetector, DetectionResult

logger = logging.getLogger(__name__)

_DEFAULT_PATHS  = ["users", "submissions", "documents", "profiles", "accounts", "orders"]
_DEFAULT_PARAMS = ["user_id", "uid", "submission_id", "doc_id", "account_id", "resource_id"]


def _build_regexes(paths: list[str], params: list[str]):
    path_pattern  = r"/(?:" + "|".join(re.escape(p.strip("/")) for p in paths) + r")/(\d+)"
    param_pattern = r"(?:" + "|".join(re.escape(p) for p in params) + r")=(\d+)"
    return re.compile(path_pattern), re.compile(param_pattern)


async def _get_config() -> tuple[list[str], list[str]]:
    try:
        from gateway.models.gateway_config import GatewayConfig
        cfg = await GatewayConfig.find_one(GatewayConfig.module_name == "SessionResourceValidator")
        if cfg and cfg.config:
            return (cfg.config.get("protected_resource_paths", _DEFAULT_PATHS),
                    cfg.config.get("id_query_params", _DEFAULT_PARAMS))
    except Exception:
        pass
    return _DEFAULT_PATHS, _DEFAULT_PARAMS


class IDORDetector(BaseDetector):
    name = "SessionResourceValidator"
    attack_type = "IDOR"

    async def detect(self, request: Request) -> DetectionResult:
        url  = str(request.url)
        path = request.url.path
        paths, params = await _get_config()
        path_re, query_re = _build_regexes(paths, params)

        match = path_re.search(path) or query_re.search(url)
        if not match:
            return self._clean()

        resource_id    = match.group(1)
        session_user_id = getattr(request.state, "user_id", None)
        if not session_user_id:
            return self._clean()

        if str(session_user_id) != str(resource_id):
            logger.warning(f"IDOR | session={session_user_id} → resource={resource_id} | {path}")
            return DetectionResult(
                detected=True, attack_type=self.attack_type,
                rule_triggered="session_resource_mismatch", confidence=0.95,
                details=f"User '{session_user_id}' accessed resource ID '{resource_id}'",
            )
        return self._clean()