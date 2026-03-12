"""
gateway/detection/engine.py
Runs all 5 detection modules concurrently on every request.
Returns the first (highest confidence) attack found, or None if clean.
"""
import asyncio
import logging
import time
from fastapi import Request
from .base import DetectionResult
from .idor import IDORDetector
from .privilege_escalation import PrivilegeEscalationDetector
from .forceful_browsing import ForcefulBrowsingDetector
from .inadequate_auth import InadequateAuthDetector
from .parameter_tampering import ParameterTamperingDetector

logger = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self):
        self.modules = [
            IDORDetector(),
            PrivilegeEscalationDetector(),
            ForcefulBrowsingDetector(),
            InadequateAuthDetector(),
            ParameterTamperingDetector(),
        ]
        self._enabled: dict[str, bool] = {m.name: True for m in self.modules}

    def set_module_state(self, module_name: str, enabled: bool) -> None:
        if module_name in self._enabled:
            self._enabled[module_name] = enabled
            logger.info(f"Module '{module_name}' {'ENABLED' if enabled else 'DISABLED'}")

    async def analyse(self, request: Request) -> tuple[DetectionResult | None, float]:
        """
        Returns (attack_result | None, processing_time_ms).
        All active modules run in parallel via asyncio.gather.
        """
        start = time.perf_counter()
        active = [m for m in self.modules if self._enabled.get(m.name, True)]
        results = await asyncio.gather(*[m.detect(request) for m in active])
        elapsed_ms = (time.perf_counter() - start) * 1000

        attacks = sorted([r for r in results if r.detected],
                         key=lambda r: r.confidence, reverse=True)
        return (attacks[0] if attacks else None), elapsed_ms
