"""
gateway/detection/base.py
Shared result dataclass and abstract base class for all 5 detection modules.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from fastapi import Request


@dataclass
class DetectionResult:
    detected: bool
    attack_type: str = ""
    rule_triggered: str = ""
    confidence: float = 1.0
    details: str = ""
    should_block: bool = True


class BaseDetector(ABC):
    name: str = "BaseDetector"
    attack_type: str = "UNKNOWN"

    @abstractmethod
    async def detect(self, request: Request) -> DetectionResult: ...

    def _clean(self) -> DetectionResult:
        return DetectionResult(detected=False, attack_type=self.attack_type)
