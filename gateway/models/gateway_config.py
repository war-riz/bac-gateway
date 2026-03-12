"""Per-module config — admin can toggle modules on/off from dashboard."""
from datetime import datetime
from typing import Any, Dict, Optional
from beanie import Document
from pydantic import Field


class GatewayConfig(Document):
    module_name: str
    display_name: str
    description: str = ""
    is_enabled: bool = True
    config: Dict[str, Any] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    updated_by: Optional[str] = None

    class Settings:
        name = "gateway_configs"
