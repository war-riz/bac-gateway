from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel


class ModuleConfigOut(BaseModel):
    module_name:  str
    display_name: str
    description:  str
    is_enabled:   bool
    config:       Dict[str, Any]
    updated_at:   datetime 
    updated_by:   Optional[str] = None


class ModuleToggleRequest(BaseModel):
    is_enabled: bool


class ModuleConfigUpdateRequest(BaseModel):
    config: Dict[str, Any]