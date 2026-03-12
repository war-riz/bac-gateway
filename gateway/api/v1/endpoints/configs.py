"""
GET   /api/v1/configs                       — List all module configs
PATCH /api/v1/configs/{module}/toggle       — Enable / disable a module
PUT   /api/v1/configs/{module}/config       — Update a module's rule config
GET   /api/v1/configs/{module}              — Get single module config
"""
from typing import Annotated, Any, Dict
from fastapi import APIRouter, Depends, HTTPException
from gateway.core.dependencies import get_current_admin
from gateway.models.user import User
from gateway.schemas.config import ModuleConfigOut, ModuleToggleRequest, ModuleConfigUpdateRequest
from gateway.services.config_service import (
    get_all_configs, get_config_by_name, toggle_module, update_module_config,
)

router = APIRouter(prefix="/configs", tags=["Configuration"])


@router.get("", response_model=list[ModuleConfigOut])
async def list_configs(admin: Annotated[User, Depends(get_current_admin)]):
    """All 5 detection module configurations."""
    return [_to_out(c) for c in await get_all_configs()]


@router.get("/{module_name}", response_model=ModuleConfigOut)
async def get_config(module_name: str, admin: Annotated[User, Depends(get_current_admin)]):
    """Single module config by name."""
    cfg = await get_config_by_name(module_name)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Module '{module_name}' not found")
    return _to_out(cfg)


@router.patch("/{module_name}/toggle", response_model=ModuleConfigOut)
async def toggle(
    module_name: str,
    body: ModuleToggleRequest,
    admin: Annotated[User, Depends(get_current_admin)],
):
    """Enable or disable a detection module. Broadcasts to WebSocket + creates notification if disabling."""
    cfg = await toggle_module(module_name, body.is_enabled, admin.username)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Module '{module_name}' not found")
    return _to_out(cfg)


@router.put("/{module_name}/config", response_model=ModuleConfigOut)
async def update_config(
    module_name: str,
    body: ModuleConfigUpdateRequest,
    admin: Annotated[User, Depends(get_current_admin)],
):
    """
    Replace the rule config for a module.
    
    Examples of what you can change per module:
    - SessionResourceValidator: protected_resource_paths, id_query_params
    - URLAuthenticationModule:  protected_prefixes, public_prefixes
    - ParameterIntegrityModule: sensitive_params, forbidden_fields
    - SessionTokenValidationModule: scope_requirements
    - RoleVerificationModule: admin_endpoints, moderator_endpoints
    """
    cfg = await update_module_config(module_name, body.config, admin.username)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Module '{module_name}' not found")
    return _to_out(cfg)


def _to_out(c) -> ModuleConfigOut:
    return ModuleConfigOut(
        module_name=c.module_name,
        display_name=c.display_name,
        description=c.description,
        is_enabled=c.is_enabled,
        config=c.config,
        updated_at=c.updated_at,
        updated_by=c.updated_by,
    )
