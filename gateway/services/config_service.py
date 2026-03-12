"""
gateway/services/config_service.py  [UPDATED]
───────────────────────────────────────────────
Now includes update_module_config() for full rule editing.
"""
from datetime import datetime, timezone
from typing import Any
from gateway.models.gateway_config import GatewayConfig

DEFAULTS = [
    {
        "module_name": "SessionResourceValidator",
        "display_name": "IDOR Detection",
        "description": "Detects IDOR attacks by validating that the session user ID matches the resource ID in the URL.",
        "config": {
            "protected_resource_paths": ["/users", "/submissions", "/documents", "/profiles", "/accounts", "/orders"],
            "id_query_params": ["user_id", "uid", "submission_id", "doc_id", "account_id", "resource_id"],
        },
    },
    {
        "module_name": "RoleVerificationModule",
        "display_name": "Privilege Escalation Detection",
        "description": "Detects vertical privilege escalation by verifying roles against endpoint requirements.",
        "config": {
            "admin_endpoints": ["/admin", "/api/v1/admin", "/api/v1/users/manage", "/api/v1/configs"],
            "moderator_endpoints": ["/api/v1/moderate", "/api/v1/reports"],
        },
    },
    {
        "module_name": "URLAuthenticationModule",
        "display_name": "Forceful Browsing Detection",
        "description": "Blocks unauthenticated access to protected URL paths.",
        "config": {
            "protected_prefixes": ["/admin", "/dashboard", "/api/v1/admin",
                                   "/api/v1/users", "/api/v1/submissions",
                                   "/api/v1/documents", "/profile", "/settings"],
            "public_prefixes": ["/api/v1/auth", "/api/v1/health", "/docs",
                                "/openapi.json", "/static"],
        },
    },
    {
        "module_name": "SessionTokenValidationModule",
        "display_name": "Inadequate Authorization Detection",
        "description": "Validates JWT token presence, expiry, and required permission scopes.",
        "config": {
            "scope_requirements": {
                "/api/v1/admin": ["admin"],
                "/api/v1/configs": ["admin"],
                "/api/v1/documents/download": ["read:documents"],
            },
        },
    },
    {
        "module_name": "ParameterIntegrityModule",
        "display_name": "Parameter Tampering Detection",
        "description": "Detects parameter manipulation using HMAC signing and mass-assignment pattern matching.",
        "config": {
            "sensitive_params": ["price", "amount", "total", "user_id", "account_id", "discount"],
            "forbidden_fields": ["is_admin", "is_superuser", "role", "privilege", "verified", "approved"],
        },
    },
]


async def seed_default_configs() -> None:
    for d in DEFAULTS:
        if not await GatewayConfig.find_one(GatewayConfig.module_name == d["module_name"]):
            await GatewayConfig(**d).insert()


async def get_all_configs() -> list[GatewayConfig]:
    return await GatewayConfig.find_all().to_list()


async def get_config_by_name(module_name: str) -> GatewayConfig | None:
    return await GatewayConfig.find_one(GatewayConfig.module_name == module_name)


async def toggle_module(module_name: str, enabled: bool, admin: str) -> GatewayConfig | None:
    cfg = await GatewayConfig.find_one(GatewayConfig.module_name == module_name)
    if cfg:
        cfg.is_enabled = enabled
        cfg.updated_at = datetime.now(timezone.utc)
        cfg.updated_by = admin
        await cfg.save()

        # Notify via WebSocket
        from gateway.services.websocket_service import broadcast_module_toggle
        await broadcast_module_toggle(module_name, enabled, admin)

        # Create notification if disabling
        if not enabled:
            from gateway.services.notification_service import create_module_disabled_notification
            await create_module_disabled_notification(module_name, admin)

    return cfg


async def update_module_config(
    module_name: str,
    new_config: dict[str, Any],
    admin: str,
) -> GatewayConfig | None:
    """
    Replaces the config dict for a module.
    Admin can update protected URL lists, sensitive params, scope mappings, etc.
    """
    cfg = await GatewayConfig.find_one(GatewayConfig.module_name == module_name)
    if cfg:
        cfg.config = new_config
        cfg.updated_at = datetime.now(timezone.utc)
        cfg.updated_by = admin
        await cfg.save()
    return cfg
