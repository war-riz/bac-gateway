from fastapi import APIRouter
from .endpoints import auth, events, dashboard, configs, metrics, notifications, websocket, health

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(events.router)
api_router.include_router(dashboard.router)
api_router.include_router(configs.router)
api_router.include_router(metrics.router)
api_router.include_router(notifications.router)
api_router.include_router(health.router)

# WebSocket is registered directly on app (no /api/v1 prefix)
ws_router = websocket.router
