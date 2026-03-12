"""
main.py — BAC Security Gateway entry point  [UPDATED]

Startup sequence:
  1. Connect MongoDB Atlas + init Beanie (all 6 collections)
  2. Seed admin user + 5 module configs (first run only)
  3. Start metrics background task (30s snapshots)
  4. Register middleware: BodyCache → AuthState → GatewayProxy
  5. Mount all REST API routes + WebSocket route
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from gateway.config.settings import get_settings
from gateway.db.database import init_db, close_db
from gateway.middleware.body_cache_middleware import BodyCacheMiddleware
from gateway.middleware.auth_middleware import AuthStateMiddleware
from gateway.middleware.gateway_middleware import GatewayProxyMiddleware
from gateway.detection.engine import DetectionEngine
from gateway.api.v1 import api_router, ws_router
from gateway.services.auth_service import seed_admin_user
from gateway.services.config_service import seed_default_configs
from gateway.services.metrics_service import metrics_background_task

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)
settings = get_settings()
engine = DetectionEngine()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── STARTUP ──────────────────────────────────────────────────
    await init_db()
    await seed_admin_user(
        settings.admin_email,
        settings.admin_username,
        settings.admin_password,
    )
    await seed_default_configs()

    # Start metrics background task
    task = asyncio.create_task(metrics_background_task())
    logger.info("Metrics background task started")

    logger.info(f"BAC Gateway → http://localhost:{settings.gateway_port}")
    logger.info(f"API docs   → http://localhost:{settings.gateway_port}/docs")
    logger.info(f"WebSocket  → ws://localhost:{settings.gateway_port}/ws/events?token=<jwt>")

    yield

    # ── SHUTDOWN ─────────────────────────────────────────────────
    task.cancel()
    await close_db()
    logger.info("Gateway shut down cleanly.")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "Rule-based security gateway that detects and prevents 5 BAC attack types in real-time. "
        "Includes WebSocket live feed, performance metrics, and admin notifications."
    ),
    lifespan=lifespan,
)

# CORS — allow the Next.js dashboard on port 3000
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware — runs bottom-up per request: BodyCache → AuthState → GatewayProxy
app.add_middleware(GatewayProxyMiddleware, engine=engine)
app.add_middleware(AuthStateMiddleware)
app.add_middleware(BodyCacheMiddleware)

# REST API routes
app.include_router(api_router)

# WebSocket route (no /api/v1 prefix — connects as ws://localhost:8000/ws/events)
app.include_router(ws_router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.gateway_host,
        port=settings.gateway_port,
        reload=settings.debug,
        log_level="info",
    )
