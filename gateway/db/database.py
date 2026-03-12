"""
gateway/db/database.py
Connects to MongoDB Atlas using Motor (async) and initialises Beanie ODM.
"""
import logging
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from gateway.config.settings import get_settings

logger = logging.getLogger(__name__)
_client: AsyncIOMotorClient | None = None


async def init_db() -> None:
    global _client
    settings = get_settings()
    logger.info("Connecting to MongoDB Atlas...")
    _client = AsyncIOMotorClient(settings.mongodb_url)

    from gateway.models.user import User
    from gateway.models.security_event import SecurityEvent
    from gateway.models.gateway_config import GatewayConfig
    from gateway.models.performance_metric import PerformanceMetric
    from gateway.models.session import UserSession
    from gateway.models.notification import Notification

    await init_beanie(
        database=_client[settings.mongodb_db_name],
        document_models=[
            User, SecurityEvent, GatewayConfig,
            PerformanceMetric, UserSession, Notification
        ],
    )
    logger.info(f"MongoDB connected: '{settings.mongodb_db_name}'")


async def close_db() -> None:
    global _client
    if _client:
        _client.close()
        logger.info("MongoDB connection closed.")
