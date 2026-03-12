"""
gateway/config/settings.py

HOW THIS WORKS:
  - Every field has a default value (used if no .env file exists).
  - When .env exists, pydantic-settings reads it and OVERRIDES those defaults.
  - So your real MongoDB URL, SECRET_KEY etc. come from .env — never hardcoded.
  - Call get_settings() anywhere in the app to access config.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App
    app_name: str = "BAC Security Gateway"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"

    # MongoDB — default is local fallback; real value comes from .env
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "bac_gateway"

    # JWT — default is insecure placeholder; real value comes from .env
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    remember_me_expire_days: int = 30

    # Gateway proxy target (the vulnerable demo site)
    protected_app_url: str = "http://localhost:5000"
    gateway_host: str = "0.0.0.0"
    gateway_port: int = 8000

    # Admin account seeded on first startup
    admin_email: str = "admin@bacgateway.com"
    admin_password: str = "Admin@123456"
    admin_username: str = "admin"

    # Detection performance targets
    min_detection_accuracy: float = 0.95
    max_false_positive_rate: float = 0.02
    max_latency_ms: int = 50

    model_config = SettingsConfigDict(
        env_file=".env",          # reads .env from project root
        env_file_encoding="utf-8",
        case_sensitive=False,     # MONGODB_URL and mongodb_url are the same
        extra="ignore"
    )


@lru_cache()
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.
    .env is read exactly once — subsequent calls return the same object.
    """
    return Settings()
