"""
gateway/utils/security.py
Password hashing, JWT creation/verification, HMAC for parameter integrity.
"""
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
import bcrypt
from gateway.config.settings import get_settings

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, remember_me: bool = False) -> str:
    settings = get_settings()
    payload  = data.copy()
    if remember_me:
        delta = timedelta(days=settings.remember_me_expire_days)
    else:
        delta = expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    payload["exp"] = datetime.now(timezone.utc) + delta
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> Optional[dict]:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError:
        return None


def hash_token(token: str) -> str:
    """SHA-256 a session token before storing it in logs (never store raw tokens)."""
    return hashlib.sha256(token.encode()).hexdigest()


def compute_hmac(value: str, secret: str) -> str:
    """HMAC-SHA256 for parameter integrity checking (Module 5)."""
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()
