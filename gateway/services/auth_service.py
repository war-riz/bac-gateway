from datetime import datetime, timezone
from typing import Optional
from gateway.models.user import User
from gateway.utils.security import verify_password, create_access_token, hash_password


async def authenticate_user(email: str, password: str) -> Optional[User]:
    user = await User.find_one(User.email == email)
    if not user or not verify_password(password, user.hashed_password) or not user.is_active:
        return None
    user.last_login = datetime.now(timezone.utc)
    await user.save()
    return user


def create_token_for_user(user: User, remember_me: bool = False) -> str:
    return create_access_token({
        "sub":      str(user.id),
        "email":    user.email,
        "username": user.username,
        "role":     "admin" if user.is_admin else "user",
        "scopes":   ["admin"] if user.is_admin else ["read"],
    }, remember_me=remember_me)


async def seed_admin_user(email: str, username: str, password: str) -> None:
    if not await User.find_one(User.email == email):
        await User(
            username=username, email=email,
            hashed_password=hash_password(password),
            is_active=True, is_admin=True,
        ).insert()
