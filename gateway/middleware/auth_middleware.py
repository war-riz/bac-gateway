"""
Decodes the JWT (if present) and attaches user info to request.state
so detection modules can read it without decoding the token again.
"""
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from gateway.utils.security import decode_access_token


class AuthStateMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.is_authenticated = False
        request.state.user_id = None
        request.state.user_role = "guest"
        request.state.username = None

        token = _get_token(request)
        if token:
            payload = decode_access_token(token)
            if payload:
                request.state.is_authenticated = True
                request.state.user_id = payload.get("sub")
                request.state.user_role = payload.get("role", "user")
                request.state.username = payload.get("username")

        return await call_next(request)


def _get_token(request: Request) -> str | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("access_token")
