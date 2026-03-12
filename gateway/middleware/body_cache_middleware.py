"""
Caches request body into request.state.cached_body before it's consumed.
Needed because FastAPI body is a stream — read once and gone.
"""
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


class BodyCacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in ("POST", "PUT", "PATCH"):
            request.state.cached_body = await request.body()
        else:
            request.state.cached_body = b""
        return await call_next(request)
