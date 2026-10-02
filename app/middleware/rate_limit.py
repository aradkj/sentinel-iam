from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.core.config import settings
from app.core.security import extract_client_ip
from app.database.session import ResilientRedisClient, get_redis, redis_client

PROTECTED_RATE_LIMIT_PATHS: set[str] = {
    "/api/v1/auth/login",
    "/api/v1/auth/register",
}


async def enforce_rate_limit(
    request: Request,
    redis: ResilientRedisClient,
    scope: str,
    max_requests: int | None = None,
    window_seconds: int | None = None,
) -> tuple[int, int, int]:
    """Increment and evaluate the per-IP Redis rate limit counter for a given route scope."""
    if not settings.RATE_LIMIT_ENABLED:
        return (
            0,
            max_requests or settings.RATE_LIMIT_REQUESTS,
            window_seconds or settings.RATE_LIMIT_WINDOW_SECONDS,
        )

    if getattr(request.state, "rate_limit_checked", False):
        return getattr(
            request.state,
            "rate_limit_meta",
            (1, settings.RATE_LIMIT_REQUESTS, settings.RATE_LIMIT_WINDOW_SECONDS),
        )

    limit = max_requests if max_requests is not None else settings.RATE_LIMIT_REQUESTS
    window = window_seconds if window_seconds is not None else settings.RATE_LIMIT_WINDOW_SECONDS
    client_ip = extract_client_ip(request)
    key = f"ratelimit:{scope}:{client_ip}"

    current_count = await redis.incr(key)
    if current_count == 1:
        await redis.expire(key, window)

    ttl = await redis.ttl(key)
    if ttl < 0:
        await redis.expire(key, window)
        ttl = window

    request.state.rate_limit_checked = True
    request.state.rate_limit_meta = (current_count, limit, ttl)

    if current_count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too Many Requests: Rate limit exceeded. Please try again later.",
            headers={
                "Retry-After": str(ttl),
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
            },
        )

    return current_count, limit, ttl


def rate_limit_dependency(
    scope: str,
    max_requests: int | None = None,
    window_seconds: int | None = None,
) -> Callable[..., Coroutine[Any, Any, None]]:
    """FastAPI route dependency enforcing Redis-backed rate limiting per client IP."""

    async def _dependency(
        request: Request,
        redis: ResilientRedisClient = Depends(get_redis),
    ) -> None:
        await enforce_rate_limit(
            request=request,
            redis=redis,
            scope=scope,
            max_requests=max_requests,
            window_seconds=window_seconds,
        )

    return _dependency


class RateLimitMiddleware(BaseHTTPMiddleware):
    """ASGI middleware enforcing Redis rate limits on sensitive authentication endpoints."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        normalized_path = request.url.path.rstrip("/") or "/"
        if request.method.upper() == "POST" and normalized_path in PROTECTED_RATE_LIMIT_PATHS:
            try:
                count, limit, ttl = await enforce_rate_limit(
                    request=request,
                    redis=redis_client,
                    scope=normalized_path,
                )
            except HTTPException as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": exc.detail},
                    headers=dict(exc.headers or {}),
                )

            response = await call_next(request)
            remaining = max(0, limit - count)
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(ttl)
            return response

        return await call_next(request)
