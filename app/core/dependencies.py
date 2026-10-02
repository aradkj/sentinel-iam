from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import verify_token
from app.database.session import ResilientRedisClient, get_db, get_redis
from app.models.user import User
from app.services.token_service import TokenService
from app.services.user_service import UserService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


async def get_current_token_payload(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    redis: ResilientRedisClient = Depends(get_redis),
) -> dict[str, Any]:
    """Validate the Bearer JWT and verify it is not present in the Redis blacklist."""
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = verify_token(token, expected_type="access")
    jti = str(payload.get("jti", ""))

    if await TokenService.is_blacklisted(redis, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked (blacklisted)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.token_payload = payload
    return payload


async def get_current_user(
    payload: dict[str, Any] = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve and return the currently authenticated active user."""
    user_id = int(payload["user_id"])
    user = await UserService.get_user_by_id(db, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )
    return user


def require_permission(
    permission_name: str,
) -> Callable[..., Coroutine[Any, Any, str]]:
    """FastAPI dependency factory enforcing granular RBAC permission checks."""

    async def permission_dependency(
        current_user: User = Depends(get_current_user),
    ) -> str:
        granted_permissions = set(current_user.permission_names)
        if permission_name not in granted_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: '{permission_name}' required",
            )
        return permission_name

    return permission_dependency


def require_role(
    role_name: str,
) -> Callable[..., Coroutine[Any, Any, str]]:
    """FastAPI dependency factory enforcing role membership."""

    async def role_dependency(
        current_user: User = Depends(get_current_user),
    ) -> str:
        user_roles = set(current_user.role_names)
        if role_name not in user_roles and "admin" not in user_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role privileges: '{role_name}' required",
            )
        return role_name

    return role_dependency
