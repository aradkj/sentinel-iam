from typing import Any

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.core.security import extract_client_ip, extract_user_agent
from app.database.session import ResilientRedisClient, get_db, get_redis
from app.models.user import User
from app.schemas.token import SessionRecord
from app.services.token_service import TokenService
from app.services.user_service import UserService

router = APIRouter(prefix="/sessions", tags=["Sessions"])


@router.get("", response_model=list[SessionRecord])
async def list_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[SessionRecord]:
    """List all active sessions for the authenticated user."""
    token_payload = getattr(request.state, "token_payload", {}) or {}
    current_jti = token_payload.get("jti")
    sessions = await TokenService.list_db_sessions(
        db=db,
        user_id=current_user.id,
        current_jti=current_jti,
    )
    return [SessionRecord(**s) for s in sessions]


@router.delete("/{id}", status_code=status.HTTP_200_OK)
async def revoke_session(
    id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> dict[str, Any]:
    """Revoke a specific active session by ID and record a SESSION_REVOKED audit log."""
    revoked_session = await TokenService.revoke_session_by_id(
        db=db,
        redis=redis,
        user_id=current_user.id,
        session_id=id,
    )
    await UserService.record_audit_log(
        db=db,
        action="SESSION_REVOKED",
        user_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
        details=f"Revoked session id={revoked_session.id} ({revoked_session.device_name})",
        metadata={"session_id": revoked_session.id, "device": revoked_session.device_name},
    )
    return {
        "message": "Session revoked successfully",
        "revoked_session_id": revoked_session.id,
    }


@router.post("/revoke-all", status_code=status.HTTP_200_OK)
async def revoke_all_sessions(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> dict[str, Any]:
    """Revoke all active sessions for the current user across all devices."""
    revoked_count = await TokenService.revoke_all_sessions(
        db=db,
        redis=redis,
        user_id=current_user.id,
    )
    await UserService.record_audit_log(
        db=db,
        action="SESSION_REVOKED",
        user_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
        details=f"Revoked all sessions (count={revoked_count})",
        metadata={"revoked_count": revoked_count, "scope": "all"},
    )
    return {
        "message": "All active sessions have been revoked",
        "revoked_count": revoked_count,
    }
