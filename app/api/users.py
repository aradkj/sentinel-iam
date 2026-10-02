from typing import Any

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import get_current_user, require_permission
from app.core.security import extract_client_ip, extract_user_agent
from app.database.session import get_db
from app.models.user import User
from app.schemas.auth import Enable2FAResponse
from app.schemas.user import (
    AuditLogResponse,
    PasswordChangeRequest,
    UserCreate,
    UserResponse,
)
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=UserResponse)
async def get_my_profile(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Return the profile, roles, and permissions of the currently authenticated user."""
    return UserService.to_user_response(current_user)


@router.post(
    "/enable-2fa",
    response_model=Enable2FAResponse,
    tags=["2FA"],
    summary="Enable TOTP two-factor authentication for the current user",
)
async def enable_two_factor_auth(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Enable2FAResponse:
    """Generate a TOTP secret key and enable two-factor authentication for the current user."""
    secret, otpauth_url = await UserService.enable_2fa(
        db=db,
        user=current_user,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return Enable2FAResponse(
        secret=secret,
        otpauth_url=otpauth_url,
        issuer=settings.TOTP_ISSUER_NAME,
    )


@router.post(
    "/disable-2fa",
    response_model=UserResponse,
    tags=["2FA"],
    summary="Disable TOTP two-factor authentication for the current user",
)
async def disable_two_factor_auth(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Disable two-factor authentication for the current user."""
    updated_user = await UserService.disable_2fa(
        db=db,
        user=current_user,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return UserService.to_user_response(updated_user)


@router.get("", response_model=list[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("report.view")),
    db: AsyncSession = Depends(get_db),
) -> list[UserResponse]:
    """List users in the system (requires 'report.view' permission)."""
    users = await UserService.list_users(db=db, skip=skip, limit=limit)
    return [UserService.to_user_response(u) for u in users]


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user_admin(
    payload: UserCreate,
    request: Request,
    user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("user.create")),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Create a new user administratively (requires 'user.create' permission)."""
    created_user = await UserService.create_user(
        db=db,
        payload=payload,
        role_name="user",
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return UserService.to_user_response(created_user)


@router.get("/reports", status_code=status.HTTP_200_OK)
async def view_security_reports(
    user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("report.view")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return an IAM security summary report (accessible to Admin and Employee roles)."""
    users = await UserService.list_users(db=db, limit=1000)
    logs = await UserService.list_audit_logs(db=db, limit=50)
    return {
        "total_users": len(users),
        "active_users": sum(1 for u in users if u.is_active),
        "verified_users": sum(1 for u in users if u.is_verified),
        "two_factor_enabled_users": sum(1 for u in users if u.two_factor_enabled),
        "recent_audit_events": len(logs),
        "viewer": user.username,
    }


@router.get("/audit-logs", response_model=list[AuditLogResponse])
async def get_audit_logs(
    limit: int = 100,
    user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("report.view")),
    db: AsyncSession = Depends(get_db),
) -> list[AuditLogResponse]:
    """Retrieve security audit logs (requires 'report.view' permission)."""
    logs = await UserService.list_audit_logs(db=db, limit=limit)
    return [AuditLogResponse.from_orm_entry(entry) for entry in logs]


@router.delete("/{id}", status_code=status.HTTP_200_OK)
async def delete_user(
    id: int,
    request: Request,
    user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("user.delete")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Delete a user by ID (requires 'user.delete' permission)."""
    client_ip = extract_client_ip(request)
    user_agent = extract_user_agent(request)
    target = await UserService.get_user_by_id(db, id)
    if target is not None:
        await UserService.delete_user(
            db=db,
            target_user_id=id,
            actor_id=user.id,
            ip_address=client_ip,
            user_agent=user_agent,
        )
    else:
        await UserService.record_audit_log(
            db=db,
            action="USER_DELETE_ATTEMPT",
            user_id=user.id,
            ip_address=client_ip,
            user_agent=user_agent,
            details=f"Attempted deletion of user_id={id}",
        )
    return {"message": "deleted", "deleted_user_id": id}
