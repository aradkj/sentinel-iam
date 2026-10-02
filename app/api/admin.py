from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user, require_permission
from app.core.security import extract_client_ip, extract_user_agent
from app.database.session import get_db
from app.models.user import User
from app.schemas.role import (
    AssignPermissionRequest,
    PermissionCreate,
    PermissionResponse,
    RoleCreate,
    RoleResponse,
    RoleUpdate,
)
from app.schemas.user import AuditLogResponse, UserResponse, UserStatusUpdate
from app.services.user_service import UserService

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/users", response_model=list[UserResponse])
async def admin_list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("user.read")),
    db: AsyncSession = Depends(get_db),
) -> list[UserResponse]:
    """List all users in the system (requires 'user.read' permission)."""
    users = await UserService.list_users(db=db, skip=skip, limit=limit)
    return [UserService.to_user_response(u) for u in users]


@router.get("/users/{id}", response_model=UserResponse)
async def admin_get_user(
    id: int,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("user.read")),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Get a single user's full account details by ID (requires 'user.read' permission)."""
    user = await UserService.get_user_by_id(db=db, user_id=id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id={id} not found.",
        )
    return UserService.to_user_response(user)


@router.patch("/users/{id}/status", response_model=UserResponse)
async def admin_update_user_status(
    id: int,
    payload: UserStatusUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("user.update")),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Activate, disable, or unlock a user account (requires 'user.update' permission)."""
    updated = await UserService.update_user_status(
        db=db,
        target_user_id=id,
        payload=payload,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return UserService.to_user_response(updated)


@router.delete("/users/{id}", status_code=status.HTTP_200_OK)
async def admin_delete_user(
    id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("user.delete")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Delete a user account by ID (requires 'user.delete' permission)."""
    await UserService.delete_user(
        db=db,
        target_user_id=id,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return {"message": "deleted", "deleted_user_id": id}


@router.get("/roles", response_model=list[RoleResponse])
async def admin_list_roles(
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> list[RoleResponse]:
    """List all RBAC roles and their permissions (requires 'role.manage' permission)."""
    roles = await UserService.list_roles(db)
    return [UserService.to_role_response(r) for r in roles]


@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def admin_create_role(
    payload: RoleCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    """Create a new RBAC role and record ROLE_CREATED audit event."""
    role = await UserService.create_role(
        db=db,
        payload=payload,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return UserService.to_role_response(role)


@router.patch("/roles/{id}", response_model=RoleResponse)
async def admin_update_role(
    id: int,
    payload: RoleUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    """Update a role's name, description, or permissions (requires 'role.manage' permission)."""
    role = await UserService.update_role(
        db=db,
        role_id=id,
        payload=payload,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return UserService.to_role_response(role)


@router.delete("/roles/{id}", status_code=status.HTTP_200_OK)
async def admin_delete_role(
    id: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Delete an RBAC role by ID (requires 'role.manage' permission)."""
    await UserService.delete_role(
        db=db,
        role_id=id,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return {"message": "Role deleted successfully", "deleted_role_id": id}


@router.post(
    "/permissions",
    response_model=PermissionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def admin_create_permission(
    payload: PermissionCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> PermissionResponse:
    """Create a new permission and record PERMISSION_CHANGED audit event."""
    created = await UserService.create_permission(
        db=db,
        payload=payload,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return PermissionResponse.model_validate(created)


@router.post("/roles/{id}/permissions", response_model=RoleResponse)
async def admin_assign_permissions_to_role(
    id: int,
    payload: AssignPermissionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    """Assign one or more permissions to a role (requires 'role.manage' permission)."""
    updated_role = await UserService.assign_permission_to_role(
        db=db,
        role_id=id,
        permission_names=payload.resolved_permissions,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return UserService.to_role_response(updated_role)


@router.get("/audit-logs", response_model=list[AuditLogResponse])
async def admin_get_audit_logs(
    limit: int = 100,
    user_id: int | None = None,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> list[AuditLogResponse]:
    """Retrieve security audit logs (restricted to administrators with 'role.manage')."""
    logs = await UserService.list_audit_logs(db=db, limit=limit, user_id=user_id)
    return [AuditLogResponse.from_orm_entry(entry) for entry in logs]
