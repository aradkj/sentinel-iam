from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user, require_permission
from app.core.security import extract_client_ip, extract_user_agent
from app.database.session import get_db
from app.models.user import User
from app.schemas.role import (
    AssignPermissionRequest,
    AssignRoleRequest,
    RoleCreate,
    RoleResponse,
)
from app.schemas.user import UserResponse
from app.services.user_service import UserService

router = APIRouter(prefix="/roles", tags=["Roles"])


@router.get("", response_model=list[RoleResponse])
async def list_roles(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[RoleResponse]:
    """List all available RBAC roles and their associated permissions."""
    roles = await UserService.list_roles(db)
    return [UserService.to_role_response(role) for role in roles]


@router.post("", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    payload: RoleCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    """Create a new RBAC role (requires 'role.manage' permission)."""
    role = await UserService.create_role(
        db=db,
        payload=payload,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return UserService.to_role_response(role)


@router.post("/assign", response_model=UserResponse)
async def assign_role(
    payload: AssignRoleRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Assign a role to a user and record a ROLE_CHANGE audit event."""
    updated_user = await UserService.assign_role_to_user(
        db=db,
        user_id=payload.user_id,
        role_name=payload.role_name,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return UserService.to_user_response(updated_user)


@router.post("/{role_id}/permissions", response_model=RoleResponse)
async def add_permission_to_role(
    role_id: int,
    payload: AssignPermissionRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    """Attach a granular permission to an existing RBAC role."""
    updated_role = await UserService.assign_permission_to_role(
        db=db,
        role_id=role_id,
        permission_names=payload.resolved_permissions,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return UserService.to_role_response(updated_role)
