from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user, require_permission
from app.core.security import extract_client_ip, extract_user_agent
from app.database.session import get_db
from app.models.user import User
from app.schemas.role import PermissionCreate, PermissionResponse
from app.services.user_service import UserService

router = APIRouter(prefix="/permissions", tags=["Permissions"])


@router.get("", response_model=list[PermissionResponse])
async def list_permissions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[PermissionResponse]:
    """List all granular permissions defined in the system."""
    permissions = await UserService.list_permissions(db)
    return [PermissionResponse.model_validate(perm) for perm in permissions]


@router.post(
    "",
    response_model=PermissionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_permission(
    payload: PermissionCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    permission: str = Depends(require_permission("role.manage")),
    db: AsyncSession = Depends(get_db),
) -> PermissionResponse:
    """Create a new granular permission (requires 'role.manage' permission)."""
    created = await UserService.create_permission(
        db=db,
        payload=payload,
        actor_id=current_user.id,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return PermissionResponse.model_validate(created)
