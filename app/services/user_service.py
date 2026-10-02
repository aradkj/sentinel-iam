from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import log_security_event, sanitize_metadata
from app.core.security import hash_password, verify_password
from app.models.audit import AuditLog
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User
from app.schemas.role import PermissionCreate, RoleCreate, RoleResponse, RoleUpdate
from app.schemas.user import (
    PasswordChangeRequest,
    UserCreate,
    UserResponse,
    UserStatusUpdate,
)
from app.services.email_service import EmailService
from app.services.otp_service import OTPService

DEFAULT_PERMISSIONS: dict[str, str] = {
    "user.create": "Create new user accounts",
    "user.read": "Read user account details",
    "user.update": "Update existing user accounts",
    "user.delete": "Delete user accounts",
    "report.view": "View system reports and audit logs",
    "role.manage": "Manage roles and permission assignments",
}

DEFAULT_ROLES: dict[str, tuple[str, list[str]]] = {
    "admin": (
        "System administrator with full user and report permissions",
        [
            "user.create",
            "user.read",
            "user.update",
            "user.delete",
            "report.view",
            "role.manage",
        ],
    ),
    "employee": (
        "Internal employee with report viewing privileges",
        ["report.view"],
    ),
    "user": (
        "Standard authenticated user",
        [],
    ),
}


class UserService:
    """Domain service for user management, RBAC role/permission administration, and audit logging."""

    @staticmethod
    def to_user_response(
        user: User,
        verification_token: str | None = None,
    ) -> UserResponse:
        """Convert a User ORM instance into a UserResponse schema."""
        return UserResponse(
            id=user.id,
            email=user.email,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name,
            is_active=user.is_active,
            is_verified=user.is_verified,
            two_factor_enabled=user.two_factor_enabled,
            failed_login_attempts=user.failed_login_attempts,
            locked_until=user.locked_until,
            last_login_at=user.last_login_at,
            roles=user.role_names,
            permissions=user.permission_names,
            created_at=user.created_at,
            updated_at=user.updated_at,
            verification_token=verification_token,
        )

    @staticmethod
    def to_role_response(role: Role) -> RoleResponse:
        """Convert a Role ORM instance into a RoleResponse schema."""
        return RoleResponse(
            id=role.id,
            name=role.name,
            description=role.description,
            permissions=sorted({p.name for p in (role.permissions or [])}),
        )

    @classmethod
    async def record_audit_log(
        cls,
        db: AsyncSession,
        action: str,
        user_id: int | None = None,
        ip_address: str | None = None,
        details: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
        commit: bool = True,
    ) -> AuditLog:
        """Record an enriched security audit event in PostgreSQL and emit structured log."""
        safe_meta = sanitize_metadata(metadata)
        log_security_event(
            event_type=action,
            user_id=user_id,
            ip_address=ip_address,
            description=details,
            metadata=safe_meta,
        )
        entry = AuditLog(
            user_id=user_id,
            event_type=action,
            action=action,
            description=details,
            details=details,
            ip_address=ip_address or "127.0.0.1",
            user_agent=user_agent or "Chrome Windows",
            audit_metadata=safe_meta,
        )
        db.add(entry)
        if commit:
            await db.commit()
            await db.refresh(entry)
        return entry

    @classmethod
    async def ensure_default_rbac(cls, db: AsyncSession) -> dict[str, Role]:
        """Seed default permissions and roles (admin, employee, user) idempotently."""
        existing_perms_res = await db.execute(select(Permission))
        perm_map: dict[str, Permission] = {
            p.name: p for p in existing_perms_res.scalars().all()
        }

        for perm_name, perm_desc in DEFAULT_PERMISSIONS.items():
            if perm_name not in perm_map:
                perm = Permission(name=perm_name, description=perm_desc)
                db.add(perm)
                perm_map[perm_name] = perm

        await db.flush()

        existing_roles_res = await db.execute(
            select(Role).options(selectinload(Role.permissions))
        )
        role_map: dict[str, Role] = {
            r.name: r for r in existing_roles_res.scalars().all()
        }

        for role_name, (role_desc, role_perm_names) in DEFAULT_ROLES.items():
            if role_name not in role_map:
                role = Role(
                    name=role_name,
                    description=role_desc,
                    permissions=[perm_map[p] for p in role_perm_names if p in perm_map],
                )
                db.add(role)
                role_map[role_name] = role
            else:
                role = role_map[role_name]
                current_perm_names = {p.name for p in (role.permissions or [])}
                for p_name in role_perm_names:
                    if p_name not in current_perm_names and p_name in perm_map:
                        role.permissions.append(perm_map[p_name])

        await db.commit()
        return role_map

    @classmethod
    async def get_user_by_id(cls, db: AsyncSession, user_id: int) -> User | None:
        """Fetch a user by ID with roles and permissions eagerly loaded."""
        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.id == user_id)
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def get_user_by_email(cls, db: AsyncSession, email: str) -> User | None:
        """Fetch a user by email address (case-insensitive)."""
        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(User.email == email.lower().strip())
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @classmethod
    async def get_user_by_identifier(
        cls,
        db: AsyncSession,
        email: str | None = None,
        username: str | None = None,
    ) -> User | None:
        """Fetch a user by email or username."""
        conditions = []
        if email:
            conditions.append(User.email == email.lower().strip())
        if username:
            conditions.append(User.username == username.strip())
            conditions.append(User.email == username.lower().strip())

        if not conditions:
            return None

        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .where(or_(*conditions))
        )
        result = await db.execute(stmt)
        return result.scalars().first()

    @classmethod
    async def create_user(
        cls,
        db: AsyncSession,
        payload: UserCreate,
        role_name: str = "user",
        ip_address: str | None = None,
        user_agent: str | None = None,
        send_verification: bool = True,
    ) -> User:
        """Create a new user with bcrypt-hashed password, assigned role, and verification token."""
        normalized_email = payload.email.lower().strip()
        normalized_username = payload.username.strip()

        existing_stmt = select(User).where(
            or_(
                User.email == normalized_email,
                User.username == normalized_username,
            )
        )
        existing_result = await db.execute(existing_stmt)
        existing_user = existing_result.scalars().first()
        if existing_user is not None:
            if existing_user.email == normalized_email:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="A user with this email is already registered.",
                )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A user with this username is already taken.",
            )

        role_map = await cls.ensure_default_rbac(db)
        assigned_role = role_map.get(role_name) or role_map["user"]

        user = User(
            email=normalized_email,
            username=normalized_username,
            first_name=payload.first_name.strip(),
            last_name=payload.last_name.strip(),
            hashed_password=hash_password(payload.password),
            is_active=True,
            is_verified=False,
            two_factor_enabled=False,
            failed_login_attempts=0,
            locked_until=None,
            roles=[assigned_role],
        )
        db.add(user)
        await db.commit()

        if send_verification:
            await EmailService.create_verification_token(db, user)

        reloaded = await cls.get_user_by_id(db, user.id)
        assert reloaded is not None

        await cls.record_audit_log(
            db=db,
            action="USER_REGISTERED",
            user_id=reloaded.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Registered user '{reloaded.username}' with role '{assigned_role.name}'",
            metadata={"username": reloaded.username, "role": assigned_role.name},
        )
        return reloaded

    @classmethod
    async def change_password(
        cls,
        db: AsyncSession,
        user: User,
        payload: PasswordChangeRequest,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> User:
        """Verify current password, update to new bcrypt hash, and write PASSWORD_CHANGED audit log."""
        if not verify_password(payload.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect.",
            )
        user.hashed_password = hash_password(payload.new_password)
        db.add(user)
        await db.commit()

        await cls.record_audit_log(
            db=db,
            action="PASSWORD_CHANGED",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details="User changed password",
            metadata={"event": "PASSWORD_CHANGED"},
        )
        return user

    @classmethod
    async def enable_2fa(
        cls,
        db: AsyncSession,
        user: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[str, str]:
        """Generate a TOTP secret for the user, enable 2FA, and return (secret, otpauth_url)."""
        secret = OTPService.generate_secret()
        otpauth_url = OTPService.get_provisioning_uri(secret=secret, email=user.email)
        user.two_factor_secret = secret
        user.two_factor_enabled = True
        db.add(user)
        await db.commit()

        await cls.record_audit_log(
            db=db,
            action="2FA_ENABLED",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details="TOTP 2FA enabled for account",
        )
        return secret, otpauth_url

    @classmethod
    async def disable_2fa(
        cls,
        db: AsyncSession,
        user: User,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> User:
        """Disable 2FA and clear TOTP secret for the user."""
        user.two_factor_enabled = False
        user.two_factor_secret = None
        db.add(user)
        await db.commit()

        await cls.record_audit_log(
            db=db,
            action="2FA_DISABLED",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details="TOTP 2FA disabled for account",
        )
        return user

    @classmethod
    async def update_user_status(
        cls,
        db: AsyncSession,
        target_user_id: int,
        payload: UserStatusUpdate,
        actor_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> User:
        """Admin action to activate/disable a user or unlock a locked account."""
        user = await cls.get_user_by_id(db, target_user_id)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with id={target_user_id} not found.",
            )

        user.is_active = payload.is_active
        if payload.is_verified is not None:
            user.is_verified = payload.is_verified
        if payload.unlock_account:
            user.failed_login_attempts = 0
            user.locked_until = None

        db.add(user)
        await db.commit()

        await cls.record_audit_log(
            db=db,
            action="USER_STATUS_UPDATED",
            user_id=actor_id or user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Updated status for user_id={user.id} (is_active={user.is_active})",
            metadata={"target_user_id": user.id, "is_active": user.is_active},
        )
        reloaded = await cls.get_user_by_id(db, user.id)
        assert reloaded is not None
        return reloaded

    @classmethod
    async def delete_user(
        cls,
        db: AsyncSession,
        target_user_id: int,
        actor_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Delete a user account by ID and log the administrative action."""
        target = await cls.get_user_by_id(db, target_user_id)
        if target is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with id={target_user_id} not found.",
            )
        username = target.username
        await db.delete(target)
        await db.commit()

        await cls.record_audit_log(
            db=db,
            action="USER_DELETED",
            user_id=actor_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Deleted user id={target_user_id} username='{username}'",
            metadata={"deleted_user_id": target_user_id, "username": username},
        )

    @classmethod
    async def list_users(cls, db: AsyncSession, skip: int = 0, limit: int = 100) -> list[User]:
        """List users with roles and permissions."""
        stmt = (
            select(User)
            .options(selectinload(User.roles).selectinload(Role.permissions))
            .offset(skip)
            .limit(limit)
            .order_by(User.id.asc())
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())

    @classmethod
    async def create_permission(
        cls,
        db: AsyncSession,
        payload: PermissionCreate,
        actor_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Permission:
        """Create a new granular permission and record PERMISSION_CHANGED audit event."""
        stmt = select(Permission).where(Permission.name == payload.name)
        res = await db.execute(stmt)
        if res.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Permission '{payload.name}' already exists.",
            )
        permission = Permission(name=payload.name, description=payload.description)
        db.add(permission)
        await db.commit()
        await db.refresh(permission)

        await cls.record_audit_log(
            db=db,
            action="PERMISSION_CHANGED",
            user_id=actor_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Created permission '{permission.name}'",
            metadata={"permission": permission.name},
        )
        return permission

    @classmethod
    async def list_permissions(cls, db: AsyncSession) -> list[Permission]:
        """List all permissions."""
        await cls.ensure_default_rbac(db)
        stmt = select(Permission).order_by(Permission.name.asc())
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def create_role(
        cls,
        db: AsyncSession,
        payload: RoleCreate,
        actor_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Role:
        """Create a new RBAC role, attach permissions, and log ROLE_CREATED audit event."""
        await cls.ensure_default_rbac(db)
        stmt = select(Role).where(Role.name == payload.name)
        res = await db.execute(stmt)
        if res.scalar_one_or_none() is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role '{payload.name}' already exists.",
            )

        permissions: list[Permission] = []
        if payload.permissions:
            perm_stmt = select(Permission).where(Permission.name.in_(payload.permissions))
            perm_res = await db.execute(perm_stmt)
            permissions = list(perm_res.scalars().all())

        role = Role(
            name=payload.name,
            description=payload.description,
            permissions=permissions,
        )
        db.add(role)
        await db.commit()

        await cls.record_audit_log(
            db=db,
            action="ROLE_CREATED",
            user_id=actor_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Created role '{role.name}'",
            metadata={"role_id": role.id, "role_name": role.name, "permissions": payload.permissions},
        )

        reloaded_stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.id == role.id)
        )
        reloaded_res = await db.execute(reloaded_stmt)
        return reloaded_res.scalar_one()

    @classmethod
    async def update_role(
        cls,
        db: AsyncSession,
        role_id: int,
        payload: RoleUpdate,
        actor_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Role:
        """Update an existing role's name, description, or permissions and log ROLE_UPDATED."""
        await cls.ensure_default_rbac(db)
        stmt = select(Role).options(selectinload(Role.permissions)).where(Role.id == role_id)
        res = await db.execute(stmt)
        role = res.scalar_one_or_none()
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role with id={role_id} not found.",
            )

        if payload.name is not None:
            role.name = payload.name
        if payload.description is not None:
            role.description = payload.description
        if payload.permissions is not None:
            perm_stmt = select(Permission).where(Permission.name.in_(payload.permissions))
            perm_res = await db.execute(perm_stmt)
            role.permissions = list(perm_res.scalars().all())

        db.add(role)
        await db.commit()

        await cls.record_audit_log(
            db=db,
            action="ROLE_UPDATED",
            user_id=actor_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Updated role id={role.id} name='{role.name}'",
            metadata={"role_id": role.id, "role_name": role.name},
        )

        reloaded_res = await db.execute(stmt)
        return reloaded_res.scalar_one()

    @classmethod
    async def delete_role(
        cls,
        db: AsyncSession,
        role_id: int,
        actor_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Delete a role by ID and log ROLE_UPDATED audit event."""
        stmt = select(Role).where(Role.id == role_id)
        res = await db.execute(stmt)
        role = res.scalar_one_or_none()
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role with id={role_id} not found.",
            )
        role_name = role.name
        await db.delete(role)
        await db.commit()

        await cls.record_audit_log(
            db=db,
            action="ROLE_UPDATED",
            user_id=actor_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Deleted role id={role_id} name='{role_name}'",
            metadata={"deleted_role_id": role_id, "role_name": role_name},
        )

    @classmethod
    async def list_roles(cls, db: AsyncSession) -> list[Role]:
        """List all RBAC roles with their permissions."""
        await cls.ensure_default_rbac(db)
        stmt = select(Role).options(selectinload(Role.permissions)).order_by(Role.name.asc())
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def assign_role_to_user(
        cls,
        db: AsyncSession,
        user_id: int,
        role_name: str,
        actor_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        replace_existing: bool = False,
    ) -> User:
        """Assign an RBAC role to a user and record a ROLE_CHANGE / ROLE_UPDATED audit log entry."""
        await cls.ensure_default_rbac(db)
        user = await cls.get_user_by_id(db, user_id)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with id={user_id} not found.",
            )

        role_stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.name == role_name)
        )
        role_res = await db.execute(role_stmt)
        role = role_res.scalar_one_or_none()
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role '{role_name}' not found.",
            )

        if replace_existing:
            user.roles = [role]
        elif all(r.id != role.id for r in user.roles):
            user.roles.append(role)

        db.add(user)
        await db.commit()

        await cls.record_audit_log(
            db=db,
            action="ROLE_CHANGE",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Assigned role '{role.name}' to user_id={user.id} (by actor={actor_id})",
            metadata={"target_user_id": user.id, "role_name": role.name, "actor_id": actor_id},
        )

        reloaded = await cls.get_user_by_id(db, user.id)
        assert reloaded is not None
        return reloaded

    @classmethod
    async def assign_permission_to_role(
        cls,
        db: AsyncSession,
        role_id: int,
        permission_name: str | None = None,
        permission_names: list[str] | None = None,
        actor_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> Role:
        """Attach one or more permissions to a role and record PERMISSION_CHANGED."""
        await cls.ensure_default_rbac(db)
        role_stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.id == role_id)
        )
        role_res = await db.execute(role_stmt)
        role = role_res.scalar_one_or_none()
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role with id={role_id} not found.",
            )

        names_to_add: list[str] = []
        if permission_name:
            names_to_add.append(permission_name)
        if permission_names:
            for p in permission_names:
                if p not in names_to_add:
                    names_to_add.append(p)

        for name in names_to_add:
            perm_stmt = select(Permission).where(Permission.name == name)
            perm_res = await db.execute(perm_stmt)
            perm = perm_res.scalar_one_or_none()
            if perm is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Permission '{name}' not found.",
                )
            if all(p.id != perm.id for p in role.permissions):
                role.permissions.append(perm)

        db.add(role)
        await db.commit()

        await cls.record_audit_log(
            db=db,
            action="PERMISSION_CHANGED",
            user_id=actor_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Assigned permissions {names_to_add} to role '{role.name}'",
            metadata={"role_id": role.id, "role_name": role.name, "permissions": names_to_add},
        )

        reloaded_res = await db.execute(role_stmt)
        return reloaded_res.scalar_one()

    @classmethod
    async def list_audit_logs(
        cls,
        db: AsyncSession,
        limit: int = 100,
        user_id: int | None = None,
    ) -> list[AuditLog]:
        """Query security audit logs ordered from newest to oldest."""
        stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
        if user_id is not None:
            stmt = stmt.where(AuditLog.user_id == user_id)
        res = await db.execute(stmt)
        return list(res.scalars().all())
