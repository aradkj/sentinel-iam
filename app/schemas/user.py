from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    """Schema for registering or creating a new user account."""

    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_.\-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)


class UserUpdate(BaseModel):
    """Schema for updating user profile fields."""

    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    is_active: bool | None = None
    is_verified: bool | None = None


class UserStatusUpdate(BaseModel):
    """Admin payload for PATCH /admin/users/{id}/status."""

    is_active: bool
    is_verified: bool | None = None
    unlock_account: bool = True


class PasswordChangeRequest(BaseModel):
    """Schema for changing an authenticated user's password."""

    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)


class UserResponse(BaseModel):
    """Public representation of a user account."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    username: str
    first_name: str
    last_name: str
    is_active: bool
    is_verified: bool
    two_factor_enabled: bool
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    last_login_at: datetime | None = None
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    verification_token: str | None = None


class AuditLogResponse(BaseModel):
    """Representation of a security audit log entry."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int | None
    event_type: str
    action: str
    description: str | None = None
    details: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: datetime

    @classmethod
    def from_orm_entry(cls, entry: Any) -> "AuditLogResponse":
        return cls(
            id=entry.id,
            user_id=entry.user_id,
            event_type=entry.event_type or entry.action,
            action=entry.action or entry.event_type,
            description=entry.description or entry.details,
            details=entry.details or entry.description,
            ip_address=entry.ip_address,
            user_agent=entry.user_agent,
            metadata=entry.audit_metadata,
            created_at=entry.created_at,
        )
