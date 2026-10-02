from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class TokenPayload(BaseModel):
    """Decoded JWT claims structure."""

    user_id: int
    sub: str | None = None
    role: str = "user"
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    jti: str
    type: str = "access"
    iat: int | None = None
    exp: int


class SessionRecord(BaseModel):
    """Representation of an active session tracked in Redis / PostgreSQL."""

    model_config = ConfigDict(from_attributes=True)

    id: int | None = None
    jti: str | None = None
    user_id: int | None = None
    device: str = "Chrome Windows"
    device_name: str = "Chrome Windows"
    ip: str = "127.0.0.1"
    ip_address: str | None = "127.0.0.1"
    user_agent: str | None = None
    last_activity: str | datetime | None = None
    created_at: datetime | str | None = None
    expires_at: datetime | str | None = None
    revoked: bool = False
    is_current: bool = False
