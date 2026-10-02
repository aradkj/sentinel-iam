from pydantic import BaseModel, ConfigDict, Field, model_validator


class PermissionCreate(BaseModel):
    """Schema for creating a new granular permission."""

    name: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-z0-9_.\-:]+$")
    description: str | None = Field(default=None, max_length=255)


class PermissionResponse(BaseModel):
    """Public schema for a permission."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None = None


class RoleCreate(BaseModel):
    """Schema for creating a new RBAC role."""

    name: str = Field(..., min_length=2, max_length=100, pattern=r"^[a-zA-Z0-9_\-]+$")
    description: str | None = Field(default=None, max_length=255)
    permissions: list[str] = Field(default_factory=list)


class RoleUpdate(BaseModel):
    """Schema for PATCH /admin/roles/{id}."""

    name: str | None = Field(default=None, min_length=2, max_length=100, pattern=r"^[a-zA-Z0-9_\-]+$")
    description: str | None = Field(default=None, max_length=255)
    permissions: list[str] | None = None


class RoleResponse(BaseModel):
    """Public schema for a role and its permissions."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None = None
    permissions: list[str] = Field(default_factory=list)


class AssignRoleRequest(BaseModel):
    """Payload to assign a role to a user."""

    user_id: int
    role_name: str = Field(..., min_length=2, max_length=100)


class AssignPermissionRequest(BaseModel):
    """Payload to attach one or more permissions to a role."""

    permission_name: str | None = Field(default=None, min_length=2, max_length=100)
    permissions: list[str] | None = None

    @model_validator(mode="after")
    def ensure_permissions_present(self) -> "AssignPermissionRequest":
        if not self.permission_name and not self.permissions:
            raise ValueError("Either 'permission_name' or 'permissions' list must be provided.")
        return self

    @property
    def resolved_permissions(self) -> list[str]:
        items: list[str] = []
        if self.permission_name:
            items.append(self.permission_name)
        if self.permissions:
            for p in self.permissions:
                if p not in items:
                    items.append(p)
        return items
