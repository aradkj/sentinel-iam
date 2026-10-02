from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.user import UserCreate
from app.services.user_service import UserService


async def test_admin_permission(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify Admin role is granted user.create, user.delete, and report.view permissions."""
    admin_user = await UserService.create_user(
        db=db_session,
        payload=UserCreate(
            email="admin@example.com",
            username="admin_user",
            password="AdminPassword123!",
            first_name="System",
            last_name="Admin",
        ),
        role_name="admin",
    )
    target_user = await UserService.create_user(
        db=db_session,
        payload=UserCreate(
            email="target@example.com",
            username="target_user",
            password="TargetPassword123!",
            first_name="Target",
            last_name="Account",
        ),
        role_name="user",
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "AdminPassword123!"},
    )
    assert login_res.status_code == 200
    admin_token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin has report.view
    report_res = await client.get("/api/v1/users/reports", headers=headers)
    assert report_res.status_code == 200

    # Admin has user.create
    create_res = await client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "created.by.admin@example.com",
            "username": "created_by_admin",
            "password": "CreatedPassword123!",
            "first_name": "Created",
            "last_name": "ByAdmin",
        },
    )
    assert create_res.status_code == 201

    # Admin has user.delete
    delete_res = await client.delete(f"/api/v1/users/{target_user.id}", headers=headers)
    assert delete_res.status_code == 200
    assert delete_res.json()["message"] == "deleted"


async def test_employee_denied_permission(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify Employee role has report.view but is denied user.delete and user.create (HTTP 403)."""
    employee_user = await UserService.create_user(
        db=db_session,
        payload=UserCreate(
            email="employee@example.com",
            username="employee_user",
            password="EmployeePassword123!",
            first_name="Staff",
            last_name="Employee",
        ),
        role_name="employee",
    )
    other_user = await UserService.create_user(
        db=db_session,
        payload=UserCreate(
            email="regular@example.com",
            username="regular_user",
            password="RegularPassword123!",
            first_name="Regular",
            last_name="User",
        ),
        role_name="user",
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": employee_user.email, "password": "EmployeePassword123!"},
    )
    assert login_res.status_code == 200
    emp_token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {emp_token}"}

    # Employee is permitted to view reports (report.view)
    report_res = await client.get("/api/v1/users/reports", headers=headers)
    assert report_res.status_code == 200

    # Employee is denied user.delete -> 403 Forbidden
    delete_res = await client.delete(f"/api/v1/users/{other_user.id}", headers=headers)
    assert delete_res.status_code == 403

    # Employee is denied user.create -> 403 Forbidden
    create_res = await client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "email": "unauthorized.new@example.com",
            "username": "unauthorized_new",
            "password": "Password123!",
            "first_name": "No",
            "last_name": "Access",
        },
    )
    assert create_res.status_code == 403


async def test_role_and_permission_management(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify creating permissions, creating roles, assigning roles, and recording audit logs."""
    admin_user = await UserService.create_user(
        db=db_session,
        payload=UserCreate(
            email="secadmin@example.com",
            username="secadmin",
            password="AdminPassword123!",
            first_name="Security",
            last_name="Admin",
        ),
        role_name="admin",
    )
    member_user = await UserService.create_user(
        db=db_session,
        payload=UserCreate(
            email="member@example.com",
            username="member_user",
            password="MemberPassword123!",
            first_name="Team",
            last_name="Member",
        ),
        role_name="user",
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "AdminPassword123!"},
    )
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Create custom permission
    perm_res = await client.post(
        "/api/v1/permissions",
        headers=headers,
        json={"name": "billing.export", "description": "Export billing statements"},
    )
    assert perm_res.status_code == 201

    # Create custom role with permission
    role_res = await client.post(
        "/api/v1/roles",
        headers=headers,
        json={
            "name": "auditor",
            "description": "Financial auditor role",
            "permissions": ["report.view", "billing.export"],
        },
    )
    assert role_res.status_code == 201
    assert "billing.export" in role_res.json()["permissions"]

    # Assign role to user (records ROLE_CHANGE in audit_logs)
    assign_res = await client.post(
        "/api/v1/roles/assign",
        headers=headers,
        json={"user_id": member_user.id, "role_name": "auditor"},
    )
    assert assign_res.status_code == 200
    assert "auditor" in assign_res.json()["roles"]
    assert "billing.export" in assign_res.json()["permissions"]

    # Verify audit logs include ROLE_CHANGE
    audit_res = await client.get("/api/v1/users/audit-logs", headers=headers)
    assert audit_res.status_code == 200
    actions = [entry["action"] for entry in audit_res.json()]
    assert "ROLE_CHANGE" in actions
    assert "LOGIN_SUCCESS" in actions


async def test_admin_access(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify Admin can access all /api/v1/admin/* management and audit log endpoints."""
    admin_user = await UserService.create_user(
        db=db_session,
        payload=UserCreate(
            email="superadmin@example.com",
            username="superadmin",
            password="AdminPassword123!",
            first_name="Super",
            last_name="Admin",
        ),
        role_name="admin",
    )
    managed_user = await UserService.create_user(
        db=db_session,
        payload=UserCreate(
            email="managed@example.com",
            username="managed_user",
            password="ManagedPassword123!",
            first_name="Managed",
            last_name="User",
        ),
        role_name="user",
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": admin_user.email, "password": "AdminPassword123!"},
    )
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # GET /api/v1/admin/users
    users_res = await client.get("/api/v1/admin/users", headers=headers)
    assert users_res.status_code == 200
    assert len(users_res.json()) >= 2

    # GET /api/v1/admin/users/{id}
    user_detail = await client.get(f"/api/v1/admin/users/{managed_user.id}", headers=headers)
    assert user_detail.status_code == 200
    assert user_detail.json()["username"] == "managed_user"

    # PATCH /api/v1/admin/users/{id}/status
    status_res = await client.patch(
        f"/api/v1/admin/users/{managed_user.id}/status",
        headers=headers,
        json={"is_active": False, "unlock_account": True},
    )
    assert status_res.status_code == 200
    assert status_res.json()["is_active"] is False

    # POST /api/v1/admin/permissions
    perm_res = await client.post(
        "/api/v1/admin/permissions",
        headers=headers,
        json={"name": "analytics.read", "description": "Read analytics"},
    )
    assert perm_res.status_code == 201

    # POST /api/v1/admin/roles
    role_res = await client.post(
        "/api/v1/admin/roles",
        headers=headers,
        json={"name": "analyst", "description": "Data analyst", "permissions": []},
    )
    assert role_res.status_code == 201
    role_id = role_res.json()["id"]

    # POST /api/v1/admin/roles/{id}/permissions
    assign_perm_res = await client.post(
        f"/api/v1/admin/roles/{role_id}/permissions",
        headers=headers,
        json={"permission_name": "analytics.read"},
    )
    assert assign_perm_res.status_code == 200
    assert "analytics.read" in assign_perm_res.json()["permissions"]

    # PATCH /api/v1/admin/roles/{id}
    patch_role_res = await client.patch(
        f"/api/v1/admin/roles/{role_id}",
        headers=headers,
        json={"description": "Senior Data Analyst"},
    )
    assert patch_role_res.status_code == 200
    assert patch_role_res.json()["description"] == "Senior Data Analyst"

    # GET /api/v1/admin/audit-logs
    audit_logs_res = await client.get("/api/v1/admin/audit-logs", headers=headers)
    assert audit_logs_res.status_code == 200
    event_types = [e["event_type"] for e in audit_logs_res.json()]
    assert "ROLE_CREATED" in event_types
    assert "ROLE_UPDATED" in event_types
    assert "PERMISSION_CHANGED" in event_types

    # DELETE /api/v1/admin/roles/{id}
    del_role_res = await client.delete(f"/api/v1/admin/roles/{role_id}", headers=headers)
    assert del_role_res.status_code == 200

    # DELETE /api/v1/admin/users/{id}
    del_user_res = await client.delete(f"/api/v1/admin/users/{managed_user.id}", headers=headers)
    assert del_user_res.status_code == 200


async def test_employee_denied(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify Employee is denied access to /api/v1/admin/* endpoints (HTTP 403)."""
    emp_user = await UserService.create_user(
        db=db_session,
        payload=UserCreate(
            email="emp.staff@example.com",
            username="emp_staff",
            password="EmployeePassword123!",
            first_name="Employee",
            last_name="Staff",
        ),
        role_name="employee",
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": emp_user.email, "password": "EmployeePassword123!"},
    )
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Denied GET /api/v1/admin/users
    assert (await client.get("/api/v1/admin/users", headers=headers)).status_code == 403

    # Denied POST /api/v1/admin/roles
    assert (
        await client.post(
            "/api/v1/admin/roles",
            headers=headers,
            json={"name": "unauthorized_role"},
        )
    ).status_code == 403

    # Denied GET /api/v1/admin/audit-logs
    assert (await client.get("/api/v1/admin/audit-logs", headers=headers)).status_code == 403
