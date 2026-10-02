from datetime import timedelta

import jwt
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.jwt import create_access_token, decode_token, get_public_key_pem
from app.database.session import ResilientRedisClient
from app.models.audit import AuditLog
from app.services.email_service import EmailService


async def test_invalid_password(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify minimum 8-char password policy and HTTP 401 + audit logging on wrong password."""
    short_pw_res = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "shortpw@example.com",
            "username": "shortpw",
            "password": "short",
            "first_name": "Short",
            "last_name": "Password",
        },
    )
    assert short_pw_res.status_code == 422

    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "frank@example.com",
            "username": "frank",
            "password": "ValidPassword123!",
            "first_name": "Frank",
            "last_name": "Castle",
        },
    )
    assert reg_res.status_code == 201

    bad_login = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "frank@example.com",
            "password": "WrongPassword999!",
        },
    )
    assert bad_login.status_code == 401

    audit_res = await db_session.execute(
        select(AuditLog).where(AuditLog.event_type == "LOGIN_FAILED")
    )
    failed_logs = audit_res.scalars().all()
    assert len(failed_logs) >= 1


async def test_blacklisted_token(
    client: AsyncClient,
    test_redis: ResilientRedisClient,
) -> None:
    """Verify that a token whose JTI is in Redis blacklist:{jwt_id} is rejected with HTTP 401."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "grace@example.com",
            "username": "grace",
            "password": "ValidPassword123!",
            "first_name": "Grace",
            "last_name": "Murray",
        },
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "grace@example.com", "password": "ValidPassword123!"},
    )
    access_token = login_res.json()["access_token"]
    payload = decode_token(access_token)
    jti = payload["jti"]

    logout_res = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_res.status_code == 200

    blacklist_val = await test_redis.get(f"blacklist:{jti}")
    assert blacklist_val == "true"
    ttl = await test_redis.ttl(f"blacklist:{jti}")
    assert ttl > 0

    protected_res = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert protected_res.status_code == 401


async def test_expired_token(client: AsyncClient) -> None:
    """Verify that an expired JWT access token is rejected with HTTP 401."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "henry@example.com",
            "username": "henry",
            "password": "ValidPassword123!",
            "first_name": "Henry",
            "last_name": "Ford",
        },
    )
    user_id = reg_res.json()["id"]

    expired_token = create_access_token(
        user_id=user_id,
        role="user",
        expires_delta=timedelta(minutes=-5),
    )

    res = await client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()


async def test_rs256_asymmetric_jwt_signing(client: AsyncClient) -> None:
    """Verify tokens are signed with RS256 private.pem and verifiable with public.pem."""
    assert settings.JWT_ALGORITHM == "RS256"
    token = create_access_token(user_id=42, role="admin")
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"

    public_pem = get_public_key_pem()
    assert "BEGIN PUBLIC KEY" in public_pem
    decoded = jwt.decode(token, public_pem, algorithms=["RS256"])
    assert decoded["user_id"] == 42
    assert decoded["role"] == "admin"


async def test_account_lock(client: AsyncClient) -> None:
    """Verify 5 failed login attempts lock the account for 15 minutes and return HTTP 423 Locked."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "lockout@example.com",
            "username": "lockout_user",
            "password": "CorrectPassword123!",
            "first_name": "Lock",
            "last_name": "Target",
        },
    )

    # Perform 5 failed login attempts (using distinct client IPs to isolate account lock from IP rate limit)
    for attempt in range(5):
        res = await client.post(
            "/api/v1/auth/login",
            json={"email": "lockout@example.com", "password": "WrongPassword!"},
            headers={"X-Forwarded-For": f"198.51.100.{10 + attempt}"},
        )
        assert res.status_code == 401

    # 6th attempt (even with the correct password!) must return HTTP 423 Locked
    locked_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "lockout@example.com", "password": "CorrectPassword123!"},
        headers={"X-Forwarded-For": "198.51.100.99"},
    )
    assert locked_res.status_code == 423
    assert "locked" in locked_res.json()["detail"].lower()


async def test_password_reset(client: AsyncClient) -> None:
    """Verify forgot-password and one-time reset-password token flow."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "resetme@example.com",
            "username": "reset_user",
            "password": "OldPassword123!",
            "first_name": "Reset",
            "last_name": "User",
        },
    )

    forgot_res = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "resetme@example.com"},
    )
    assert forgot_res.status_code == 200
    reset_token = forgot_res.json().get("reset_token") or EmailService.last_reset_tokens.get(
        "resetme@example.com"
    )
    assert reset_token is not None

    # Consume reset token to set a new password
    reset_res = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": "BrandNewPassword456!",
        },
    )
    assert reset_res.status_code == 200

    # Re-using the same reset token must fail (one-time usage)
    reuse_res = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": reset_token,
            "new_password": "AnotherPassword789!",
        },
    )
    assert reuse_res.status_code == 400

    # Login with the new password succeeds
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "resetme@example.com", "password": "BrandNewPassword456!"},
    )
    assert login_res.status_code == 200


async def test_email_verification(client: AsyncClient) -> None:
    """Verify registration generates email verification token and GET /api/v1/auth/verify-email/{token} verifies user."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "verifyme@example.com",
            "username": "verify_user",
            "password": "ValidPassword123!",
            "first_name": "Verify",
            "last_name": "Me",
        },
    )
    assert reg_res.status_code == 201
    assert reg_res.json()["is_verified"] is False

    # Resend verification token
    resend_res = await client.post(
        "/api/v1/auth/resend-verification",
        json={"email": "verifyme@example.com"},
    )
    assert resend_res.status_code == 200
    token = resend_res.json()["verification_token"]

    # Verify email
    verify_res = await client.get(f"/api/v1/auth/verify-email/{token}")
    assert verify_res.status_code == 200
    assert verify_res.json()["is_verified"] is True

    # Re-using the verification token must fail
    reuse_verify = await client.get(f"/api/v1/auth/verify-email/{token}")
    assert reuse_verify.status_code == 400
