from httpx import AsyncClient

from app.core.jwt import decode_token
from app.services.otp_service import OTPService


async def test_register(client: AsyncClient) -> None:
    """Verify user registration hashes password and creates default user role."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "username": "alice",
            "password": "StrongPassword123!",
            "first_name": "Alice",
            "last_name": "Anderson",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "alice@example.com"
    assert data["username"] == "alice"
    assert data["first_name"] == "Alice"
    assert data["last_name"] == "Anderson"
    assert data["is_active"] is True
    assert data["two_factor_enabled"] is False
    assert "user" in data["roles"]
    assert "password" not in data
    assert "hashed_password" not in data


async def test_login(client: AsyncClient) -> None:
    """Verify registered user can authenticate and receive JWT access and refresh tokens."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "bob@example.com",
            "username": "bob",
            "password": "StrongPassword123!",
            "first_name": "Bob",
            "last_name": "Builder",
        },
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "bob@example.com",
            "password": "StrongPassword123!",
        },
    )
    assert login_res.status_code == 200
    tokens = login_res.json()
    assert tokens["access_token"] is not None
    assert tokens["refresh_token"] is not None
    assert tokens["token_type"] == "bearer"

    access_claims = decode_token(tokens["access_token"])
    assert access_claims["role"] == "user"
    assert "jti" in access_claims
    assert "exp" in access_claims


async def test_refresh_token(client: AsyncClient) -> None:
    """Verify refresh token rotation issues new tokens and revokes the old refresh token."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "carol@example.com",
            "username": "carol",
            "password": "StrongPassword123!",
            "first_name": "Carol",
            "last_name": "Danvers",
        },
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "carol@example.com", "password": "StrongPassword123!"},
    )
    first_tokens = login_res.json()
    old_refresh = first_tokens["refresh_token"]

    refresh_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh},
    )
    assert refresh_res.status_code == 200
    rotated_tokens = refresh_res.json()
    assert rotated_tokens["access_token"] != first_tokens["access_token"]
    assert rotated_tokens["refresh_token"] != old_refresh

    # Re-using the revoked refresh token must be rejected with HTTP 401
    reuse_res = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": old_refresh},
    )
    assert reuse_res.status_code == 401


async def test_logout(client: AsyncClient) -> None:
    """Verify logout blacklists the JWT in Redis and removes the active session."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "dave@example.com",
            "username": "dave",
            "password": "StrongPassword123!",
            "first_name": "Dave",
            "last_name": "Bowman",
        },
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "dave@example.com", "password": "StrongPassword123!"},
    )
    tokens = login_res.json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    sessions_before = await client.get("/api/v1/sessions", headers=headers)
    assert sessions_before.status_code == 200
    assert len(sessions_before.json()) == 1

    logout_res = await client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers=headers,
    )
    assert logout_res.status_code == 200
    assert logout_res.json()["message"] == "Successfully logged out"

    # Subsequent protected request with the logged-out token must return 401
    me_res = await client.get("/api/v1/users/me", headers=headers)
    assert me_res.status_code == 401


async def test_two_factor_auth_flow(client: AsyncClient) -> None:
    """Verify enabling TOTP 2FA and completing the two-step OTP login flow."""
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "eve@example.com",
            "username": "eve",
            "password": "StrongPassword123!",
            "first_name": "Eve",
            "last_name": "Polastri",
        },
    )

    initial_login = await client.post(
        "/api/v1/auth/login",
        json={"email": "eve@example.com", "password": "StrongPassword123!"},
    )
    access_token = initial_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    # Enable 2FA
    enable_res = await client.post("/api/v1/users/enable-2fa", headers=headers)
    assert enable_res.status_code == 200
    secret = enable_res.json()["secret"]
    assert "otpauth://totp/" in enable_res.json()["otpauth_url"]

    # Login now returns temporary token and requires_2fa=True
    step1_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "eve@example.com", "password": "StrongPassword123!"},
    )
    assert step1_res.status_code == 200
    step1_data = step1_res.json()
    assert step1_data["requires_2fa"] is True
    assert step1_data["access_token"] is None
    assert step1_data["temp_token"] is not None

    # Verify TOTP code
    otp_code = OTPService.generate_current_otp(secret)
    step2_res = await client.post(
        "/api/v1/auth/verify-otp",
        json={"temp_token": step1_data["temp_token"], "otp_code": otp_code},
    )
    assert step2_res.status_code == 200
    final_tokens = step2_res.json()
    assert final_tokens["access_token"] is not None
    assert final_tokens["refresh_token"] is not None


async def test_oauth_social_login(client: AsyncClient) -> None:
    """Verify OAuth2 callback auto-provisions user and returns JWT tokens for Google and GitHub."""
    google_res = await client.post(
        "/api/v1/auth/oauth/google/callback",
        json={
            "email": "social.google@example.com",
            "username": "google_user",
            "first_name": "Grace",
            "last_name": "Hopper",
            "provider_id": "google-12345",
        },
    )
    assert google_res.status_code == 200
    assert google_res.json()["access_token"] is not None

    github_res = await client.post(
        "/api/v1/auth/oauth/github/callback",
        json={
            "email": "social.github@example.com",
            "username": "octocat",
            "first_name": "Mona",
            "last_name": "Octocat",
            "provider_id": "github-67890",
        },
    )
    assert github_res.status_code == 200
    assert github_res.json()["access_token"] is not None


async def test_oauth_callback(client: AsyncClient) -> None:
    """Verify /api/v1/auth/google/callback and /api/v1/auth/github/callback create or login users and create sessions."""
    google_cb = await client.post(
        "/api/v1/auth/google/callback",
        json={
            "email": "oauth.google.cb@example.com",
            "username": "google_cb_user",
            "first_name": "Google",
            "last_name": "Callback",
            "provider_id": "google-cb-001",
        },
    )
    assert google_cb.status_code == 200
    tokens = google_cb.json()
    assert tokens["access_token"] is not None
    assert tokens["session_id"] is not None

    github_cb = await client.post(
        "/api/v1/auth/github/callback",
        json={
            "email": "oauth.github.cb@example.com",
            "username": "github_cb_user",
            "first_name": "GitHub",
            "last_name": "Callback",
            "provider_id": "github-cb-002",
        },
    )
    assert github_cb.status_code == 200
    assert github_cb.json()["access_token"] is not None
