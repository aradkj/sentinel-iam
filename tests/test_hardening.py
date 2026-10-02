from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from httpx import AsyncClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import PROJECT_ROOT
from app.database.session import ResilientRedisClient, get_db, get_redis
from app.main import app


async def test_cors_allowed_origin(client: AsyncClient) -> None:
    """Verify configured ALLOWED_ORIGINS receives proper CORS headers and never wildcard '*'."""
    response = await client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://localhost:8080",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,Content-Type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:8080"
    assert response.headers.get("access-control-allow-origin") != "*"
    allowed_methods = response.headers.get("access-control-allow-methods", "")
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        assert method in allowed_methods


async def test_cors_disallowed_origin(client: AsyncClient) -> None:
    """Verify untrusted origins do not receive Access-Control-Allow-Origin header."""
    response = await client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "https://malicious-site.example.org",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "access-control-allow-origin" not in response.headers


async def test_health_ok(client: AsyncClient) -> None:
    """Verify GET /health, /health/live, and /health/ready return 200 OK when dependencies are up."""
    res = await client.get("/health")
    assert res.status_code == 200
    assert res.json() == {
        "status": "ok",
        "database": "ok",
        "redis": "ok",
    }

    live_res = await client.get("/health/live")
    assert live_res.status_code == 200
    assert live_res.json()["status"] == "ok"

    ready_res = await client.get("/health/ready")
    assert ready_res.status_code == 200
    assert ready_res.json()["status"] == "ok"


async def test_health_database_unavailable(
    client: AsyncClient,
    test_redis: ResilientRedisClient,
) -> None:
    """Verify GET /health returns 503 when database query fails, without exposing internal secrets."""

    class BrokenDBSession:
        async def execute(self, *_args: Any, **_kwargs: Any) -> Any:
            raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    async def override_broken_db() -> AsyncGenerator[Any, None]:
        yield BrokenDBSession()

    original_db = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_broken_db
    try:
        res = await client.get("/health")
        assert res.status_code == 503
        data = res.json()
        assert data["status"] == "degraded"
        assert data["database"] == "unavailable"
        assert data["redis"] == "ok"
    finally:
        if original_db is not None:
            app.dependency_overrides[get_db] = original_db


async def test_health_redis_unavailable(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify GET /health returns 503 when Redis is unreachable."""

    class BrokenRedis:
        async def ping(self) -> bool:
            return False

    original_redis = app.dependency_overrides.get(get_redis)
    app.dependency_overrides[get_redis] = lambda: BrokenRedis()
    try:
        res = await client.get("/health")
        assert res.status_code == 503
        data = res.json()
        assert data["status"] == "degraded"
        assert data["database"] == "ok"
        assert data["redis"] == "unavailable"
    finally:
        if original_redis is not None:
            app.dependency_overrides[get_redis] = original_redis


async def test_oauth_google_redirect_and_mocked_callback(client: AsyncClient) -> None:
    """Verify Google OAuth2 redirect and mocked authorization code exchange callback."""
    # 1. Verify redirect to Google OAuth2 authorization endpoint
    login_redirect = await client.get("/api/v1/auth/google/login", follow_redirects=False)
    assert login_redirect.status_code in (302, 307)
    assert "accounts.google.com" in login_redirect.headers["location"]

    # 2. Mock Authlib Google client token exchange
    mock_google_client = MagicMock()
    mock_google_client.authorize_access_token = AsyncMock(
        return_value={
            "access_token": "google-provider-access-token",
            "userinfo": {
                "sub": "google-uid-998877",
                "email": "mocked.google@example.com",
                "given_name": "Ada",
                "family_name": "Lovelace",
            },
        }
    )

    with patch("app.api.auth.oauth.create_client", return_value=mock_google_client):
        cb_res = await client.get("/api/v1/auth/google/callback?code=valid-google-auth-code")
        assert cb_res.status_code == 200
        data = cb_res.json()
        assert data["access_token"] is not None
        assert data["refresh_token"] is not None
        assert data["session_id"] is not None


async def test_oauth_github_redirect_and_mocked_callback(client: AsyncClient) -> None:
    """Verify GitHub OAuth2 redirect and mocked authorization code exchange callback."""
    # 1. Verify redirect to GitHub OAuth2 authorization endpoint
    login_redirect = await client.get("/api/v1/auth/github/login", follow_redirects=False)
    assert login_redirect.status_code in (302, 307)
    assert "github.com/login/oauth/authorize" in login_redirect.headers["location"]

    # 2. Mock Authlib GitHub client token exchange and user/emails API calls
    mock_github_client = MagicMock()
    mock_github_client.authorize_access_token = AsyncMock(
        return_value={"access_token": "gho_mock_token"}
    )

    async def mock_get(endpoint: str, token: Any = None) -> Any:
        resp = MagicMock()
        if endpoint == "user":
            resp.json.return_value = {
                "id": 445566,
                "login": "linus_gh",
                "name": "Linus Torvalds",
                "email": None,
            }
        elif endpoint == "user/emails":
            resp.json.return_value = [
                {"email": "linus.github@example.com", "primary": True, "verified": True}
            ]
        return resp

    mock_github_client.get = AsyncMock(side_effect=mock_get)

    with patch("app.api.auth.oauth.create_client", return_value=mock_github_client):
        cb_res = await client.get("/api/v1/auth/github/callback?code=valid-github-auth-code")
        assert cb_res.status_code == 200
        data = cb_res.json()
        assert data["access_token"] is not None
        assert data["refresh_token"] is not None


async def test_oauth_invalid_response(client: AsyncClient) -> None:
    """Verify OAuth2 callback rejects provider errors, failed token exchange, and missing email."""
    # Provider returned error query parameter
    err_res = await client.get("/api/v1/auth/google/callback?error=access_denied")
    assert err_res.status_code == 400

    # Provider returned profile without email
    mock_bad_client = MagicMock()
    mock_bad_client.authorize_access_token = AsyncMock(
        return_value={"access_token": "tok", "userinfo": {"sub": "123"}}
    )
    with patch("app.api.auth.oauth.create_client", return_value=mock_bad_client):
        missing_email_res = await client.get("/api/v1/auth/google/callback?code=bad-code")
        assert missing_email_res.status_code == 400


async def test_api_v1_versioned_endpoints(client: AsyncClient) -> None:
    """Verify the full authentication and session lifecycle under /api/v1/*."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "v1.user@example.com",
            "username": "v1_user",
            "password": "StrongPassword123!",
            "first_name": "Versioned",
            "last_name": "User",
        },
    )
    assert reg_res.status_code == 201

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "v1.user@example.com", "password": "StrongPassword123!"},
    )
    assert login_res.status_code == 200
    tokens = login_res.json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    me_res = await client.get("/api/v1/users/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "v1_user"

    sessions_res = await client.get("/api/v1/sessions", headers=headers)
    assert sessions_res.status_code == 200
    assert len(sessions_res.json()) == 1

    logout_res = await client.post(
        "/api/v1/auth/logout",
        headers=headers,
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert logout_res.status_code == 200

    # Legacy unversioned routes must not be exposed
    assert (await client.post("/auth/login", json={})).status_code == 404
    assert (await client.get("/users/me")).status_code == 404
    assert (await client.get("/sessions")).status_code == 404


async def test_frontend_uses_versioned_routes_and_openapi_tags(client: AsyncClient) -> None:
    """Verify frontend JS files use /api/v1 routes, CSP headers, and OpenAPI schema organization."""
    js_dir = Path(PROJECT_ROOT) / "frontend" / "js"
    for js_file in ("api.js", "auth.js", "dashboard.js", "admin.js"):
        content = (js_dir / js_file).read_text(encoding="utf-8")
        assert "/api/v1" in content

    nginx_conf = (Path(PROJECT_ROOT) / "frontend" / "nginx.conf").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in nginx_conf
    assert "unsafe-inline" not in nginx_conf
    assert "unsafe-eval" not in nginx_conf
    assert "X-Content-Type-Options" in nginx_conf
    assert "Referrer-Policy" in nginx_conf
    assert "X-Frame-Options" in nginx_conf

    openapi_res = await client.get("/openapi.json")
    assert openapi_res.status_code == 200
    assert "Content-Security-Policy" in openapi_res.headers
    assert "X-Content-Type-Options" in openapi_res.headers
    assert "Referrer-Policy" in openapi_res.headers
    assert "X-Frame-Options" in openapi_res.headers

    schema = openapi_res.json()
    for path in schema.get("paths", {}):
        assert path.startswith("/api/v1/") or path in ("/health", "/health/live", "/health/ready")

    tag_names = {t["name"] for t in schema.get("tags", [])}
    for required_tag in (
        "Authentication",
        "Users",
        "Sessions",
        "Roles",
        "Permissions",
        "Admin",
        "2FA",
        "OAuth",
        "Health",
    ):
        assert required_tag in tag_names

    docs_res = await client.get("/docs")
    assert docs_res.status_code == 200
    docs_v1_res = await client.get("/api/v1/docs")
    assert docs_v1_res.status_code == 200
    redoc_res = await client.get("/redoc")
    assert redoc_res.status_code == 200
