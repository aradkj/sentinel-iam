import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response

from app.api import admin, auth, permissions, roles, sessions, users
from app.core.config import PROJECT_ROOT, settings
from app.database.session import ResilientRedisClient, get_db, get_redis, redis_client
from app.middleware.rate_limit import RateLimitMiddleware

logger = logging.getLogger("iam.app")
FRONTEND_DIR = PROJECT_ROOT / "frontend"

OPENAPI_TAGS: list[dict[str, str]] = [
    {
        "name": "Authentication",
        "description": "User registration, login, RS256 token rotation, logout, email verification, and password recovery.",
    },
    {
        "name": "Users",
        "description": "Self-service user profile management, password updates, and security reporting.",
    },
    {
        "name": "Sessions",
        "description": "Multi-device active session inspection and single/global session revocation.",
    },
    {
        "name": "Roles",
        "description": "Role-Based Access Control (RBAC) role definitions and user role assignments.",
    },
    {
        "name": "Permissions",
        "description": "Granular permission definitions for fine-grained endpoint authorization.",
    },
    {
        "name": "Admin",
        "description": "Privileged administration endpoints for user lifecycle, RBAC governance, and security audit logs.",
    },
    {
        "name": "2FA",
        "description": "RFC 6238 Time-based One-Time Password (TOTP) two-factor authentication provisioning and verification.",
    },
    {
        "name": "OAuth",
        "description": "External OAuth2 social identity provider login and callback flows (Google & GitHub).",
    },
    {
        "name": "Health",
        "description": "Service liveness and dependency readiness probes (PostgreSQL & Redis).",
    },
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown resources."""
    yield
    await redis_client.aclose()


def create_application() -> FastAPI:
    """Application factory creating and configuring the FastAPI IAM microservice."""
    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=(
            "Enterprise Identity Provider (IdP) & Authentication/Authorization Microservice "
            "featuring RS256 asymmetric JWTs, stateful session management, account lockout protection, "
            "email verification, password reset, Redis token blacklisting, granular RBAC, "
            "TOTP 2FA, OAuth2 social login (Google & GitHub), rate limiting, and audit logging."
        ),
        openapi_tags=OPENAPI_TAGS,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Accept",
            "Origin",
            "X-Requested-With",
            "X-CSRF-Token",
            "X-Forwarded-For",
            "X-Real-IP",
        ],
    )
    application.add_middleware(
        SessionMiddleware,
        secret_key=settings.SESSION_SECRET_KEY,
    )
    application.add_middleware(RateLimitMiddleware)

    @application.exception_handler(SQLAlchemyError)
    async def sqlalchemy_exception_handler(
        request: Request,
        exc: SQLAlchemyError,
    ) -> JSONResponse:
        logger.error("Database operation failed on %s: %s", request.url.path, type(exc).__name__)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Database service is temporarily unavailable."},
        )

    @application.exception_handler(RedisError)
    async def redis_exception_handler(
        request: Request,
        exc: RedisError,
    ) -> JSONResponse:
        logger.error("Redis operation failed on %s: %s", request.url.path, type(exc).__name__)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Cache service is temporarily unavailable."},
        )

    @application.middleware("http")
    async def security_headers_middleware(
        request: Request,
        call_next: Any,
    ) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Frame-Options"] = "DENY"
        if not request.url.path.endswith(("/docs", "/redoc")):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "font-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            )
        return response

    # Versioned API v1 routers (/api/v1/...)
    v1_prefix = settings.API_V1_PREFIX
    application.include_router(auth.router, prefix=v1_prefix)
    application.include_router(users.router, prefix=v1_prefix)
    application.include_router(sessions.router, prefix=v1_prefix)
    application.include_router(roles.router, prefix=v1_prefix)
    application.include_router(permissions.router, prefix=v1_prefix)
    application.include_router(admin.router, prefix=v1_prefix)

    @application.get(
        f"{v1_prefix}/docs",
        include_in_schema=False,
    )
    async def swagger_ui_v1() -> HTMLResponse:
        """Serve Swagger UI at /api/v1/docs."""
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title=f"{settings.APP_NAME} - Swagger UI",
        )

    @application.get(
        f"{v1_prefix}/redoc",
        include_in_schema=False,
    )
    async def redoc_v1() -> HTMLResponse:
        """Serve ReDoc UI at /api/v1/redoc."""
        return get_redoc_html(
            openapi_url="/openapi.json",
            title=f"{settings.APP_NAME} - ReDoc",
        )

    @application.get(
        "/",
        include_in_schema=False,
    )
    async def root(request: Request) -> Any:
        """Root service metadata endpoint (or Frontend UI when accessed by a browser accepting text/html)."""
        accept = request.headers.get("accept", "")
        if "text/html" in accept and (FRONTEND_DIR / "index.html").exists():
            return FileResponse(FRONTEND_DIR / "index.html")
        return {
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "api_v1": settings.API_V1_PREFIX,
            "jwt_algorithm": settings.JWT_ALGORITHM,
            "status": "operational",
            "docs": "/docs",
            "health": "/health",
        }

    @application.get(
        "/health",
        tags=["Health"],
        summary="Check application, PostgreSQL database, and Redis readiness",
    )
    async def health_check(
        db: AsyncSession = Depends(get_db),
        redis: ResilientRedisClient = Depends(get_redis),
    ) -> JSONResponse:
        """Verify application health and connectivity to PostgreSQL and Redis."""
        db_status = "ok"
        redis_status = "ok"

        try:
            await db.execute(text("SELECT 1"))
        except Exception:
            db_status = "unavailable"

        try:
            ping_ok = await redis.ping()
            if not ping_ok:
                redis_status = "unavailable"
        except Exception:
            redis_status = "unavailable"

        overall_ok = db_status == "ok" and redis_status == "ok"
        payload = {
            "status": "ok" if overall_ok else "degraded",
            "database": db_status,
            "redis": redis_status,
        }
        http_status = (
            status.HTTP_200_OK
            if overall_ok
            else status.HTTP_503_SERVICE_UNAVAILABLE
        )
        return JSONResponse(status_code=http_status, content=payload)

    @application.get(
        "/health/live",
        tags=["Health"],
        summary="Lightweight container liveness probe",
    )
    async def liveness_check() -> dict[str, str]:
        """Return 200 OK when the ASGI process is alive."""
        return {"status": "ok"}

    @application.get(
        "/health/ready",
        tags=["Health"],
        summary="Readiness probe verifying database and Redis dependencies",
    )
    async def readiness_check(
        db: AsyncSession = Depends(get_db),
        redis: ResilientRedisClient = Depends(get_redis),
    ) -> JSONResponse:
        """Verify database and Redis readiness before accepting traffic."""
        return await health_check(db=db, redis=redis)

    if FRONTEND_DIR.exists():
        if (FRONTEND_DIR / "css").exists():
            application.mount(
                "/css",
                StaticFiles(directory=str(FRONTEND_DIR / "css")),
                name="frontend-css",
            )
        if (FRONTEND_DIR / "js").exists():
            application.mount(
                "/js",
                StaticFiles(directory=str(FRONTEND_DIR / "js")),
                name="frontend-js",
            )

        for page_name in (
            "index.html",
            "login.html",
            "register.html",
            "dashboard.html",
            "profile.html",
            "sessions.html",
            "admin.html",
        ):
            page_path = FRONTEND_DIR / page_name

            def _make_page_handler(target: Path) -> Any:
                async def _serve_page() -> FileResponse:
                    return FileResponse(target)

                return _serve_page

            application.add_api_route(
                f"/{page_name}",
                _make_page_handler(page_path),
                methods=["GET", "HEAD"],
                include_in_schema=False,
            )

    return application


app = create_application()
