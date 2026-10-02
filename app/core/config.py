import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def _get_ephemeral_rsa_keypair() -> tuple[str, str]:
    """Generate an in-memory 2048-bit RSA keypair when local .pem files have not been generated yet."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_pem, public_pem


class Settings(BaseSettings):
    """Centralized application settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application Metadata
    APP_NAME: str = "Secure Identity & Access Management Service (IAM)"
    APP_VERSION: str = "2.1.0"
    APP_ENV: Literal["development", "staging", "production", "test"] = "development"
    APP_DEBUG: bool = False
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_V1_PREFIX: str = "/api/v1"
    FRONTEND_URL: str = "http://localhost:8080"

    # CORS Configuration (no wildcard origins)
    ALLOWED_ORIGINS: list[str] | str = Field(
        default=[
            "http://localhost",
            "http://localhost:80",
            "http://localhost:3000",
            "http://localhost:8080",
        ],
        description="Explicit list or comma-separated string of allowed CORS origins.",
    )

    # Database Configuration
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://iam_user:change_me@postgres:5432/iam_db",
        description="SQLAlchemy database connection string.",
    )

    # Redis Configuration
    REDIS_URL: str = Field(
        default="redis://redis:6379/0",
        description="Redis connection URL for token blacklisting, sessions, and rate limiting.",
    )

    # JWT Asymmetric (RS256) & Symmetric (HS256) Configuration
    JWT_ALGORITHM: Literal["RS256", "HS256"] = "RS256"
    JWT_PRIVATE_KEY_PATH: str = "/app/keys/private.pem"
    JWT_PUBLIC_KEY_PATH: str = "/app/keys/public.pem"
    JWT_PRIVATE_KEY: str | None = None
    JWT_PUBLIC_KEY: str | None = None
    JWT_SECRET_KEY: str = Field(
        default="dev-only-hs256-fallback-key-replace-via-env-in-production-012345",
        min_length=32,
        description="Fallback secret key when HS256 is explicitly selected.",
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    TEMP_2FA_TOKEN_EXPIRE_MINUTES: int = 5

    # Account Security & Lockout Policy
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15

    # Email Verification & Password Reset (MailHog in development)
    SMTP_HOST: str = "mailhog"
    SMTP_PORT: int = 1025
    SMTP_FROM_EMAIL: str = "noreply@iam-service.local"
    EMAIL_VERIFICATION_EXPIRE_HOURS: int = 24
    PASSWORD_RESET_EXPIRE_MINUTES: int = 30

    # Rate Limiting Configuration
    RATE_LIMIT_REQUESTS: int = 5
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    RATE_LIMIT_ENABLED: bool = True

    # Two-Factor Authentication (TOTP)
    TOTP_ISSUER_NAME: str = "Enterprise IAM Service"

    # OAuth2 Social Login Providers
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/google/callback"

    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_REDIRECT_URI: str = "http://localhost:8000/api/v1/auth/github/callback"

    # Session Middleware Secret (required by Authlib OAuth state tracking)
    SESSION_SECRET_KEY: str = "dev-session-secret-override-in-env-file-for-production"

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_allowed_origins(cls, value: Any) -> list[str]:
        """Parse comma-separated or JSON-encoded ALLOWED_ORIGINS into a list of non-wildcard origins."""
        if isinstance(value, str):
            raw = value.strip()
            if raw.startswith("["):
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list):
                        return [str(o).strip() for o in parsed if str(o).strip() and str(o).strip() != "*"]
                except Exception:
                    pass
            return [o.strip() for o in raw.split(",") if o.strip() and o.strip() != "*"]
        if isinstance(value, list):
            return [str(o).strip() for o in value if str(o).strip() and str(o).strip() != "*"]
        return ["http://localhost"]

    @property
    def allowed_origins_list(self) -> list[str]:
        """Return the validated list of allowed CORS origins (never containing '*')."""
        if isinstance(self.ALLOWED_ORIGINS, str):
            return self.parse_allowed_origins(self.ALLOWED_ORIGINS)
        return [o for o in self.ALLOWED_ORIGINS if o and o != "*"]

    def resolve_key_path(self, raw_path: str, filename: str) -> Path | None:
        """Resolve an RSA key file across configured path, ./keys/, or ./security/."""
        candidates = [
            Path(raw_path),
            PROJECT_ROOT / raw_path.lstrip("/"),
            PROJECT_ROOT / "keys" / filename,
            PROJECT_ROOT / "security" / filename,
        ]
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate.resolve()
        return None

    def load_private_key(self) -> str:
        """Load the RSA private key PEM content for RS256 signing."""
        if self.JWT_PRIVATE_KEY:
            return self.JWT_PRIVATE_KEY
        path = self.resolve_key_path(self.JWT_PRIVATE_KEY_PATH, "private.pem")
        if path is not None:
            return path.read_text(encoding="utf-8")
        priv_pem, _ = _get_ephemeral_rsa_keypair()
        return priv_pem

    def load_public_key(self) -> str:
        """Load the RSA public key PEM content for RS256 verification."""
        if self.JWT_PUBLIC_KEY:
            return self.JWT_PUBLIC_KEY
        path = self.resolve_key_path(self.JWT_PUBLIC_KEY_PATH, "public.pem")
        if path is not None:
            return path.read_text(encoding="utf-8")
        _, pub_pem = _get_ephemeral_rsa_keypair()
        return pub_pem

    @property
    def async_database_url(self) -> str:
        """Return an async-compatible SQLAlchemy database URL."""
        if self.DATABASE_URL.startswith("postgresql://"):
            return self.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
        if self.DATABASE_URL.startswith("sqlite:///"):
            return self.DATABASE_URL.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
        return self.DATABASE_URL

    @property
    def sync_database_url(self) -> str:
        """Return a synchronous SQLAlchemy URL suitable for offline Alembic operations."""
        if self.DATABASE_URL.startswith("postgresql+asyncpg://"):
            return self.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)
        if self.DATABASE_URL.startswith("sqlite+aiosqlite:///"):
            return self.DATABASE_URL.replace("sqlite+aiosqlite:///", "sqlite:///", 1)
        return self.DATABASE_URL


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()


settings = get_settings()
