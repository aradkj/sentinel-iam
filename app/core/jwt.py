import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import HTTPException, status
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.core.config import settings


def _get_signing_key() -> str:
    """Return the RSA private key (RS256) or HMAC secret key (HS256) for signing JWTs."""
    if settings.JWT_ALGORITHM == "RS256":
        return settings.load_private_key()
    return settings.JWT_SECRET_KEY


def _get_verification_key() -> str:
    """Return the RSA public key (RS256) or HMAC secret key (HS256) for verifying JWTs."""
    if settings.JWT_ALGORITHM == "RS256":
        return settings.load_public_key()
    return settings.JWT_SECRET_KEY


def get_public_key_pem() -> str:
    """Return the PEM-encoded public key used by external microservices to verify tokens."""
    return settings.load_public_key()


def create_access_token(
    data: dict[str, Any] | None = None,
    *,
    user_id: int | None = None,
    role: str = "user",
    roles: list[str] | None = None,
    permissions: list[str] | None = None,
    expires_delta: timedelta | None = None,
    jti: str | None = None,
) -> str:
    """Create an RS256/HS256 signed JWT access token (default expiration: 15 minutes)."""
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    payload: dict[str, Any] = dict(data) if data else {}
    resolved_user_id = user_id if user_id is not None else payload.get("user_id")
    resolved_role = payload.get("role", role)
    resolved_jti = jti or payload.get("jti") or str(uuid.uuid4())

    payload.update(
        {
            "user_id": resolved_user_id,
            "sub": str(resolved_user_id) if resolved_user_id is not None else payload.get("sub", ""),
            "role": resolved_role,
            "jti": resolved_jti,
            "type": payload.get("type", "access"),
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
        }
    )
    if roles is not None:
        payload["roles"] = roles
    elif "roles" not in payload and resolved_role:
        payload["roles"] = [resolved_role]

    if permissions is not None:
        payload["permissions"] = permissions

    return str(
        jwt.encode(
            payload,
            _get_signing_key(),
            algorithm=settings.JWT_ALGORITHM,
        )
    )


def create_refresh_token(
    data: dict[str, Any] | None = None,
    *,
    user_id: int | None = None,
    role: str = "user",
    expires_delta: timedelta | None = None,
    jti: str | None = None,
) -> str:
    """Create an RS256/HS256 signed JWT refresh token (default expiration: 7 days)."""
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )

    payload: dict[str, Any] = dict(data) if data else {}
    resolved_user_id = user_id if user_id is not None else payload.get("user_id")
    resolved_role = payload.get("role", role)
    resolved_jti = jti or payload.get("jti") or str(uuid.uuid4())

    payload.update(
        {
            "user_id": resolved_user_id,
            "sub": str(resolved_user_id) if resolved_user_id is not None else payload.get("sub", ""),
            "role": resolved_role,
            "jti": resolved_jti,
            "type": "refresh",
            "iat": int(now.timestamp()),
            "exp": int(expire.timestamp()),
        }
    )

    return str(
        jwt.encode(
            payload,
            _get_signing_key(),
            algorithm=settings.JWT_ALGORITHM,
        )
    )


def create_temp_2fa_token(
    user_id: int,
    role: str = "user",
    expires_delta: timedelta | None = None,
) -> str:
    """Create a short-lived temporary token for the second step of 2FA login."""
    delta = (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.TEMP_2FA_TOKEN_EXPIRE_MINUTES)
    )
    return create_access_token(
        {"user_id": user_id, "role": role, "type": "2fa_temp"},
        expires_delta=delta,
    )


def decode_token(token: str, verify_exp: bool = True) -> dict[str, Any]:
    """Decode and verify a JWT token using the configured RSA public key or HMAC secret."""
    options = {"verify_exp": verify_exp}
    decoded: dict[str, Any] = jwt.decode(
        token,
        _get_verification_key(),
        algorithms=[settings.JWT_ALGORITHM, "RS256", "HS256"],
        options=options,
    )
    return decoded


def verify_token(token: str, expected_type: str | None = None) -> dict[str, Any]:
    """Verify a JWT signature, expiration, structure, and optional token type."""
    try:
        payload = decode_token(token, verify_exp=True)
    except ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if "jti" not in payload or payload.get("user_id") is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_type = payload.get("type", "access")
    if expected_type is not None and token_type != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token type: expected '{expected_type}', got '{token_type}'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload
