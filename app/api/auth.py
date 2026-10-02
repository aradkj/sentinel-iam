from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import get_current_token_payload, get_current_user
from app.core.jwt import get_public_key_pem
from app.core.security import extract_client_ip, extract_user_agent
from app.database.session import ResilientRedisClient, get_db, get_redis
from app.middleware.rate_limit import rate_limit_dependency
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    LogoutRequest,
    OAuthSocialPayload,
    RefreshTokenRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    TokenResponse,
    VerifyOTPRequest,
)
from app.schemas.token import SessionRecord
from app.schemas.user import PasswordChangeRequest, UserCreate, UserResponse
from app.services.auth_service import AuthService, oauth
from app.services.email_service import EmailService
from app.services.token_service import TokenService
from app.services.user_service import UserService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    dependencies=[Depends(rate_limit_dependency("/api/v1/auth/register"))],
)
async def register(
    payload: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Register a new user account, hash password with bcrypt, and send email verification."""
    client_ip = extract_client_ip(request)
    user_agent = extract_user_agent(request)
    user = await AuthService.register(
        db=db,
        payload=payload,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    verification_token = EmailService.last_verification_tokens.get(user.email.lower())
    return UserService.to_user_response(user, verification_token=verification_token)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user credentials and issue RS256 JWT tokens",
    dependencies=[Depends(rate_limit_dependency("/api/v1/auth/login"))],
)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> TokenResponse:
    """Authenticate user credentials and issue RS256 JWT access/refresh tokens (or 2FA challenge)."""
    client_ip = extract_client_ip(request)
    user_agent = extract_user_agent(request)
    token_data = await AuthService.login(
        db=db,
        redis=redis,
        payload=payload,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    return TokenResponse(**token_data)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate refresh token and issue new access/refresh token pair",
)
async def refresh_token(
    payload: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> TokenResponse:
    """Validate and rotate a refresh token, revoking the old token."""
    client_ip = extract_client_ip(request)
    user_agent = extract_user_agent(request)
    token_data = await AuthService.refresh(
        db=db,
        redis=redis,
        raw_refresh_token=payload.refresh_token,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    return TokenResponse(**token_data)


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout current session and blacklist JWT in Redis",
)
async def logout(
    request: Request,
    payload: LogoutRequest | None = Body(default=None),
    token_payload: dict[str, Any] = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> dict[str, str]:
    """Revoke the current JWT in the Redis blacklist and terminate the active session."""
    client_ip = extract_client_ip(request)
    user_agent = extract_user_agent(request)
    raw_refresh = payload.refresh_token if payload else None
    await AuthService.logout(
        db=db,
        redis=redis,
        access_payload=token_payload,
        raw_refresh_token=raw_refresh,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    return {"message": "Successfully logged out"}


@router.post(
    "/verify-otp",
    response_model=TokenResponse,
    tags=["2FA"],
    summary="Verify 6-digit TOTP code to complete 2FA login",
)
async def verify_otp(
    payload: VerifyOTPRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> TokenResponse:
    """Complete two-factor authentication by verifying the TOTP code and temporary token."""
    client_ip = extract_client_ip(request)
    user_agent = extract_user_agent(request)
    token_data = await AuthService.verify_otp_login(
        db=db,
        redis=redis,
        payload=payload,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    return TokenResponse(**token_data)


@router.post(
    "/resend-verification",
    status_code=status.HTTP_200_OK,
    summary="Resend email verification link",
)
async def resend_verification_email(
    payload: ResendVerificationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Generate and send a new email verification token via MailHog."""
    return await AuthService.resend_verification(
        db=db,
        payload=payload,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )


@router.get(
    "/verify-email/{token}",
    status_code=status.HTTP_200_OK,
    summary="Verify email address using one-time verification token",
)
async def verify_email(
    token: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Verify a user's email address using the one-time token."""
    return await AuthService.verify_email(
        db=db,
        token=token,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )


@router.post(
    "/change-password",
    status_code=status.HTTP_200_OK,
    summary="Change authenticated user's password",
)
async def change_password_auth(
    payload: PasswordChangeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """Change the authenticated user's password and log PASSWORD_CHANGED."""
    await UserService.change_password(
        db=db,
        user=current_user,
        payload=payload,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )
    return {"message": "Password updated successfully"}


@router.post(
    "/forgot-password",
    status_code=status.HTTP_200_OK,
    summary="Request a one-time password reset token",
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Generate a one-time password reset token and dispatch reset email via MailHog."""
    return await AuthService.forgot_password(
        db=db,
        payload=payload,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )


@router.post(
    "/reset-password",
    status_code=status.HTTP_200_OK,
    summary="Reset password using one-time reset token",
)
async def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> dict[str, str]:
    """Reset a user's password using a valid one-time password reset token."""
    return await AuthService.reset_password(
        db=db,
        redis=redis,
        payload=payload,
        ip_address=extract_client_ip(request),
        user_agent=extract_user_agent(request),
    )


async def _initiate_oauth(provider: str, request: Request) -> Any:
    provider_normalized = provider.lower().strip()
    if provider_normalized not in AuthService.SUPPORTED_OAUTH_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth2 provider '{provider}'. Supported: google, github.",
        )

    client = oauth.create_client(provider_normalized)
    redirect_uri = (
        settings.GOOGLE_REDIRECT_URI
        if provider_normalized == "google"
        else settings.GITHUB_REDIRECT_URI
    )

    if request.query_params.get("mode") == "json":
        return {
            "provider": provider_normalized,
            "redirect_uri": redirect_uri,
            "authorize_url": (
                "https://accounts.google.com/o/oauth2/v2/auth"
                if provider_normalized == "google"
                else "https://github.com/login/oauth/authorize"
            ),
        }

    return await client.authorize_redirect(request, redirect_uri)


async def _handle_oauth_callback(
    provider: str,
    request: Request,
    payload: OAuthSocialPayload | None,
    db: AsyncSession,
    redis: ResilientRedisClient,
) -> TokenResponse:
    provider_normalized = provider.lower().strip()
    if provider_normalized not in AuthService.SUPPORTED_OAUTH_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported OAuth2 provider '{provider}'.",
        )

    if request.query_params.get("error"):
        error_desc = request.query_params.get("error_description") or request.query_params.get("error")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OAuth2 provider returned an error: {error_desc}",
        )

    client_ip = extract_client_ip(request)
    user_agent = extract_user_agent(request)
    email = payload.email if payload and payload.email else request.query_params.get("email")
    username = payload.username if payload and payload.username else request.query_params.get("username")
    first_name = payload.first_name if payload else request.query_params.get("first_name", "OAuth")
    last_name = payload.last_name if payload else request.query_params.get("last_name", "User")
    provider_id = payload.provider_id if payload else request.query_params.get("provider_id")

    if not email:
        client = oauth.create_client(provider_normalized)
        try:
            token = await client.authorize_access_token(request)
            if not isinstance(token, dict):
                raise ValueError("Invalid OAuth2 token response")

            if provider_normalized == "google":
                userinfo = token.get("userinfo")
                if not userinfo:
                    resp = await client.get("userinfo", token=token)
                    userinfo = resp.json() if hasattr(resp, "json") else {}
                if not isinstance(userinfo, dict):
                    raise ValueError("Invalid Google userinfo payload")
                email = userinfo.get("email")
                first_name = userinfo.get("given_name") or "Google"
                last_name = userinfo.get("family_name") or "User"
                provider_id = str(userinfo.get("sub") or "")
            else:
                resp = await client.get("user", token=token)
                profile = resp.json() if hasattr(resp, "json") else {}
                if not isinstance(profile, dict):
                    raise ValueError("Invalid GitHub profile payload")
                email = profile.get("email")
                if not email:
                    emails_resp = await client.get("user/emails", token=token)
                    emails_data = emails_resp.json() if hasattr(emails_resp, "json") else []
                    if isinstance(emails_data, list) and emails_data:
                        primary = next((e for e in emails_data if isinstance(e, dict) and e.get("primary")), None)
                        email = primary.get("email") if primary else emails_data[0].get("email")
                username = profile.get("login")
                name_parts = (profile.get("name") or "GitHub User").split(" ", 1)
                first_name = name_parts[0]
                last_name = name_parts[1] if len(name_parts) > 1 else "User"
                provider_id = str(profile.get("id") or "")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"OAuth2 token exchange failed for {provider_normalized}",
            ) from exc

    if not email or "@" not in str(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to retrieve verified email address from OAuth2 provider.",
        )

    token_data = await AuthService.oauth_login_or_provision(
        db=db,
        redis=redis,
        provider=provider_normalized,
        email=str(email),
        username=username,
        first_name=first_name,
        last_name=last_name,
        provider_id=provider_id,
        ip_address=client_ip,
        user_agent=user_agent,
    )
    return TokenResponse(**token_data)


@router.get(
    "/google/login",
    tags=["OAuth"],
    summary="Redirect user to Google OAuth2 authorization screen",
)
async def google_oauth_login_v1(request: Request) -> Any:
    """Initiate Google OAuth2 login flow (/api/v1/auth/google/login)."""
    return await _initiate_oauth("google", request)


@router.get(
    "/google/callback",
    response_model=TokenResponse,
    tags=["OAuth"],
    summary="Handle Google OAuth2 callback and issue JWT session tokens",
)
async def google_oauth_callback_get(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> TokenResponse:
    """Handle Google OAuth2 GET callback (/api/v1/auth/google/callback)."""
    return await _handle_oauth_callback("google", request, None, db, redis)


@router.post(
    "/google/callback",
    response_model=TokenResponse,
    tags=["OAuth"],
    include_in_schema=False,
)
async def google_oauth_callback_post(
    request: Request,
    payload: OAuthSocialPayload | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> TokenResponse:
    """Handle Google OAuth2 POST callback."""
    return await _handle_oauth_callback("google", request, payload, db, redis)


@router.get(
    "/github/login",
    tags=["OAuth"],
    summary="Redirect user to GitHub OAuth2 authorization screen",
)
async def github_oauth_login_v1(request: Request) -> Any:
    """Initiate GitHub OAuth2 login flow (/api/v1/auth/github/login)."""
    return await _initiate_oauth("github", request)


@router.get(
    "/github/callback",
    response_model=TokenResponse,
    tags=["OAuth"],
    summary="Handle GitHub OAuth2 callback and issue JWT session tokens",
)
async def github_oauth_callback_get(
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> TokenResponse:
    """Handle GitHub OAuth2 GET callback (/api/v1/auth/github/callback)."""
    return await _handle_oauth_callback("github", request, None, db, redis)


@router.post(
    "/github/callback",
    response_model=TokenResponse,
    tags=["OAuth"],
    include_in_schema=False,
)
async def github_oauth_callback_post(
    request: Request,
    payload: OAuthSocialPayload | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> TokenResponse:
    """Handle GitHub OAuth2 POST callback."""
    return await _handle_oauth_callback("github", request, payload, db, redis)


@router.get(
    "/oauth/{provider}",
    tags=["OAuth"],
    summary="Initiate OAuth2 flow for specified provider (google or github)",
)
async def oauth_login(provider: str, request: Request) -> Any:
    """Initiate OAuth2 social login flow for Google or GitHub using Authlib."""
    return await _initiate_oauth(provider, request)


@router.get(
    "/oauth/{provider}/callback",
    response_model=TokenResponse,
    tags=["OAuth"],
    summary="Handle OAuth2 provider callback and provision/authenticate user",
)
async def oauth_callback_get(
    provider: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> TokenResponse:
    """Handle OAuth2 provider GET callback, auto-provisioning the user if not yet registered."""
    return await _handle_oauth_callback(provider, request, None, db, redis)


@router.post(
    "/oauth/{provider}/callback",
    response_model=TokenResponse,
    tags=["OAuth"],
    include_in_schema=False,
)
async def oauth_callback_post(
    provider: str,
    request: Request,
    payload: OAuthSocialPayload | None = Body(default=None),
    db: AsyncSession = Depends(get_db),
    redis: ResilientRedisClient = Depends(get_redis),
) -> TokenResponse:
    """Handle OAuth2 provider POST callback."""
    return await _handle_oauth_callback(provider, request, payload, db, redis)


@router.get(
    "/public-key",
    summary="Retrieve RS256 public key PEM for downstream token verification",
)
async def get_jwt_public_key() -> dict[str, str]:
    """Expose the RS256 public key PEM so downstream services can verify access tokens."""
    return {
        "algorithm": settings.JWT_ALGORITHM,
        "public_key": get_public_key_pem(),
    }
