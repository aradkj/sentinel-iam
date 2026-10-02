import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.jwt import create_temp_2fa_token, verify_token
from app.core.security import hash_password, verify_password
from app.database.session import ResilientRedisClient
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    VerifyOTPRequest,
)
from app.schemas.user import UserCreate
from app.services.email_service import EmailService
from app.services.otp_service import OTPService
from app.services.token_service import TokenService
from app.services.user_service import UserService

oauth = OAuth()

oauth.register(
    name="google",
    client_id=settings.GOOGLE_CLIENT_ID or "google-client-id-unconfigured",
    client_secret=settings.GOOGLE_CLIENT_SECRET or "google-client-secret-unconfigured",
    authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    api_base_url="https://openidconnect.googleapis.com/v1/",
    client_kwargs={"scope": "openid email profile"},
)

oauth.register(
    name="github",
    client_id=settings.GITHUB_CLIENT_ID or "github-client-id-unconfigured",
    client_secret=settings.GITHUB_CLIENT_SECRET or "github-client-secret-unconfigured",
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "read:user user:email"},
)


class AuthService:
    """Application service orchestrating registration, authentication, lockout, 2FA, OAuth2, email verification, and password reset."""

    SUPPORTED_OAUTH_PROVIDERS = {"google", "github"}

    @classmethod
    async def register(
        cls,
        db: AsyncSession,
        payload: UserCreate,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> User:
        """Register a new user account and dispatch verification email."""
        return await UserService.create_user(
            db=db,
            payload=payload,
            role_name="user",
            ip_address=ip_address,
            user_agent=user_agent,
            send_verification=True,
        )

    @classmethod
    async def login(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        payload: LoginRequest,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Authenticate a user with account lockout protection, 2FA, and session creation."""
        user = await UserService.get_user_by_identifier(
            db=db,
            email=payload.email,
            username=payload.username,
        )
        now = datetime.now(timezone.utc)

        if user is not None and user.locked_until is not None:
            locked_until = user.locked_until
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if locked_until > now:
                await UserService.record_audit_log(
                    db=db,
                    action="ACCOUNT_LOCKED",
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details="Login blocked because account is locked",
                    metadata={"locked_until": locked_until.isoformat()},
                )
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Account is temporarily locked due to 5 failed login attempts. Try again in 15 minutes.",
                )
            user.locked_until = None
            user.failed_login_attempts = 0
            db.add(user)
            await db.commit()

        if user is None or not verify_password(payload.password, user.hashed_password):
            locked_now = False
            if user is not None:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                    user.locked_until = now + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
                    locked_now = True
                db.add(user)
                await db.commit()

            await UserService.record_audit_log(
                db=db,
                action="LOGIN_FAILED",
                user_id=user.id if user is not None else None,
                ip_address=ip_address,
                user_agent=user_agent,
                details="Invalid credentials supplied during login",
                metadata={
                    "failed_attempts": user.failed_login_attempts if user else 1,
                    "locked": locked_now,
                },
            )
            if locked_now and user is not None:
                await UserService.record_audit_log(
                    db=db,
                    action="ACCOUNT_LOCKED",
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details="Account locked for 15 minutes after 5 consecutive failed login attempts",
                    metadata={"failed_attempts": user.failed_login_attempts},
                )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email/username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            await UserService.record_audit_log(
                db=db,
                action="LOGIN_FAILED",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details="Login attempt on deactivated user account",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive",
            )

        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = now
        db.add(user)
        await db.commit()

        if user.two_factor_enabled and user.two_factor_secret:
            temp_token = create_temp_2fa_token(
                user_id=user.id,
                role=user.primary_role,
            )
            return {
                "access_token": None,
                "refresh_token": None,
                "token_type": "bearer",
                "requires_2fa": True,
                "temp_token": temp_token,
            }

        token_response = await TokenService.issue_tokens_for_user(
            db=db,
            redis=redis,
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        await UserService.record_audit_log(
            db=db,
            action="LOGIN_SUCCESS",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details="Standard password login succeeded",
            metadata={"session_id": token_response.get("session_id")},
        )
        return token_response

    @classmethod
    async def verify_otp_login(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        payload: VerifyOTPRequest,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Verify a temporary 2FA token and TOTP code, then issue access and refresh tokens."""
        temp_claims = verify_token(payload.temp_token, expected_type="2fa_temp")
        jti = str(temp_claims["jti"])
        user_id = int(temp_claims["user_id"])

        if await TokenService.is_blacklisted(redis, jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Temporary 2FA token has already been used or revoked",
            )

        user = await UserService.get_user_by_id(db, user_id)
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account not found or inactive",
            )

        if not user.two_factor_enabled or not user.two_factor_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Two-factor authentication is not enabled for this user",
            )

        if not OTPService.verify_otp(user.two_factor_secret, payload.otp_code):
            await UserService.record_audit_log(
                db=db,
                action="LOGIN_FAILED",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                details="Invalid 2FA TOTP code",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired OTP code",
            )

        await TokenService.blacklist_jti(redis, jti, int(temp_claims["exp"]))

        token_response = await TokenService.issue_tokens_for_user(
            db=db,
            redis=redis,
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        await UserService.record_audit_log(
            db=db,
            action="LOGIN_SUCCESS",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details="2FA TOTP login succeeded",
        )
        return token_response

    @classmethod
    async def refresh(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        raw_refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Rotate a valid refresh token and issue a fresh token pair."""
        return await TokenService.rotate_refresh_token(
            db=db,
            redis=redis,
            raw_refresh_token=raw_refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    @classmethod
    async def logout(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        access_payload: dict[str, Any],
        raw_refresh_token: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Blacklist the access token in Redis, remove session, and log LOGOUT & TOKEN_REVOKED events."""
        await TokenService.revoke_tokens_on_logout(
            db=db,
            redis=redis,
            access_payload=access_payload,
            raw_refresh_token=raw_refresh_token,
        )

        user_id = int(access_payload["user_id"])
        jti = str(access_payload.get("jti", ""))
        await UserService.record_audit_log(
            db=db,
            action="TOKEN_REVOKED",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Revoked token jti={jti}",
            metadata={"jti": jti},
        )
        await UserService.record_audit_log(
            db=db,
            action="LOGOUT",
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Logged out session jti={jti}",
            metadata={"jti": jti},
        )

    @classmethod
    async def resend_verification(
        cls,
        db: AsyncSession,
        payload: ResendVerificationRequest,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Generate and send a fresh email verification token."""
        user = await UserService.get_user_by_email(db, payload.email)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User with this email address was not found.",
            )
        if user.is_verified:
            return {"message": "Email address is already verified.", "is_verified": True}

        raw_token = await EmailService.create_verification_token(db, user)
        return {
            "message": "Verification email sent. Please check your inbox.",
            "email": user.email,
            "verification_token": raw_token,
        }

    @classmethod
    async def verify_email(
        cls,
        db: AsyncSession,
        token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Verify a user's email address using a one-time verification token."""
        user = await EmailService.verify_email_token(db, token)
        await UserService.record_audit_log(
            db=db,
            action="EMAIL_VERIFIED",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Verified email '{user.email}'",
        )
        return {
            "message": "Email verified successfully",
            "email": user.email,
            "is_verified": user.is_verified,
        }

    @classmethod
    async def forgot_password(
        cls,
        db: AsyncSession,
        payload: ForgotPasswordRequest,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Issue a one-time password reset token and send reset instructions via email."""
        user = await UserService.get_user_by_email(db, payload.email)
        if user is None:
            return {
                "message": "If an account with that email exists, a password reset link has been sent."
            }

        raw_token = await EmailService.create_password_reset_token(db, user)
        return {
            "message": "If an account with that email exists, a password reset link has been sent.",
            "reset_token": raw_token,
        }

    @classmethod
    async def reset_password(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        payload: ResetPasswordRequest,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, str]:
        """Consume a one-time password reset token, update password, and revoke active sessions."""
        user = await EmailService.consume_password_reset_token(db, payload.token)
        user.hashed_password = hash_password(payload.new_password)
        user.failed_login_attempts = 0
        user.locked_until = None
        db.add(user)
        await db.commit()

        await TokenService.revoke_all_sessions(db, redis, user.id)

        await UserService.record_audit_log(
            db=db,
            action="PASSWORD_CHANGED",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details="Password reset completed via one-time reset token",
        )
        return {"message": "Password has been reset successfully"}

    @classmethod
    async def oauth_login_or_provision(
        cls,
        db: AsyncSession,
        redis: ResilientRedisClient,
        provider: str,
        email: str,
        username: str | None = None,
        first_name: str = "OAuth",
        last_name: str = "User",
        provider_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Provision a user from an OAuth2 provider (Google/GitHub) if needed and issue tokens."""
        provider_normalized = provider.lower().strip()
        if provider_normalized not in cls.SUPPORTED_OAUTH_PROVIDERS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported OAuth2 provider: {provider}",
            )

        if not email or "@" not in email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email address returned by OAuth2 provider.",
            )

        normalized_email = email.lower().strip()
        user = await UserService.get_user_by_email(db, normalized_email)

        if user is None:
            role_map = await UserService.ensure_default_rbac(db)
            base_username = (username or normalized_email.split("@")[0]).strip()
            candidate_username = base_username
            existing = await UserService.get_user_by_identifier(db, username=candidate_username)
            if existing is not None:
                candidate_username = f"{base_username}_{secrets.token_hex(3)}"

            random_secret_password = secrets.token_urlsafe(24)
            user = User(
                email=normalized_email,
                username=candidate_username,
                first_name=first_name or "OAuth",
                last_name=last_name or "User",
                hashed_password=hash_password(random_secret_password),
                is_active=True,
                is_verified=True,
                two_factor_enabled=False,
                failed_login_attempts=0,
                locked_until=None,
                last_login_at=datetime.now(timezone.utc),
                oauth_provider=provider_normalized,
                oauth_provider_id=provider_id or normalized_email,
                roles=[role_map["user"]],
            )
            db.add(user)
            await db.commit()
            user = await UserService.get_user_by_id(db, user.id)
            assert user is not None
        else:
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is inactive",
                )
            user.last_login_at = datetime.now(timezone.utc)
            user.failed_login_attempts = 0
            user.locked_until = None
            if not user.oauth_provider:
                user.oauth_provider = provider_normalized
                user.oauth_provider_id = provider_id or normalized_email
                user.is_verified = True
            db.add(user)
            await db.commit()

        token_response = await TokenService.issue_tokens_for_user(
            db=db,
            redis=redis,
            user=user,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        await UserService.record_audit_log(
            db=db,
            action="LOGIN_SUCCESS",
            user_id=user.id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"OAuth2 login via {provider_normalized}",
            metadata={"provider": provider_normalized},
        )
        return token_response
