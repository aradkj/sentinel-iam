import asyncio
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_token
from app.models.token import EmailVerification, PasswordResetToken
from app.models.user import User


class EmailService:
    """Service managing email verification tokens, password reset tokens, and MailHog SMTP delivery."""

    outbox: list[dict[str, Any]] = []
    last_verification_tokens: dict[str, str] = {}
    last_reset_tokens: dict[str, str] = {}

    @classmethod
    def _send_smtp_sync(cls, message: EmailMessage) -> bool:
        """Send an EmailMessage synchronously over SMTP (e.g., MailHog on port 1025)."""
        try:
            with smtplib.SMTP(
                host=settings.SMTP_HOST,
                port=settings.SMTP_PORT,
                timeout=1.5,
            ) as smtp:
                smtp.send_message(message)
            return True
        except Exception:
            return False

    @classmethod
    async def send_email(
        cls,
        to_email: str,
        subject: str,
        html_body: str,
        text_body: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Send an email via MailHog SMTP (if reachable) and record in local outbox."""
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = to_email
        msg.set_content(text_body)
        msg.add_alternative(html_body, subtype="html")

        delivered = False
        if settings.APP_ENV != "test":
            delivered = await asyncio.to_thread(cls._send_smtp_sync, msg)

        cls.outbox.append(
            {
                "to": to_email,
                "subject": subject,
                "text": text_body,
                "html": html_body,
                "delivered_smtp": delivered,
                "metadata": metadata or {},
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

    @classmethod
    async def create_verification_token(
        cls,
        db: AsyncSession,
        user: User,
    ) -> str:
        """Generate a one-time email verification token, store its hash, and send email."""
        # Invalidate previous unused verification tokens for this user
        await db.execute(
            update(EmailVerification)
            .where(
                EmailVerification.user_id == user.id,
                EmailVerification.used.is_(False),
            )
            .values(used=True)
        )

        raw_token = secrets.token_urlsafe(32)
        token_digest = hash_token(raw_token)
        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS
        )

        record = EmailVerification(
            user_id=user.id,
            token_hash=token_digest,
            expires_at=expires_at,
            used=False,
        )
        db.add(record)
        await db.commit()

        cls.last_verification_tokens[user.email.lower()] = raw_token
        verify_url = f"http://localhost:{settings.API_PORT}/auth/verify-email/{raw_token}"

        await cls.send_email(
            to_email=user.email,
            subject="Verify your Enterprise IAM Account",
            text_body=(
                f"Hello {user.first_name},\n\n"
                f"Please verify your email address by visiting:\n{verify_url}\n\n"
                f"Verification Token: {raw_token}\n"
            ),
            html_body=(
                f"<h2>Welcome to {settings.APP_NAME}</h2>"
                f"<p>Hello <strong>{user.first_name}</strong>,</p>"
                f"<p>Please verify your email address by clicking the link below:</p>"
                f"<p><a href='{verify_url}'>{verify_url}</a></p>"
                f"<p>Or use token: <code>{raw_token}</code></p>"
            ),
            metadata={"type": "email_verification", "token": raw_token, "user_id": user.id},
        )
        return raw_token

    @classmethod
    async def verify_email_token(
        cls,
        db: AsyncSession,
        raw_token: str,
    ) -> User:
        """Validate a verification token, mark it used, and set user.is_verified = True."""
        token_digest = hash_token(raw_token.strip())
        stmt = select(EmailVerification).where(EmailVerification.token_hash == token_digest)
        result = await db.execute(stmt)
        verification = result.scalar_one_or_none()

        if verification is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email verification token.",
            )

        if verification.used:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email verification token has already been used.",
            )

        now = datetime.now(timezone.utc)
        expires_at = verification.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email verification token has expired.",
            )

        user_stmt = select(User).where(User.id == verification.user_id)
        user_res = await db.execute(user_stmt)
        user = user_res.scalar_one_or_none()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User associated with token not found.",
            )

        verification.used = True
        user.is_verified = True
        db.add(verification)
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    @classmethod
    async def create_password_reset_token(
        cls,
        db: AsyncSession,
        user: User,
    ) -> str:
        """Generate a one-time password reset token, store its hash, and send reset email."""
        await db.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used.is_(False),
            )
            .values(used=True)
        )

        raw_token = secrets.token_urlsafe(32)
        token_digest = hash_token(raw_token)
        expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES
        )

        reset_record = PasswordResetToken(
            user_id=user.id,
            token_hash=token_digest,
            expires_at=expires_at,
            used=False,
        )
        db.add(reset_record)
        await db.commit()

        cls.last_reset_tokens[user.email.lower()] = raw_token
        reset_url = f"{settings.FRONTEND_URL}/login.html?reset_token={raw_token}"

        await cls.send_email(
            to_email=user.email,
            subject="Password Reset Request - Enterprise IAM",
            text_body=(
                f"Hello {user.first_name},\n\n"
                f"Use the following token to reset your password (expires in "
                f"{settings.PASSWORD_RESET_EXPIRE_MINUTES} minutes):\n{raw_token}\n\n"
                f"Reset URL: {reset_url}\n"
            ),
            html_body=(
                f"<h2>Password Reset Request</h2>"
                f"<p>Hello <strong>{user.first_name}</strong>,</p>"
                f"<p>Your one-time password reset token is: <code>{raw_token}</code></p>"
                f"<p><a href='{reset_url}'>Reset Password</a></p>"
            ),
            metadata={"type": "password_reset", "token": raw_token, "user_id": user.id},
        )
        return raw_token

    @classmethod
    async def consume_password_reset_token(
        cls,
        db: AsyncSession,
        raw_token: str,
    ) -> User:
        """Validate a password reset token, mark it used, and return the associated User."""
        token_digest = hash_token(raw_token.strip())
        stmt = select(PasswordResetToken).where(PasswordResetToken.token_hash == token_digest)
        result = await db.execute(stmt)
        reset_record = result.scalar_one_or_none()

        if reset_record is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid password reset token.",
            )

        if reset_record.used:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password reset token has already been used.",
            )

        now = datetime.now(timezone.utc)
        expires_at = reset_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password reset token has expired.",
            )

        user_stmt = select(User).where(User.id == reset_record.user_id)
        user_res = await db.execute(user_stmt)
        user = user_res.scalar_one_or_none()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User account not found.",
            )

        reset_record.used = True
        db.add(reset_record)
        await db.commit()
        return user
