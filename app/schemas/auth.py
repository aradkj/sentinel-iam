from pydantic import BaseModel, EmailStr, Field, model_validator


class LoginRequest(BaseModel):
    """Credentials payload for POST /auth/login."""

    email: EmailStr | None = None
    username: str | None = None
    password: str = Field(..., min_length=1)

    @model_validator(mode="after")
    def validate_identifier(self) -> "LoginRequest":
        if not self.email and not self.username:
            raise ValueError("Either 'email' or 'username' must be provided.")
        return self


class TokenResponse(BaseModel):
    """Standard JWT token pair response."""

    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    requires_2fa: bool = False
    temp_token: str | None = None
    session_id: int | None = None


class RefreshTokenRequest(BaseModel):
    """Payload for rotating a refresh token via POST /auth/refresh."""

    refresh_token: str = Field(..., min_length=10)


class LogoutRequest(BaseModel):
    """Optional body for POST /auth/logout to also revoke a refresh token."""

    refresh_token: str | None = None


class Enable2FAResponse(BaseModel):
    """Response returned when enabling TOTP 2FA for a user."""

    secret: str
    otpauth_url: str
    issuer: str
    message: str = "Two-factor authentication secret generated and enabled."


class VerifyOTPRequest(BaseModel):
    """Request payload for POST /auth/verify-otp."""

    temp_token: str
    otp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class ResendVerificationRequest(BaseModel):
    """Payload for POST /auth/resend-verification."""

    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    """Payload for POST /auth/forgot-password."""

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    """Payload for POST /auth/reset-password."""

    token: str = Field(..., min_length=6)
    new_password: str = Field(..., min_length=8, max_length=128)


class OAuthSocialPayload(BaseModel):
    """Payload for exchanging or simulating an OAuth2 callback in tests/integrations."""

    code: str | None = None
    email: EmailStr | None = None
    username: str | None = None
    first_name: str = "OAuth"
    last_name: str = "User"
    provider_id: str | None = None
