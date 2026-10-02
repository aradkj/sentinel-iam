import pyotp

from app.core.config import settings


class OTPService:
    """Service for Time-based One-Time Password (TOTP) 2FA management using PyOTP."""

    @staticmethod
    def generate_secret() -> str:
        """Generate a cryptographically random Base32 TOTP secret."""
        return str(pyotp.random_base32())

    @staticmethod
    def get_provisioning_uri(
        secret: str,
        email: str,
        issuer_name: str | None = None,
    ) -> str:
        """Return an otpauth:// URI suitable for QR code provisioning."""
        issuer = issuer_name or settings.TOTP_ISSUER_NAME
        totp = pyotp.TOTP(secret)
        return str(totp.provisioning_uri(name=email, issuer_name=issuer))

    @staticmethod
    def verify_otp(secret: str | None, otp_code: str) -> bool:
        """Verify a 6-digit TOTP code against a user's Base32 secret."""
        if not secret or not otp_code:
            return False
        totp = pyotp.TOTP(secret)
        return bool(totp.verify(otp_code.strip(), valid_window=1))

    @staticmethod
    def generate_current_otp(secret: str) -> str:
        """Return the current 6-digit TOTP code for a given Base32 secret."""
        return str(pyotp.TOTP(secret).now())
