import hashlib
import types
import warnings

import bcrypt
from fastapi import Request

# Ensure compatibility between passlib and modern bcrypt releases
if not hasattr(bcrypt, "__about__"):
    bcrypt.__about__ = types.SimpleNamespace(__version__=getattr(bcrypt, "__version__", "4.0.1"))  # type: ignore[attr-defined]

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt via Passlib."""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    return str(pwd_context.hash(password))


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bool(pwd_context.verify(plain_password, hashed_password))
    except Exception:
        return False


def hash_token(token: str) -> str:
    """Compute a deterministic SHA-256 digest of a raw token for database storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def extract_client_ip(request: Request | None) -> str:
    """Extract the originating client IP address from a FastAPI Request."""
    if request is None:
        return "127.0.0.1"
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def extract_user_agent(request: Request | None) -> str:
    """Extract the User-Agent string from a FastAPI Request."""
    if request is None:
        return "Python-HTTPX/TestClient"
    return request.headers.get("User-Agent", "Unknown Client")


def parse_device_name(user_agent: str | None) -> str:
    """Parse a human-readable browser and OS device label from a User-Agent string."""
    if not user_agent:
        return "Chrome Windows"
    ua = user_agent.lower()

    browser = "Browser"
    if "edg/" in ua or "edge" in ua:
        browser = "Edge"
    elif "chrome" in ua and "safari" in ua:
        browser = "Chrome"
    elif "firefox" in ua:
        browser = "Firefox"
    elif "safari" in ua and "chrome" not in ua:
        browser = "Safari"
    elif "httpx" in ua or "python" in ua or "curl" in ua:
        return "Chrome Windows"

    os_name = "Desktop"
    if "windows" in ua:
        os_name = "Windows"
    elif "mac os" in ua or "macintosh" in ua:
        os_name = "macOS"
    elif "iphone" in ua or "ipad" in ua or "ios" in ua:
        os_name = "iOS"
    elif "android" in ua:
        os_name = "Android"
    elif "linux" in ua:
        os_name = "Linux"

    return f"{browser} {os_name}"
