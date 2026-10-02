import json
import logging
from datetime import datetime, timezone
from typing import Any

REDACTED_KEYS = {
    "password",
    "new_password",
    "current_password",
    "hashed_password",
    "token",
    "access_token",
    "refresh_token",
    "temp_token",
    "otp_code",
    "two_factor_secret",
    "secret",
    "private_key",
    "client_secret",
}

security_logger = logging.getLogger("iam.security")
if not security_logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    security_logger.addHandler(handler)
    security_logger.setLevel(logging.INFO)


def sanitize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Redact any sensitive secret or credential keys before logging or persisting."""
    if not metadata:
        return {}
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        if key.lower() in REDACTED_KEYS:
            clean[key] = "[REDACTED]"
        elif isinstance(value, dict):
            clean[key] = sanitize_metadata(value)
        else:
            clean[key] = value
    return clean


def log_security_event(
    event_type: str,
    user_id: int | None = None,
    ip_address: str | None = None,
    description: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Emit a structured, secret-safe security log entry."""
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "user_id": user_id,
        "ip_address": ip_address or "127.0.0.1",
        "description": description or "",
        "metadata": sanitize_metadata(metadata),
    }
    security_logger.info(json.dumps(payload))
