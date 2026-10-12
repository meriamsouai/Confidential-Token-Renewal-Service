import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def _derive_fernet_key(master_key: str) -> bytes:
    digest = hashlib.sha256(master_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def get_fernet() -> Fernet:
    return Fernet(_derive_fernet_key(settings.master_key))


def encrypt_secret(plaintext: str) -> str:
    return get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    try:
        return get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt secret") from exc


def generate_handle(token_id: str) -> str:
    random_part = secrets.token_hex(8)
    payload = f"{token_id}:{random_part}"
    sig = hmac.new(
        settings.master_key.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"ctrs.h.{token_id}.{random_part}.{sig}"


def verify_handle(handle: str) -> str | None:
    if not handle.startswith("ctrs.h."):
        return None
    parts = handle.split(".")
    if len(parts) != 5:
        return None
    _, _, token_id, random_part, sig = parts
    payload = f"{token_id}:{random_part}"
    expected = hmac.new(
        settings.master_key.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()[:16]
    if not hmac.compare_digest(sig, expected):
        return None
    return token_id


def sign_runner_request(runner_secret: str, timestamp: str, nonce: str) -> str:
    message = f"{timestamp}:{nonce}".encode()
    return hmac.new(runner_secret.encode(), message, hashlib.sha256).hexdigest()


def verify_runner_signature(
    runner_secret: str, timestamp: str, nonce: str, signature: str, max_age_seconds: int = 300
) -> bool:
    try:
        ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    now = datetime.now(timezone.utc)
    if abs((now - ts).total_seconds()) > max_age_seconds:
        return False
    expected = sign_runner_request(runner_secret, timestamp, nonce)
    return hmac.compare_digest(expected, signature)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(dt: datetime) -> datetime:
    """Normalize datetimes loaded from SQLite (often naive) to UTC-aware."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def mint_short_lived_token(long_lived: str, target: str, ttl_seconds: int) -> tuple[str, datetime]:
    """
    Return the vault credential for an approved exchange.

    GitLab project access tokens have no API to mint shorter derivatives, so CTRS
    returns the real stored token and records a policy-enforced expiry in the
    exchange response (the runner should discard it after the job).
    """
    expires = utcnow() + timedelta(seconds=ttl_seconds)
    return long_lived, expires
