"""Session JWT auth for dashboard users (GitLab OAuth)."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import settings
from app.models import User, get_db

ALGORITHM = "HS256"


def generate_runner_secret() -> str:
    return secrets.token_urlsafe(32)


def create_session_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=settings.session_ttl_hours)).timestamp()),
    }
    return jwt.encode(payload, settings.session_secret, algorithm=ALGORITHM)


def decode_session_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.session_secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "Invalid or expired session") from exc
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(401, "Invalid session")
    return str(user_id)


def _extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip() or None
    return None


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    token = _extract_bearer(authorization)
    if not token:
        token = request.cookies.get(settings.session_cookie_name)
    if not token:
        raise HTTPException(401, "Authentication required — sign in with GitLab")

    user_id = decode_session_token(token)
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(401, "User not found — sign in again")
    return user


def require_user(user: User = Depends(get_current_user)) -> User:
    return user


def require_admin(x_admin_key: str = Header(default="", alias="X-Admin-Key")) -> None:
    """Legacy admin key guard. Prefer require_user for dashboard routes."""
    if not settings.admin_api_key:
        return
    if not x_admin_key or not secrets.compare_digest(x_admin_key, settings.admin_api_key):
        raise HTTPException(403, "Valid X-Admin-Key header required")
