"""Runtime operator settings stored in SQLite (per-user, editable from dashboard)."""

from __future__ import annotations

from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.config import DEFAULT_GITLAB_BASE_URL, settings
from app.models import OperatorSettings, User

DEFAULT_THRESHOLD_DAYS = 14


def get_or_create_operator_settings(db: Session, user_id: str | None = None) -> OperatorSettings:
    if user_id:
        row = db.query(OperatorSettings).filter(OperatorSettings.user_id == user_id).first()
        if row:
            return row
        row = OperatorSettings(
            user_id=user_id,
            renewal_check_interval_minutes=settings.renewal_check_interval_minutes,
            renewal_threshold_days=DEFAULT_THRESHOLD_DAYS,
            gitlab_base_url=DEFAULT_GITLAB_BASE_URL,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    # Legacy / system row (id=1) used at startup before any user is logged in
    row = db.query(OperatorSettings).filter(OperatorSettings.id == 1).first()
    if row:
        return row
    row = OperatorSettings(
        id=1,
        user_id=None,
        renewal_check_interval_minutes=settings.renewal_check_interval_minutes,
        renewal_threshold_days=DEFAULT_THRESHOLD_DAYS,
        gitlab_base_url=DEFAULT_GITLAB_BASE_URL,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_renewal_threshold_days(db: Session, user_id: str | None = None) -> int:
    if user_id:
        return get_or_create_operator_settings(db, user_id).renewal_threshold_days
    # Scheduler: use the most permissive (minimum) threshold among users, else default
    rows = db.query(OperatorSettings).filter(OperatorSettings.user_id.isnot(None)).all()
    if not rows:
        return get_or_create_operator_settings(db).renewal_threshold_days
    return min(r.renewal_threshold_days for r in rows)


def get_renewal_interval_minutes(db: Session) -> int:
    rows = db.query(OperatorSettings).filter(OperatorSettings.user_id.isnot(None)).all()
    if not rows:
        return get_or_create_operator_settings(db).renewal_check_interval_minutes
    return min(r.renewal_check_interval_minutes for r in rows)


def normalize_gitlab_base_url(value: str) -> str:
    url = (value or "").strip().rstrip("/")
    if not url:
        raise ValueError("GitLab URL cannot be empty")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("GitLab URL must start with http:// or https:// (e.g. https://gitlab.example.com)")
    return url


def effective_gitlab_base_url(db: Session, user_id: str | None = None) -> str:
    """DB is the source of truth for GitLab URL (set from the dashboard)."""
    row = get_or_create_operator_settings(db, user_id)
    stored = (row.gitlab_base_url or "").strip()
    if stored:
        return stored.rstrip("/")
    row.gitlab_base_url = DEFAULT_GITLAB_BASE_URL
    db.commit()
    db.refresh(row)
    return DEFAULT_GITLAB_BASE_URL


def apply_runtime_gitlab_base_url(db: Session) -> str:
    """Sync in-memory settings from system/default DB row so oauth uses the URL."""
    url = effective_gitlab_base_url(db, user_id=None)
    settings.gitlab_base_url = url
    return url


def set_gitlab_base_url(db: Session, value: str, user_id: str | None = None) -> tuple[str, int]:
    """Set GitLab URL for a user. If it changes, clear that user's tracked projects."""
    from app.models import TrackedGitLabProject

    url = normalize_gitlab_base_url(value)
    row = get_or_create_operator_settings(db, user_id)
    previous = (row.gitlab_base_url or "").strip().rstrip("/")
    row.gitlab_base_url = url
    cleared = 0
    if previous != url and user_id:
        cleared = (
            db.query(TrackedGitLabProject)
            .filter(TrackedGitLabProject.user_id == user_id)
            .delete()
        )
    elif previous != url and not user_id:
        cleared = db.query(TrackedGitLabProject).delete()
    db.commit()
    db.refresh(row)
    # Prototype assumes one GitLab host; keep runtime client URL in sync.
    settings.gitlab_base_url = url
    return url, cleared


def user_has_gitlab_token(user: User | None) -> bool:
    if not user:
        return bool(settings.gitlab_pat)
    return bool((user.encrypted_gitlab_token or "").strip())


def operator_settings_dict(db: Session, user: User | None = None) -> dict:
    user_id = user.id if user else None
    row = get_or_create_operator_settings(db, user_id)
    return {
        "renewal_check_interval_minutes": row.renewal_check_interval_minutes,
        "renewal_threshold_days": row.renewal_threshold_days,
        "default_short_lived_ttl_seconds": settings.default_short_lived_ttl_seconds,
        "gitlab_pat_configured": user_has_gitlab_token(user),
        "gitlab_base_url": effective_gitlab_base_url(db, user_id),
        "smtp_configured": bool(settings.smtp_host and (settings.smtp_from or settings.smtp_user)),
        "oauth_configured": bool(
            settings.gitlab_oauth_client_id and settings.gitlab_oauth_client_secret
        ),
    }
