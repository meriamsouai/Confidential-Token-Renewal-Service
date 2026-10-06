import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.crypto import (
    decrypt_secret,
    encrypt_secret,
    ensure_utc,
    generate_handle,
    mint_short_lived_token,
    utcnow,
)
from app.gitlab_client import (
    DEFAULT_ROTATION_EXPIRES_DAYS,
    GitLabApiError,
    build_gitlab_provider_metadata,
    find_project_access_token_id,
    list_all_accessible_runners,
    list_membership_projects,
    list_project_access_tokens,
    normalize_gitlab_runner,
    resolve_project_id,
    revoke_project_access_token,
    rotate_project_access_token,
    validate_gitlab_project_token_secret,
)
from app.models import (
    AuditEvent,
    ManagedToken,
    Policy,
    RenewalEvent,
    Runner,
    TokenHandle,
    TrackedGitLabProject,
    User,
)
from app.notifications import (
    notify_token_created,
    notify_token_expiring_soon,
    notify_token_revoked,
    notify_token_rotated,
)


def log_audit(
    db: Session,
    event_type: str,
    outcome: str,
    detail: str = "",
    token_id: str | None = None,
    runner_id: str | None = None,
    repository: str = "",
    workflow: str = "",
    branch: str = "",
    policy_id: str = "",
    user_id: str | None = None,
) -> None:
    db.add(
        AuditEvent(
            user_id=user_id,
            event_type=event_type,
            token_id=token_id,
            runner_id=runner_id,
            repository=repository,
            workflow=workflow,
            branch=branch,
            policy_id=policy_id or "",
            outcome=outcome,
            detail=detail,
            created_at=utcnow(),
        )
    )
    db.commit()


def get_user_gitlab_token(db: Session, user_id: str | None) -> str:
    """Decrypt the user's OAuth access token (fallback: legacy global GITLAB_PAT)."""
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
        if user and (user.encrypted_gitlab_token or "").strip():
            return decrypt_secret(user.encrypted_gitlab_token)
    if settings.gitlab_pat:
        return settings.gitlab_pat
    raise ValueError(
        "No GitLab credentials for this user. Sign in with GitLab OAuth, "
        "or set GITLAB_PAT in service/.env for legacy mode."
    )


def get_token_owner(db: Session, token: ManagedToken) -> User | None:
    if not token.user_id:
        return None
    return db.query(User).filter(User.id == token.user_id).first()


def _parse_provider_metadata(token: ManagedToken) -> dict[str, Any]:
    if not token.provider_metadata:
        return {}
    try:
        return json.loads(token.provider_metadata)
    except json.JSONDecodeError:
        return {}


def _is_demo_token(token: ManagedToken) -> bool:
    if token.is_demo:
        return True
    locations = json.loads(token.usage_locations) if token.usage_locations else []
    return token.owner == "platform-team" and any(str(loc).startswith("acme/") for loc in locations)


def _active_handles(db: Session, token_id: str) -> list[str]:
    rows = (
        db.query(TokenHandle)
        .filter(TokenHandle.token_id == token_id, TokenHandle.active.is_(True))
        .order_by(TokenHandle.created_at.desc())
        .all()
    )
    return [row.handle for row in rows]


RENEWAL_SOURCE_LABELS = {
    "manual": "Manual rotation (dashboard)",
    "scheduler": "Automatic scheduler",
    "gitlab_external": "Rotated in GitLab (detected)",
    "gitlab_resync": "Vault updated from GitLab UI secret",
}


def _latest_renewal_source(db: Session | None, token_id: str) -> tuple[str | None, str | None]:
    if not db:
        return None, None
    event = (
        db.query(RenewalEvent)
        .filter(RenewalEvent.token_id == token_id)
        .order_by(RenewalEvent.created_at.desc())
        .first()
    )
    if not event:
        return None, None
    source = getattr(event, "source", None) or "manual"
    return source, RENEWAL_SOURCE_LABELS.get(source, source)


def token_to_dict(token: ManagedToken, db: Session | None = None) -> dict:
    now = utcnow()
    expires_at = ensure_utc(token.expires_at)
    expires_in = (expires_at - now).total_seconds()
    last_renewed = ensure_utc(token.last_renewed_at) if token.last_renewed_at else None
    next_renewal = ensure_utc(token.next_renewal_at) if token.next_renewal_at else None
    provider = _parse_provider_metadata(token)
    handles = _active_handles(db, token.id) if db else []
    last_source, last_source_label = _latest_renewal_source(db, token.id)

    provider_summary = ""
    if token.target_system == "gitlab" and provider:
        provider_summary = (
            f"project {provider.get('gitlab_project_path', '?')} "
            f"(token id {provider.get('gitlab_access_token_id', '?')})"
        )

    return {
        "id": token.id,
        "name": token.name,
        "target_system": token.target_system,
        "owner": token.owner,
        "scopes": token.scopes.split(",") if token.scopes else [],
        "renewal_method": token.renewal_method,
        "expires_at": expires_at.isoformat(),
        "expires_in_days": round(expires_in / 86400, 1),
        "last_renewed_at": last_renewed.isoformat() if last_renewed else None,
        "next_renewal_at": next_renewal.isoformat() if next_renewal else None,
        "renewal_status": token.renewal_status,
        "usage_locations": json.loads(token.usage_locations) if token.usage_locations else [],
        "health": _health_status(expires_in, token.renewal_status),
        "handles": handles,
        "is_demo": _is_demo_token(token),
        "provider_summary": provider_summary,
        "renewal_mode": _renewal_mode(token),
        "created_at": token.created_at.isoformat() if token.created_at else None,
        "last_renewal_source": last_source,
        "last_renewal_source_label": last_source_label,
    }


def _renewal_mode(token: ManagedToken) -> str:
    if token.renewal_method == "manual":
        return "manual"
    if _is_demo_token(token):
        return "simulated"
    if token.target_system == "gitlab":
        provider = _parse_provider_metadata(token)
        if provider.get("gitlab_project_id") and provider.get("gitlab_access_token_id"):
            return "gitlab_rotate_api"
    return "simulated"


_GITLAB_ACCESS_LEVELS = {
    10: "Guest",
    20: "Reporter",
    30: "Developer",
    40: "Maintainer",
    50: "Owner",
}


def _gitlab_token_expires_in_days(expires_at: str | None) -> float | None:
    if not expires_at:
        return None
    try:
        dt = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return round((dt - utcnow()).total_seconds() / 86400, 1)
    except ValueError:
        return None


def fetch_gitlab_access_tokens(db: Session, user_id: str | None = None) -> dict[str, Any]:
    """Live GitLab project access tokens for vault-linked + explicitly tracked projects."""
    auth = get_user_gitlab_token(db, user_id)

    vault_q = db.query(ManagedToken).filter(ManagedToken.target_system == "gitlab")
    if user_id:
        vault_q = vault_q.filter(ManagedToken.user_id == user_id)
    vault_gitlab = vault_q.all()
    vault_by_gitlab_id: dict[tuple[int, int], ManagedToken] = {}
    vault_by_name: dict[tuple[int, str], ManagedToken] = {}
    projects: dict[int, str] = {}

    for token in vault_gitlab:
        meta = _parse_provider_metadata(token)
        pid = meta.get("gitlab_project_id")
        tid = meta.get("gitlab_access_token_id")
        path = meta.get("gitlab_project_path", "")
        name = meta.get("gitlab_access_token_name", "")
        if pid:
            projects[int(pid)] = path or projects.get(int(pid), "")
            if tid:
                vault_by_gitlab_id[(int(pid), int(tid))] = token
            if name:
                vault_by_name[(int(pid), name)] = token

    tracked_q = db.query(TrackedGitLabProject)
    if user_id:
        tracked_q = tracked_q.filter(TrackedGitLabProject.user_id == user_id)
    for tracked in tracked_q.all():
        if tracked.project_id:
            projects[int(tracked.project_id)] = tracked.project_path or projects.get(
                int(tracked.project_id), ""
            )
        elif tracked.project_path:
            try:
                resolved_id = resolve_project_id(tracked.project_path, auth)
                tracked.project_id = resolved_id
                db.commit()
                projects[resolved_id] = tracked.project_path
            except GitLabApiError:
                pass

    results: list[dict[str, Any]] = []
    errors: list[str] = []

    for project_id, project_path in projects.items():
        try:
            raw_tokens = list_project_access_tokens(project_id, auth)
        except GitLabApiError as exc:
            errors.append(f"{project_path or project_id}: {exc}")
            continue

        for entry in raw_tokens:
            gitlab_id = int(entry.get("id") or entry.get("user_id") or 0)
            name = entry.get("name") or ""
            revoked = bool(entry.get("revoked", False))
            active = bool(entry.get("active", True))
            vault = vault_by_gitlab_id.get((project_id, gitlab_id))

            # Active GitLab token with same name but different id → rotated outside CTRS.
            if not vault and active and not revoked and name:
                by_name = vault_by_name.get((project_id, name))
                if by_name and by_name.renewal_status != "revoked":
                    stored_id = _parse_provider_metadata(by_name).get("gitlab_access_token_id")
                    if stored_id and int(stored_id) != gitlab_id:
                        _record_gitlab_external_rotation(
                            db,
                            by_name,
                            project_path=project_path or str(project_id),
                            old_access_token_id=int(stored_id),
                            new_access_token_id=gitlab_id,
                            token_name=name,
                        )
                        # Re-index so later rows see updated metadata.
                        vault_by_gitlab_id.pop((project_id, int(stored_id)), None)
                        vault_by_gitlab_id[(project_id, gitlab_id)] = by_name
                        vault = by_name
                    elif not stored_id or int(stored_id) == gitlab_id:
                        vault = by_name

            # If GitLab already revoked/disabled this token, sync CTRS vault → revoked
            # unless a same-name active sibling exists (that case is external rotate above).
            if vault and (revoked or not active) and vault.renewal_status != "revoked":
                has_active_sibling = any(
                    (e.get("name") or "") == name
                    and bool(e.get("active", True))
                    and not bool(e.get("revoked", False))
                    and int(e.get("id") or e.get("user_id") or 0) != gitlab_id
                    for e in raw_tokens
                )
                if has_active_sibling:
                    vault = None
                else:
                    mark_managed_token_revoked_locally(
                        db,
                        vault,
                        reason=(
                            f"Synced from GitLab: project access token '{name}' "
                            f"(id {gitlab_id}) is revoked/inactive on {project_path or project_id}"
                        ),
                        gitlab_already_revoked=True,
                    )
                    vault = None
            elif vault and (revoked or not active):
                vault = None
            if not vault and active and not revoked:
                vault = vault_by_name.get((project_id, name))
                if vault and vault.renewal_status == "revoked":
                    vault = None
            expires_at = entry.get("expires_at")
            access_level = entry.get("access_level")
            if access_level is not None:
                access_level = int(access_level)

            vault_dict = token_to_dict(vault, db) if vault else None
            results.append(
                {
                    "gitlab_token_id": gitlab_id,
                    "name": name,
                    "project_path": project_path,
                    "project_id": project_id,
                    "scopes": entry.get("scopes") or [],
                    "access_level": access_level,
                    "access_level_label": _GITLAB_ACCESS_LEVELS.get(access_level or 0, "Unknown"),
                    "expires_at": expires_at,
                    "expires_in_days": _gitlab_token_expires_in_days(expires_at),
                    "active": bool(entry.get("active", True)),
                    "revoked": bool(entry.get("revoked", False)),
                    "created_at": entry.get("created_at"),
                    "last_used_at": entry.get("last_used_at"),
                    "vault_token_id": vault.id if vault else None,
                    "in_vault": vault is not None,
                    "vault_health": vault_dict["health"] if vault_dict else None,
                    "vault_renewal_status": vault_dict["renewal_status"] if vault_dict else None,
                    "usage_locations": vault_dict["usage_locations"] if vault_dict else [project_path],
                    "renewal_mode": vault_dict["renewal_mode"] if vault_dict else "unmanaged",
                    "next_renewal_at": vault_dict["next_renewal_at"] if vault_dict else None,
                    "last_renewed_at": vault_dict["last_renewed_at"] if vault_dict else None,
                    "last_renewal_source": vault_dict["last_renewal_source"] if vault_dict else None,
                    "last_renewal_source_label": (
                        vault_dict["last_renewal_source_label"] if vault_dict else None
                    ),
                    "owner": vault_dict["owner"] if vault_dict else "",
                    "token_kind": "gitlab_project_access_token",
                }
            )

    results.sort(key=lambda t: (t["project_path"], t["name"]))
    tracked_rows = [
        {
            "id": row.id,
            "project_path": row.project_path,
            "project_id": row.project_id,
            "display_name": row.display_name or row.project_path,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in db.query(TrackedGitLabProject).order_by(TrackedGitLabProject.project_path).all()
    ]
    return {
        "gitlab_base_url": settings.gitlab_base_url,
        "tokens": results,
        "errors": errors,
        "tracked_projects": tracked_rows,
    }


def _health_status(expires_in_seconds: float, renewal_status: str) -> str:
    if renewal_status == "revoked":
        return "critical"
    if renewal_status == "failed":
        return "critical"
    if expires_in_seconds < 86400:
        return "warning"
    if expires_in_seconds < 7 * 86400:
        return "attention"
    return "healthy"


def _simulate_renewal(token: ManagedToken) -> tuple[bool, str, str | None, int | None]:
    if token.renewal_method == "manual":
        return False, "Token requires manual renewal", None, None
    if token.target_system == "github":
        return True, "Simulated GitHub fine-grained PAT renewal via REST API", None, DEFAULT_ROTATION_EXPIRES_DAYS
    if token.target_system == "gitlab":
        return True, "Simulated GitLab project token rotation (demo token)", None, DEFAULT_ROTATION_EXPIRES_DAYS
    if token.target_system == "registry":
        return True, "Simulated container registry OAuth refresh", None, DEFAULT_ROTATION_EXPIRES_DAYS
    return False, f"Unknown target system: {token.target_system}", None, None


def _gitlab_renewal_auth(token: ManagedToken, db: Session | None = None) -> str:
    if db is not None and token.user_id:
        try:
            return get_user_gitlab_token(db, token.user_id)
        except ValueError:
            pass
    if settings.gitlab_pat:
        return settings.gitlab_pat
    return decrypt_secret(token.encrypted_secret)


def _refresh_gitlab_access_token_id(provider: dict[str, Any], auth: str) -> dict[str, Any] | None:
    """Resolve the current active GitLab project access token id by name."""
    project_id = provider.get("gitlab_project_id")
    project_path = provider.get("gitlab_project_path")
    token_name = provider.get("gitlab_access_token_name")
    if not token_name:
        return None
    try:
        resolved_project_id = int(project_id) if project_id else None
        if not resolved_project_id and project_path:
            resolved_project_id = resolve_project_id(project_path, auth)
        if not resolved_project_id:
            return None
        new_id = find_project_access_token_id(resolved_project_id, token_name, auth)
    except GitLabApiError:
        return None
    return {
        **provider,
        "gitlab_project_id": resolved_project_id,
        "gitlab_project_path": project_path or str(resolved_project_id),
        "gitlab_access_token_id": new_id,
        "gitlab_access_token_name": token_name,
    }


def _renew_gitlab_token(
    token: ManagedToken,
    db: Session | None = None,
) -> tuple[bool, str, str | None, int | None, dict[str, Any] | None]:
    provider = _parse_provider_metadata(token)
    project_id = provider.get("gitlab_project_id")
    access_token_id = provider.get("gitlab_access_token_id")
    if not project_id or not access_token_id:
        return (
            False,
            "GitLab renewal metadata missing. Re-register via /admin/gitlab/register "
            "with a signed-in GitLab user, or provide gitlab_project_id and gitlab_access_token_id.",
            None,
            None,
            None,
        )

    auth = _gitlab_renewal_auth(token, db=db)
    try:
        new_secret, expires_at, new_access_token_id = rotate_project_access_token(
            int(project_id),
            int(access_token_id),
            auth,
            expires_days=DEFAULT_ROTATION_EXPIRES_DAYS,
        )
    except GitLabApiError as exc:
        err = str(exc).lower()
        if "revoked" not in err and exc.status_code != 400:
            return False, str(exc), None, None, None
        refreshed = _refresh_gitlab_access_token_id(provider, auth)
        if not refreshed or refreshed.get("gitlab_access_token_id") == access_token_id:
            return False, str(exc), None, None, None
        provider = refreshed
        try:
            new_secret, expires_at, new_access_token_id = rotate_project_access_token(
                int(provider["gitlab_project_id"]),
                int(provider["gitlab_access_token_id"]),
                auth,
                expires_days=DEFAULT_ROTATION_EXPIRES_DAYS,
            )
        except GitLabApiError as retry_exc:
            return False, str(retry_exc), None, None, refreshed

    # Prefer the configured default; fall back to GitLab's returned date if present.
    expires_days = DEFAULT_ROTATION_EXPIRES_DAYS
    if expires_at:
        expires_days = max(int((expires_at - utcnow()).total_seconds() / 86400), 1)

    project_path = provider.get("gitlab_project_path", str(provider.get("gitlab_project_id")))
    updated_metadata = {
        **provider,
        "gitlab_project_id": int(provider["gitlab_project_id"]),
        "gitlab_access_token_id": new_access_token_id,
        "gitlab_access_token_name": provider.get("gitlab_access_token_name", ""),
        "gitlab_project_path": project_path,
    }
    return (
        True,
        f"GitLab project access token rotated via API for {project_path} ({expires_days}d)",
        new_secret,
        expires_days,
        updated_metadata,
    )


def _is_already_revoked_error(message: str) -> bool:
    text = (message or "").lower()
    return "already revoked" in text or "token has been revoked" in text


def _record_gitlab_external_rotation(
    db: Session,
    token: ManagedToken,
    *,
    project_path: str,
    old_access_token_id: int,
    new_access_token_id: int,
    token_name: str,
) -> None:
    """
    GitLab rotated the project access token outside CTRS (new token id, same name).
    CTRS cannot learn the new secret from the list API — mark vault out of sync.
    """
    provider = _parse_provider_metadata(token)
    if int(provider.get("gitlab_access_token_id") or 0) == new_access_token_id:
        return

    # Avoid duplicate detection on every inventory refresh.
    latest = (
        db.query(RenewalEvent)
        .filter(RenewalEvent.token_id == token.id)
        .order_by(RenewalEvent.created_at.desc())
        .first()
    )
    if (
        latest
        and latest.source == "gitlab_external"
        and latest.status == "failed"
        and str(new_access_token_id) in (latest.message or "")
    ):
        provider["gitlab_access_token_id"] = new_access_token_id
        token.provider_metadata = json.dumps(provider)
        if token.renewal_status != "revoked":
            token.renewal_status = "failed"
        db.commit()
        return

    now = utcnow()
    provider["gitlab_access_token_id"] = new_access_token_id
    token.provider_metadata = json.dumps(provider)
    token.renewal_status = "failed"
    message = (
        f"Detected rotation in GitLab for '{token_name}' on {project_path}: "
        f"access token id {old_access_token_id} → {new_access_token_id}. "
        "Vault secret is stale — re-register the new glpat in CTRS (CI handle can stay)."
    )
    db.add(
        RenewalEvent(
            token_id=token.id,
            status="failed",
            message=message,
            source="gitlab_external",
            created_at=now,
        )
    )
    log_audit(db, "renewal_failed", "failed", f"[gitlab_external] {message}", token_id=token.id)
    db.commit()


def resync_vault_secret(db: Session, token: ManagedToken, secret: str) -> RenewalEvent:
    """
    Operator pasted the glpat GitLab showed after an in-GitLab rotation.
    Replaces the vault ciphertext only; CI handles stay active.
    """
    if token.renewal_status == "revoked":
        raise ValueError(f"Token {token.id} is revoked — register a new token instead")

    secret = (secret or "").strip()
    if not secret:
        raise ValueError("Paste the new GitLab token secret (glpat-…)")

    provider = _parse_provider_metadata(token)
    project_path = str(provider.get("gitlab_project_path") or "")
    project_id = provider.get("gitlab_project_id")

    if token.target_system == "gitlab":
        try:
            validate_gitlab_project_token_secret(
                secret,
                project_path=project_path,
                project_id=int(project_id) if project_id else None,
            )
        except GitLabApiError as exc:
            raise ValueError(str(exc)) from exc

    now = utcnow()
    token.encrypted_secret = encrypt_secret(secret)
    token.last_renewed_at = now
    token.renewal_status = "healthy"

    if token.target_system == "gitlab" and project_id:
        try:
            auth = _gitlab_renewal_auth(token, db=db)
            token_name = provider.get("gitlab_access_token_name")
            if token_name:
                provider["gitlab_access_token_id"] = find_project_access_token_id(
                    int(project_id), str(token_name), auth
                )
            for entry in list_project_access_tokens(int(project_id), auth):
                if int(entry.get("id") or 0) != int(provider.get("gitlab_access_token_id") or 0):
                    continue
                raw_expires = entry.get("expires_at")
                if raw_expires:
                    expires_at = datetime.fromisoformat(str(raw_expires).replace("Z", "+00:00"))
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                    token.expires_at = expires_at
                    token.next_renewal_at = expires_at - timedelta(days=30)
                break
            token.provider_metadata = json.dumps(provider)
        except (GitLabApiError, ValueError, TypeError):
            pass

    event = RenewalEvent(
        token_id=token.id,
        status="success",
        message="Vault secret updated from GitLab UI rotation. CI handle unchanged.",
        source="gitlab_resync",
        created_at=now,
    )
    db.add(event)
    log_audit(
        db,
        "renewal_success",
        "success",
        "[gitlab_resync] Vault secret replaced after GitLab UI rotation",
        token_id=token.id,
    )
    db.commit()
    db.refresh(event)
    return event


def renew_token(db: Session, token: ManagedToken, *, source: str = "manual") -> RenewalEvent:
    if token.renewal_status == "revoked":
        now = utcnow()
        event = RenewalEvent(
            token_id=token.id,
            status="revoked",
            message=f"Token {token.id} is already revoked — skipping renewal",
            source=source,
            created_at=now,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    updated_metadata: dict[str, Any] | None = None
    if _renewal_mode(token) == "gitlab_rotate_api":
        success, message, new_secret, expires_days, updated_metadata = _renew_gitlab_token(token, db=db)
    else:
        success, message, new_secret, expires_days = _simulate_renewal(token)
        if success and new_secret is None:
            new_secret = f"{token.target_system}_renewed_{secrets.token_hex(16)}"

    now = utcnow()

    # GitLab already revoked this token → sync CTRS instead of looping on "failed".
    if not success and _is_already_revoked_error(message or ""):
        if updated_metadata:
            token.provider_metadata = json.dumps(updated_metadata)
        mark_managed_token_revoked_locally(
            db,
            token,
            reason=f"Auto-revoked after rotate failed: {message}",
            gitlab_already_revoked=True,
            commit=False,
            record_event=False,
        )
        event = RenewalEvent(
            token_id=token.id,
            status="revoked",
            message=f"Auto-revoked in CTRS because GitLab reports token already revoked: {message}",
            source=source,
            created_at=now,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event

    event = RenewalEvent(
        token_id=token.id,
        status="success" if success else "failed",
        message=message,
        source=source,
        created_at=now,
    )
    db.add(event)

    if success and new_secret:
        token.encrypted_secret = encrypt_secret(new_secret)
        token.last_renewed_at = now
        token.expires_at = now + timedelta(days=expires_days or DEFAULT_ROTATION_EXPIRES_DAYS)
        token.next_renewal_at = now + timedelta(
            days=max((expires_days or DEFAULT_ROTATION_EXPIRES_DAYS) - 30, 1)
        )
        token.renewal_status = "healthy"
        if updated_metadata:
            token.provider_metadata = json.dumps(updated_metadata)
        log_audit(
            db,
            "renewal_success",
            "success",
            f"[{source}] {message}",
            token_id=token.id,
            user_id=token.user_id,
        )
        notify_token_rotated(get_token_owner(db, token), token, message)
    else:
        if updated_metadata:
            token.provider_metadata = json.dumps(updated_metadata)
        token.renewal_status = "failed"
        log_audit(
            db,
            "renewal_failed",
            "failed",
            f"[{source}] {message}",
            token_id=token.id,
            user_id=token.user_id,
        )

    db.commit()
    db.refresh(event)
    return event


def mark_managed_token_revoked_locally(
    db: Session,
    token: ManagedToken,
    *,
    reason: str,
    gitlab_already_revoked: bool = False,
    commit: bool = True,
    record_event: bool = True,
) -> dict[str, Any]:
    """Deactivate vault handles/policies and mark token revoked without calling GitLab again."""
    if token.renewal_status == "revoked":
        return {
            "token_id": token.id,
            "gitlab_revoked": gitlab_already_revoked,
            "message": f"Token {token.id} already revoked in CTRS",
        }

    detail_parts = [reason]
    handles = (
        db.query(TokenHandle)
        .filter(TokenHandle.token_id == token.id, TokenHandle.active.is_(True))
        .all()
    )
    for handle in handles:
        handle.active = False
    if handles:
        detail_parts.append(f"Deactivated {len(handles)} CI handle(s)")

    token.encrypted_secret = encrypt_secret(f"revoked-{secrets.token_hex(8)}")
    token.renewal_status = "revoked"
    token.next_renewal_at = None

    policies = db.query(Policy).filter(Policy.token_id == token.id, Policy.enabled.is_(True)).all()
    for policy in policies:
        policy.enabled = False
    if policies:
        detail_parts.append(f"Disabled {len(policies)} policy(ies)")

    message = "; ".join(detail_parts) or f"Token {token.id} revoked"
    log_audit(db, "token_revoked", "success", message, token_id=token.id, user_id=token.user_id)
    if record_event:
        db.add(
            RenewalEvent(
                token_id=token.id,
                status="revoked",
                message=message,
                source="manual",
                created_at=utcnow(),
            )
        )
    if commit:
        db.commit()
    notify_token_revoked(get_token_owner(db, token), token, message)
    return {
        "token_id": token.id,
        "gitlab_revoked": gitlab_already_revoked,
        "message": message,
    }


def revoke_managed_token(db: Session, token: ManagedToken) -> dict[str, Any]:
    """
    Revoke a managed token: revoke in GitLab when metadata exists, deactivate CI handles,
    and mark the vault entry so exchange can no longer succeed.
    """
    if token.renewal_status == "revoked":
        return {
            "token_id": token.id,
            "gitlab_revoked": False,
            "message": f"Token {token.id} is already revoked",
        }

    provider = _parse_provider_metadata(token)
    project_id = provider.get("gitlab_project_id")
    access_token_id = provider.get("gitlab_access_token_id")
    gitlab_revoked = False
    detail_parts: list[str] = []

    if token.target_system == "gitlab" and project_id and access_token_id:
        auth = _gitlab_renewal_auth(token, db=db)
        try:
            revoke_project_access_token(int(project_id), int(access_token_id), auth)
            gitlab_revoked = True
            detail_parts.append(
                f"Revoked GitLab project access token {access_token_id} "
                f"on project {provider.get('gitlab_project_path') or project_id}"
            )
        except GitLabApiError as exc:
            if _is_already_revoked_error(str(exc)):
                gitlab_revoked = True
                detail_parts.append(
                    f"GitLab token already revoked ({access_token_id}) — syncing CTRS"
                )
            else:
                # Prefer refreshing id by name once, then retry (same pattern as rotate).
                refreshed = _refresh_gitlab_access_token_id(provider, auth)
                if refreshed and refreshed.get("gitlab_access_token_id") != access_token_id:
                    try:
                        revoke_project_access_token(
                            int(refreshed["gitlab_project_id"]),
                            int(refreshed["gitlab_access_token_id"]),
                            auth,
                        )
                        provider = refreshed
                        token.provider_metadata = json.dumps(provider)
                        gitlab_revoked = True
                        detail_parts.append(
                            f"Revoked GitLab project access token "
                            f"{refreshed['gitlab_access_token_id']} on project "
                            f"{refreshed.get('gitlab_project_path') or refreshed['gitlab_project_id']}"
                        )
                    except GitLabApiError as retry_exc:
                        if _is_already_revoked_error(str(retry_exc)):
                            gitlab_revoked = True
                            detail_parts.append(
                                "GitLab token already revoked — syncing CTRS"
                            )
                        else:
                            raise ValueError(str(retry_exc)) from retry_exc
                else:
                    raise ValueError(str(exc)) from exc
    else:
        detail_parts.append("No GitLab rotation metadata — revoked in CTRS vault only")

    return mark_managed_token_revoked_locally(
        db,
        token,
        reason="; ".join(detail_parts) or f"Token {token.id} revoked",
        gitlab_already_revoked=gitlab_revoked,
        commit=True,
    )


def check_expiring_tokens(db: Session) -> list[str]:
    """Return token IDs that were renewed. Also send expiry-soon emails once per window."""
    from app.operator_settings import get_renewal_threshold_days

    now = utcnow()
    renewed = []
    tokens = db.query(ManagedToken).filter(ManagedToken.renewal_status != "revoked").all()
    for token in tokens:
        user_threshold = get_renewal_threshold_days(db, token.user_id)
        expires_at = ensure_utc(token.expires_at)
        days_left = (expires_at - now).total_seconds() / 86400

        # Expiry-soon notification (once per threshold window)
        if 0 < days_left <= user_threshold:
            last_notified = (
                ensure_utc(token.last_expiry_notified_at) if token.last_expiry_notified_at else None
            )
            should_notify = last_notified is None or (now - last_notified).total_seconds() > 86400 * max(
                user_threshold // 2, 1
            )
            if should_notify:
                notify_token_expiring_soon(get_token_owner(db, token), token, days_left)
                token.last_expiry_notified_at = now
                db.commit()

        if expires_at > now + timedelta(days=user_threshold):
            continue
        if token.renewal_method != "manual":
            # renew_token uses the token owner's GitLab OAuth token for API rotate
            event = renew_token(db, token, source="scheduler")
            if event.status == "success":
                renewed.append(token.id)
    return renewed


def set_provider_metadata(db: Session, token: ManagedToken, metadata: dict[str, Any]) -> None:
    token.provider_metadata = json.dumps(metadata)
    db.commit()


def resolve_gitlab_registration_metadata(
    project_path: str,
    access_token_name: str,
    vault_secret: str,
    *,
    project_id: int | None = None,
    access_token_id: int | None = None,
    validate_secret: bool = True,
    auth_token: str | None = None,
) -> dict[str, Any]:
    if validate_secret:
        validate_gitlab_project_token_secret(
            vault_secret,
            project_path=project_path,
            project_id=project_id,
        )
    auth = auth_token or settings.gitlab_pat or vault_secret
    return build_gitlab_provider_metadata(
        project_path,
        access_token_name,
        auth,
        project_id=project_id,
        access_token_id=access_token_id,
    )


def create_managed_token(
    db: Session,
    token_id: str,
    name: str,
    target_system: str,
    owner: str,
    scopes: list[str],
    secret: str,
    renewal_method: str,
    expires_days: int,
    usage_locations: list[str],
    *,
    is_demo: bool = False,
    provider_metadata: dict[str, Any] | None = None,
    user_id: str | None = None,
) -> tuple[ManagedToken, str]:
    now = utcnow()
    token = ManagedToken(
        id=token_id,
        user_id=user_id,
        name=name,
        target_system=target_system,
        owner=owner,
        scopes=",".join(scopes),
        encrypted_secret=encrypt_secret(secret),
        renewal_method=renewal_method,
        expires_at=now + timedelta(days=expires_days),
        last_renewed_at=now,
        next_renewal_at=now + timedelta(days=max(expires_days - 30, 1)),
        renewal_status="healthy",
        usage_locations=json.dumps(usage_locations),
        default_short_lived_ttl=3600,
        provider_metadata=json.dumps(provider_metadata or {}),
        is_demo=is_demo,
        created_at=now,
    )
    db.add(token)
    handle = generate_handle(token_id)
    db.add(TokenHandle(handle=handle, token_id=token_id, active=True, created_at=now))
    db.commit()
    db.refresh(token)
    notify_token_created(get_token_owner(db, token), token)
    return token, handle


def register_runner(
    db: Session,
    runner_id: str,
    name: str,
    runner_type: str,
    secret: str,
    *,
    user_id: str | None = None,
) -> Runner:
    now = utcnow()
    runner = Runner(
        id=runner_id,
        user_id=user_id,
        name=name,
        runner_type=runner_type,
        encrypted_secret=encrypt_secret(secret),
        fingerprint="",
        active=True,
        created_at=now,
    )
    db.add(runner)
    db.commit()
    db.refresh(runner)
    return runner


def verify_runner_host(
    db: Session,
    runner_id: str,
    signature: str,
    timestamp: str,
    nonce: str,
) -> dict:
    """
    Prove the caller has the CTRS runner secret (host install script was applied).
    Does not mint tokens — only updates last_seen_at.
    """
    from app.crypto import verify_runner_signature

    runner = db.query(Runner).filter(Runner.id == runner_id, Runner.active.is_(True)).first()
    if not runner:
        log_audit(db, "runner_host_verify_denied", "denied", "Unregistered runner", runner_id=runner_id)
        raise ValueError("Unregistered or inactive runner")

    runner_secret = decrypt_secret(runner.encrypted_secret)
    if not verify_runner_signature(runner_secret, timestamp, nonce, signature):
        log_audit(
            db,
            "runner_host_verify_denied",
            "denied",
            "Invalid runner signature — secret file missing or wrong?",
            runner_id=runner_id,
        )
        raise ValueError("Runner authentication failed — is /etc/ctrs/runner-secret installed?")

    now = utcnow()
    runner.last_seen_at = now
    db.commit()
    log_audit(
        db,
        "runner_host_verified",
        "success",
        "Host proved CTRS runner secret is installed",
        runner_id=runner_id,
    )
    return {
        "runner_id": runner.id,
        "host_setup": "verified",
        "last_seen_at": now.isoformat(),
        "message": "Host setup verified. This runner can authenticate exchanges.",
    }


def create_policy(
    db: Session,
    policy_id: str,
    name: str,
    token_id: str,
    effect: str,
    conditions: dict,
    priority: int = 100,
    *,
    user_id: str | None = None,
) -> Policy:
    policy = Policy(
        id=policy_id,
        user_id=user_id,
        name=name,
        priority=priority,
        enabled=True,
        token_id=token_id,
        effect=effect,
        conditions_json=json.dumps(conditions),
        created_at=utcnow(),
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)
    return policy


def update_policy(
    db: Session,
    policy: Policy,
    *,
    name: str | None = None,
    effect: str | None = None,
    conditions: dict | None = None,
    priority: int | None = None,
    enabled: bool | None = None,
) -> Policy:
    if name is not None:
        policy.name = name
    if effect is not None:
        policy.effect = effect
    if conditions is not None:
        policy.conditions_json = json.dumps(conditions)
    if priority is not None:
        policy.priority = priority
    if enabled is not None:
        policy.enabled = enabled
    db.commit()
    db.refresh(policy)
    return policy


def exchange_token(
    db: Session,
    handle: str,
    runner_id: str,
    signature: str,
    timestamp: str,
    nonce: str,
    repository: str,
    workflow: str,
    branch: str,
    runner_environment: str,
    default_ttl: int,
) -> dict:
    from app.crypto import verify_handle, verify_runner_signature
    from app.policy_engine import RequestContext, evaluate_policies

    token_id = verify_handle(handle)
    if not token_id:
        log_audit(db, "exchange_denied", "denied", "Invalid handle")
        raise ValueError("Invalid or tampered generic handle")

    handle_row = (
        db.query(TokenHandle)
        .filter(TokenHandle.handle == handle, TokenHandle.active.is_(True))
        .first()
    )
    if not handle_row:
        log_audit(db, "exchange_denied", "denied", "Handle revoked or unknown", token_id=token_id)
        raise ValueError("Handle revoked or unknown")

    runner = db.query(Runner).filter(Runner.id == runner_id, Runner.active.is_(True)).first()
    if not runner:
        log_audit(
            db, "exchange_denied", "denied", "Unregistered runner",
            token_id=token_id, runner_id=runner_id,
        )
        raise ValueError("Unregistered or inactive runner")

    runner_secret = decrypt_secret(runner.encrypted_secret)
    if not verify_runner_signature(runner_secret, timestamp, nonce, signature):
        log_audit(
            db, "exchange_denied", "denied", "Invalid runner signature",
            token_id=token_id, runner_id=runner_id,
        )
        raise ValueError("Runner authentication failed")

    runner.last_seen_at = utcnow()
    db.commit()

    token = db.query(ManagedToken).filter(ManagedToken.id == token_id).first()
    if not token:
        raise ValueError("Token not found")

    if token.user_id and runner.user_id and token.user_id != runner.user_id:
        log_audit(
            db,
            "exchange_denied",
            "denied",
            "Runner and token belong to different users",
            token_id=token_id,
            runner_id=runner_id,
            user_id=token.user_id,
        )
        raise PermissionError("Runner is not authorized for this token")

    ctx = RequestContext(
        token_id=token_id,
        runner_id=runner_id,
        runner_type=runner.runner_type,
        repository=repository,
        workflow=workflow,
        branch=branch,
        runner_environment=runner_environment,
    )
    policies_q = db.query(Policy)
    if token.user_id:
        policies_q = policies_q.filter(
            (Policy.user_id == token.user_id) | (Policy.user_id.is_(None))
        )
    policies = policies_q.all()
    decision = evaluate_policies(policies, ctx)

    if not decision.allowed:
        log_audit(
            db, "exchange_denied", "denied", decision.reason,
            token_id=token_id, runner_id=runner_id,
            repository=repository, workflow=workflow, branch=branch,
            policy_id=decision.policy_id or "",
            user_id=token.user_id,
        )
        raise PermissionError(decision.reason)

    ttl = min(decision.max_token_lifetime_seconds, token.default_short_lived_ttl, default_ttl)
    long_lived = decrypt_secret(token.encrypted_secret)
    short_token, short_expires = mint_short_lived_token(long_lived, token.target_system, ttl)

    log_audit(
        db, "exchange_success", "success",
        f"Issued token via policy {decision.policy_id}, TTL={ttl}s",
        token_id=token_id, runner_id=runner_id,
        repository=repository, workflow=workflow, branch=branch,
        policy_id=decision.policy_id or "",
        user_id=token.user_id,
    )

    return {
        "access_token": short_token,
        "token_type": "Bearer",
        "expires_at": short_expires.isoformat(),
        "expires_in": ttl,
        "target_system": token.target_system,
        "scopes": token.scopes.split(",") if token.scopes else [],
        "policy_id": decision.policy_id,
    }


def list_tracked_gitlab_projects(db: Session, user_id: str | None = None) -> list[dict[str, Any]]:
    q = db.query(TrackedGitLabProject)
    if user_id:
        q = q.filter(TrackedGitLabProject.user_id == user_id)
    rows = q.order_by(TrackedGitLabProject.project_path).all()
    return [
        {
            "id": row.id,
            "project_path": row.project_path,
            "project_id": row.project_id,
            "display_name": row.display_name or row.project_path,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


def add_tracked_gitlab_project(
    db: Session,
    project_path: str,
    *,
    project_id: int | None = None,
    display_name: str = "",
    user_id: str | None = None,
) -> TrackedGitLabProject:
    path = project_path.strip().lstrip("/")
    if not path or "/" not in path:
        raise ValueError("project_path must look like namespace/project (CI_PROJECT_PATH)")

    existing_q = db.query(TrackedGitLabProject).filter(TrackedGitLabProject.project_path == path)
    if user_id:
        existing_q = existing_q.filter(TrackedGitLabProject.user_id == user_id)
    existing = existing_q.first()
    if existing:
        raise ValueError(f"Project '{path}' is already tracked")

    resolved_id = project_id
    resolved_name = display_name.strip() or path
    try:
        auth = get_user_gitlab_token(db, user_id)
    except ValueError:
        auth = ""
    if auth:
        try:
            if not resolved_id:
                resolved_id = resolve_project_id(path, auth)
        except GitLabApiError as exc:
            raise ValueError(f"Could not resolve project '{path}': {exc}") from exc

    row = TrackedGitLabProject(
        user_id=user_id,
        project_path=path,
        project_id=resolved_id,
        display_name=resolved_name,
        created_at=utcnow(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log_audit(db, "project_tracked", "success", f"Tracking GitLab project {path}", user_id=user_id)
    return row


def remove_tracked_gitlab_project(
    db: Session, tracked_id: int, *, user_id: str | None = None
) -> None:
    q = db.query(TrackedGitLabProject).filter(TrackedGitLabProject.id == tracked_id)
    if user_id:
        q = q.filter(TrackedGitLabProject.user_id == user_id)
    row = q.first()
    if not row:
        raise ValueError("Tracked project not found")
    path = row.project_path
    db.delete(row)
    db.commit()
    log_audit(db, "project_untracked", "success", f"Stopped tracking GitLab project {path}", user_id=user_id)


def fetch_gitlab_membership_projects(
    db: Session,
    search: str = "",
    *,
    quick: bool = False,
    user_id: str | None = None,
) -> dict[str, Any]:
    auth = get_user_gitlab_token(db, user_id)
    tracked_q = db.query(TrackedGitLabProject)
    if user_id:
        tracked_q = tracked_q.filter(TrackedGitLabProject.user_id == user_id)
    tracked_paths = {p.project_path for p in tracked_q.all()}
    query = search.strip().lower()
    timeout = httpx.Timeout(5.0, connect=1.5) if quick else None
    try:
        projects = list_membership_projects(auth, search="", timeout=timeout)
    except GitLabApiError as exc:
        return {
            "gitlab_base_url": settings.gitlab_base_url,
            "projects": [],
            "errors": [str(exc)],
        }
    if query:
        projects = [
            p
            for p in projects
            if query in (p.get("name") or "").lower()
            or query in (p.get("project_path") or "").lower()
        ]
    for project in projects:
        project["tracked"] = project["project_path"] in tracked_paths
    return {
        "gitlab_base_url": settings.gitlab_base_url,
        "projects": projects,
        "errors": [],
    }


def fetch_gitlab_runners(db: Session, user_id: str | None = None) -> dict[str, Any]:
    """List GitLab runners visible to the user's OAuth token, marked if already in CTRS."""
    auth = get_user_gitlab_token(db, user_id)
    runners_q = db.query(Runner)
    if user_id:
        runners_q = runners_q.filter(Runner.user_id == user_id)
    registered_ids = {r.id for r in runners_q.all()}
    try:
        raw = list_all_accessible_runners(auth)
    except GitLabApiError as exc:
        return {
            "gitlab_base_url": settings.gitlab_base_url,
            "runners": [],
            "errors": [str(exc)],
        }

    runners: list[dict[str, Any]] = []
    for entry in raw:
        row = normalize_gitlab_runner(entry)
        suggested = row["suggested_ctrs_id"]
        row["already_registered"] = suggested in registered_ids
        runners.append(row)

    runners.sort(
        key=lambda r: (
            not r["suitable_for_ctrs"],
            r["already_registered"],
            not r["online"],
            (r["description"] or "").lower(),
        )
    )
    return {
        "gitlab_base_url": settings.gitlab_base_url,
        "runners": runners,
        "errors": [],
    }
