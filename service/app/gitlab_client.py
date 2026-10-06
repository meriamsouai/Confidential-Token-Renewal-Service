"""GitLab REST API helpers for token registration metadata and rotation."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

from app.config import settings

# Default lifetime applied on every GitLab project access token rotate.
DEFAULT_ROTATION_EXPIRES_DAYS = 60


class GitLabApiError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def _api_url(path: str) -> str:
    base = settings.gitlab_base_url.rstrip("/")
    return f"{base}/api/v4{path}"


def _request(
    method: str,
    path: str,
    *,
    auth_token: str,
    data: dict | None = None,
    timeout: float | httpx.Timeout | None = None,
    return_response: bool = False,
) -> Any:
    headers = {"PRIVATE-TOKEN": auth_token}
    url = _api_url(path)
    # Short connect timeout so bad/unreachable GitLab URLs fail fast in the UI.
    req_timeout = timeout if timeout is not None else httpx.Timeout(8.0, connect=2.0)
    try:
        with httpx.Client(timeout=req_timeout) as client:
            resp = client.request(method, url, headers=headers, data=data)
    except httpx.RequestError as exc:
        raise GitLabApiError(f"GitLab API unreachable: {exc}") from exc

    if resp.status_code >= 400:
        detail = resp.text
        try:
            payload = resp.json()
            detail = payload.get("message") or payload.get("error") or detail
        except json.JSONDecodeError:
            pass
        raise GitLabApiError(f"GitLab API {resp.status_code}: {detail}", resp.status_code)

    if return_response:
        return resp

    if not resp.content:
        return {}
    return resp.json()


def _request_paginated_list(
    path: str,
    *,
    auth_token: str,
    per_page: int = 100,
    max_pages: int = 20,
    timeout: float | httpx.Timeout | None = None,
) -> list[dict[str, Any]]:
    """Follow GitLab page/per_page pagination until exhausted."""
    results: list[dict[str, Any]] = []
    sep = "&" if "?" in path else "?"
    for page in range(1, max_pages + 1):
        paged = f"{path}{sep}per_page={per_page}&page={page}"
        resp = _request(
            "GET",
            paged,
            auth_token=auth_token,
            timeout=timeout,
            return_response=True,
        )
        data = resp.json() if resp.content else []
        if not isinstance(data, list):
            raise GitLabApiError("Unexpected GitLab paginated list response")
        results.extend(data)
        if len(data) < per_page:
            break
        next_page = resp.headers.get("X-Next-Page")
        if not next_page:
            break
    return results


def resolve_project_id(project_path: str, auth_token: str) -> int:
    encoded = quote(project_path, safe="")
    data = _request("GET", f"/projects/{encoded}", auth_token=auth_token)
    project_id = data.get("id")
    if not project_id:
        raise GitLabApiError(f"Project not found: {project_path}")
    return int(project_id)


def find_project_access_token_id(
    project_id: int,
    token_name: str,
    auth_token: str,
) -> int:
    tokens = list_project_access_tokens(project_id, auth_token)
    matches: list[dict[str, Any]] = []
    for entry in tokens:
        if entry.get("name") == token_name:
            matches.append(entry)
    if not matches:
        raise GitLabApiError(
            f"Project access token '{token_name}' not found on project {project_id}. "
            "Create it in GitLab Settings → Access tokens."
        )
    # After rotation GitLab keeps revoked entries; prefer the active token.
    for entry in matches:
        if entry.get("active", True) and not entry.get("revoked", False):
            token_id = entry.get("id") or entry.get("user_id")
            if token_id is not None:
                return int(token_id)
    entry = matches[0]
    token_id = entry.get("id") or entry.get("user_id")
    if token_id is not None:
        return int(token_id)
    raise GitLabApiError(
        f"Project access token '{token_name}' on project {project_id} has no id in GitLab response."
    )


def list_all_accessible_runners(auth_token: str) -> list[dict[str, Any]]:
    """List runners the operator PAT can see (GET /runners)."""
    try:
        return _request_paginated_list("/runners", auth_token=auth_token, max_pages=10)
    except GitLabApiError as exc:
        if exc.status_code in (401, 403):
            return []
        raise


def suggest_ctrs_runner_id(gitlab_runner: dict[str, Any]) -> str:
    """Build a stable CTRS runner_id from GitLab description or numeric id."""
    desc = (gitlab_runner.get("description") or "").strip()
    if desc:
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", desc).strip("-").lower()
        slug = re.sub(r"-{2,}", "-", slug)[:48].strip("-")
        if slug:
            return slug
    return f"gl-runner-{int(gitlab_runner.get('id') or 0)}"


def normalize_gitlab_runner(entry: dict[str, Any]) -> dict[str, Any]:
    runner_type = str(entry.get("runner_type") or "")
    is_shared = bool(entry.get("is_shared", runner_type == "instance_type"))
    tag_list = entry.get("tag_list") or []
    if not isinstance(tag_list, list):
        tag_list = []
    return {
        "gitlab_runner_id": int(entry.get("id") or 0),
        "description": entry.get("description") or "",
        "active": bool(entry.get("active", True)),
        "online": bool(entry.get("online", False)),
        "status": entry.get("status") or ("online" if entry.get("online") else "unknown"),
        "is_shared": is_shared,
        "runner_type": runner_type or ("instance_type" if is_shared else "project_type"),
        "tag_list": [str(t) for t in tag_list],
        "ip_address": entry.get("ip_address") or "",
        "suggested_ctrs_id": suggest_ctrs_runner_id(entry),
        "suitable_for_ctrs": not is_shared,
    }


def list_project_access_tokens(project_id: int, auth_token: str) -> list[dict[str, Any]]:
    return _request_paginated_list(
        f"/projects/{project_id}/access_tokens",
        auth_token=auth_token,
    )


def validate_gitlab_project_token_secret(
    secret: str,
    *,
    project_path: str,
    project_id: int | None = None,
) -> None:
    """
    Prove the pasted project access token works before vaulting it.
    Rejects wrong/revoked/expired secrets and tokens that cannot access the project.
    """
    secret = (secret or "").strip()
    if not secret:
        raise GitLabApiError("GitLab token secret is empty.")

    try:
        _request("GET", "/user", auth_token=secret)
    except GitLabApiError as exc:
        if exc.status_code in (401, 403):
            raise GitLabApiError(
                "Invalid GitLab token secret: authentication failed. "
                "Paste the exact project access token value (glpat-…) shown once in GitLab."
            ) from exc
        raise GitLabApiError(f"Could not validate GitLab token secret: {exc}") from exc

    path = (project_path or "").strip().lstrip("/")
    try:
        if project_id:
            _request("GET", f"/projects/{int(project_id)}", auth_token=secret)
        elif path:
            encoded = quote(path, safe="")
            _request("GET", f"/projects/{encoded}", auth_token=secret)
    except GitLabApiError as exc:
        if exc.status_code in (401, 403, 404):
            raise GitLabApiError(
                f"Token secret is not valid for project '{path or project_id}'. "
                "Use the secret belonging to this project's access token."
            ) from exc
        raise GitLabApiError(f"Could not verify token access to project: {exc}") from exc


def list_membership_projects(
    auth_token: str,
    *,
    search: str = "",
    per_page: int = 50,
    timeout: float | httpx.Timeout | None = None,
) -> list[dict[str, Any]]:
    """Projects the operator PAT can access (for the dashboard project picker)."""
    path = (
        f"/projects?membership=true&simple=true&order_by=last_activity_at&sort=desc"
        f"&per_page={min(max(per_page, 1), 100)}"
    )
    if search.strip():
        path += f"&search={quote(search.strip())}"
    data = _request("GET", path, auth_token=auth_token, timeout=timeout)
    if not isinstance(data, list):
        raise GitLabApiError("Unexpected GitLab projects list response")
    results: list[dict[str, Any]] = []
    for entry in data:
        path_with_namespace = entry.get("path_with_namespace") or ""
        if not path_with_namespace:
            continue
        results.append(
            {
                "project_id": int(entry.get("id")),
                "project_path": path_with_namespace,
                "name": entry.get("name") or path_with_namespace,
                "description": (entry.get("description") or "")[:200],
            }
        )
    return results


def rotate_project_access_token(
    project_id: int,
    access_token_id: int,
    auth_token: str,
    *,
    expires_days: int = DEFAULT_ROTATION_EXPIRES_DAYS,
) -> tuple[str, datetime | None, int]:
    """
    Rotate a GitLab project access token. Returns (new_secret, expires_at, new_token_id).
    GitLab revokes the old token id and issues a new id in the same family.
    Requires a PAT with Maintainer+ access or sufficient token-management scope.
    Always requests a fixed expires_at so GitLab does not fall back to its short default.
    """
    expires_at_date = (datetime.now(timezone.utc) + timedelta(days=max(expires_days, 1))).date()
    data = _request(
        "POST",
        f"/projects/{project_id}/access_tokens/{access_token_id}/rotate",
        auth_token=auth_token,
        data={"expires_at": expires_at_date.isoformat()},
    )
    new_secret = data.get("token")
    if not new_secret:
        raise GitLabApiError("GitLab rotate response did not include a new token")

    new_token_id = data.get("id") or data.get("user_id")
    if new_token_id is None:
        raise GitLabApiError("GitLab rotate response did not include a new token id")

    expires_at: datetime | None = None
    raw_expires = data.get("expires_at")
    if raw_expires:
        expires_at = datetime.fromisoformat(str(raw_expires).replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

    return new_secret, expires_at, int(new_token_id)


def revoke_project_access_token(
    project_id: int,
    access_token_id: int,
    auth_token: str,
) -> None:
    """Revoke a GitLab project access token (DELETE). Idempotent if already revoked."""
    try:
        _request(
            "DELETE",
            f"/projects/{project_id}/access_tokens/{access_token_id}",
            auth_token=auth_token,
        )
    except GitLabApiError as exc:
        # Already gone / already revoked is fine for our purposes.
        if exc.status_code in (404, 400):
            detail = str(exc).lower()
            if "not found" in detail or "revoked" in detail:
                return
        raise


def build_gitlab_provider_metadata(
    project_path: str,
    access_token_name: str,
    auth_token: str,
    *,
    project_id: int | None = None,
    access_token_id: int | None = None,
) -> dict[str, Any]:
    resolved_project_id = project_id or resolve_project_id(project_path, auth_token)
    resolved_token_id = access_token_id or find_project_access_token_id(
        resolved_project_id, access_token_name, auth_token
    )
    return {
        "gitlab_project_path": project_path,
        "gitlab_project_id": resolved_project_id,
        "gitlab_access_token_id": resolved_token_id,
        "gitlab_access_token_name": access_token_name,
    }
