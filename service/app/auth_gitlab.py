"""GitLab OAuth authorization-code helpers."""

from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import urlencode

import httpx

from app.config import DEFAULT_GITLAB_BASE_URL, settings


class GitLabOAuthError(Exception):
    pass


def _gitlab_base() -> str:
    return (settings.gitlab_base_url or DEFAULT_GITLAB_BASE_URL).rstrip("/")


def oauth_configured() -> bool:
    return bool(settings.gitlab_oauth_client_id and settings.gitlab_oauth_client_secret)


def build_authorize_url(state: str) -> str:
    if not oauth_configured():
        raise GitLabOAuthError(
            "GitLab OAuth is not configured. Set GITLAB_OAUTH_CLIENT_ID and "
            "GITLAB_OAUTH_CLIENT_SECRET in service/.env"
        )
    params = {
        "client_id": settings.gitlab_oauth_client_id,
        "redirect_uri": settings.gitlab_oauth_redirect_uri,
        "response_type": "code",
        "scope": settings.gitlab_oauth_scopes,
        "state": state,
    }
    return f"{_gitlab_base()}/oauth/authorize?{urlencode(params)}"


def new_oauth_state() -> str:
    return secrets.token_urlsafe(24)


def exchange_code_for_token(code: str) -> dict[str, Any]:
    url = f"{_gitlab_base()}/oauth/token"
    data = {
        "client_id": settings.gitlab_oauth_client_id,
        "client_secret": settings.gitlab_oauth_client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.gitlab_oauth_redirect_uri,
    }
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(url, data=data)
    except httpx.RequestError as exc:
        raise GitLabOAuthError(f"GitLab OAuth unreachable: {exc}") from exc
    if resp.status_code >= 400:
        raise GitLabOAuthError(f"GitLab OAuth token exchange failed: {resp.text}")
    payload = resp.json()
    if not payload.get("access_token"):
        raise GitLabOAuthError("GitLab OAuth response missing access_token")
    return payload


def fetch_gitlab_user(access_token: str) -> dict[str, Any]:
    url = f"{_gitlab_base()}/api/v4/user"
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(url, headers={"Authorization": f"Bearer {access_token}"})
    except httpx.RequestError as exc:
        raise GitLabOAuthError(f"GitLab /user unreachable: {exc}") from exc
    if resp.status_code >= 400:
        raise GitLabOAuthError(f"GitLab /user failed: {resp.text}")
    return resp.json()
