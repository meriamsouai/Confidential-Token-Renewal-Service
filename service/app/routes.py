import json

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.admin_auth import create_session_token, generate_runner_secret, require_user
from app.auth_gitlab import (
    GitLabOAuthError,
    build_authorize_url,
    exchange_code_for_token,
    fetch_gitlab_user,
    new_oauth_state,
)
from app.models import AuditEvent, ManagedToken, Policy, RenewalEvent, Runner, User, get_db
from app.schemas import (
    AuditEventResponse,
    BootstrapResponse,
    ExchangeRequest,
    ExchangeResponse,
    HealthResponse,
    PolicyResponse,
    RegisterGitLabSetupRequest,
    RegisterGitLabSetupResponse,
    RegisterPolicyRequest,
    RegisterPolicyResponse,
    RegisterRunnerRequest,
    RegisterRunnerResponse,
    RegisterTokenRequest,
    RegisterTokenResponse,
    ResyncVaultSecretRequest,
    LinkGitLabMetadataRequest,
    UpdatePolicyRequest,
    AdminConfigResponse,
    OperatorSettingsResponse,
    OperatorSettingsUpdate,
    SetupVerifyResponse,
    SetupCheckItem,
    GitLabAccessTokensResponse,
    GitLabAccessTokenView,
    GitLabProjectsResponse,
    GitLabProjectOption,
    GitLabRunnersResponse,
    GitLabRunnerOption,
    TrackGitLabProjectRequest,
    TrackedGitLabProjectView,
    RenewalEventResponse,
    RunnerResponse,
    RunnerHeartbeatRequest,
    RunnerHeartbeatResponse,
    TokenResponse,
    UserResponse,
    GitLabPatLoginRequest,
)
from app.services import (
    add_tracked_gitlab_project,
    check_expiring_tokens,
    create_managed_token,
    create_policy,
    resync_vault_secret,
    exchange_token,
    fetch_gitlab_access_tokens,
    fetch_gitlab_membership_projects,
    fetch_gitlab_runners,
    get_user_gitlab_token,
    list_tracked_gitlab_projects,
    log_audit,
    register_runner,
    remove_tracked_gitlab_project,
    renew_token,
    resolve_gitlab_registration_metadata,
    revoke_managed_token,
    set_provider_metadata,
    token_to_dict,
    update_policy,
    verify_runner_host,
)
from app.config import settings
from app.crypto import decrypt_secret, encrypt_secret, utcnow
from app.gitlab_client import GitLabApiError
from app.operator_settings import (
    get_or_create_operator_settings,
    operator_settings_dict,
    set_gitlab_base_url,
)
from app.scheduler import reschedule_renewal_job


router = APIRouter(prefix="/api/v1")

# In-memory OAuth state (prototype). Restart clears pending logins.
_oauth_states: set[str] = set()


def _user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        name=user.name,
        gitlab_connected=bool((user.encrypted_gitlab_token or "").strip()),
        notify_email_enabled=bool(user.notify_email_enabled),
    )


def _owned_token(db, token_id: str, user: User) -> ManagedToken:
    token = (
        db.query(ManagedToken)
        .filter(ManagedToken.id == token_id, ManagedToken.user_id == user.id)
        .first()
    )
    if not token:
        raise HTTPException(404, "Token not found")
    return token


def _owned_runner(db, runner_id: str, user: User) -> Runner:
    runner = db.query(Runner).filter(Runner.id == runner_id, Runner.user_id == user.id).first()
    if not runner:
        raise HTTPException(404, "Runner not found")
    return runner


def _owned_policy(db, policy_id: str, user: User) -> Policy:
    policy = db.query(Policy).filter(Policy.id == policy_id, Policy.user_id == user.id).first()
    if not policy:
        raise HTTPException(404, "Policy not found")
    return policy


def _upsert_user_from_gitlab(
    db: Session,
    gl_user: dict,
    *,
    access: str,
    refresh: str = "",
) -> User:
    import uuid

    gitlab_user_id = int(gl_user["id"])
    user = db.query(User).filter(User.gitlab_user_id == gitlab_user_id).first()
    now = utcnow()
    if not user:
        user = User(
            id=str(uuid.uuid4()),
            gitlab_user_id=gitlab_user_id,
            username=gl_user.get("username") or "",
            email=gl_user.get("email") or "",
            name=gl_user.get("name") or gl_user.get("username") or "",
            encrypted_gitlab_token=encrypt_secret(access),
            encrypted_gitlab_refresh_token=encrypt_secret(refresh) if refresh else "",
            notify_email_enabled=True,
            created_at=now,
            last_login_at=now,
        )
        db.add(user)
    else:
        user.username = gl_user.get("username") or user.username
        user.email = gl_user.get("email") or user.email
        user.name = gl_user.get("name") or user.name
        user.encrypted_gitlab_token = encrypt_secret(access)
        if refresh:
            user.encrypted_gitlab_refresh_token = encrypt_secret(refresh)
        user.last_login_at = now
    db.commit()
    db.refresh(user)
    get_or_create_operator_settings(db, user.id)
    return user


def _set_session_cookie(response: Response, user_id: str) -> None:
    session = create_session_token(user_id)
    response.set_cookie(
        key=settings.session_cookie_name,
        value=session,
        httponly=True,
        samesite="lax",
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )


@router.get("/auth/gitlab/login")
def auth_gitlab_login():
    """Redirect browser to GitLab OAuth authorize URL (optional; needs OAuth app)."""
    try:
        state = new_oauth_state()
        _oauth_states.add(state)
        url = build_authorize_url(state)
    except GitLabOAuthError as exc:
        raise HTTPException(503, str(exc)) from exc
    return RedirectResponse(url)


@router.get("/auth/gitlab/callback")
def auth_gitlab_callback(code: str = "", state: str = "", db: Session = Depends(get_db)):
    if not code or not state or state not in _oauth_states:
        raise HTTPException(400, "Invalid OAuth callback (missing or unknown state)")
    _oauth_states.discard(state)
    try:
        token_payload = exchange_code_for_token(code)
        access = token_payload["access_token"]
        refresh = token_payload.get("refresh_token") or ""
        gl_user = fetch_gitlab_user(access)
    except GitLabOAuthError as exc:
        raise HTTPException(400, str(exc)) from exc

    user = _upsert_user_from_gitlab(db, gl_user, access=access, refresh=refresh)
    redirect = RedirectResponse(f"{settings.dashboard_url.rstrip('/')}/?login=ok")
    _set_session_cookie(redirect, user.id)
    return redirect


@router.post("/auth/gitlab/pat", response_model=UserResponse)
def auth_gitlab_pat(req: GitLabPatLoginRequest, response: Response, db: Session = Depends(get_db)):
    """
    Sign in with a GitLab personal access token.

    Use this when the GitLab instance disables user-owned OAuth applications
    (common on university instances). Create a PAT under Edit profile → Access tokens
    with scopes: api (and read_user if offered).
    """
    token = (req.token or "").strip()
    if not token:
        raise HTTPException(400, "Paste your GitLab personal access token")
    try:
        gl_user = fetch_gitlab_user(token)
    except GitLabOAuthError as exc:
        raise HTTPException(401, f"GitLab rejected this token: {exc}") from exc

    user = _upsert_user_from_gitlab(db, gl_user, access=token)
    _set_session_cookie(response, user.id)
    log_audit(db, "user_login_pat", "success", f"User {user.username} signed in with PAT", user_id=user.id)
    return _user_response(user)


@router.get("/auth/me", response_model=UserResponse)
def auth_me(user: User = Depends(require_user)):
    return _user_response(user)


@router.post("/auth/logout")
def auth_logout():
    response = Response(content='{"message":"logged out"}', media_type="application/json")
    response.delete_cookie(settings.session_cookie_name, path="/")
    return response




@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)):
    return HealthResponse(
        status="ok",
        timestamp=utcnow().isoformat(),
        tokens_managed=db.query(ManagedToken).count(),
        runners_registered=db.query(Runner).count(),
    )


@router.get("/gitlab/access-tokens", response_model=GitLabAccessTokensResponse)
def list_gitlab_access_tokens(db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Live GitLab project access tokens (metadata only — secrets never returned)."""
    try:
        data = fetch_gitlab_access_tokens(db, user_id=user.id)
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from exc
    return GitLabAccessTokensResponse(
        gitlab_base_url=data["gitlab_base_url"],
        tokens=[GitLabAccessTokenView(**t) for t in data["tokens"]],
        errors=data["errors"],
        tracked_projects=[TrackedGitLabProjectView(**p) for p in data.get("tracked_projects", [])],
    )


@router.get("/gitlab/projects", response_model=GitLabProjectsResponse)
def list_gitlab_projects(search: str = "", quick: bool = False, db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Projects visible to the signed-in user's GitLab OAuth token."""
    try:
        data = fetch_gitlab_membership_projects(db, search=search, quick=quick, user_id=user.id)
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from exc
    return GitLabProjectsResponse(
        gitlab_base_url=data["gitlab_base_url"],
        projects=[GitLabProjectOption(**p) for p in data["projects"]],
        errors=data["errors"],
    )


@router.get("/gitlab/runners", response_model=GitLabRunnersResponse)
def list_gitlab_runners(db: Session = Depends(get_db), user: User = Depends(require_user)):
    """GitLab runners visible to the signed-in user — pick one to register in CTRS."""
    try:
        data = fetch_gitlab_runners(db, user_id=user.id)
    except ValueError as exc:
        raise HTTPException(503, str(exc)) from exc
    return GitLabRunnersResponse(
        gitlab_base_url=data["gitlab_base_url"],
        runners=[GitLabRunnerOption(**r) for r in data["runners"]],
        errors=data["errors"],
    )


@router.get("/gitlab/tracked-projects", response_model=list[TrackedGitLabProjectView])
def get_tracked_projects(db: Session = Depends(get_db), user: User = Depends(require_user)):
    return [TrackedGitLabProjectView(**p) for p in list_tracked_gitlab_projects(db, user_id=user.id)]


@router.post(
    "/gitlab/tracked-projects",
    response_model=TrackedGitLabProjectView,
)
def track_gitlab_project(req: TrackGitLabProjectRequest, db: Session = Depends(get_db), user: User = Depends(require_user)):
    try:
        row = add_tracked_gitlab_project(
            db,
            req.project_path,
            project_id=req.project_id,
            display_name=req.display_name,
            user_id=user.id,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return TrackedGitLabProjectView(
        id=row.id,
        project_path=row.project_path,
        project_id=row.project_id,
        display_name=row.display_name or row.project_path,
        created_at=row.created_at.isoformat() if row.created_at else None,
    )


@router.delete("/gitlab/tracked-projects/{tracked_id}")
def untrack_gitlab_project(tracked_id: int, db: Session = Depends(get_db), user: User = Depends(require_user)):
    try:
        remove_tracked_gitlab_project(db, tracked_id, user_id=user.id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"message": "Project removed from tracking", "id": tracked_id}


@router.get("/tokens", response_model=list[TokenResponse])
def list_tokens(db: Session = Depends(get_db), user: User = Depends(require_user)):
    tokens = db.query(ManagedToken).filter(ManagedToken.user_id == user.id).all()
    return [TokenResponse(**token_to_dict(t, db)) for t in tokens]


@router.get("/tokens/{token_id}", response_model=TokenResponse)
def get_token(token_id: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    token = _owned_token(db, token_id, user)
    return TokenResponse(**token_to_dict(token, db))


@router.get("/tokens/{token_id}/renewals", response_model=list[RenewalEventResponse])
def get_token_renewals(token_id: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    _owned_token(db, token_id, user)
    events = (
        db.query(RenewalEvent)
        .filter(RenewalEvent.token_id == token_id)
        .order_by(RenewalEvent.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        RenewalEventResponse(
            id=e.id,
            token_id=e.token_id,
            status=e.status,
            message=e.message,
            source=getattr(e, "source", None) or "manual",
            created_at=e.created_at.isoformat(),
        )
        for e in events
    ]


@router.post("/tokens/{token_id}/renew", response_model=RenewalEventResponse)
def trigger_renewal(token_id: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    token = _owned_token(db, token_id, user)
    event = renew_token(db, token, source="manual")
    return RenewalEventResponse(
        id=event.id,
        token_id=event.token_id,
        status=event.status,
        message=event.message,
        source=getattr(event, "source", None) or "manual",
        created_at=event.created_at.isoformat(),
    )


@router.post(
    "/admin/tokens/{token_id}/vault-secret",
    response_model=RenewalEventResponse,
)
def admin_resync_vault_secret(
    token_id: str, req: ResyncVaultSecretRequest, db: Session = Depends(get_db), user: User = Depends(require_user)
):
    """Replace the vaulted glpat after a rotation done in GitLab. CI handle is unchanged."""
    token = _owned_token(db, token_id, user)
    try:
        event = resync_vault_secret(db, token, req.secret)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return RenewalEventResponse(
        id=event.id,
        token_id=event.token_id,
        status=event.status,
        message=event.message,
        source=getattr(event, "source", None) or "gitlab_resync",
        created_at=event.created_at.isoformat(),
    )


@router.post("/tokens/{token_id}/revoke")
def trigger_revoke(token_id: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    token = _owned_token(db, token_id, user)
    if token.renewal_status == "revoked":
        raise HTTPException(409, f"Token '{token_id}' is already revoked")
    try:
        result = revoke_managed_token(db, token)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return result


@router.post("/exchange", response_model=ExchangeResponse)
def token_exchange(req: ExchangeRequest, db: Session = Depends(get_db)):
    try:
        result = exchange_token(
            db,
            handle=req.handle,
            runner_id=req.runner_id,
            signature=req.signature,
            timestamp=req.timestamp,
            nonce=req.nonce,
            repository=req.repository,
            workflow=req.workflow,
            branch=req.branch,
            runner_environment=req.runner_environment,
            default_ttl=settings.default_short_lived_ttl_seconds,
        )
        return ExchangeResponse(**result)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    except ValueError as e:
        raise HTTPException(401, str(e))


@router.get("/policies", response_model=list[PolicyResponse])
def list_policies(db: Session = Depends(get_db), user: User = Depends(require_user)):
    policies = (
        db.query(Policy)
        .filter(Policy.user_id == user.id)
        .order_by(Policy.priority.desc())
        .all()
    )
    return [
        PolicyResponse(
            id=p.id,
            name=p.name,
            priority=p.priority,
            enabled=p.enabled,
            token_id=p.token_id,
            effect=p.effect,
            conditions=json.loads(p.conditions_json),
        )
        for p in policies
    ]


@router.get("/runners", response_model=list[RunnerResponse])
def list_runners(db: Session = Depends(get_db), user: User = Depends(require_user)):
    runners = db.query(Runner).filter(Runner.user_id == user.id).all()
    return [
        RunnerResponse(
            id=r.id,
            name=r.name,
            runner_type=r.runner_type,
            active=r.active,
            last_seen_at=r.last_seen_at.isoformat() if r.last_seen_at else None,
            host_setup="verified" if r.last_seen_at else "pending",
        )
        for r in runners
    ]


@router.post("/runners/heartbeat", response_model=RunnerHeartbeatResponse)
def runner_heartbeat(req: RunnerHeartbeatRequest, db: Session = Depends(get_db)):
    """Prove the runner host has the CTRS secret installed (signed challenge)."""
    try:
        result = verify_runner_host(
            db,
            runner_id=req.runner_id,
            signature=req.signature,
            timestamp=req.timestamp,
            nonce=req.nonce,
        )
    except ValueError as exc:
        raise HTTPException(401, str(exc)) from exc
    return RunnerHeartbeatResponse(**result)


@router.get("/audit", response_model=list[AuditEventResponse])
def list_audit(limit: int = 100, db: Session = Depends(get_db), user: User = Depends(require_user)):
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.user_id == user.id)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        AuditEventResponse(
            id=e.id,
            event_type=e.event_type,
            token_id=e.token_id,
            runner_id=e.runner_id,
            repository=e.repository,
            workflow=e.workflow,
            branch=e.branch,
            policy_id=e.policy_id or "",
            outcome=e.outcome,
            detail=e.detail,
            created_at=e.created_at.isoformat(),
        )
        for e in events
    ]


@router.post("/admin/bootstrap", response_model=BootstrapResponse)
def bootstrap_demo(db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Create demo tokens, policies, and runner for testing (scoped to the signed-in user)."""
    if db.query(ManagedToken).filter(ManagedToken.user_id == user.id).count() > 0:
        raise HTTPException(400, "Your account already has tokens. Delete them or use a fresh user.")

    suffix = user.id.replace("-", "")[:8]
    runner_id = f"runner-demo-{suffix}"
    tok_gh = f"tok-github-deploy-{suffix}"
    tok_gl = f"tok-gitlab-registry-{suffix}"
    runner_secret = "demo-runner-secret-change-in-production"
    register_runner(
        db, runner_id, runner_id, "self-hosted", runner_secret, user_id=user.id
    )

    _, gh_handle = create_managed_token(
        db,
        token_id=tok_gh,
        name=tok_gh,
        target_system="github",
        owner="platform-team",
        scopes=["repo", "workflow"],
        secret="ghp_long_lived_simulated_secret_abc123",
        renewal_method="api",
        expires_days=45,
        usage_locations=["acme/deploy-pipeline:release", "acme/deploy-pipeline:deploy"],
        is_demo=True,
        user_id=user.id,
    )

    _, gl_handle = create_managed_token(
        db,
        token_id=tok_gl,
        name=tok_gl,
        target_system="gitlab",
        owner="platform-team",
        scopes=["read_registry", "write_registry"],
        secret="glpat-long-lived-simulated-xyz789",
        renewal_method="api",
        expires_days=60,
        usage_locations=["acme/container-images:build"],
        is_demo=True,
        user_id=user.id,
    )

    create_policy(
        db,
        policy_id=f"pol-deny-hosted-{suffix}",
        name=f"pol-deny-hosted-{suffix}",
        token_id=tok_gh,
        effect="deny",
        conditions={"deny_github_hosted": True, "deny_gitlab_shared": True},
        priority=1000,
        user_id=user.id,
    )

    create_policy(
        db,
        policy_id=f"pol-allow-demo-{suffix}",
        name=f"pol-allow-demo-{suffix}",
        token_id=tok_gh,
        effect="allow",
        conditions={
            "runner_ids": [runner_id],
            "runner_types": ["self-hosted"],
            "repositories": ["acme/deploy-pipeline"],
            "workflows": ["release", "deploy"],
            "branches": ["main", "release/*"],
            "max_token_lifetime_seconds": 3600,
        },
        priority=100,
        user_id=user.id,
    )

    create_policy(
        db,
        policy_id=f"pol-gitlab-registry-{suffix}",
        name=f"pol-gitlab-registry-{suffix}",
        token_id=tok_gl,
        effect="allow",
        conditions={
            "runner_ids": [runner_id],
            "runner_types": ["self-hosted"],
            "repositories": ["acme/container-images"],
            "workflows": ["build", "publish"],
            "branches": ["main"],
            "max_token_lifetime_seconds": 1800,
        },
        priority=100,
        user_id=user.id,
    )

    log_audit(db, "bootstrap", "success", "Demo data created", user_id=user.id)

    return BootstrapResponse(
        message="Demo environment bootstrapped successfully",
        runner_id=runner_id,
        runner_secret=runner_secret,
        handles={
            tok_gh: gh_handle,
            tok_gl: gl_handle,
        },
    )


@router.post("/admin/runners", response_model=RegisterRunnerResponse)
def admin_register_runner(req: RegisterRunnerRequest, db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Register a self-hosted runner. Returns runner_secret once — store on the runner host only."""
    runner_id = req.runner_id
    if db.query(Runner).filter(Runner.id == runner_id, Runner.user_id == user.id).first():
        raise HTTPException(409, f"Runner '{runner_id}' already exists")
    # Global id uniqueness (CI uses CTRS_RUNNER_ID)
    if db.query(Runner).filter(Runner.id == runner_id).first():
        raise HTTPException(409, f"Runner id '{runner_id}' is already taken")

    runner_secret = req.runner_secret or generate_runner_secret()
    register_runner(
        db,
        runner_id,
        (req.name or runner_id).strip() or runner_id,
        req.runner_type,
        runner_secret,
        user_id=user.id,
    )
    log_audit(db, "runner_registered", "success", f"Runner {runner_id} registered", runner_id=runner_id, user_id=user.id)
    return RegisterRunnerResponse(
        message="Runner registered. Store runner_secret on the runner host (not in GitLab CI).",
        runner_id=runner_id,
        runner_secret=runner_secret,
    )


@router.delete("/admin/runners/{runner_id}")
def admin_delete_runner(runner_id: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    runner = _owned_runner(db, runner_id, user)
    db.delete(runner)
    db.commit()
    log_audit(db, "runner_deleted", "success", f"Runner {runner_id} deleted", runner_id=runner_id, user_id=user.id)
    return {"message": "Runner deleted", "runner_id": runner_id}


@router.post("/admin/tokens", response_model=RegisterTokenResponse)
def admin_register_token(req: RegisterTokenRequest, db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Register a real long-lived token in the encrypted vault. Returns generic handle for CI."""
    token_id = req.token_id
    if db.query(ManagedToken).filter(ManagedToken.id == token_id).first():
        raise HTTPException(409, f"Token '{token_id}' already exists")

    _, handle = create_managed_token(
        db,
        token_id=token_id,
        name=token_id,
        target_system=req.target_system,
        owner=req.owner or user.username,
        scopes=req.scopes,
        secret=req.secret,
        renewal_method=req.renewal_method,
        expires_days=req.expires_days,
        usage_locations=req.usage_locations,
        user_id=user.id,
    )
    token = db.query(ManagedToken).filter(ManagedToken.id == token_id).first()
    if token:
        token.default_short_lived_ttl = req.default_short_lived_ttl
        db.commit()

    log_audit(db, "token_registered", "success", f"Token {token_id} registered", token_id=token_id, user_id=user.id)
    return RegisterTokenResponse(
        message="Token registered. Put the handle (not the secret) in GitLab CI variables.",
        token_id=token_id,
        handle=handle,
    )


@router.post("/admin/policies", response_model=RegisterPolicyResponse)
def admin_register_policy(req: RegisterPolicyRequest, db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Create an allow/deny policy for token exchange."""
    policy_id = req.policy_id
    if db.query(Policy).filter(Policy.id == policy_id, Policy.user_id == user.id).first():
        raise HTTPException(409, f"Policy '{policy_id}' already exists")
    if db.query(Policy).filter(Policy.id == policy_id).first():
        raise HTTPException(409, f"Policy id '{policy_id}' is already taken")
    _owned_token(db, req.token_id, user)

    create_policy(
        db,
        policy_id=policy_id,
        name=policy_id,
        token_id=req.token_id,
        effect=req.effect,
        conditions=req.conditions,
        priority=req.priority,
        user_id=user.id,
    )
    log_audit(
        db, "policy_created", "success", f"Policy {policy_id} created", token_id=req.token_id, user_id=user.id
    )
    return RegisterPolicyResponse(message="Policy created", policy_id=policy_id)


@router.patch("/admin/policies/{policy_id}", response_model=PolicyResponse)
def admin_update_policy(policy_id: str, req: UpdatePolicyRequest, db: Session = Depends(get_db), user: User = Depends(require_user)):
    policy = _owned_policy(db, policy_id, user)
    update_policy(
        db,
        policy,
        name=req.name,
        effect=req.effect,
        conditions=req.conditions,
        priority=req.priority,
        enabled=req.enabled,
    )
    log_audit(
        db, "policy_updated", "success", f"Policy {policy_id} updated", token_id=policy.token_id
    )
    return PolicyResponse(
        id=policy.id,
        name=policy.name,
        priority=policy.priority,
        enabled=policy.enabled,
        token_id=policy.token_id,
        effect=policy.effect,
        conditions=json.loads(policy.conditions_json),
    )


@router.delete("/admin/policies/{policy_id}")
def admin_delete_policy(policy_id: str, db: Session = Depends(get_db), user: User = Depends(require_user)):
    policy = _owned_policy(db, policy_id, user)
    token_id = policy.token_id
    db.delete(policy)
    db.commit()
    log_audit(db, "policy_deleted", "success", f"Policy {policy_id} deleted", token_id=token_id, user_id=user.id)
    return {"message": "Policy deleted", "policy_id": policy_id}


@router.get("/admin/config", response_model=AdminConfigResponse)
def admin_config(db: Session = Depends(get_db), user: User = Depends(require_user)):
    ops = operator_settings_dict(db, user)
    return AdminConfigResponse(
        admin_key_required=False,
        gitlab_base_url=ops["gitlab_base_url"],
        gitlab_pat_configured=ops["gitlab_pat_configured"],
        renewal_check_interval_minutes=ops["renewal_check_interval_minutes"],
        renewal_threshold_days=ops["renewal_threshold_days"],
        oauth_configured=ops.get("oauth_configured", False),
        smtp_configured=ops.get("smtp_configured", False),
        authenticated=True,
        user=_user_response(user),
    )


@router.get("/admin/operator-settings", response_model=OperatorSettingsResponse)
def get_operator_settings(db: Session = Depends(get_db), user: User = Depends(require_user)):
    return OperatorSettingsResponse(**operator_settings_dict(db, user))


@router.patch("/admin/operator-settings", response_model=OperatorSettingsResponse)
def patch_operator_settings(req: OperatorSettingsUpdate, db: Session = Depends(get_db), user: User = Depends(require_user)):
    row = get_or_create_operator_settings(db, user.id)
    if req.renewal_check_interval_minutes is not None:
        row.renewal_check_interval_minutes = req.renewal_check_interval_minutes
    if req.renewal_threshold_days is not None:
        row.renewal_threshold_days = req.renewal_threshold_days
    db.commit()
    db.refresh(row)

    cleared_tracked = 0
    if req.gitlab_base_url is not None:
        try:
            new_url, cleared_tracked = set_gitlab_base_url(db, req.gitlab_base_url, user_id=user.id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    else:
        new_url = None

    reschedule_renewal_job(row.renewal_check_interval_minutes)
    detail_parts = [
        f"Renewal interval={row.renewal_check_interval_minutes}min",
        f"threshold={row.renewal_threshold_days}d",
    ]
    if new_url is not None:
        detail_parts.append(f"gitlab_base_url={new_url}")
    if cleared_tracked:
        detail_parts.append(f"cleared_tracked_projects={cleared_tracked}")
    log_audit(
        db,
        "operator_settings_updated",
        "success",
        ", ".join(detail_parts),
    )
    return OperatorSettingsResponse(**operator_settings_dict(db, user))


@router.get("/admin/setup-verify", response_model=SetupVerifyResponse)
def verify_setup(db: Session = Depends(get_db), user: User = Depends(require_user)):
    """Server-side checklist — does not run confstr (that happens on the runner host)."""
    runners = db.query(Runner).filter(Runner.user_id == user.id).count()
    tokens = db.query(ManagedToken).filter(ManagedToken.user_id == user.id, ManagedToken.is_demo.is_(False)).count()
    policies = db.query(Policy).filter(Policy.user_id == user.id, Policy.enabled.is_(True)).count()
    pat_ok = bool((user.encrypted_gitlab_token or "").strip()) or bool(settings.gitlab_pat)
    exchanges = (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == "exchange_success", AuditEvent.user_id == user.id)
        .count()
    )

    checks = [
        SetupCheckItem(
            id="renewal_pat",
            label="GitLab renewal PAT configured (service/.env)",
            passed=pat_ok,
            detail="Sign in with GitLab OAuth (or set GITLAB_PAT for legacy).",
        ),
        SetupCheckItem(
            id="runner",
            label="At least one CTRS runner registered",
            passed=runners > 0,
            detail=f"{runners} runner(s) in CTRS.",
        ),
        SetupCheckItem(
            id="vault_token",
            label="At least one real token in vault",
            passed=tokens > 0,
            detail=f"{tokens} non-demo token(s).",
        ),
        SetupCheckItem(
            id="policies",
            label="At least one enabled policy",
            passed=policies > 0,
            detail=f"{policies} enabled policy/policies.",
        ),
        SetupCheckItem(
            id="exchange",
            label="Successful exchange recorded (after you test)",
            passed=exchanges > 0,
            detail=f"{exchanges} exchange_success event(s) in audit log.",
        ),
    ]
    server_ready = pat_ok and runners > 0 and tokens > 0 and policies > 0
    next_steps = []
    if not pat_ok:
        next_steps.append("Sign in with GitLab so CTRS can call the GitLab API on your behalf.")
    if runners == 0:
        next_steps.append("Complete Setup wizard step 2 (register runner).")
    if tokens == 0:
        next_steps.append("Complete Setup wizard step 3 (register GitLab token).")
    if server_ready and exchanges == 0:
        next_steps.append("Run confstr exchange on the runner host, then check Audit log.")
    if server_ready and exchanges > 0:
        next_steps.append("Push GitLab CI pipeline for full end-to-end demo.")

    return SetupVerifyResponse(
        ready=server_ready and exchanges > 0,
        checks=checks,
        next_steps=next_steps,
    )


@router.post(
    "/admin/gitlab/register",
    response_model=RegisterGitLabSetupResponse,
)
def admin_register_gitlab_setup(req: RegisterGitLabSetupRequest, db: Session = Depends(get_db), user: User = Depends(require_user)):
    """
    One-call setup for real GitLab integration:
    registers vault token + allow policy (+ optional deny shared-runner policy).
    """
    def _slug(value: str) -> str:
        cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in (value or "").strip().lower())
        while "--" in cleaned:
            cleaned = cleaned.replace("--", "-")
        return cleaned.strip("-_")[:48] or "gitlab-token"

    token_id = (req.token_id or "").strip()
    if not token_id:
        base = _slug(req.gitlab_access_token_name) or _slug(req.project_path.split("/")[-1])
        token_id = base
        if req.gitlab_access_token_id:
            candidate = f"{base}-{req.gitlab_access_token_id}"
            if len(candidate) <= 64:
                token_id = candidate
        n = 2
        while db.query(ManagedToken).filter(ManagedToken.id == token_id).first():
            suffix = f"-{n}"
            token_id = f"{base[: max(1, 64 - len(suffix))]}{suffix}"
            n += 1
    elif db.query(ManagedToken).filter(ManagedToken.id == token_id).first():
        raise HTTPException(409, f"Token '{token_id}' already exists. Use a new token_id.")

    if not db.query(Runner).filter(Runner.id == req.runner_id, Runner.user_id == user.id).first():
        raise HTTPException(
            404,
            f"Runner '{req.runner_id}' not found. POST /admin/runners first.",
        )

    usage = req.usage_locations or [f"{req.project_path}:{w}" for w in req.workflows]

    provider_metadata: dict = {}
    try:
        try:
            auth_token = get_user_gitlab_token(db, user.id)
        except ValueError:
            auth_token = None
        provider_metadata = resolve_gitlab_registration_metadata(
            req.project_path,
            req.gitlab_access_token_name,
            req.secret,
            project_id=req.gitlab_project_id,
            access_token_id=req.gitlab_access_token_id,
            auth_token=auth_token,
        )
    except GitLabApiError as exc:
        # Invalid/wrong secret (or GitLab API auth failure) must never be stored.
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        if req.gitlab_project_id and req.gitlab_access_token_id:
            # Secret already validated; allow explicit IDs if metadata lookup had a soft failure.
            provider_metadata = {
                "gitlab_project_path": req.project_path,
                "gitlab_project_id": req.gitlab_project_id,
                "gitlab_access_token_id": req.gitlab_access_token_id,
                "gitlab_access_token_name": req.gitlab_access_token_name,
            }
        else:
            raise HTTPException(
                400,
                f"Could not resolve GitLab metadata: {exc}. "
                "Sign in with GitLab, or pass gitlab_project_id "
                "and gitlab_access_token_id in the registration payload.",
            ) from exc

    display_name = req.gitlab_access_token_name or token_id
    _, handle = create_managed_token(
        db,
        token_id=token_id,
        name=display_name,
        target_system="gitlab",
        owner=req.owner or user.username,
        scopes=req.scopes,
        secret=req.secret,
        renewal_method="api",
        expires_days=req.expires_days,
        usage_locations=usage,
        provider_metadata=provider_metadata,
        user_id=user.id,
    )
    token = db.query(ManagedToken).filter(ManagedToken.id == token_id).first()
    if token:
        token.default_short_lived_ttl = req.max_token_lifetime_seconds
        db.commit()

    policy_ids: list[str] = []

    if req.add_deny_shared_runner_policy:
        deny_id = f"deny-shared-{token_id}"
        create_policy(
            db,
            policy_id=deny_id,
            name=deny_id,
            token_id=token_id,
            effect="deny",
            conditions={"deny_gitlab_shared": True, "deny_github_hosted": True},
            priority=1000,
            user_id=user.id,
        )
        policy_ids.append(deny_id)

    allow_id = f"allow-{token_id}"
    create_policy(
        db,
        policy_id=allow_id,
        name=allow_id,
        token_id=token_id,
        effect="allow",
        conditions={
            "runner_ids": [req.runner_id],
            "runner_types": ["self-hosted"],
            "repositories": [req.project_path],
            "workflows": req.workflows,
            "branches": req.branches,
            "max_token_lifetime_seconds": req.max_token_lifetime_seconds,
        },
        priority=100,
        user_id=user.id,
    )
    policy_ids.append(allow_id)

    log_audit(
        db,
        "gitlab_setup",
        "success",
        f"GitLab token {token_id} registered for {req.project_path}",
        token_id=token_id,
        user_id=user.id,
    )

    try:
        add_tracked_gitlab_project(
            db,
            req.project_path,
            project_id=provider_metadata.get("gitlab_project_id"),
            display_name=req.project_path,
            user_id=user.id,
        )
    except ValueError:
        pass  # already tracked

    return RegisterGitLabSetupResponse(
        message="GitLab token registered. Use gitlab_ci_variables in your GitLab project (handle only).",
        token_id=token_id,
        handle=handle,
        policy_ids=policy_ids,
        gitlab_ci_variables={
            "CTRS_GENERIC_HANDLE": handle,
            "CTRS_RUNNER_ID": req.runner_id,
            "CTRS_SERVICE_URL": "http://127.0.0.1:8080",
        },
        provider_metadata=provider_metadata,
        renewal_mode="gitlab_rotate_api",
    )


@router.post(
    "/admin/tokens/{token_id}/gitlab-metadata",
)
def admin_link_gitlab_metadata(
    token_id: str,
    req: LinkGitLabMetadataRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Backfill GitLab rotation metadata on an existing vault token."""
    token = _owned_token(db, token_id, user)
    if token.target_system != "gitlab":
        raise HTTPException(400, "Token is not a GitLab token")

    try:
        metadata = resolve_gitlab_registration_metadata(
            req.project_path,
            req.gitlab_access_token_name,
            decrypt_secret(token.encrypted_secret),
            project_id=req.gitlab_project_id,
            access_token_id=req.gitlab_access_token_id,
        )
    except GitLabApiError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        if req.gitlab_project_id and req.gitlab_access_token_id:
            metadata = {
                "gitlab_project_path": req.project_path,
                "gitlab_project_id": req.gitlab_project_id,
                "gitlab_access_token_id": req.gitlab_access_token_id,
                "gitlab_access_token_name": req.gitlab_access_token_name,
            }
        else:
            raise HTTPException(400, str(exc)) from exc

    set_provider_metadata(db, token, metadata)
    if token.renewal_status == "failed":
        token.renewal_status = "healthy"
        db.commit()
    log_audit(
        db,
        "gitlab_metadata_linked",
        "success",
        f"Linked GitLab metadata for {token_id}",
        token_id=token_id,
    )
    return {"message": "GitLab metadata linked", "token_id": token_id, "provider_metadata": metadata}


@router.post("/admin/scheduler/run")
def run_scheduler(db: Session = Depends(get_db), user: User = Depends(require_user)):
    renewed = check_expiring_tokens(db)
    return {"renewed_tokens": renewed}
