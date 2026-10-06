from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class TokenResponse(BaseModel):
    id: str
    name: str
    target_system: str
    owner: str
    scopes: list[str]
    renewal_method: str
    expires_at: str
    expires_in_days: float
    last_renewed_at: Optional[str]
    next_renewal_at: Optional[str]
    renewal_status: str
    usage_locations: list[str]
    health: str
    handles: list[str] = Field(default_factory=list)
    is_demo: bool = False
    provider_summary: str = ""
    renewal_mode: str = "simulated"
    last_renewal_source: Optional[str] = None
    last_renewal_source_label: Optional[str] = None


class ExchangeRequest(BaseModel):
    handle: str
    runner_id: str
    signature: str
    timestamp: str
    nonce: str
    repository: str = ""
    workflow: str = ""
    branch: str = ""
    runner_environment: str = ""


class ExchangeResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_at: str
    expires_in: int
    target_system: str
    scopes: list[str]
    policy_id: Optional[str]


class PolicyResponse(BaseModel):
    id: str
    name: str
    priority: int
    enabled: bool
    token_id: str
    effect: str
    conditions: dict


class RunnerResponse(BaseModel):
    id: str
    name: str
    runner_type: str
    active: bool
    last_seen_at: Optional[str]
    host_setup: str = "pending"  # pending | verified


class RunnerHeartbeatRequest(BaseModel):
    """Signed proof that the host has the CTRS runner secret installed."""

    runner_id: str = Field(..., min_length=1, max_length=64)
    signature: str
    timestamp: str
    nonce: str


class RunnerHeartbeatResponse(BaseModel):
    message: str
    runner_id: str
    host_setup: str
    last_seen_at: str


class OperatorSettingsResponse(BaseModel):
    renewal_check_interval_minutes: int
    renewal_threshold_days: int
    default_short_lived_ttl_seconds: int
    gitlab_pat_configured: bool
    gitlab_base_url: str
    smtp_configured: bool = False
    oauth_configured: bool = False


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    name: str
    gitlab_connected: bool
    notify_email_enabled: bool = True


class GitLabPatLoginRequest(BaseModel):
    """Login with a GitLab personal access token (when OAuth apps are disabled)."""
    token: str = Field(..., min_length=8, description="GitLab PAT with api (and preferably read_user) scope")


class AdminConfigResponse(BaseModel):
    admin_key_required: bool
    gitlab_base_url: str
    gitlab_pat_configured: bool
    renewal_check_interval_minutes: int
    renewal_threshold_days: int
    oauth_configured: bool = False
    smtp_configured: bool = False
    authenticated: bool = False
    user: UserResponse | None = None


class OperatorSettingsUpdate(BaseModel):
    renewal_check_interval_minutes: int | None = Field(default=None, ge=5, le=1440)
    renewal_threshold_days: int | None = Field(default=None, ge=1, le=90)
    gitlab_base_url: str | None = None


class SetupCheckItem(BaseModel):
    id: str
    label: str
    passed: bool
    detail: str


class SetupVerifyResponse(BaseModel):
    ready: bool
    checks: list[SetupCheckItem]
    next_steps: list[str]


class AuditEventResponse(BaseModel):
    id: int
    event_type: str
    token_id: Optional[str]
    runner_id: Optional[str]
    repository: str
    workflow: str
    branch: str
    policy_id: str = ""
    outcome: str
    detail: str
    created_at: str


class RenewalEventResponse(BaseModel):
    id: int
    token_id: str
    status: str
    message: str
    source: str = "manual"
    created_at: str


class BootstrapResponse(BaseModel):
    message: str
    runner_id: str
    runner_secret: str
    handles: dict[str, str]


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    tokens_managed: int
    runners_registered: int


class RegisterRunnerRequest(BaseModel):
    runner_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Unique runner id (CTRS_RUNNER_ID in GitLab CI).",
    )
    runner_type: str = Field(default="self-hosted", max_length=32)
    runner_secret: str | None = Field(
        default=None,
        description="If omitted, a random secret is generated and returned once.",
    )
    name: str | None = Field(
        default=None,
        max_length=256,
        description="Optional display name (e.g. GitLab runner description).",
    )


class RegisterRunnerResponse(BaseModel):
    message: str
    runner_id: str
    runner_secret: str


class RegisterTokenRequest(BaseModel):
    token_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Unique token id in the CTRS vault.",
    )
    target_system: str = Field(..., pattern="^(github|gitlab|registry)$")
    owner: str = Field(..., min_length=1, max_length=256)
    secret: str = Field(..., min_length=1, description="Real long-lived token; stored encrypted, never returned again.")
    scopes: list[str] = Field(default_factory=list)
    renewal_method: str = Field(default="api", pattern="^(api|manual|oauth)$")
    expires_days: int = Field(default=60, ge=1, le=365)
    usage_locations: list[str] = Field(default_factory=list)
    default_short_lived_ttl: int = Field(default=3600, ge=60, le=86400)


class RegisterTokenResponse(BaseModel):
    message: str
    token_id: str
    handle: str


class ResyncVaultSecretRequest(BaseModel):
    secret: str = Field(..., min_length=1, description="New glpat shown once after rotating in GitLab")


class RegisterPolicyRequest(BaseModel):
    policy_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Unique policy id.",
    )
    token_id: str = Field(..., min_length=1, max_length=64)
    effect: str = Field(default="allow", pattern="^(allow|deny)$")
    conditions: dict = Field(default_factory=dict)
    priority: int = Field(default=100, ge=0, le=10000)


class RegisterPolicyResponse(BaseModel):
    message: str
    policy_id: str


class UpdatePolicyRequest(BaseModel):
    name: str | None = None
    effect: str | None = Field(default=None, pattern="^(allow|deny)$")
    conditions: dict | None = None
    priority: int | None = Field(default=None, ge=0, le=10000)
    enabled: bool | None = None


class GitLabAccessTokenView(BaseModel):
    gitlab_token_id: int
    name: str
    project_path: str
    project_id: int
    scopes: list[str]
    access_level: int | None = None
    access_level_label: str = ""
    expires_at: str | None = None
    expires_in_days: float | None = None
    active: bool = True
    revoked: bool = False
    created_at: str | None = None
    last_used_at: str | None = None
    vault_token_id: str | None = None
    in_vault: bool = False
    vault_health: str | None = None
    vault_renewal_status: str | None = None
    usage_locations: list[str] = Field(default_factory=list)
    renewal_mode: str = "unmanaged"
    next_renewal_at: str | None = None
    last_renewed_at: str | None = None
    last_renewal_source: str | None = None
    last_renewal_source_label: str | None = None
    owner: str = ""
    token_kind: str = "gitlab_project_access_token"


class TrackedGitLabProjectView(BaseModel):
    id: int
    project_path: str
    project_id: int | None = None
    display_name: str = ""
    created_at: str | None = None


class GitLabAccessTokensResponse(BaseModel):
    gitlab_base_url: str
    tokens: list[GitLabAccessTokenView]
    errors: list[str] = Field(default_factory=list)
    tracked_projects: list[TrackedGitLabProjectView] = Field(default_factory=list)


class TrackGitLabProjectRequest(BaseModel):
    project_path: str = Field(..., min_length=1, description="GitLab CI_PROJECT_PATH, e.g. meso598i/token-test")
    project_id: int | None = None
    display_name: str = ""


class GitLabProjectOption(BaseModel):
    project_id: int
    project_path: str
    name: str
    description: str = ""
    tracked: bool = False


class GitLabProjectsResponse(BaseModel):
    gitlab_base_url: str
    projects: list[GitLabProjectOption]
    errors: list[str] = Field(default_factory=list)


class GitLabRunnerOption(BaseModel):
    gitlab_runner_id: int
    description: str = ""
    active: bool = True
    online: bool = False
    status: str = "unknown"
    is_shared: bool = False
    runner_type: str = ""
    tag_list: list[str] = Field(default_factory=list)
    ip_address: str = ""
    suggested_ctrs_id: str
    suitable_for_ctrs: bool = True
    already_registered: bool = False


class GitLabRunnersResponse(BaseModel):
    gitlab_base_url: str
    runners: list[GitLabRunnerOption]
    errors: list[str] = Field(default_factory=list)


class RegisterGitLabSetupRequest(BaseModel):
    """Register a real GitLab project token + allow policy in one call."""

    token_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="Optional vault token id. Auto-generated from GitLab token name if omitted.",
    )
    secret: str = Field(..., min_length=1, description="Real GitLab project/group access token (glpat-...)")
    owner: str = Field(
        default="",
        description="Optional owner label (not used in policy matching)",
    )
    scopes: list[str] = Field(default_factory=lambda: ["read_api"])
    expires_days: int = Field(default=60, ge=1, le=365)
    project_path: str = Field(..., min_length=1, description="GitLab CI_PROJECT_PATH, e.g. meso598i/token-test")
    gitlab_access_token_name: str = Field(
        default="ctrs-vault",
        description="Name of the project access token in GitLab (for renewal metadata lookup)",
    )
    gitlab_project_id: int | None = Field(
        default=None,
        description="Optional GitLab project ID if auto-resolve is unavailable",
    )
    gitlab_access_token_id: int | None = Field(
        default=None,
        description="Optional GitLab project access token ID for rotation API",
    )
    runner_id: str = Field(..., min_length=1, description="Registered runner id")
    workflows: list[str] = Field(default_factory=lambda: ["build"])
    branches: list[str] = Field(default_factory=lambda: ["master", "main"])
    max_token_lifetime_seconds: int = Field(default=3600, ge=60, le=86400)
    usage_locations: list[str] | None = None
    add_deny_shared_runner_policy: bool = Field(
        default=True,
        description="Add a deny policy for GitLab shared runners on this token",
    )


class LinkGitLabMetadataRequest(BaseModel):
    project_path: str = Field(..., min_length=1)
    gitlab_access_token_name: str = Field(default="ctrs-vault")
    gitlab_project_id: int | None = None
    gitlab_access_token_id: int | None = None


class RegisterGitLabSetupResponse(BaseModel):
    message: str
    token_id: str
    handle: str
    policy_ids: list[str]
    gitlab_ci_variables: dict[str, str]
    provider_metadata: dict = Field(default_factory=dict)
    renewal_mode: str = "gitlab_rotate_api"
