import fnmatch
import json
from dataclasses import dataclass

from app.models import Policy


@dataclass
class RequestContext:
    token_id: str
    runner_id: str
    runner_type: str
    repository: str
    workflow: str
    branch: str
    runner_environment: str = ""


@dataclass
class PolicyDecision:
    allowed: bool
    policy_id: str | None = None
    max_token_lifetime_seconds: int = 3600
    reason: str = ""


def _glob_match(patterns: list[str], value: str) -> bool:
    if not patterns:
        return True
    value = value or ""
    for pattern in patterns:
        if fnmatch.fnmatch(value, pattern):
            return True
    return False


def evaluate_policies(policies: list[Policy], ctx: RequestContext) -> PolicyDecision:
    sorted_policies = sorted(
        [p for p in policies if p.enabled and p.token_id == ctx.token_id],
        key=lambda p: p.priority,
        reverse=True,
    )

    for policy in sorted_policies:
        conditions = json.loads(policy.conditions_json)
        if not _match_policy(conditions, ctx):
            continue
        if policy.effect == "deny":
            return PolicyDecision(
                allowed=False,
                policy_id=policy.id,
                reason=f"Denied by policy '{policy.name}'",
            )
        max_ttl = conditions.get("max_token_lifetime_seconds", 3600)
        return PolicyDecision(
            allowed=True,
            policy_id=policy.id,
            max_token_lifetime_seconds=max_ttl,
            reason=f"Allowed by policy '{policy.name}'",
        )

    return PolicyDecision(allowed=False, reason="No matching policy (default deny)")


def _is_deny_trigger(conditions: dict, ctx: RequestContext) -> bool:
    if conditions.get("deny_github_hosted") and ctx.runner_environment == "github-hosted":
        return True
    if conditions.get("deny_gitlab_shared") and ctx.runner_environment in (
        "gitlab-shared",
        "shared",
        "instance",
    ):
        return True
    if conditions.get("deny_gitlab_shared") and ctx.runner_type == "gitlab-shared":
        return True
    return False


def _match_policy(conditions: dict, ctx: RequestContext) -> bool:
    # Deny-only policies match on hosted/shared runner detection
    if _is_deny_trigger(conditions, ctx):
        return True

    has_allow_constraints = any(
        conditions.get(k)
        for k in ("runner_ids", "runner_types", "repositories", "workflows", "branches")
    )
    if not has_allow_constraints:
        return False

    runner_ids = conditions.get("runner_ids", [])
    if runner_ids and ctx.runner_id not in runner_ids:
        return False

    runner_types = conditions.get("runner_types", [])
    if runner_types and ctx.runner_type not in runner_types:
        return False

    if not _glob_match(conditions.get("repositories", []), ctx.repository):
        return False
    if not _glob_match(conditions.get("workflows", []), ctx.workflow):
        return False
    if not _glob_match(conditions.get("branches", []), ctx.branch):
        return False

    return True
