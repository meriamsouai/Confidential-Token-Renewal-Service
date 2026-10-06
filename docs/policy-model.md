# Policy Model

## 1. Overview

Policies define **who** (runner, workflow context) may obtain **which** token under **what constraints**. The policy engine evaluates policies in priority order; the first matching policy wins. If no policy matches, the request is **denied**.

## 2. Policy Structure

```json
{
  "id": "pol-github-release",
  "name": "GitHub release workflow on main",
  "priority": 100,
  "enabled": true,
  "token_id": "tok-github-deploy",
  "effect": "allow",
  "conditions": {
    "runner_ids": ["runner-prod-01", "runner-prod-02"],
    "runner_types": ["self-hosted"],
    "repositories": ["acme/deploy-pipeline"],
    "workflows": ["release", "deploy"],
    "branches": ["main", "release/*"],
    "max_token_lifetime_seconds": 3600,
    "deny_github_hosted": true,
    "deny_gitlab_shared": true
  }
}
```

## 3. Condition Fields

| Field | Type | Description |
|-------|------|-------------|
| `runner_ids` | `string[]` | Allowed registered runner IDs (empty = any registered) |
| `runner_types` | `string[]` | `self-hosted`, `bare-metal`, `tee` |
| `repositories` | `string[]` | Glob patterns for `owner/repo` |
| `workflows` | `string[]` | Workflow name patterns |
| `branches` | `string[]` | Branch/ref patterns (`main`, `feature/*`) |
| `max_token_lifetime_seconds` | `int` | Cap on issued token TTL |
| `deny_github_hosted` | `bool` | Reject if `RUNNER_ENVIRONMENT=github-hosted` |
| `deny_gitlab_shared` | `bool` | Reject unregistered GitLab runners |
| `required_scopes` | `string[]` | Subset of token scopes that must be requested |
| `attestation_required` | `bool` | Future: require TEE attestation token |

## 4. Evaluation Algorithm

```
function evaluate(request, policies):
    sorted = policies.filter(enabled).sortByDescending(priority)
    for policy in sorted:
        if policy.token_id != request.token_id:
            continue
        if not match_runner(policy, request):
            continue
        if not match_context(policy, request):
            continue
        if policy.effect == "deny":
            return DENY
        return ALLOW with constraints
    return DENY (default)
```

### 4.1 Context Matching

Request context is collected by the CLI from environment variables:

| Variable | Source |
|----------|--------|
| `repository` | `GITHUB_REPOSITORY` / `CI_PROJECT_PATH` |
| `workflow` | `GITHUB_WORKFLOW` / `CI_JOB_NAME` |
| `branch` | `GITHUB_REF` / `CI_COMMIT_REF_NAME` |
| `runner_environment` | `RUNNER_ENVIRONMENT` / `CI_RUNNER_DESCRIPTION` |

### 4.2 Glob Matching

Branch and repository patterns use Unix shell-style globs:

- `main` — exact match
- `release/*` — prefix glob
- `acme/*` — all repos under org

## 5. Default Policies (Prototype)

| Policy | Effect | Description |
|--------|--------|-------------|
| `deny-hosted-runners` | DENY | Block all GitHub-hosted and unregistered GitLab runners |
| `allow-demo-runner` | ALLOW | Demo self-hosted runner for `acme/deploy-pipeline` |

## 6. Token Lifetime Constraints

When a policy allows issuance:

```
issued_ttl = min(
    policy.max_token_lifetime_seconds,
    token.default_short_lived_ttl,
    seconds_until(token.expires_at)
)
```

Short-lived tokens are minted by the service (simulated in prototype) rather than returning the full long-lived credential.

## 7. Emergency Controls

| Action | API | Effect |
|--------|-----|--------|
| Revoke handle | `DELETE /handles/{id}` | Handle immediately invalid |
| Disable policy | `PATCH /policies/{id}` | Stops new issuances |
| Emergency rotate | `POST /tokens/{id}/rotate` | New long-lived secret + invalidate all handles |
| Runner decommission | `DELETE /runners/{id}` | Runner can no longer authenticate |

## 8. Example Policies

### Production deploy (strict)

```json
{
  "name": "prod-deploy-main-only",
  "priority": 200,
  "token_id": "tok-github-deploy",
  "effect": "allow",
  "conditions": {
    "runner_ids": ["runner-prod-01"],
    "repositories": ["acme/deploy-pipeline"],
    "workflows": ["deploy-production"],
    "branches": ["main"],
    "max_token_lifetime_seconds": 900,
    "deny_github_hosted": true
  }
}
```

### Deny fork PRs (conceptual)

Fork PR workflows often run with `pull_request` trigger. Additional condition:

```json
{
  "branches": ["main"],
  "deny_fork_prs": true
}
```

Implementation checks `GITHUB_EVENT_NAME` != `pull_request` from forks (prototype logs warning).

## 9. Policy Authoring Guidelines

1. **Default deny**: no policy match = denial.
2. **Least privilege**: narrow `runner_ids`, `workflows`, `branches`.
3. **Short TTL**: prefer 15–60 minute issued tokens.
4. **Separate policies per environment**: dev/staging/prod tokens with different runner sets.
5. **Audit after changes**: all policy CRUD is logged.
