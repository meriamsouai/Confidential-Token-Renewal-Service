# Architecture Description

## 1. Problem Context

CI/CD platforms (GitHub Actions, GitLab CI) inject secrets into job environments. When those secrets are long-lived access tokens, two risks emerge:

1. **Operational**: tokens expire without notice, causing pipeline failures.
2. **Confidentiality**: the CI provider and any job on shared runners can read the secret.

CTRS separates **visibility** (metadata for operators) from **control** (actual secret values), and limits real token release to **authorized execution environments**.

## 2. Components

### 2.1 Confidential Token Service

Central backend responsible for:

- **Token inventory**: metadata about managed tokens (target system, scope, owner, expiry, renewal method, usage locations).
- **Secret vault**: encrypted storage of long-lived credentials and refresh tokens. Never exposed via dashboard API to standard users.
- **Renewal scheduler**: background job that checks tokens approaching expiry and triggers renewal via provider REST APIs.
- **Issuance API**: endpoint used by the CLI to exchange a generic handle for a short-lived real token, after policy and runner checks.
- **Policy engine**: evaluates whether a given request (runner, repo, workflow, branch) is authorized.
- **Audit log**: immutable-style event stream for issuance, renewal, denial, and policy changes.

### 2.2 Confidential CLI (`confstr`)

Runs **only on authorized self-hosted runners** (or trusted machines). The CI job:

1. Receives a **generic handle** (not a usable API token) as a CI secret.
2. Invokes `confstr exchange` with workflow context (repo, branch, workflow name).
3. The CLI proves runner identity to the service.
4. On success, prints a short-lived token to stdout (or writes to a masked env var).

The generic handle is an opaque, HMAC-signed reference. It cannot be used to call GitHub/GitLab directly.

### 2.3 Operator Dashboard

Web UI for operators. Shows:

- Token inventory with health/expiry status
- Renewal history and next scheduled renewal
- Policy configuration
- Audit events and usage locations

Dashboard users see **metadata only**. Token values and long-lived secrets require an explicit break-glass admin role (not enabled in default prototype).

Operators authenticate with a **GitLab personal access token** pasted at login (university instances often disable user OAuth apps) or optionally with **GitLab OAuth** when an application is available. Each user only sees their own tokens, runners, policies, and tracked projects. GitLab list/rotate/revoke calls use that user’s stored token (encrypted). CI `confstr` exchange remains runner-HMAC based (no browser login in the pipeline). SMTP notifications are sent on token create/rotate/revoke and upcoming expiry.

### 2.4 Policy-Controlled Token Store

SQLite (prototype) / PostgreSQL (production) with:

- Encrypted secret column (Fernet symmetric encryption)
- Separate tables for tokens, handles, runners, policies, audit events
- Role-based API access

## 3. Data Flow

### 3.1 Token Issuance (CI job)

```
CI Job                    CLI (runner)              Token Service
  |                            |                          |
  |-- generic handle --------->|                          |
  |-- workflow context ------->|                          |
  |                            |-- runner proof ---------->| 
  |                            |                          |-- verify handle
  |                            |                          |-- check policy
  |                            |                          |-- decrypt secret
  |                            |                          |-- mint short-lived token
  |                            |<-- short-lived token -----|
  |<-- token (stdout) ---------|                          |
  |                            |                          |-- audit log
```

### 3.2 Automatic Renewal (scheduler)

```
Scheduler                 Token Service              Provider API
    |                          |                          |
    |-- check expiring tokens->|                          |
    |                          |-- call refresh API ----->|
    |                          |<-- new credentials ------|
    |                          |-- update vault + metadata|
    |                          |-- audit log              |
```

## 4. Runner Identity

### 4.1 Self-Hosted Runner Proof (Prototype)

Each authorized runner is pre-registered with:

- `runner_id`: unique identifier
- `runner_secret`: shared secret known only to the runner and the service
- `runner_fingerprint`: optional machine fingerprint (hostname + stable ID)

The CLI sends `HMAC-SHA256(runner_secret, timestamp || nonce)` with each request. The service rejects requests with timestamps older than 5 minutes (replay protection).

### 4.2 Distinguishing Runner Types

| Runner Type | Detection | Token Issuance |
|-------------|-----------|----------------|
| GitHub-hosted | `RUNNER_ENVIRONMENT=github-hosted` | **Denied** by default policy |
| GitLab shared | `CI_RUNNER_TAGS` without registered ID | **Denied** |
| Self-hosted (registered) | Valid `runner_id` + HMAC proof | **Allowed** if policy matches |
| Trusted bare metal | Attestation token (future) | **Allowed** with attestation policy |

### 4.3 Future: Remote Attestation

Intel SGX / AMD SEV / TPM-backed attestation could replace shared secrets. The policy engine would require `attestation.pcr_match` or `tee.measurement` constraints.

## 5. Generic Handle Design

A generic handle has the form:

```
ctrs.h.<token_id>.<random>.<hmac_signature>
```

Properties:

- **Opaque**: no embedded JWT claims readable without the service master key
- **Scoped**: bound to a specific managed token record
- **Revocable**: service can invalidate handles without rotating the underlying secret
- **Useless externally**: cannot authenticate to GitHub, GitLab, or any target API

CI platforms store only the handle string. Even if leaked from a job log, an attacker cannot use it without also compromising an authorized runner and passing policy checks.

## 6. API Surface

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/auth/gitlab/login` | GET | Start GitLab OAuth |
| `/api/v1/auth/gitlab/callback` | GET | OAuth callback → session cookie |
| `/api/v1/auth/me` | GET | Current user profile |
| `/api/v1/auth/logout` | POST | Clear session cookie |
| `/api/v1/tokens` | GET | List token metadata (no secrets; per-user) |
| `/api/v1/tokens/{id}` | GET | Token detail + renewal history |
| `/api/v1/tokens/{id}/renew` | POST | Manual renewal trigger |
| `/api/v1/exchange` | POST | CLI token exchange (runner HMAC; no JWT) |
| `/api/v1/policies` | GET/POST | Policy management (per-user) |
| `/api/v1/runners` | GET/POST | Runner registration (per-user) |
| `/api/v1/audit` | GET | Audit log query (per-user) |
| `/api/v1/health` | GET | Service health |

## 7. Deployment Topology

```
                    ┌─────────────────────────────┐
                    │  Private network / VPC      │
                    │  ┌───────────────────────┐  │
                    │  │ Token Service         │  │
                    │  │ Dashboard             │  │
                    │  │ Encrypted DB          │  │
                    │  └───────────────────────┘  │
                    └──────────────┬──────────────┘
                                   │ TLS
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
   ┌─────▼─────┐            ┌──────▼──────┐           ┌──────▼──────┐
   │ SH Runner │            │ SH Runner   │           │ SH Runner   │
   │ + confstr │            │ + confstr   │           │ + confstr   │
   └───────────┘            └─────────────┘           └─────────────┘
```

The token service and dashboard should run in infrastructure the organization controls—not on the CI provider's servers.

**Auth / tenancy note:** upgrading from the single-tenant prototype may require wiping `ctrs.db` once (existing rows lack `user_id`). Create a GitLab OAuth application with redirect URI `http://127.0.0.1:5173/api/v1/auth/gitlab/callback` (via the Vite proxy) and fill `GITLAB_OAUTH_*` / `SMTP_*` in `service/.env` (see `.env.example`).

## 8. Technology Choices (Prototype)

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Service | Python FastAPI | Rapid prototyping, async scheduler |
| Database | SQLite | Zero-config for demo |
| Encryption | Fernet (AES-128-CBC) | Simple at-rest encryption |
| CLI | Python Click | Cross-platform, easy install |
| Dashboard | React + Vite | Modern SPA, fast dev |
| Scheduler | APScheduler | In-process cron for prototype |
