# Threat Model

## 1. Assets

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| Long-lived tokens / refresh credentials | **Critical** | GitHub PATs, GitLab tokens, registry passwords |
| Generic handles | **Medium** | Opaque references; useless without runner + policy |
| Runner secrets | **High** | Shared secrets proving runner identity |
| Token metadata | **Low–Medium** | Expiry, owner, usage locations (no secret values) |
| Audit logs | **Medium** | Operational and forensic value |
| Policy definitions | **Medium** | Define authorization boundaries |
| Service master encryption key | **Critical** | Decrypts all stored secrets |

## 2. Actors

| Actor | Trust Level | Capabilities |
|-------|-------------|--------------|
| CI/CD platform (GitHub/GitLab) | **Untrusted** | Reads CI secrets, runs job code, logs output |
| CI job / workflow code | **Untrusted** | Executes on runner, may be fork PRs |
| Dashboard viewer (operator) | **Semi-trusted** | Views metadata, cannot see secrets by default |
| Dashboard admin | **Trusted** | Manages policies, runners; break-glass secret access |
| Self-hosted runner host | **Conditionally trusted** | Runs CLI, holds runner secret |
| Cloud/hosting admin | **Untrusted** | Can access VMs, disks, memory |
| External attacker | **Malicious** | Network access, stolen handles, compromised accounts |

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ TRUSTED ZONE (organization-controlled)                        │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Token Svc   │  │ Secret Vault │  │ Registered SH       │ │
│  │ + Dashboard │  │ (encrypted)  │  │ Runners + confstr   │ │
│  └─────────────┘  └──────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
         ▲                                        │
         │ TLS + runner auth                      │ short-lived token
         │                                        ▼
┌────────┴────────────────────────────────────────────────────┐
│ UNTRUSTED ZONE (CI/CD provider)                             │
│  GitHub/GitLab secrets store  │  CI jobs  │  hosted runners │
└─────────────────────────────────────────────────────────────┘
```

## 4. Threat Scenarios

### T1: CI provider reads all secrets

**Threat**: GitHub/GitLab administrator or platform bug exposes CI secrets.

**Mitigation**: Only generic handles are stored in CI secrets. Long-lived tokens never enter the CI secret store.

**Residual risk**: Handle + compromised self-hosted runner still yields tokens.

### T2: Malicious workflow on self-hosted runner

**Threat**: Attacker submits PR that exfiltrates exchanged token from job output.

**Mitigation**: Policies restrict by repository, branch, workflow. Short-lived tokens limit blast radius. Audit logging detects anomalous issuance.

**Residual risk**: Legitimate workflow on allowed branch can still be abused by malicious commit.

### T3: Job runs on GitHub-hosted runner

**Threat**: Developer accidentally uses `confstr` on a shared runner.

**Mitigation**: Default policy denies unregistered runners. CLI checks `RUNNER_ENVIRONMENT` and refuses on `github-hosted`.

**Residual risk**: Misconfiguration could register a hosted runner ID (operational control required).

### T4: Stolen generic handle

**Threat**: Handle leaked via log or artifact.

**Mitigation**: Handle alone is insufficient. Attacker also needs runner secret, valid timestamp, and policy match.

**Residual risk**: Combined compromise of handle + runner host.

### T5: Dashboard user escalates to secrets

**Threat**: Operator attempts to extract token values via API.

**Mitigation**: API never returns decrypted secrets to viewer role. Separate break-glass endpoint with additional auth (not in default prototype).

**Residual risk**: Service admin with DB access can decrypt offline.

### T6: Cloud administrator accesses VM disk

**Threat**: Hosting provider admin reads SQLite DB and master key from env.

**Mitigation**: Confidential computing (SGX/SEV) would protect memory and keys at runtime. Prototype assumes trusted hosting.

**Residual risk**: Without TEE, disk snapshot reveals encrypted secrets if key is co-located.

### T7: Token renewal API failure

**Threat**: Provider API changes; renewal silently fails until expiry.

**Mitigation**: Scheduler records failures; dashboard shows health status; alerting on `renewal_failed` events.

**Residual risk**: Alert fatigue or missed notifications cause outage.

### T8: Replay of runner authentication

**Threat**: Attacker captures valid HMAC and replays.

**Mitigation**: Timestamp window (±5 min) + nonce tracking (prototype uses timestamp only).

**Residual risk**: Replay within window if nonce store not implemented.

## 5. Security Goals Mapping

| Goal | Mechanism |
|------|-----------|
| Confidential handling of secrets | Encrypted vault; CI stores handles only |
| Runner-bound access | HMAC runner proof + registration |
| Auditable usage | Audit log per issuance/renewal/denial |
| Separation of visibility/control | Dashboard API excludes secret fields |
| Early failure detection | Scheduler + health status + expiry warnings |

## 6. Out of Scope (Prototype)

- Hardware-backed attestation (TPM/SGX)
- HSM integration for master key
- Multi-tenant isolation
- Formal verification of policy engine
- Side-channel resistance on runner host
