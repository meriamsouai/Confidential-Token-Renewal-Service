# Security and Operational Evaluation

## 1. Protected Secrets by Party

| Secret | CI Provider | CI Job | Dashboard Viewer | Dashboard Admin | Cloud Admin | External Attacker |
|--------|-------------|--------|------------------|-----------------|-------------|-------------------|
| Long-lived token | **Protected** | **Protected** | **Protected** | Partial¹ | Partial² | **Protected** |
| Refresh credential | **Protected** | **Protected** | **Protected** | Partial¹ | Partial² | **Protected** |
| Generic handle | Visible | Visible | Metadata only | Visible | Visible | If leaked |
| Short-lived token | Not stored | Visible³ | Not visible | Not visible | If host compromised | If runner compromised |
| Runner secret | **Protected** | **Protected**⁴ | **Protected** | Visible | If host compromised | If runner compromised |

¹ Break-glass admin role can decrypt (not enabled in default prototype).  
² Disk/memory access with co-located encryption key.  
³ Only during job execution; masked in logs if configured.  
⁴ Job can read env vars on same runner; runner secret should be file-based with restricted permissions.

## 2. Assumptions

1. **Self-hosted runners** are administered by the organization and hardened (patching, access control).
2. **Token service** runs on infrastructure separate from CI provider control.
3. **Network path** between runner and service is TLS-protected and reachable only from trusted networks (or mTLS in production).
4. **Operators** configure policies correctly; misconfiguration is an operational risk.
5. **Provider APIs** support programmatic token renewal for managed token types.

## 3. Malicious Actor Analysis

### 3.1 Malicious CI Provider

**Can**: read generic handles, run arbitrary code on hosted runners, log job output.

**Cannot**: obtain long-lived tokens (not stored in CI). Cannot pass runner authentication without a registered self-hosted runner.

**Limitation**: if organization mistakenly stores real tokens instead of handles, protection is bypassed.

### 3.2 Malicious Dashboard User

**Can**: view token metadata, expiry, audit logs, policies.

**Cannot**: retrieve decrypted secrets via standard API (prototype enforces field exclusion).

**Limitation**: admin with database and `MASTER_KEY` access can decrypt offline.

### 3.3 Malicious Cloud Administrator

**Can**: snapshot VMs, read environment variables, access SQLite files.

**Cannot** (without key): decrypt vault if master key is in HSM/KMS separate from disk.

**Limitation**: prototype stores key in `.env` — vulnerable to co-located compromise. Confidential computing would mitigate.

### 3.4 Compromised Self-Hosted Runner

**Can**: authenticate to service, obtain short-lived tokens for any policy-permitted workflow.

**Cannot**: directly read long-lived secrets from vault (service mints short-lived subset).

**Mitigation**: narrow policies, short TTL, monitor audit log for anomalous issuance volume.

## 4. Operational Limitations

### 4.1 APIs Without Renewal Support

| Token Type | Auto-Renewal | Notes |
|------------|--------------|-------|
| GitHub fine-grained PAT | Partial | Regenerate via API; some scopes need manual approval |
| GitHub classic PAT | No | Must be manually rotated |
| GitLab project token | Yes | API supports rotation |
| OAuth refresh tokens | Yes | Standard refresh flow |
| SSH deploy keys | No | Must regenerate key pair |
| Cloud IAM static keys | Varies | Prefer workload identity instead |

### 4.2 Runner Identity Limitations

- **GitHub-hosted runners**: no stable org-controlled identity; correctly denied by default.
- **GitLab shared runners**: multi-tenant; identity is weak without dedicated registration.
- **Spoofed environment variables**: malicious job can set fake `GITHUB_REPOSITORY`; CLI should prefer attested metadata from runner agent (future).
- **Container escape**: runner host compromise equals runner secret compromise.

### 4.3 Failure Modes

| Failure | Detection | Impact |
|---------|-----------|--------|
| Renewal API down | Scheduler marks `renewal_failed` | Token may expire; CI jobs fail at exchange |
| Service unreachable | CLI exits non-zero | Pipeline fails fast (fail-closed) |
| Policy too strict | Audit `denied` events | Legitimate jobs blocked |
| Clock skew | HMAC timestamp rejected | Intermittent auth failures |

### 4.4 Early Expiry Detection

Prototype implements:

- Scheduler runs every 15 minutes
- Dashboard shows `expires_in_days` with color coding (green > 7d, yellow 1–7d, red < 1d)
- Audit event `renewal_failed` with error detail

Production would add: PagerDuty/webhook alerts, SLO on successful renewal rate.

## 5. Confidential Computing Potential

| Technology | Benefit |
|------------|---------|
| Intel SGX / TDX | Token service and vault logic in enclave; cloud admin cannot read memory |
| AMD SEV-SNP | Encrypted VM memory |
| TPM attestation | Runner proves firmware/OS state before receiving runner credential |

Prototype uses shared-secret runner auth as a baseline. Attestation would replace `runner_secret` with hardware-backed challenge-response.

## 6. Prototype Fidelity

The prototype **simulates** GitHub/GitLab API renewal and short-lived token minting. In production:

- Integrate real GitHub App or fine-grained PAT APIs
- Use GitLab token rotation endpoints
- Deploy with PostgreSQL, KMS-backed encryption, mTLS
- Add nonce store for replay protection
- Implement break-glass with MFA and full audit

## 7. Conclusion

The architecture demonstrates that CI jobs can obtain fresh short-lived tokens without storing long-lived secrets in the CI provider. Protection holds when:

1. Only generic handles are stored as CI secrets.
2. Token exchange runs exclusively on registered self-hosted runners.
3. Policies are narrowly scoped.
4. Operators monitor renewal health via the dashboard.

Primary residual risks are **runner host compromise**, **policy misconfiguration**, and **hosting environment access to encryption keys** — addressable with TEE, HSM, and operational discipline.
