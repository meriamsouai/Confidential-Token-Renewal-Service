import { useEffect, useState } from 'react'
import { deleteRequest, fetchJson, patchJson, postJson } from '../api'

function splitList(value) {
  return value.split(',').map((s) => s.trim()).filter(Boolean)
}

export function FormMessage({ message, type = 'info' }) {
  if (!message) return null
  return <div className={`form-message form-message-${type}`}>{message}</div>
}

export function Field({ label, hint, children }) {
  return (
    <label className="form-field">
      <span className="form-label">{label}</span>
      {children}
      {hint && <span className="form-hint">{hint}</span>}
    </label>
  )
}

function maskSecret(secret) {
  if (!secret) return ''
  return '•'.repeat(Math.min(Math.max(secret.length, 12), 40))
}

function runnerInstallScript(secret, runnerId, serviceUrl = "http://127.0.0.1:8080") {
  const escaped = String(secret).replace(/'/g, `'\"'\"'`)
  const id = runnerId || "YOUR_CTRS_RUNNER_ID"
  return `sudo mkdir -p /etc/ctrs
echo '${escaped}' | sudo tee /etc/ctrs/runner-secret
sudo chmod 600 /etc/ctrs/runner-secret
sudo chown gitlab-runner:gitlab-runner /etc/ctrs/runner-secret 2>/dev/null || true

# Prove the secret matches CTRS (must run as gitlab-runner — that user owns the file)
export CTRS_RUNNER_ID='${id}'
export CTRS_SERVICE_URL='${serviceUrl}'
export CTRS_RUNNER_SECRET_FILE=/etc/ctrs/runner-secret
CONFSTR_BIN="$(command -v confstr)"
sudo -u gitlab-runner env \\
  CTRS_RUNNER_ID="$CTRS_RUNNER_ID" \\
  CTRS_SERVICE_URL="$CTRS_SERVICE_URL" \\
  CTRS_RUNNER_SECRET_FILE="$CTRS_RUNNER_SECRET_FILE" \\
  PATH="$PATH" \\
  "$CONFSTR_BIN" prove-host`
}

export function OneTimeSecretReveal({ title, secret, hint, children, onDismiss }) {
  const [revealed, setRevealed] = useState(false)
  const [copied, setCopied] = useState(false)

  if (!secret) return null

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="one-time-secret" role="status">
      <div className="one-time-secret-header">
        <div>
          <div className="one-time-secret-title">{title}</div>
          <p className="one-time-secret-warning">
            Copy this now. It disappears when you refresh or leave this page.
          </p>
        </div>
        <span className="one-time-secret-badge">Shown once</span>
      </div>
      <div className="one-time-secret-row">
        <code className="one-time-secret-value">{revealed ? secret : maskSecret(secret)}</code>
        <div className="one-time-secret-actions">
          <button
            type="button"
            className="btn btn-sm btn-ghost one-time-secret-toggle"
            onClick={() => setRevealed((v) => !v)}
            aria-label={revealed ? 'Hide secret' : 'Show secret'}
            title={revealed ? 'Hide' : 'Show'}
          >
            {revealed ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
                <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
                <line x1="1" y1="1" x2="23" y2="23" />
              </svg>
            ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                <circle cx="12" cy="12" r="3" />
              </svg>
            )}
          </button>
          <button type="button" className="btn btn-sm btn-primary" onClick={copy}>
            {copied ? 'Copied' : 'Copy'}
          </button>
          {onDismiss && (
            <button type="button" className="btn btn-sm btn-ghost" onClick={onDismiss}>
              Dismiss
            </button>
          )}
        </div>
      </div>
      {children}
      {hint && <p className="one-time-secret-hint">{hint}</p>}
    </div>
  )
}

export { splitList }

export function RegisterRunnerPanel({ onSuccess, compact = false, showForm = true, registeredRunners = [] }) {
  const [gitlabRunners, setGitlabRunners] = useState([])
  const [loadErrors, setLoadErrors] = useState([])
  const [loading, setLoading] = useState(false)
  const [manualId, setManualId] = useState('')
  const [showManual, setShowManual] = useState(false)
  const [message, setMessage] = useState(null)
  const [secretReveal, setSecretReveal] = useState(null)
  const [busyId, setBusyId] = useState(null)
  const [scriptCopied, setScriptCopied] = useState(false)

  const registeredIds = new Set((registeredRunners || []).map((r) => r.id))
  const registeredKey = (registeredRunners || []).map((r) => r.id).sort().join(',')

  const loadGitlabRunners = async () => {
    setLoading(true)
    setLoadErrors([])
    try {
      const data = await fetchJson('/gitlab/runners')
      setGitlabRunners(data.runners || [])
      setLoadErrors(data.errors || [])
    } catch (err) {
      setGitlabRunners([])
      setLoadErrors([err.message])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (showForm) {
      setMessage(null)
      setScriptCopied(false)
      loadGitlabRunners()
    }
  }, [showForm])

  // When a CTRS runner is deleted, drop stale "registered" UI and any install banner for it.
  useEffect(() => {
    setSecretReveal((prev) => (prev && !registeredIds.has(prev.runnerId) ? null : prev))
  }, [registeredKey])

  const register = async ({ runnerId, name }) => {
    const id = (runnerId || '').trim()
    if (!id) return
    setBusyId(id)
    setMessage(null)
    setSecretReveal(null)
    setScriptCopied(false)
    try {
      const res = await postJson('/admin/runners', {
        runner_id: id,
        runner_type: 'self-hosted',
        name: name || id,
      })
      setSecretReveal({
        runnerId: res.runner_id,
        secret: res.runner_secret,
      })
      setManualId('')
      await loadGitlabRunners()
      onSuccess?.(true, res)
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setBusyId(null)
    }
  }

  const submitManual = async (e) => {
    e.preventDefault()
    await register({ runnerId: manualId, name: manualId })
  }

  const installScript = secretReveal?.secret
    ? runnerInstallScript(secretReveal.secret, secretReveal.runnerId)
    : ''

  const copyInstallScript = async () => {
    try {
      await navigator.clipboard.writeText(installScript)
      setScriptCopied(true)
      window.setTimeout(() => setScriptCopied(false), 2000)
    } catch {
      setScriptCopied(false)
    }
  }

  const suitable = gitlabRunners.filter((r) => r.suitable_for_ctrs)
  const shared = gitlabRunners.filter((r) => !r.suitable_for_ctrs)

  return (
    <div className="register-panel">
      {secretReveal?.secret && (
        <div className="one-time-secret" role="status">
          <div className="runner-install-block runner-install-block-solo">
            <div className="runner-install-header">
              <span className="form-label">Install on the runner host</span>
              <div className="one-time-secret-actions">
                <button type="button" className="btn btn-sm btn-primary" onClick={copyInstallScript}>
                  {scriptCopied ? 'Copied' : 'Copy install script'}
                </button>
                <button type="button" className="btn btn-sm btn-ghost" onClick={() => setSecretReveal(null)}>
                  Dismiss
                </button>
              </div>
            </div>
            <pre className="code-block runner-install-script">{installScript}</pre>
            <p className="one-time-secret-hint">
              After running the script, refresh Monitor → Runners. Status should become &quot;Host ready&quot;.
              Use CTRS_RUNNER_ID={secretReveal.runnerId} in GitLab CI.
            </p>
          </div>
        </div>
      )}

      {showForm && (
        <div className={`operator-form ${compact ? 'compact-wizard' : ''}`}>
          {!compact && <h3>Register runner</h3>}

          {loading && <p className="cell-muted">Loading GitLab runners…</p>}

          {loadErrors.length > 0 && (
            <div className="alert alert-error">
              <strong>Could not load GitLab runners</strong>
              <ul className="error-list">
                {loadErrors.map((err) => <li key={err}>{err}</li>)}
              </ul>
              <p className="form-hint">Your PAT needs permission to list runners, or use manual registration below.</p>
            </div>
          )}

          <ul className="suggest-list runner-pick-list">
            {suitable.map((r) => {
              const ctrsId = r.suggested_ctrs_id
              const ctrsRow = (registeredRunners || []).find((x) => x.id === ctrsId)
              // Only trust live CTRS list — not the stale already_registered flag from the GitLab fetch.
              const already = Boolean(ctrsRow)
              const hostReady = ctrsRow?.host_setup === 'verified' || Boolean(ctrsRow?.last_seen_at)
              return (
                <li key={r.gitlab_runner_id}>
                  <div>
                    <div className="cell-primary">{r.description || `GitLab runner #${r.gitlab_runner_id}`}</div>
                    <div className="token-cell-sub">
                      <span className="cell-mono">CTRS id: {ctrsId}</span>
                      <span className={`status-dot ${r.online ? 'active' : 'inactive'}`}>
                        {r.online ? 'online' : r.status || 'offline'}
                      </span>
                      {(r.tag_list || []).map((t) => (
                        <span key={t} className="tag tag-sm">{t}</span>
                      ))}
                    </div>
                  </div>
                  {already ? (
                    <span className={`source-badge ${hostReady ? 'source-real' : 'source-demo'}`}>
                      {hostReady ? 'host ready' : 'pending host setup'}
                    </span>
                  ) : (
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      disabled={Boolean(busyId)}
                      onClick={() => register({ runnerId: ctrsId, name: r.description || ctrsId })}
                    >
                      {busyId === ctrsId ? 'Registering…' : 'Register'}
                    </button>
                  )}
                </li>
              )
            })}
            {!loading && suitable.length === 0 && loadErrors.length === 0 && (
              <li className="cell-muted">No self-hosted GitLab runners found. Use manual registration or check PAT permissions.</li>
            )}
          </ul>

          {shared.length > 0 && (
            <p className="form-hint">
              {shared.length} shared/instance runner(s) hidden — CTRS only trusts self-hosted runners.
            </p>
          )}

          <div className="wizard-actions" style={{ marginTop: '0.75rem' }}>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShowManual((v) => !v)}>
              {showManual ? 'Hide manual registration' : 'Register manually (custom id)'}
            </button>
          </div>

          {showManual && (
            <form className="manual-runner-form" onSubmit={submitManual}>
              <Field label="CTRS runner ID" hint="Same value as CTRS_RUNNER_ID in GitLab CI">
                <input
                  value={manualId}
                  onChange={(e) => setManualId(e.target.value)}
                  placeholder="e.g. runner-wsl-01"
                  required
                />
              </Field>
              <button type="submit" className="btn btn-primary" disabled={Boolean(busyId)}>
                {busyId === manualId.trim() ? 'Registering…' : 'Register runner'}
              </button>
            </form>
          )}

          <FormMessage message={message?.text} type={message?.type} />
        </div>
      )}
    </div>
  )
}

export function RegisterGitLabPanel({ runners, onSuccess, compact = false }) {
  const [form, setForm] = useState({
    secret: '',
    scopes: 'read_api',
    expires_days: 60,
    project_path: '',
    gitlab_access_token_name: 'ctrs-vault',
    runner_id: runners[0]?.id || '',
    workflows: 'ctrs_verify_runner,ctrs_exchange_and_api,ctrs_project_metadata',
    branches: 'master,main',
    max_token_lifetime_seconds: 3600,
    add_deny_shared_runner_policy: true,
  })
  const [message, setMessage] = useState(null)
  const [setupResult, setSetupResult] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (runners.length && !form.runner_id) {
      setForm((prev) => ({ ...prev, runner_id: runners[0].id }))
    }
  }, [runners, form.runner_id])

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setMessage(null)
    setSetupResult(null)
    try {
      const res = await postJson('/admin/gitlab/register', {
        ...form,
        scopes: splitList(form.scopes),
        workflows: splitList(form.workflows),
        branches: splitList(form.branches),
        expires_days: Number(form.expires_days),
        max_token_lifetime_seconds: Number(form.max_token_lifetime_seconds),
      })
      setSetupResult(res)
      setMessage({ type: 'success', text: res.message })
      onSuccess?.(true, res)
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="register-panel">
      {setupResult?.handle && (
        <OneTimeSecretReveal
          title="CI handle for GitLab variables"
          secret={setupResult.handle}
          hint={`Policies created: ${setupResult.policy_ids?.join(', ') || '—'} · Renewal: ${setupResult.renewal_mode || '—'}`}
          onDismiss={() => setSetupResult(null)}
        >
          {setupResult.gitlab_ci_variables && (
            <div className="one-time-secret-extra">
              <strong>GitLab CI variables</strong>
              <ul className="ci-vars-list">
                {Object.entries(setupResult.gitlab_ci_variables).map(([key, value]) => (
                  <li key={key}>
                    <code>{key}</code>
                    {key === 'CTRS_GENERIC_HANDLE' ? (
                      <span className="cell-muted"> (use handle above)</span>
                    ) : (
                      <> = <code>{value}</code></>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </OneTimeSecretReveal>
      )}
      <form className={`operator-form ${compact ? 'compact-wizard' : ''}`} onSubmit={submit}>
      {!compact && <h3>Register GitLab token + policies</h3>}
      {!compact && <p className="form-intro">Vault token is encrypted and never shown again. Only the handle goes into GitLab CI variables.</p>}
      <div className="form-grid">
        <Field label="GitLab project access token (secret)" hint="From GitLab → Settings → Access tokens. Shown once.">
          <input type="password" value={form.secret} onChange={(e) => setForm({ ...form, secret: e.target.value })} required />
        </Field>
        <Field label="Project path" hint="CI_PROJECT_PATH e.g. user/project">
          <input value={form.project_path} onChange={(e) => setForm({ ...form, project_path: e.target.value })} required />
        </Field>
        <Field label="Vault token name in GitLab" hint="For renewal metadata lookup">
          <input value={form.gitlab_access_token_name} onChange={(e) => setForm({ ...form, gitlab_access_token_name: e.target.value })} />
        </Field>
        <Field label="CTRS runner">
          <select value={form.runner_id} onChange={(e) => setForm({ ...form, runner_id: e.target.value })} required>
            <option value="" disabled={!!runners.length}>Select a registered runner</option>
            {runners.map((r) => <option key={r.id} value={r.id}>{r.id}</option>)}
          </select>
        </Field>
        <Field label="Allowed job names (comma-separated)">
          <input value={form.workflows} onChange={(e) => setForm({ ...form, workflows: e.target.value })} />
        </Field>
        <Field label="Allowed branches (comma-separated)">
          <input value={form.branches} onChange={(e) => setForm({ ...form, branches: e.target.value })} />
        </Field>
        <Field label="Scopes (comma-separated)">
          <input value={form.scopes} onChange={(e) => setForm({ ...form, scopes: e.target.value })} />
        </Field>
        <Field label="Expires (days)">
          <input type="number" value={form.expires_days} onChange={(e) => setForm({ ...form, expires_days: e.target.value })} />
        </Field>
        <Field label="Max exchange TTL (seconds)">
          <input type="number" value={form.max_token_lifetime_seconds} onChange={(e) => setForm({ ...form, max_token_lifetime_seconds: e.target.value })} />
        </Field>
      </div>
      <label className="form-checkbox">
        <input type="checkbox" checked={form.add_deny_shared_runner_policy} onChange={(e) => setForm({ ...form, add_deny_shared_runner_policy: e.target.checked })} />
        Deny shared / GitHub-hosted runners for this token
      </label>
      <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'Registering…' : 'Register GitLab setup'}</button>
      <FormMessage message={message?.text} type={message?.type} />
      </form>
    </div>
  )
}

export function QuickRegisterGitLabToken({ token, runners, onSuccess, onCancel, onRunnersChanged }) {
  const [secret, setSecret] = useState('')
  const [busy, setBusy] = useState(false)
  const [creatingRunner, setCreatingRunner] = useState(false)
  const [message, setMessage] = useState(null)
  const [setupResult, setSetupResult] = useState(null)
  const [runnerId, setRunnerId] = useState(runners[0]?.id || '')
  const [newRunnerSecret, setNewRunnerSecret] = useState(null)

  useEffect(() => {
    if (!runnerId && runners[0]?.id) setRunnerId(runners[0].id)
    if (runnerId && runners.length && !runners.some((r) => r.id === runnerId)) {
      setRunnerId(runners[0]?.id || '')
    }
  }, [runners, runnerId])

  const expiresDays = token.expires_in_days != null && token.expires_in_days > 0
    ? Math.max(1, Math.ceil(token.expires_in_days))
    : 60

  const createRunnerQuick = async () => {
    setCreatingRunner(true)
    setMessage(null)
    const id = `runner-${(token.project || 'host').split('/').pop() || 'host'}`.replace(/[^a-zA-Z0-9._-]/g, '-').slice(0, 64)
    try {
      const res = await postJson('/admin/runners', { runner_id: id, name: id, runner_type: 'self-hosted' })
      setRunnerId(res.runner_id || id)
      if (res.runner_secret) setNewRunnerSecret(res.runner_secret)
      setMessage({
        type: 'success',
        text: `Runner “${res.runner_id || id}” created. Save the runner secret below, then Register this token.`,
      })
      onRunnersChanged?.()
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setCreatingRunner(false)
    }
  }

  const submit = async (e) => {
    e.preventDefault()
    if (!runnerId) {
      setMessage({
        type: 'error',
        text: 'Register a CTRS runner first (button below), then paste the glpat and click Register.',
      })
      return
    }
    if (!secret.trim()) {
      setMessage({ type: 'error', text: 'Paste the GitLab token secret (glpat-…).' })
      return
    }
    setBusy(true)
    setMessage(null)
    setSetupResult(null)
    try {
      const res = await postJson('/admin/gitlab/register', {
        secret: secret.trim(),
        project_path: token.project,
        gitlab_access_token_name: token.name,
        gitlab_project_id: token.gitlab_project_id || undefined,
        gitlab_access_token_id: token.gitlab_token_id || undefined,
        scopes: token.scopes?.length ? token.scopes : ['read_api'],
        expires_days: expiresDays,
        runner_id: runnerId,
        workflows: ['ctrs_verify_runner', 'ctrs_exchange_and_api', 'ctrs_project_metadata'],
        branches: ['master', 'main'],
        max_token_lifetime_seconds: 3600,
        add_deny_shared_runner_policy: true,
      })
      setSetupResult(res)
      setMessage({ type: 'success', text: res.message })
      onSuccess?.(true, res)
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <aside className="token-detail-panel quick-register-panel token-detail-inline">
      {setupResult?.handle ? (
        <OneTimeSecretReveal
          title="CI handle for GitLab variables"
          secret={setupResult.handle}
          hint="Add this as CTRS_GENERIC_HANDLE in GitLab CI variables."
          onDismiss={onCancel}
        />
      ) : (
        <form className="operator-form compact-wizard" onSubmit={submit}>
          {!runnerId ? (
            <div className="alert alert-error">
              Register is locked until you have a <strong>CTRS runner</strong> (not the glpat).
              Create one here or under Monitor → Runners.
            </div>
          ) : null}
          <div className="tdi-row">
            <span className="tdi-label">CTRS runner</span>
            <span className="cell-mono">
              {runnerId || 'none yet'}
            </span>
          </div>
          {!runnerId ? (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              disabled={creatingRunner}
              onClick={createRunnerQuick}
            >
              {creatingRunner ? 'Creating runner…' : 'Create CTRS runner now'}
            </button>
          ) : runners.length > 1 ? (
            <Field label="Runner for policy">
              <select value={runnerId} onChange={(e) => setRunnerId(e.target.value)}>
                {runners.map((r) => (
                  <option key={r.id} value={r.id}>{r.id}</option>
                ))}
              </select>
            </Field>
          ) : null}
          {newRunnerSecret ? (
            <OneTimeSecretReveal
              title="CTRS runner secret (install on the runner host)"
              secret={newRunnerSecret}
              hint={`Write to /etc/ctrs/runner-secret. CI needs CTRS_RUNNER_ID=${runnerId}.`}
              onDismiss={() => setNewRunnerSecret(null)}
            />
          ) : null}
          <Field label="GitLab token secret" hint="Paste the real glpat-… for this token.">
            <input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} required autoFocus={Boolean(runnerId)} />
          </Field>
          <div className="wizard-actions">
            <button type="button" className="btn btn-ghost" onClick={onCancel}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={busy || !runnerId || !secret.trim()}>
              {busy ? 'Registering…' : 'Register'}
            </button>
          </div>
          <FormMessage message={message?.text} type={message?.type} />
        </form>
      )}
    </aside>
  )
}

export function LinkGitLabMetadataPanel({ tokenId, onSuccess }) {
  const [form, setForm] = useState({
    project_path: '',
    gitlab_access_token_name: 'ctrs-vault',
  })
  const [message, setMessage] = useState(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setMessage(null)
    try {
      const res = await postJson(`/admin/tokens/${tokenId}/gitlab-metadata`, form)
      setMessage({ type: 'success', text: `${res.message} — project ${res.provider_metadata?.gitlab_project_id}` })
      onSuccess?.()
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="operator-form compact" onSubmit={submit}>
      <h4>Link GitLab rotation metadata</h4>
      <div className="form-grid">
        <Field label="Project path">
          <input value={form.project_path} onChange={(e) => setForm({ ...form, project_path: e.target.value })} required />
        </Field>
        <Field label="Access token name in GitLab">
          <input value={form.gitlab_access_token_name} onChange={(e) => setForm({ ...form, gitlab_access_token_name: e.target.value })} />
        </Field>
      </div>
      <button type="submit" className="btn btn-sm btn-primary" disabled={busy}>{busy ? 'Linking…' : 'Link metadata'}</button>
      <FormMessage message={message?.text} type={message?.type} />
    </form>
  )
}

export function ResyncVaultSecretPanel({ tokenId, stale = false, onSuccess }) {
  const [secret, setSecret] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setMessage(null)
    try {
      const res = await postJson(`/admin/tokens/${tokenId}/vault-secret`, { secret })
      setSecret('')
      setMessage({ type: 'success', text: res.message })
      onSuccess?.()
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="operator-form compact" onSubmit={submit}>
      <h4>{stale ? 'Vault secret is stale' : 'Update vault after GitLab UI rotation'}</h4>
      <p className="form-hint">
        Paste the new <code>glpat-…</code> GitLab showed once. The CI handle does not change.
      </p>
      <Field label="New GitLab token secret">
        <input
          type="password"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          required
          autoComplete="off"
        />
      </Field>
      <button type="submit" className="btn btn-sm btn-primary" disabled={busy}>
        {busy ? 'Updating…' : 'Save into vault'}
      </button>
      <FormMessage message={message?.text} type={message?.type} />
    </form>
  )
}

export function AddPolicyPanel({ tokens, onSuccess }) {
  const [form, setForm] = useState({
    policy_id: '',
    token_id: tokens[0]?.id || '',
    effect: 'allow',
    priority: 100,
    runner_ids: '',
    runner_types: 'self-hosted',
    repositories: '',
    workflows: '',
    branches: 'main,master',
    max_token_lifetime_seconds: 3600,
    deny_gitlab_shared: false,
    deny_github_hosted: false,
  })
  const [message, setMessage] = useState(null)
  const [busy, setBusy] = useState(false)

  const buildConditions = () => {
    if (form.effect === 'deny' && (form.deny_gitlab_shared || form.deny_github_hosted)) {
      const c = {}
      if (form.deny_gitlab_shared) c.deny_gitlab_shared = true
      if (form.deny_github_hosted) c.deny_github_hosted = true
      return c
    }
    const c = {}
    const runners = splitList(form.runner_ids)
    const types = splitList(form.runner_types)
    const repos = splitList(form.repositories)
    const workflows = splitList(form.workflows)
    const branches = splitList(form.branches)
    if (runners.length) c.runner_ids = runners
    if (types.length) c.runner_types = types
    if (repos.length) c.repositories = repos
    if (workflows.length) c.workflows = workflows
    if (branches.length) c.branches = branches
    if (form.max_token_lifetime_seconds) c.max_token_lifetime_seconds = Number(form.max_token_lifetime_seconds)
    return c
  }

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setMessage(null)
    try {
      await postJson('/admin/policies', {
        policy_id: form.policy_id,
        token_id: form.token_id,
        effect: form.effect,
        priority: Number(form.priority),
        conditions: buildConditions(),
      })
      setMessage({ type: 'success', text: `Policy ${form.policy_id} created` })
      onSuccess?.()
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="operator-form" onSubmit={submit}>
      <h3>Add policy</h3>
      <div className="form-grid">
        <Field label="Policy ID">
          <input value={form.policy_id} onChange={(e) => setForm({ ...form, policy_id: e.target.value })} placeholder="allow-build" required />
        </Field>
        <Field label="Token">
          <select value={form.token_id} onChange={(e) => setForm({ ...form, token_id: e.target.value })} required>
            {tokens.map((t) => <option key={t.id} value={t.id}>{t.id}</option>)}
          </select>
        </Field>
        <Field label="Effect">
          <select value={form.effect} onChange={(e) => setForm({ ...form, effect: e.target.value })}>
            <option value="allow">allow</option>
            <option value="deny">deny</option>
          </select>
        </Field>
        <Field label="Priority" hint="Higher = evaluated first. Deny policies usually 1000.">
          <input type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })} />
        </Field>
      </div>
      {form.effect === 'allow' ? (
        <div className="form-grid">
          <Field label="Runner IDs (comma-separated)">
            <input value={form.runner_ids} onChange={(e) => setForm({ ...form, runner_ids: e.target.value })} />
          </Field>
          <Field label="Runner types">
            <input value={form.runner_types} onChange={(e) => setForm({ ...form, runner_types: e.target.value })} />
          </Field>
          <Field label="Repositories (glob)">
            <input value={form.repositories} onChange={(e) => setForm({ ...form, repositories: e.target.value })} />
          </Field>
          <Field label="Workflows / job names (glob)">
            <input value={form.workflows} onChange={(e) => setForm({ ...form, workflows: e.target.value })} />
          </Field>
          <Field label="Branches (glob)">
            <input value={form.branches} onChange={(e) => setForm({ ...form, branches: e.target.value })} />
          </Field>
          <Field label="Max token TTL (seconds)">
            <input type="number" value={form.max_token_lifetime_seconds} onChange={(e) => setForm({ ...form, max_token_lifetime_seconds: e.target.value })} />
          </Field>
        </div>
      ) : (
        <div className="form-checkboxes">
          <label className="form-checkbox">
            <input type="checkbox" checked={form.deny_gitlab_shared} onChange={(e) => setForm({ ...form, deny_gitlab_shared: e.target.checked })} />
            Deny GitLab shared / instance runners
          </label>
          <label className="form-checkbox">
            <input type="checkbox" checked={form.deny_github_hosted} onChange={(e) => setForm({ ...form, deny_github_hosted: e.target.checked })} />
            Deny GitHub-hosted runners
          </label>
        </div>
      )}
      <button type="submit" className="btn btn-primary" disabled={busy}>{busy ? 'Creating…' : 'Create policy'}</button>
      <FormMessage message={message?.text} type={message?.type} />
    </form>
  )
}

export function PolicyActions({ policy, onUpdated }) {
  const [busy, setBusy] = useState(false)

  const toggle = async () => {
    setBusy(true)
    try {
      await patchJson(`/admin/policies/${policy.id}`, { enabled: !policy.enabled })
      onUpdated?.()
    } finally {
      setBusy(false)
    }
  }

  const remove = async () => {
    if (!window.confirm(`Delete policy ${policy.id}?`)) return
    setBusy(true)
    try {
      await deleteRequest(`/admin/policies/${policy.id}`)
      onUpdated?.()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="row-actions">
      <button type="button" className="btn btn-sm btn-ghost" onClick={toggle} disabled={busy}>
        {policy.enabled ? 'Disable' : 'Enable'}
      </button>
      <button type="button" className="btn btn-sm btn-ghost danger" onClick={remove} disabled={busy}>Delete</button>
    </div>
  )
}

export function RunnerActions({ runner, onUpdated }) {
  const [busy, setBusy] = useState(false)

  const remove = async () => {
    if (
      !window.confirm(
        `Delete runner ${runner.id}? You can register it again with a new secret. Policies that reference this runner id may need updating.`,
      )
    ) {
      return
    }
    setBusy(true)
    try {
      await deleteRequest(`/admin/runners/${runner.id}`)
      onUpdated?.()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="row-actions">
      <button type="button" className="btn btn-sm btn-ghost danger" onClick={remove} disabled={busy}>
        Delete
      </button>
    </div>
  )
}
