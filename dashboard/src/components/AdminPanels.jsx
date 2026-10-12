import { useEffect, useState } from 'react'
import { deleteRequest, fetchJson, patchJson, postJson } from '../api'
import { Field, FormMessage } from './OperatorPanels'

export function TrackedProjectsPanel({ trackedProjects = [], onChanged, adminConfig, hideLoadErrors = false }) {
  const [search, setSearch] = useState('')
  const [suggestions, setSuggestions] = useState([])
  const [suggestErrors, setSuggestErrors] = useState([])
  const [message, setMessage] = useState(null)
  const [busy, setBusy] = useState(false)
  const [loadingSuggest, setLoadingSuggest] = useState(false)

  const loadSuggestions = async (q = '') => {
    if (!adminConfig?.gitlab_pat_configured) return
    if (hideLoadErrors) {
      setSuggestions([])
      setSuggestErrors([])
      setLoadingSuggest(false)
      return
    }
    setLoadingSuggest(true)
    try {
      const data = await fetchJson(`/gitlab/projects?search=${encodeURIComponent(q)}`)
      setSuggestions(data.projects || [])
      setSuggestErrors(data.errors || [])
    } catch (err) {
      setSuggestions([])
      setSuggestErrors([err.message])
    } finally {
      setLoadingSuggest(false)
    }
  }

  useEffect(() => {
    if (!adminConfig?.gitlab_pat_configured) {
      setSuggestions([])
      setSuggestErrors([])
      return
    }
    if (hideLoadErrors) {
      setSuggestions([])
      setSuggestErrors([])
      return
    }
    setSuggestions([])
    loadSuggestions('')
  }, [adminConfig?.gitlab_pat_configured, adminConfig?.gitlab_base_url, hideLoadErrors])

  useEffect(() => {
    if (!adminConfig?.gitlab_pat_configured || hideLoadErrors) return
    const timer = setTimeout(() => {
      loadSuggestions(search)
    }, 250)
    return () => clearTimeout(timer)
  }, [search, adminConfig?.gitlab_pat_configured, adminConfig?.gitlab_base_url, hideLoadErrors])

  useEffect(() => {
    if (!message) return undefined
    const timer = setTimeout(() => setMessage(null), 1200)
    return () => clearTimeout(timer)
  }, [message])

  const searchQuery = search.trim().toLowerCase()
  const matchesSearch = (name = '', path = '') => {
    if (!searchQuery) return true
    return name.toLowerCase().includes(searchQuery) || path.toLowerCase().includes(searchQuery)
  }

  // One GitLab host at a time: when URL is unreachable/wrong, do not show stale tracked rows.
  const visibleTracked = hideLoadErrors ? [] : trackedProjects

  const untrackedSuggestions = suggestions
    .filter((p) => !p.tracked)
    .filter((p) => matchesSearch(p.name, p.project_path))
    .slice(0, 12)

  const filteredTracked = visibleTracked.filter((p) =>
    matchesSearch(p.display_name || p.project_path, p.project_path),
  )

  const addProject = async (projectPath, projectId = null, displayName = '') => {
    setBusy(true)
    setMessage(null)
    try {
      await postJson('/gitlab/tracked-projects', {
        project_path: projectPath,
        project_id: projectId || undefined,
        display_name: displayName || projectPath,
      })
      setMessage({ type: 'success', text: `Now tracking ${projectPath}` })
      await loadSuggestions(search)
      onChanged?.()
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setBusy(false)
    }
  }

  const removeProject = async (id, projectPath) => {
    setBusy(true)
    setMessage(null)
    try {
      await deleteRequest(`/gitlab/tracked-projects/${id}`)
      setMessage({ type: 'info', text: `Stopped tracking ${projectPath}` })
      await loadSuggestions(search)
      onChanged?.()
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="overview-card overview-wide tracked-projects-panel">
      <h3>Projects to track</h3>

      {!adminConfig?.gitlab_pat_configured ? (
        <div className="alert alert-error">
          Sign in with GitLab (OAuth scopes <code>api</code>) so CTRS can list your projects and tokens.
        </div>
      ) : (
        <>
          <div className="tracked-search-row">
            <Field label="Search projects">
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search projects…"
              />
            </Field>
          </div>

          <div className="tracked-projects-layout">
            <div className="tracked-column">
              <h4>Choose from GitLab projects</h4>
              {!hideLoadErrors && suggestErrors.length > 0 && (
                <div className="alert alert-error">
                  <strong>Could not load GitLab projects</strong>
                  <ul className="error-list">
                    {suggestErrors.map((err) => <li key={err}>{err}</li>)}
                  </ul>
                </div>
              )}
              {loadingSuggest && <p className="cell-muted">Searching…</p>}
              <ul className="suggest-list">
                {untrackedSuggestions.map((p) => (
                  <li key={p.project_id}>
                    <div>
                      <div className="cell-primary">{p.name}</div>
                      <div className="cell-mono">{p.project_path}</div>
                    </div>
                    <button
                      type="button"
                      className="btn btn-sm btn-primary"
                      disabled={busy}
                      onClick={() => addProject(p.project_path, p.project_id, p.name)}
                    >
                      Track
                    </button>
                  </li>
                ))}
                {!loadingSuggest && untrackedSuggestions.length === 0 && (
                  <li className="cell-muted">
                    {hideLoadErrors || suggestErrors.length > 0
                      ? 'No projects available.'
                      : suggestions.some((p) => !p.tracked)
                        ? 'No untracked projects match this search.'
                        : suggestions.length > 0
                          ? 'All matching projects are already tracked.'
                          : 'No projects found for this search.'}
                  </li>
                )}
              </ul>
            </div>

            <div className="tracked-column">
              <h4>
                Currently tracking
                {hideLoadErrors
                  ? ''
                  : searchQuery
                    ? ` (${filteredTracked.length}/${visibleTracked.length})`
                    : ` (${visibleTracked.length})`}
              </h4>
              {hideLoadErrors ? (
                <p className="overview-empty">
                  This GitLab URL is unreachable
                </p>
              ) : visibleTracked.length === 0 ? (
                <p className="overview-empty">No projects yet. Pick one from GitLab on the left.</p>
              ) : filteredTracked.length === 0 ? (
                <p className="overview-empty">No tracked projects match this search.</p>
              ) : (
                <ul className="tracked-list">
                  {filteredTracked.map((p) => (
                    <li key={p.id}>
                      <div>
                        <div className="cell-primary">{p.display_name || p.project_path}</div>
                        <div className="cell-mono">{p.project_path}</div>
                      </div>
                      <div className="tracked-item-actions">
                        <span className="source-badge source-real">tracked</span>
                        <button
                          type="button"
                          className="btn btn-sm btn-ghost"
                          disabled={busy}
                          onClick={() => removeProject(p.id, p.project_path)}
                        >
                          Remove
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
          <FormMessage message={message?.text} type={message?.type} />
        </>
      )}
    </section>
  )
}

export function AdminSettingsPanel({ onSaved }) {
  const [form, setForm] = useState({
    renewal_check_interval_minutes: 15,
    renewal_threshold_days: 14,
  })
  const [message, setMessage] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    fetchJson('/admin/operator-settings')
      .then((data) => setForm({
        renewal_check_interval_minutes: data.renewal_check_interval_minutes,
        renewal_threshold_days: data.renewal_threshold_days,
      }))
      .catch(() => {})
  }, [])

  const save = async (e) => {
    e.preventDefault()
    setBusy(true)
    setMessage(null)
    try {
      await patchJson('/admin/operator-settings', {
        renewal_check_interval_minutes: Number(form.renewal_check_interval_minutes),
        renewal_threshold_days: Number(form.renewal_threshold_days),
      })
      setMessage({ type: 'success', text: 'Renewal settings saved. Scheduler interval updated immediately.' })
      onSaved?.()
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setBusy(false)
    }
  }

  const runNow = async () => {
    setBusy(true)
    setMessage(null)
    try {
      const res = await postJson('/admin/scheduler/run', {})
      setMessage({
        type: 'success',
        text: `Scheduler ran. Renewed: ${res.renewed_tokens?.length ? res.renewed_tokens.join(', ') : 'none (no tokens within threshold)'}`,
      })
      onSaved?.()
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="wizard-panel admin-settings">
      <h3>Auto-renewal settings</h3>
      <p className="wizard-lead">
        While CTRS is running, a background job checks tokens on a schedule. Tokens expiring within the threshold are rotated via GitLab automatically.
      </p>
      <form className="operator-form compact-wizard" onSubmit={save}>
        <div className="form-grid">
          <Field label="Check every (minutes)" hint="How often CTRS looks for tokens to renew (5–1440)">
            <input
              type="number"
              min={5}
              max={1440}
              value={form.renewal_check_interval_minutes}
              onChange={(e) => setForm({ ...form, renewal_check_interval_minutes: e.target.value })}
              required
            />
          </Field>
          <Field label="Renew when expiring within (days)" hint="1 = last day only, 14 = two weeks before expiry">
            <input
              type="number"
              min={1}
              max={90}
              value={form.renewal_threshold_days}
              onChange={(e) => setForm({ ...form, renewal_threshold_days: e.target.value })}
              required
            />
          </Field>
        </div>
        <div className="wizard-actions">
          <button type="submit" className="btn btn-primary" disabled={busy}>Save settings</button>
          <button type="button" className="btn btn-ghost" onClick={runNow} disabled={busy}>Run renewal check now</button>
        </div>
        <FormMessage message={message?.text} type={message?.type} />
      </form>
      <p className="form-hint">
        Emails for create / rotate / revoke / expiry are sent via the server SMTP settings
        (SMTP_* in service/.env). GitLab API calls use your OAuth token from Sign in with GitLab.
      </p>
    </section>
  )
}

export function VerifySetupPanel() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = () => {
    setLoading(true)
    setError(null)
    fetchJson('/admin/setup-verify')
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  if (loading) return <p className="cell-muted">Checking setup…</p>
  if (error) return <div className="alert alert-error">{error}</div>
  if (!data) return null

  return (
    <section className="wizard-panel verify-setup">
      <div className="verify-header">
        <h3>Is my setup working?</h3>
        <button type="button" className="btn btn-sm btn-ghost" onClick={load}>↻ Re-check</button>
      </div>
      <p className="wizard-lead">
        Green = CTRS server is configured. The last check proves a real token exchange happened (after you run confstr or a CI job).
      </p>
      <ul className="verify-checklist">
        {data.checks.map((c) => (
          <li key={c.id} className={c.passed ? 'check-ok' : 'check-warn'}>
            <span className="verify-icon">{c.passed ? '✓' : '○'}</span>
            <div>
              <strong>{c.label}</strong>
              <p>{c.detail}</p>
            </div>
          </li>
        ))}
      </ul>
      {data.ready ? (
        <div className="wizard-callout success">
          <strong>Solution is working end-to-end.</strong> CTRS registered, policies active, and at least one successful exchange logged.
        </div>
      ) : (
        <div className="wizard-callout warn">
          <strong>Not fully proven yet.</strong>
          <ul className="explainer-list">
            {data.next_steps.map((s) => <li key={s}>{s}</li>)}
          </ul>
        </div>
      )}
      <details className="advanced-panel">
        <summary>Manual test commands (run on WSL runner host)</summary>
        <pre className="code-block">{`export PATH="$HOME/ctrs/venv/bin:$PATH"
export CTRS_SERVICE_URL=http://localhost:8080
export CTRS_GENERIC_HANDLE=<handle from setup>
export CTRS_RUNNER_ID=<runner id from setup>
export CTRS_RUNNER_SECRET=<secret on runner disk>
export CI_PROJECT_PATH=your-user/your-project
export CI_JOB_NAME=ctrs_exchange_and_api
export CI_COMMIT_REF_NAME=main

confstr verify-runner
TOKEN=$(confstr exchange --target gitlab)
curl -s -w "\\nHTTP %{http_code}\\n" -H "PRIVATE-TOKEN: $TOKEN" \\
  "https://se-gitlab.inf.tu-dresden.de/api/v4/user"`}</pre>
        <p className="form-hint">HTTP 200 = exchange works. Then click Re-check above — exchange_success should turn green.</p>
      </details>
    </section>
  )
}
