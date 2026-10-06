import { Fragment, useEffect, useState } from 'react'
import { fetchCurrentUser, fetchJson, loginWithGitLabPat, logout, patchJson } from './api'
import appLogo from './fe231354-be2f-4ac9-8d9e-67d957bf53e7.png'
import {
  AddPolicyPanel,
  LinkGitLabMetadataPanel,
  PolicyActions,
  QuickRegisterGitLabToken,
  ResyncVaultSecretPanel,
  RegisterRunnerPanel,
  RunnerActions,
} from './components/OperatorPanels'
import { AdminSettingsPanel, TrackedProjectsPanel } from './components/AdminPanels'

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: '◈' },
  { id: 'monitor', label: 'Monitor', icon: '🔑' },
  { id: 'audit', label: 'Audit Log', icon: '📋' },
]

const PAGE_META = {
  overview: {
    title: 'Overview',
    subtitle: 'Tracked projects and GitLab connection.',
  },
  monitor: {
    title: 'Monitor',
    subtitle: 'Token health, policies, runners, and renewal settings.',
  },
  audit: {
    title: 'Audit Log',
    subtitle: 'Who exchanged tokens, renewals, and denials.',
  },
}

function StatusBadge({ status }) {
  const styles = {
    active: 'source-real',
    expired: 'source-error',
    revoked: 'source-error',
    inactive: 'source-demo',
  }
  return <span className={`source-badge ${styles[status] || 'source-demo'}`}>{status}</span>
}

function expiryTone(expiresInDays, inactive = false) {
  if (inactive || expiresInDays == null) return 'neutral'
  if (expiresInDays <= 0) return 'critical'
  if (expiresInDays < 1) return 'warning'
  if (expiresInDays < 7) return 'attention'
  return 'healthy'
}

function formatExpiresAt(expiresAt) {
  if (!expiresAt) return null
  const date = new Date(expiresAt)
  if (Number.isNaN(date.getTime())) return String(expiresAt)
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function IconRotate({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M21 12a9 9 0 1 1-2.6-6.2" />
      <polyline points="21 3 21 9 15 9" />
    </svg>
  )
}

function IconTrash({ size = 16 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
      <path d="M10 11v6" />
      <path d="M14 11v6" />
      <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
    </svg>
  )
}

function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  danger = false,
  icon = null,
  onConfirm,
  onCancel,
}) {
  useEffect(() => {
    if (!open) return undefined
    const onKey = (e) => {
      if (e.key === 'Escape') onCancel?.()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onCancel])

  if (!open) return null

  return (
    <div className="confirm-overlay" onClick={onCancel} role="presentation">
      <div
        className={`confirm-dialog ${danger ? 'danger' : ''}`}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-message"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="confirm-dialog-top">
          {icon ? (
            <div className="confirm-dialog-icon" aria-hidden="true">
              {icon}
            </div>
          ) : null}
          <div className="confirm-dialog-body">
            <h3 id="confirm-dialog-title">{title}</h3>
            <p id="confirm-dialog-message">{message}</p>
          </div>
        </div>
        <div className="confirm-dialog-actions">
          <button type="button" className="btn btn-sm btn-ghost" onClick={onCancel}>
            {cancelLabel}
          </button>
          <button
            type="button"
            className={`btn btn-sm ${danger ? 'btn-danger' : 'btn-primary'}`}
            onClick={onConfirm}
            autoFocus
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

function TokenDetailPanel({
  selected,
  selectedVault,
  renewals,
  renewalsLoading,
  onRefresh,
}) {
  const project = selected?.project && selected.project !== '—'
    ? selected.project
    : selectedVault?.provider_summary || null
  const scopes = selectedVault?.scopes || selected?.scopes || []
  const handles = selectedVault?.handles || []
  const recentRenewals = (renewals || []).slice(0, 3)
  const latestRenewal = (renewals && renewals[0]) || null
  const lastRegenLabel =
    selectedVault?.last_renewal_source_label
    || selected?.last_renewal_source_label
    || (latestRenewal?.source === 'scheduler'
      ? 'Automatic scheduler'
      : latestRenewal?.source === 'gitlab_external'
        ? 'Rotated in GitLab (detected)'
        : latestRenewal?.source === 'gitlab_resync'
          ? 'Vault updated from GitLab UI secret'
        : latestRenewal?.source === 'manual'
          ? 'Manual rotation (dashboard)'
          : null)
  const lastRegenAt =
    latestRenewal?.created_at
    || selectedVault?.last_renewed_at
    || selected?.last_renewed_at
    || null
  const usage = (selectedVault?.usage_locations || selected?.usage || []).filter(
    (u) => u && u !== project,
  )
  const needsGitlabLink =
    selectedVault?.target_system === 'gitlab' && selectedVault.renewal_mode !== 'gitlab_rotate_api'

  return (
    <div className="token-detail-panel token-detail-inline">
      {scopes.length > 0 ? (
        <div className="tdi-row">
          <span className="tdi-label">Scopes</span>
          <div className="tdi-tags">
            {scopes.map((s) => (
              <span key={s} className="tag tag-sm">{s}</span>
            ))}
          </div>
        </div>
      ) : null}

      {handles.length > 0 ? (
        <div className="tdi-row">
          <span className="tdi-label">CI handle</span>
          <div className="tdi-handles">
            {handles.map((h) => (
              <code key={h} className="tdi-handle cell-mono">{h}</code>
            ))}
          </div>
        </div>
      ) : selected?.managed === false ? (
        <div className="tdi-row">
          <span className="tdi-label">CI handle</span>
          <span className="cell-muted">Register into vault to get a handle</span>
        </div>
      ) : null}

      {selected?.vault_token_id || selectedVault ? (
        <div className="tdi-row">
          <span className="tdi-label">Last regen</span>
          <div className="tdi-regen">
            <span>{lastRegenLabel || 'No regeneration yet'}</span>
            {lastRegenLabel && lastRegenAt ? (
              <span className="cell-muted tdi-regen-time">
                {new Date(lastRegenAt).toLocaleString()}
              </span>
            ) : null}
          </div>
        </div>
      ) : null}

      {usage.length > 0 ? (
        <div className="tdi-row">
          <span className="tdi-label">Also used in</span>
          <div className="tdi-tags">
            {usage.map((u) => (
              <span key={u} className="tag tag-sm">{u}</span>
            ))}
          </div>
        </div>
      ) : null}

      {needsGitlabLink ? (
        <div className="tdi-link-gitlab">
          <LinkGitLabMetadataPanel tokenId={selectedVault.id} onSuccess={onRefresh} />
        </div>
      ) : null}

      {selectedVault?.id
        && selectedVault.target_system === 'gitlab'
        && selectedVault.renewal_status === 'failed'
        && latestRenewal?.source === 'gitlab_external' ? (
        <div className="tdi-link-gitlab">
          <ResyncVaultSecretPanel
            tokenId={selectedVault.id}
            stale
            onSuccess={onRefresh}
          />
        </div>
      ) : null}

      {selected?.vault_token_id ? (
        <div className="tdi-row tdi-history">
          <span className="tdi-label">Recent renewals</span>
          {renewalsLoading ? (
            <span className="cell-muted">Loading…</span>
          ) : recentRenewals.length === 0 ? (
            <span className="cell-muted">No events yet</span>
          ) : (
            <ul className="tdi-history-list">
              {recentRenewals.map((e) => (
                <li key={e.id}>
                  <span className={`outcome-badge outcome-${e.status === 'success' ? 'success' : 'denied'}`}>
                    {e.status}
                  </span>
                  <span className="tdi-history-source">
                    {e.source === 'scheduler'
                      ? 'scheduler'
                      : e.source === 'gitlab_external'
                        ? 'GitLab'
                        : e.source === 'gitlab_resync'
                          ? 'GitLab paste'
                        : e.source === 'manual'
                          ? 'dashboard'
                          : (e.source || '—')}
                  </span>
                  <span className="tdi-history-time">{new Date(e.created_at).toLocaleString()}</span>
                  {e.message ? <span className="tdi-history-msg" title={e.message}>{e.message}</span> : null}
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
    </div>
  )
}

function TokenTable({
  rows,
  selectedKey,
  registerRowKey,
  detailPanel,
  registerPanel,
  onSelect,
  onRenew,
  onRevoke,
  onRegister,
}) {
  if (!rows.length) {
    return <p className="token-section-empty">Empty</p>
  }

  return (
    <div className="token-table-wrap">
      <table className="token-table">
        <thead>
          <tr>
            <th>Token</th>
            <th>Expires</th>
            <th>Created</th>
            <th>Role</th>
            <th>Scopes</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const isSelected = selectedKey === row.key
            const isRegistering = registerRowKey === row.key
            const expiresTone = expiryTone(row.expires_in_days, row.inactive)
            const expiresAtLabel = formatExpiresAt(row.expires_at)
            const showActions = !row.inactive && (row.can_rotate || row.can_revoke || !row.managed)
            return (
              <Fragment key={row.key}>
                <tr
                  className={`${isSelected || isRegistering ? 'selected' : ''} ${row.inactive ? 'faded' : ''}`}
                  onClick={() => onSelect?.(isSelected ? null : row)}
                >
                  <td className="token-col-main">
                    <div className="token-cell-title">
                      <span className="mtc-name">{row.name}</span>
                      {row.status && row.status !== 'active' ? (
                        <StatusBadge status={row.status} />
                      ) : null}
                    </div>
                    <div className="token-cell-sub">
                      {row.project && row.project !== '—' && (
                        <span className="mtc-project cell-mono">{row.project}</span>
                      )}
                      {row.kind ? <span className="mtc-kind">{row.kind}</span> : null}
                    </div>
                  </td>
                  <td>
                    <span
                      className={`mtc-expires expires-${expiresTone}`}
                      title={expiresAtLabel ? `Expires ${expiresAtLabel}` : undefined}
                    >
                      {row.expires_in_days != null ? `${row.expires_in_days}d` : '—'}
                    </span>
                  </td>
                  <td className="cell-muted">
                    {row.created_at ? new Date(row.created_at).toLocaleDateString() : '—'}
                  </td>
                  <td>{row.role && row.role !== '—' ? row.role : '—'}</td>
                  <td>
                    {(row.scopes || []).length > 0 ? (
                      <div className="mtc-scopes">
                        {row.scopes.map((s) => <span key={s} className="tag tag-sm">{s}</span>)}
                      </div>
                    ) : (
                      <span className="cell-muted">—</span>
                    )}
                  </td>
                  <td className="token-col-actions" onClick={(e) => e.stopPropagation()}>
                    {showActions ? (
                      <div className="mtc-actions">
                        {row.can_rotate ? (
                          <button
                            type="button"
                            className="btn-icon btn-icon-rotate"
                            title="Rotate token"
                            aria-label={`Rotate token ${row.name}`}
                            onClick={() => onRenew?.(row)}
                          >
                            <IconRotate />
                          </button>
                        ) : null}
                        {row.can_revoke ? (
                          <button
                            type="button"
                            className="btn-icon btn-icon-revoke"
                            title="Revoke token"
                            aria-label={`Revoke token ${row.name}`}
                            onClick={() => onRevoke?.(row)}
                          >
                            <IconTrash />
                          </button>
                        ) : null}
                        {!row.managed ? (
                          <button
                            type="button"
                            className="btn btn-sm btn-primary"
                            onClick={() => onRegister?.(row)}
                          >
                            Register
                          </button>
                        ) : null}
                      </div>
                    ) : null}
                  </td>
                </tr>
                {isSelected && detailPanel ? (
                  <tr className="token-expand-row">
                    <td colSpan={6}>{detailPanel}</td>
                  </tr>
                ) : null}
                {isRegistering && registerPanel ? (
                  <tr className="token-expand-row">
                    <td colSpan={6}>{registerPanel}</td>
                  </tr>
                ) : null}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function TokenSection({ title, hint, count, tone, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <section className={`token-section tone-${tone}`}>
      <button type="button" className="token-section-header" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
        <div className="token-section-title-wrap">
          <span className={`token-section-dot tone-${tone}`} aria-hidden="true" />
          <div>
            <div className="token-section-title">
              {title}
              <span className="token-section-count">{count}</span>
            </div>
            {hint ? <p className="token-section-hint">{hint}</p> : null}
          </div>
        </div>
        <span className={`token-section-chevron ${open ? 'open' : ''}`} aria-hidden="true">▾</span>
      </button>
      {open && <div className="token-section-body">{children}</div>}
    </section>
  )
}

function EmptyState({ icon, title, description, hint }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">{icon}</div>
      <h3>{title}</h3>
      <p>{description}</p>
      {hint && <p className="empty-hint">{hint}</p>}
    </div>
  )
}
function PoliciesTab({ policies, tokens, onRefresh }) {
  return (
    <div className="policies-layout">
      <details className="advanced-panel">
        <summary>Add policy manually (advanced)</summary>
        <AddPolicyPanel tokens={tokens} onSuccess={onRefresh} />
      </details>
      {!policies.length ? (
        <EmptyState icon="🛡" title="No policies yet" description="Create a policy above or register a GitLab token from Tokens." />
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Priority</th>
                <th>Policy</th>
                <th>Token</th>
                <th>Effect</th>
                <th>Status</th>
                <th>Conditions</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id} className={!p.enabled ? 'row-disabled' : ''}>
                  <td><span className="priority-badge">{p.priority}</span></td>
                  <td>
                    <div className="cell-primary">{p.name}</div>
                    {p.id !== p.name && <div className="cell-mono">{p.id}</div>}
                  </td>
                  <td className="cell-mono">{p.token_id}</td>
                  <td><span className={`effect-badge effect-${p.effect}`}>{p.effect}</span></td>
                  <td>{p.enabled ? 'enabled' : 'disabled'}</td>
                  <td>
                    <div className="conditions-list">
                      {Object.entries(p.conditions || {}).map(([k, v]) => (
                        <span key={k} className="condition-chip">
                          <span className="condition-key">{k}</span>
                          <span className="condition-val">{JSON.stringify(v)}</span>
                        </span>
                      ))}
                    </div>
                  </td>
                  <td><PolicyActions policy={p} onUpdated={onRefresh} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function RunnersTab({ runners, onRefresh }) {
  return (
    <div className="runners-layout">
      <RegisterRunnerPanel
        compact
        showForm
        registeredRunners={runners}
        onSuccess={(silent) => onRefresh?.(silent)}
      />

      {runners.length > 0 ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Runner ID</th>
                <th>Type</th>
                <th>CTRS status</th>
                <th>Host setup</th>
                <th>Last proved</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {runners.map((r) => {
                const hostReady = r.host_setup === 'verified' || Boolean(r.last_seen_at)
                return (
                <tr key={r.id}>
                  <td>
                    <div className="cell-primary cell-mono">{r.id}</div>
                    {r.name && r.name !== r.id ? <div className="cell-muted">{r.name}</div> : null}
                  </td>
                  <td><span className="tag">{r.runner_type}</span></td>
                  <td>
                    <span className={`status-dot ${r.active ? 'active' : 'inactive'}`}>
                      {r.active ? 'in CTRS' : 'inactive'}
                    </span>
                  </td>
                  <td>
                    <span className={`source-badge ${hostReady ? 'source-real' : 'source-demo'}`}>
                      {hostReady ? 'Host ready' : 'Pending host setup'}
                    </span>
                  </td>
                  <td className="cell-muted">{r.last_seen_at ? new Date(r.last_seen_at).toLocaleString() : '—'}</td>
                  <td><RunnerActions runner={r} onUpdated={onRefresh} /></td>
                </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  )
}

function AuditTab({ events }) {
  if (!events.length) {
    return <EmptyState icon="📋" title="No audit events yet" description="Events appear after setup, exchange, renewal, or denied requests." />
  }
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Event</th>
            <th>Outcome</th>
            <th>Token</th>
            <th>Runner</th>
            <th>Policy</th>
            <th>Context</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td className="cell-mono nowrap">{new Date(e.created_at).toLocaleString()}</td>
              <td><span className="event-type">{e.event_type}</span></td>
              <td><span className={`outcome-badge outcome-${e.outcome}`}>{e.outcome}</span></td>
              <td className="cell-mono">{e.token_id || '—'}</td>
              <td className="cell-mono">{e.runner_id || '—'}</td>
              <td className="cell-mono">{e.policy_id || '—'}</td>
              <td className="cell-muted">{[e.repository, e.workflow, e.branch].filter(Boolean).join(' / ') || '—'}</td>
              <td className="cell-detail">{e.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AllTokensPanel({
  tokens,
  gitlabData,
  gitlabLoading,
  adminConfig,
  onRenew,
  onRevoke,
  runners,
  selectedTokenId,
  onSelectToken,
  renewals,
  renewalsLoading,
  onRefresh,
}) {
  const [registerRow, setRegisterRow] = useState(null)
  const [selectedKey, setSelectedKey] = useState(null)
  const [confirmAction, setConfirmAction] = useState(null)
  const inventory = buildInventoryRows(tokens, gitlabData)
  const selected = selectedKey
    ? inventory.find((r) => r.key === selectedKey)
    : null
  const selectedVault = selected?.vault_token_id
    ? tokens.find((t) => t.id === selected.vault_token_id)
    : selectedTokenId
      ? tokens.find((t) => t.id === selectedTokenId)
      : null
  const showDetail = Boolean(!registerRow && selected)
  const fetchErrors = gitlabData?.errors || []

  const selectRow = (row) => {
    if (!row) {
      setSelectedKey(null)
      onSelectToken?.(null)
      return
    }
    setRegisterRow(null)
    setSelectedKey(row.key)
    onSelectToken?.(row.vault_token_id || null)
  }

  // Keep local selection in sync when parent sets a vault id (e.g. after register / rotate)
  useEffect(() => {
    if (!selectedTokenId) return
    const match = inventory.find((r) => r.vault_token_id === selectedTokenId)
    if (match) setSelectedKey((prev) => (prev === match.key ? prev : match.key))
  }, [selectedTokenId, tokens, gitlabData]) // eslint-disable-line react-hooks/exhaustive-deps — inventory derived from tokens/gitlabData

  const registered = inventory.filter((r) => r.managed && !r.inactive)
  const needsRegister = inventory.filter((r) => !r.managed && !r.inactive)
  const archived = inventory.filter((r) => r.inactive)
  const askRotate = (row) => setConfirmAction({ type: 'rotate', row })
  const askRevoke = (row) => setConfirmAction({ type: 'revoke', row })
  const closeConfirm = () => setConfirmAction(null)
  const runConfirm = () => {
    if (!confirmAction?.row?.vault_token_id) {
      closeConfirm()
      return
    }
    const { type, row } = confirmAction
    closeConfirm()
    if (type === 'rotate') onRenew?.(row.vault_token_id)
    if (type === 'revoke') onRevoke?.(row.vault_token_id)
  }

  const detailPanel = showDetail ? (
    <TokenDetailPanel
      selected={selected}
      selectedVault={selectedVault}
      renewals={renewals}
      renewalsLoading={renewalsLoading}
      onRefresh={onRefresh}
    />
  ) : null

  const registerPanel = registerRow ? (
    <QuickRegisterGitLabToken
      token={registerRow}
      runners={runners || []}
      onCancel={() => setRegisterRow(null)}
      onRunnersChanged={() => onRefresh?.()}
      onSuccess={(_silent, res) => {
        setRegisterRow(null)
        onRefresh?.()
        if (res?.token_id) onSelectToken?.(res.token_id)
      }}
    />
  ) : null

  const renderTable = (rows) => (
    <TokenTable
      rows={rows}
      selectedKey={selectedKey}
      registerRowKey={registerRow?.key || null}
      detailPanel={selected && rows.some((r) => r.key === selected.key) ? detailPanel : null}
      registerPanel={registerRow && rows.some((r) => r.key === registerRow.key) ? registerPanel : null}
      onSelect={selectRow}
      onRenew={askRotate}
      onRevoke={askRevoke}
      onRegister={(r) => {
        selectRow(null)
        setRegisterRow(r)
      }}
    />
  )

  return (
    <div className="monitor-tokens-section">
      <ConfirmDialog
        open={Boolean(confirmAction)}
        danger={confirmAction?.type === 'revoke'}
        icon={confirmAction?.type === 'revoke' ? <IconTrash size={16} /> : <IconRotate size={16} />}
        title={
          confirmAction?.type === 'revoke'
            ? `Revoke “${confirmAction.row.name}”?`
            : `Rotate “${confirmAction?.row?.name}”?`
        }
        message={
          confirmAction?.type === 'revoke'
            ? 'This permanently revokes the token in GitLab and deactivates its CTRS handle. This cannot be undone.'
            : 'GitLab will revoke the current secret and issue a new one (default 60 days). CI keeps using the same handle.'
        }
        confirmLabel={confirmAction?.type === 'revoke' ? 'Revoke token' : 'Rotate token'}
        onCancel={closeConfirm}
        onConfirm={runConfirm}
      />

      {!adminConfig?.gitlab_pat_configured && (
        <div className="alert alert-error">
          Your GitLab OAuth session has no API token stored. Sign out and sign in again with GitLab (scopes <code>read_user api</code>).
        </div>
      )}

      {fetchErrors.length > 0 && (
        <div className="alert alert-error">
          <strong>Could not load some GitLab tokens</strong>
          <ul className="error-list">
            {fetchErrors.map((err) => <li key={err}>{err}</li>)}
          </ul>
        </div>
      )}

      {gitlabLoading && inventory.length === 0 ? (
        <div className="loading-state"><div className="spinner" /><p>Loading tokens…</p></div>
      ) : inventory.length === 0 ? (
        <EmptyState
          icon="🔑"
          title="No GitLab tokens yet"
          description="Track a GitLab project on Overview, then register a project access token here with its secret."
        />
      ) : (
        <div className="monitor-token-cards">
          <TokenSection
            title="Registered in CTRS"
            hint="Vaulted tokens — rotate and revoke from here"
            count={registered.length}
            tone="registered"
            defaultOpen
          >
            {renderTable(registered)}
          </TokenSection>

          <TokenSection
            title="Needs registration"
            hint="Seen in GitLab but not yet vaulted — paste the secret to register"
            count={needsRegister.length}
            tone="pending"
            defaultOpen={needsRegister.length > 0}
          >
            {renderTable(needsRegister)}
          </TokenSection>

          <TokenSection
            title="Revoked & inactive"
            hint="Expired, revoked, or inactive tokens kept for history"
            count={archived.length}
            tone="archived"
            defaultOpen={archived.length > 0 && registered.length === 0 && needsRegister.length === 0}
          >
            {renderTable(archived)}
          </TokenSection>
        </div>
      )}
    </div>
  )
}

function MonitorTab(props) {
  const [section, setSection] = useState('tokens')
  const sections = [
    { id: 'tokens', label: 'Tokens', icon: '🔑' },
    { id: 'policies', label: 'Policies', icon: '🛡' },
    { id: 'runners', label: 'Runners', icon: '⚙' },
    { id: 'settings', label: 'Settings', icon: '⟳' },
  ]

  return (
    <div className="monitor-tab">
      <nav className="monitor-nav">
        {sections.map((s) => (
          <button
            key={s.id}
            type="button"
            className={`monitor-nav-btn ${section === s.id ? 'active' : ''}`}
            onClick={() => setSection(s.id)}
          >
            <span className="monitor-nav-icon">{s.icon}</span>
            {s.label}
          </button>
        ))}
      </nav>

      {section === 'tokens' && (
        <AllTokensPanel
          tokens={props.tokens}
          gitlabData={props.gitlabData}
          gitlabLoading={props.gitlabLoading}
          adminConfig={props.adminConfig}
          onRenew={props.onRenew}
          onRevoke={props.onRevoke}
          runners={props.runners}
          selectedTokenId={props.selectedTokenId}
          onSelectToken={props.onSelectToken}
          renewals={props.renewals}
          renewalsLoading={props.renewalsLoading}
          onRefresh={props.onRefresh}
        />
      )}
      {section === 'policies' && (
        <PoliciesTab policies={props.policies} tokens={props.tokens} onRefresh={props.onRefresh} />
      )}
      {section === 'runners' && (
        <RunnersTab runners={props.runners} onRefresh={props.onRefresh} />
      )}
      {section === 'settings' && <AdminSettingsPanel onSaved={props.onRefresh} />}
    </div>
  )
}

function renewalLabel(mode) {
  const labels = {
    gitlab_rotate_api: 'Automatic (GitLab rotate API)',
    simulated: 'Simulated renewal',
    manual: 'Manual only',
    unmanaged: 'Not managed by CTRS',
  }
  return labels[mode] || mode || '—'
}

function buildInventoryRows(vaultTokens, gitlabData) {
  const rows = []
  const gitlabTokens = gitlabData?.tokens || []
  const vaultIdsInGitlab = new Set(
    gitlabTokens.filter((g) => g.vault_token_id).map((g) => g.vault_token_id),
  )

  for (const g of gitlabTokens) {
    const isExpired = g.expires_in_days != null && g.expires_in_days <= 0
    const isInactive = !g.active || g.revoked || isExpired
    rows.push({
      key: `gl-${g.project_id}-${g.gitlab_token_id}`,
      name: g.name,
      kind: 'GitLab project access token',
      project: g.project_path,
      scopes: g.scopes || [],
      role: g.access_level_label || '—',
      expires_at: g.expires_at,
      expires_in_days: g.expires_in_days,
      usage: g.usage_locations?.length ? g.usage_locations : [g.project_path],
      regenerated_how: renewalLabel(g.renewal_mode),
      renewal_mode: g.renewal_mode,
      next_renewal_at: g.next_renewal_at,
      last_renewal_source: g.last_renewal_source,
      last_renewal_source_label: g.last_renewal_source_label,
      last_renewed_at: g.last_renewed_at || null,
      managed: g.in_vault,
      vault_token_id: g.vault_token_id,
      gitlab_project_id: g.project_id,
      gitlab_token_id: g.gitlab_token_id,
      health: g.in_vault
        ? g.vault_health
        : (g.expires_in_days != null && g.expires_in_days < 7 ? 'warning' : 'attention'),
      owner: g.owner || '—',
      created_at: g.created_at,
      status: g.revoked ? 'revoked' : !g.active ? 'inactive' : isExpired ? 'expired' : 'active',
      inactive: isInactive,
      source: g.in_vault ? 'gitlab+vault' : 'gitlab-only',
      can_rotate: Boolean(g.in_vault && g.vault_token_id && g.active && !g.revoked && !isExpired),
      can_revoke: Boolean(g.in_vault && g.vault_token_id && g.active && !g.revoked),
    })
  }

  for (const t of vaultTokens) {
    if (vaultIdsInGitlab.has(t.id)) continue
    if (t.target_system !== 'gitlab') continue
    const isExpired = t.expires_in_days != null && t.expires_in_days <= 0
    const isRevoked = t.renewal_status === 'revoked'
    rows.push({
      key: `vault-${t.id}`,
      name: t.name || t.id,
      kind: t.is_demo ? `Demo ${t.target_system} token` : `${t.target_system} vault token`,
      project: t.provider_summary || '—',
      scopes: t.scopes || [],
      role: '—',
      expires_at: t.expires_at,
      expires_in_days: t.expires_in_days,
      usage: t.usage_locations || [],
      regenerated_how: renewalLabel(t.renewal_mode),
      renewal_mode: t.renewal_mode,
      next_renewal_at: t.next_renewal_at,
      last_renewal_source: t.last_renewal_source,
      last_renewal_source_label: t.last_renewal_source_label,
      last_renewed_at: t.last_renewed_at || null,
      managed: true,
      vault_token_id: t.id,
      health: t.health,
      owner: t.owner || '—',
      created_at: t.created_at,
      status: isRevoked ? 'revoked' : isExpired ? 'expired' : 'active',
      inactive: isRevoked || isExpired,
      source: 'vault-only',
      can_rotate: !isRevoked && !isExpired && (t.renewal_mode === 'gitlab_rotate_api' || t.renewal_mode === 'simulated'),
      can_revoke: !isRevoked,
    })
  }

  // Active tokens first (sorted by expiry), then inactive/expired/revoked at the bottom
  rows.sort((a, b) => {
    if (a.inactive !== b.inactive) return a.inactive ? 1 : -1
    const ad = a.expires_in_days ?? 9999
    const bd = b.expires_in_days ?? 9999
    return ad - bd
  })
  return rows
}

function OverviewTab({
  adminConfig,
  gitlabData,
  onRefreshGitlab,
  onRefreshConfig,
}) {
  const [gitlabUrl, setGitlabUrl] = useState(adminConfig?.gitlab_base_url || '')
  const [urlBusy, setUrlBusy] = useState(false)
  const [urlBusyLabel, setUrlBusyLabel] = useState('Save URL')
  const [urlMessage, setUrlMessage] = useState(null)
  // null = not checked yet; true = reachable; false = missing/bad/error
  const [urlHealthy, setUrlHealthy] = useState(null)

  useEffect(() => {
    setGitlabUrl(adminConfig?.gitlab_base_url || '')
    if (!adminConfig?.gitlab_base_url) {
      setUrlHealthy(false)
    }
  }, [adminConfig?.gitlab_base_url])

  useEffect(() => {
    if (!urlMessage || urlMessage.type !== 'success') return undefined
    const timer = setTimeout(() => setUrlMessage(null), 1200)
    return () => clearTimeout(timer)
  }, [urlMessage])

  // On load (and when URL/PAT become available), quickly check whether projects can be loaded.
  useEffect(() => {
    if (!adminConfig?.gitlab_pat_configured || !adminConfig?.gitlab_base_url) {
      if (!adminConfig?.gitlab_base_url) setUrlHealthy(false)
      return undefined
    }
    let cancelled = false
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 7000)
    ;(async () => {
      try {
        const data = await fetchJson('/gitlab/projects?quick=true', { signal: controller.signal })
        if (cancelled) return
        setUrlHealthy(!(data.errors && data.errors.length))
      } catch {
        if (!cancelled) setUrlHealthy(false)
      } finally {
        clearTimeout(timer)
      }
    })()
    return () => {
      cancelled = true
      controller.abort()
      clearTimeout(timer)
    }
  }, [adminConfig?.gitlab_pat_configured, adminConfig?.gitlab_base_url])

  const saveGitlabUrl = async (e) => {
    e.preventDefault()
    setUrlBusy(true)
    setUrlBusyLabel('Saving…')
    setUrlMessage(null)
    setUrlHealthy(null)
    try {
      const savedUrl = gitlabUrl.trim().replace(/\/$/, '')
      const previousUrl = (adminConfig?.gitlab_base_url || '').replace(/\/$/, '')
      const urlChanged = previousUrl !== savedUrl
      await patchJson('/admin/operator-settings', { gitlab_base_url: savedUrl })
      await onRefreshConfig?.()

      setUrlBusyLabel('Checking…')
      try {
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), 7000)
        let projectsData
        try {
          projectsData = await fetchJson('/gitlab/projects?quick=true', { signal: controller.signal })
        } finally {
          clearTimeout(timer)
        }
        const clearedNote = urlChanged
          ? ' Tracked projects were cleared (one GitLab host at a time).'
          : ''
        if (projectsData.errors?.length) {
          setUrlHealthy(false)
          setUrlMessage({
            type: 'error',
            text: `Could not load GitLab projects from ${savedUrl}: ${projectsData.errors.join('; ')}.${clearedNote}`,
          })
        } else {
          setUrlHealthy(true)
          setUrlMessage({
            type: 'success',
            text: `${savedUrl} is saved as the Gitlab URL.${clearedNote}`,
          })
        }
      } catch (probeErr) {
        setUrlHealthy(false)
        const timedOut = probeErr.name === 'AbortError' || /aborted/i.test(probeErr.message || '')
        const clearedNote = urlChanged
          ? ' Tracked projects were cleared (one GitLab host at a time).'
          : ''
        setUrlMessage({
          type: 'error',
          text: `Could not load GitLab projects from ${savedUrl}: ${timedOut ? 'connection timed out' : probeErr.message}.${clearedNote}`,
        })
      }

      await onRefreshGitlab?.()
    } catch (err) {
      setUrlHealthy(false)
      setUrlMessage({ type: 'error', text: err.message })
    } finally {
      setUrlBusy(false)
      setUrlBusyLabel('Save URL')
    }
  }

  return (
    <div className="overview">
      <section className={`overview-card overview-wide gitlab-connection-card ${adminConfig?.gitlab_pat_configured ? 'connection-ok' : 'connection-warn'}`}>
        <h3>GitLab connection</h3>
        <div className="gitlab-connection-grid">
          <div className="gitlab-connection-status">
            <div>
              <div className="cell-muted">Your GitLab OAuth token</div>
              <div className="cell-primary">
                {adminConfig?.gitlab_pat_configured ? (
                  <span className="source-badge source-real">Connected for your account</span>
                ) : (
                  <span className="source-badge source-demo">Not connected</span>
                )}
              </div>
              {!adminConfig?.gitlab_pat_configured && (
                <p className="form-hint">
                  Sign in with GitLab again so CTRS can store your OAuth access token for list/rotate/revoke.
                </p>
              )}
            </div>
            <div>
              <div className="cell-muted">GitLab URL in use</div>
              <div className="cell-primary">
                {!adminConfig?.gitlab_base_url ? (
                  <span className="source-badge source-error">Not configured</span>
                ) : (
                  <span
                    className={`gitlab-url-badge ${
                      urlHealthy === false
                        ? 'source-error'
                        : urlHealthy === true
                          ? 'source-real'
                          : 'source-demo'
                    }`}
                    title={
                      urlHealthy === false
                        ? 'GitLab URL unreachable or returned an error'
                        : urlHealthy === true
                          ? 'GitLab URL reachable'
                          : 'Checking GitLab URL…'
                    }
                  >
                    {adminConfig.gitlab_base_url}
                  </span>
                )}
              </div>
            </div>
          </div>
          <div>
            <div className="cell-muted">GitLab URL (projects &amp; tokens)</div>
            <form className="gitlab-url-form" onSubmit={saveGitlabUrl}>
              <input
                value={gitlabUrl}
                onChange={(e) => setGitlabUrl(e.target.value)}
                placeholder="https://gitlab.example.com"
                required
              />
              <button type="submit" className="btn btn-sm btn-primary" disabled={urlBusy}>
                {urlBusy ? urlBusyLabel : 'Save URL'}
              </button>
            </form>
            {urlMessage && (
              <div className={`form-message form-message-${urlMessage.type}`}>{urlMessage.text}</div>
            )}
          </div>
        </div>
      </section>

      <TrackedProjectsPanel
        trackedProjects={gitlabData?.tracked_projects || []}
        adminConfig={adminConfig}
        onChanged={onRefreshGitlab}
        hideLoadErrors={urlHealthy === false || urlMessage?.type === 'error'}
      />
    </div>
  )
}

function LoginPage({ error, onLoggedIn }) {
  const [pat, setPat] = useState('')
  const [busy, setBusy] = useState(false)
  const [localError, setLocalError] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setLocalError(null)
    try {
      const user = await loginWithGitLabPat(pat.trim())
      onLoggedIn?.(user)
    } catch (err) {
      setLocalError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-panel">
        <img src={appLogo} alt="CTRS logo" className="login-logo" />
        <h1>Confidential Token Renewal Service</h1>
        <p className="login-lead">
          Your GitLab instance does not allow OAuth apps for students. Sign in with a
          <strong> personal access token</strong> instead — CTRS stores it encrypted for your account only.
        </p>
        {(localError || error) ? <div className="alert alert-error">{localError || error}</div> : null}
        <form className="login-form" onSubmit={submit}>
          <label className="form-label" htmlFor="gitlab-pat">GitLab personal access token</label>
          <input
            id="gitlab-pat"
            type="password"
            className="admin-key-input"
            value={pat}
            onChange={(e) => setPat(e.target.value)}
            placeholder="glpat-…"
            autoComplete="off"
            required
          />
          <button type="submit" className="btn btn-primary login-cta" disabled={busy || !pat.trim()}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        <p className="form-hint login-hint">
          Create one at GitLab → avatar → <strong>Edit profile</strong> → <strong>Access tokens</strong>
          (or Personal access tokens). Scope: <code>api</code> (and <code>read_user</code> if listed).
        </p>
      </div>
    </div>
  )
}

export default function App() {
  const [page, setPage] = useState('overview')
  const [user, setUser] = useState(null)
  const [authChecked, setAuthChecked] = useState(false)
  const [health, setHealth] = useState(null)
  const [adminConfig, setAdminConfig] = useState(null)
  const [tokens, setTokens] = useState([])
  const [policies, setPolicies] = useState([])
  const [runners, setRunners] = useState([])
  const [audit, setAudit] = useState([])
  const [selectedTokenId, setSelectedTokenId] = useState(null)
  const [renewals, setRenewals] = useState([])
  const [renewalsLoading, setRenewalsLoading] = useState(false)

  const [gitlabData, setGitlabData] = useState(null)
  const [gitlabLoading, setGitlabLoading] = useState(false)
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!success) return undefined
    const timer = setTimeout(() => setSuccess(null), 1500)
    return () => clearTimeout(timer)
  }, [success])

  const [refreshing, setRefreshing] = useState(false)
  const [monitorRefreshKey, setMonitorRefreshKey] = useState(0)

  const load = async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const [h, cfg, t, p, r, a] = await Promise.all([
        fetchJson('/health'),
        fetchJson('/admin/config'),
        fetchJson('/tokens'),
        fetchJson('/policies'),
        fetchJson('/runners'),
        fetchJson('/audit?limit=50'),
      ])
      setHealth(h)
      setAdminConfig(cfg)
      if (cfg?.user) setUser(cfg.user)
      setTokens(t)
      setPolicies(p)
      setRunners(r)
      setAudit(a)
    } catch (e) {
      if (String(e.message || '').toLowerCase().includes('authentication')) {
        setUser(null)
      }
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const me = await fetchCurrentUser()
        if (cancelled) return
        setUser(me)
        await load()
      } catch {
        if (!cancelled) {
          setUser(null)
          setLoading(false)
        }
      } finally {
        if (!cancelled) setAuthChecked(true)
      }
    })()
    return () => { cancelled = true }
  }, [])

  const loadGitlabTokens = async () => {
    setGitlabLoading(true)
    try {
      const data = await fetchJson('/gitlab/access-tokens')
      setGitlabData(data)
    } catch (e) {
      setGitlabData(null)
      if (page === 'gitlab') setError(e.message)
    } finally {
      setGitlabLoading(false)
    }
  }

  useEffect(() => {
    if (!user) return
    if ((page === 'overview' || page === 'monitor' || page === 'gitlab' || page === 'tokens') && adminConfig?.gitlab_pat_configured) {
      loadGitlabTokens()
    }
  }, [page, adminConfig?.gitlab_pat_configured, user])

  useEffect(() => {
    if (!selectedTokenId) { setRenewals([]); return }
    setRenewalsLoading(true)
    fetchJson(`/tokens/${selectedTokenId}/renewals`)
      .then(setRenewals)
      .catch((e) => setError(e.message))
      .finally(() => setRenewalsLoading(false))
  }, [selectedTokenId, monitorRefreshKey])

  const handleRenew = async (tokenId) => {
    setError(null)
    setSuccess(null)
    try {
      const res = await fetchJson(`/tokens/${tokenId}/renew`, { method: 'POST' })
      setSelectedTokenId(tokenId)
      setSuccess(res.message || `Token ${tokenId} renewal: ${res.status}`)
      await load(true)
      if (page === 'monitor' || page === 'overview') await loadGitlabTokens()
      setRenewals(await fetchJson(`/tokens/${tokenId}/renewals`))
    } catch (e) {
      setError(e.message)
    }
  }

  const handleRevoke = async (tokenId) => {
    setError(null)
    setSuccess(null)
    try {
      const res = await fetchJson(`/tokens/${tokenId}/revoke`, { method: 'POST' })
      setSuccess(res.message || `Token ${tokenId} revoked`)
      setSelectedTokenId(null)
      await load(true)
      await loadGitlabTokens()
    } catch (e) {
      setError(e.message)
    }
  }

  const handleLogout = async () => {
    try {
      await logout()
    } catch {
      /* ignore */
    }
    setUser(null)
    setAdminConfig(null)
    setTokens([])
    setPolicies([])
    setRunners([])
    setAudit([])
    setGitlabData(null)
  }

  if (!authChecked) {
    return (
      <div className="login-page">
        <div className="loading-state"><div className="spinner" /><p>Checking session…</p></div>
      </div>
    )
  }

  if (!user) {
    return (
      <LoginPage
        error={error}
        onLoggedIn={async (me) => {
          setUser(me)
          setAuthChecked(true)
          await load()
        }}
      />
    )
  }

  const meta = PAGE_META[page]
  const inventory = buildInventoryRows(tokens, gitlabData)
  const activeTokenCount = inventory.filter((r) => !r.inactive && r.status === 'active').length
  const attentionTokenCount = inventory.filter((r) => {
    if (r.inactive || r.status !== 'active') return false
    const days = r.expires_in_days
    const soon = days != null && days > 0 && days < 14
    const needsAttention = r.health === 'warning' || r.health === 'attention' || r.health === 'critical'
    return soon || needsAttention
  }).length

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <img src={appLogo} alt="CTRS logo" className="brand-logo" />
          <div className="brand-text">
            <div className="brand-word">Confidential</div>
            <div className="brand-word">Token Renewal</div>
            <div className="brand-word">Service</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <button key={item.id} type="button" className={`nav-item ${page === item.id ? 'active' : ''}`} onClick={() => setPage(item.id)}>
              <span className="nav-icon">{item.icon}</span>
              <span className="nav-label">{item.label}</span>
            </button>
          ))}

          <div className="sidebar-stats" aria-label="Token statistics">
            <div className="sidebar-stat">
              <span className="sidebar-stat-label">Active tokens</span>
              <span className="sidebar-stat-value">{activeTokenCount}</span>
            </div>
            <div className={`sidebar-stat ${attentionTokenCount ? 'sidebar-stat-warn' : ''}`}>
              <span className="sidebar-stat-label">Expiring / attention</span>
              <span className="sidebar-stat-value">{attentionTokenCount}</span>
            </div>
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className={`service-pill ${health?.status === 'ok' ? 'online' : 'offline'}`}>
            <span className="pill-dot" />
            {health ? `Service ${health.status}` : 'Service offline'}
          </div>
          <div className="user-menu">
            <div className="user-menu-meta">
              <div className="user-menu-name">{user.name || user.username}</div>
              <div className="user-menu-email">{user.email || `@${user.username}`}</div>
            </div>
            <button type="button" className="btn btn-sm btn-ghost" onClick={handleLogout}>
              Logout
            </button>
          </div>
        </div>
      </aside>

      <div className={`main ${page === 'overview' ? 'main-compact' : ''}`}>
        {page !== 'overview' && (
          <header className="topbar">
            <div>
              <h1>{meta.title}</h1>
              {meta.subtitle ? <p>{meta.subtitle}</p> : null}
            </div>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => {
                load(true)
                if (page === 'monitor') loadGitlabTokens()
              }}
              disabled={refreshing}
            >
              {refreshing ? 'Refreshing…' : '↻ Refresh'}
            </button>
          </header>
        )}

        {error && (
          <div className="alert alert-error">
            <strong>Error</strong>
            <span>{error}</span>
          </div>
        )}
        {success && (
          <div className="alert alert-success">
            <strong>Success</strong>
            <span>{success}</span>
          </div>
        )}

        <main className="content-panel">
          {loading ? (
            <div className="loading-state"><div className="spinner" /><p>Loading dashboard…</p></div>
          ) : (
            <>
              {page === 'overview' && (
                <OverviewTab
                  adminConfig={adminConfig}
                  gitlabData={gitlabData}
                  onRefreshGitlab={loadGitlabTokens}
                  onRefreshConfig={() => load(true)}
                />
              )}
              {page === 'monitor' && (
                <MonitorTab
                  tokens={tokens}
                  gitlabTokens={gitlabData?.tokens || []}
                  gitlabData={gitlabData}
                  gitlabLoading={gitlabLoading}
                  adminConfig={adminConfig}
                  onRenew={handleRenew}
                  onRevoke={handleRevoke}
                  onRefresh={() => { load(true); setMonitorRefreshKey((k) => k + 1) }}
                  loadGitlabTokens={loadGitlabTokens}
                  selectedTokenId={selectedTokenId}
                  onSelectToken={setSelectedTokenId}
                  renewals={renewals}
                  renewalsLoading={renewalsLoading}
                  policies={policies}
                  runners={runners}
                />
              )}
              {page === 'audit' && <AuditTab events={audit} />}
            </>
          )}
        </main>
      </div>
    </div>
  )
}
