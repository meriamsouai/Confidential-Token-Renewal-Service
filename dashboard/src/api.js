const API = '/api/v1'

async function parseError(res) {
  try {
    const body = await res.json()
    if (typeof body.detail === 'string') return body.detail
    if (Array.isArray(body.detail)) {
      return body.detail.map((d) => d.msg || JSON.stringify(d)).join('; ')
    }
    return body.message || JSON.stringify(body)
  } catch {
    return `${res.status} ${res.statusText}`
  }
}

export async function fetchJson(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  const res = await fetch(`${API}${path}`, {
    ...options,
    headers,
    credentials: 'include',
  })
  if (!res.ok) throw new Error(await parseError(res))

  if (res.status === 204 || res.headers.get('content-length') === '0') return null
  const text = await res.text()
  return text ? JSON.parse(text) : null
}

export async function postJson(path, body) {
  return fetchJson(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  })
}

export async function patchJson(path, body) {
  return fetchJson(path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export async function deleteRequest(path) {
  return fetchJson(path, { method: 'DELETE' })
}

export async function fetchCurrentUser() {
  return fetchJson('/auth/me')
}

export async function logout() {
  return postJson('/auth/logout', {})
}

export async function loginWithGitLabPat(token) {
  return postJson('/auth/gitlab/pat', { token })
}

export function gitlabLoginUrl() {
  return `${API}/auth/gitlab/login`
}
