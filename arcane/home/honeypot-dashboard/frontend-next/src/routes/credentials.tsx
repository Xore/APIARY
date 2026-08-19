// Credentials — the dashboard-owned record of bait usernames/passwords
// planted live into a honeypot's filesystem via honeyfs-implant
// (backend-service/src/credentials.rs, ported from
// dashboard/credentials_manager.go + credentials_api.go, #1487 items 3/5).
// Provision writes the file immediately (not a draft); rotate re-implants
// at the same path with a new password; link-token is bookkeeping-only —
// an optional soft reference to a canarytokens.tsx-tracked token id,
// cross-referenced here by id/label rather than reinvented.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useMemo, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { when } from '../components/StoreList'
import { getSessionUser } from '../lib/auth'

type CredentialRecord = {
  id: string
  target: string
  path: string
  username: string
  password: string
  content_template: string
  memo: string
  linked_token_id?: string
  created_by: string
  created_at: string
  rotated_by?: string
  rotated_at?: string
}

type CredentialsResponse = { available: boolean; error?: string; credentials: CredentialRecord[] }

// Subset of canarytokens.rs's list() record shape (auth_token already
// stripped server-side) — just enough to label and cross-reference a link.
type TokenRecord = { id: string; token_type: string; memo: string }

const fetchCredentials = createServerFn({ method: 'GET' }).handler(async (): Promise<CredentialsResponse | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<CredentialsResponse>('/api/v1/credentials')
})

// GET /api/v1/canarytokens — the same full-history endpoint the Rust tier's
// own doc comment says exists for "credentials' link-token id validation";
// reused here to populate the link dropdown and label linked tokens.
const fetchLinkableTokens = createServerFn({ method: 'GET' }).handler(async (): Promise<TokenRecord[]> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const result = await serviceJSON<{ tokens: TokenRecord[] }>('/api/v1/canarytokens')
  return result?.tokens ?? []
})

const createCredential = createServerFn({ method: 'POST' })
  .inputValidator((input: { path: string; username: string; password: string; memo: string; content_template: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF — the Rust tier itself has no admin check; its
    // own doc comments say the BFF-side gate is the only one that exists.
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/credentials', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...data, actor_subject: user?.sub ?? '', actor_username: user?.username ?? '' }),
    })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

const rotateCredential = createServerFn({ method: 'POST' })
  .inputValidator((input: { id: string; password: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/credentials/${encodeURIComponent(data.id)}/rotate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: data.password, actor_subject: user?.sub ?? '', actor_username: user?.username ?? '' }),
    })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

const linkCredentialToken = createServerFn({ method: 'POST' })
  .inputValidator((input: { id: string; token_id: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/credentials/${encodeURIComponent(data.id)}/link-token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token_id: data.token_id, actor_subject: user?.sub ?? '', actor_username: user?.username ?? '' }),
    })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

// Mirrors credentials.rs's PASSWORD_ALPHABET (visually-unambiguous
// look-alikes excluded) — client-side convenience only. crypto.getRandomValues
// costs nothing extra over Math.random() here, so there's no reason to use
// the weaker generator even for a bait value.
const PASSWORD_ALPHABET = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%*'
function randomPassword(): string {
  const bytes = new Uint32Array(20)
  crypto.getRandomValues(bytes)
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += PASSWORD_ALPHABET[bytes[i] % PASSWORD_ALPHABET.length]
  return out
}

function ProvisionForm({ onCreated }: { onCreated: () => void }) {
  const [path, setPath] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [memo, setMemo] = useState('')
  const [template, setTemplate] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  return (
    <div className="card wide">
      <h2>Provision a new credential</h2>
      <p className="note">
        Writes the bait file live into the honeypot's filesystem via honeyfs-implant as soon as you submit — this isn't a
        draft. Cowrie's honeyfs is the only implant target wired up today.
      </p>
      <form
        className="filters"
        onSubmit={async (event) => {
          event.preventDefault()
          if (busy) return
          setBusy(true)
          setMessage('')
          try {
            const result = await createCredential({ data: { path, username, password, memo, content_template: template } })
            if (result.ok) {
              setPath('')
              setUsername('')
              setPassword('')
              setMemo('')
              setTemplate('')
              setMessage('Credential provisioned.')
              onCreated()
            } else {
              setMessage(result.error || 'Provisioning failed.')
            }
          } finally {
            setBusy(false)
          }
        }}
      >
        <input
          className="input"
          type="text"
          required
          placeholder="path — e.g. home/mwagner/.aws/credentials"
          value={path}
          onChange={(event) => setPath(event.target.value)}
          aria-label="Honeyfs path"
        />
        <input
          className="input"
          type="text"
          required
          placeholder="username"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          aria-label="Username"
        />
        <input
          className="input"
          type="text"
          required
          placeholder="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          aria-label="Password"
        />
        <button className="btn btn-ghost btn-sm" type="button" onClick={() => setPassword(randomPassword())}>
          Generate
        </button>
        <input
          className="input"
          type="text"
          required
          placeholder="memo — why this bait exists"
          value={memo}
          onChange={(event) => setMemo(event.target.value)}
          aria-label="Memo"
        />
        <textarea
          className="input"
          rows={2}
          placeholder="content template (optional) — defaults to a two-line username=/password= file using {{username}}/{{password}} placeholders"
          value={template}
          onChange={(event) => setTemplate(event.target.value)}
          aria-label="Content template"
        />
        <button
          className="btn btn-secondary btn-sm"
          type="submit"
          disabled={busy || !path.trim() || !username.trim() || !password.trim() || !memo.trim()}
        >
          {busy ? 'Provisioning…' : 'Provision credential'}
        </button>
        {message ? <span className="note">{message}</span> : null}
      </form>
    </div>
  )
}

function CredentialActions({
  credential,
  tokens,
  isAdmin,
  onChanged,
}: {
  credential: CredentialRecord
  tokens: TokenRecord[]
  isAdmin: boolean
  onChanged: () => void
}) {
  const [newPassword, setNewPassword] = useState('')
  const [rotateBusy, setRotateBusy] = useState(false)
  const [rotateMessage, setRotateMessage] = useState('')
  const [tokenChoice, setTokenChoice] = useState(credential.linked_token_id ?? '')
  const [linkBusy, setLinkBusy] = useState(false)
  const [linkMessage, setLinkMessage] = useState('')

  useEffect(() => {
    setTokenChoice(credential.linked_token_id ?? '')
    setNewPassword('')
    setRotateMessage('')
    setLinkMessage('')
  }, [credential.id])

  const rotate = async () => {
    setRotateBusy(true)
    setRotateMessage('')
    try {
      const result = await rotateCredential({ data: { id: credential.id, password: newPassword.trim() } })
      setRotateMessage(result.ok ? 'Rotated.' : result.error || 'Rotation failed.')
      if (result.ok) {
        setNewPassword('')
        onChanged()
      }
    } finally {
      setRotateBusy(false)
    }
  }

  const applyLink = async (tokenId: string) => {
    setLinkBusy(true)
    setLinkMessage('')
    try {
      const result = await linkCredentialToken({ data: { id: credential.id, token_id: tokenId } })
      setLinkMessage(result.ok ? (tokenId ? 'Linked.' : 'Unlinked.') : result.error || 'Link failed.')
      if (result.ok) onChanged()
    } finally {
      setLinkBusy(false)
    }
  }

  return (
    <>
      <div className="filters">
        <input
          className="input"
          type="text"
          placeholder="new password (blank = auto-generate)"
          value={newPassword}
          onChange={(event) => setNewPassword(event.target.value)}
          disabled={!isAdmin || rotateBusy}
          aria-label="New password"
        />
        <button className="btn btn-secondary btn-sm" type="button" disabled={!isAdmin || rotateBusy} onClick={rotate}>
          {rotateBusy ? 'Rotating…' : 'Rotate password'}
        </button>
        {rotateMessage ? <span className="note">{rotateMessage}</span> : null}
      </div>
      <div className="filters">
        <select
          className="input"
          aria-label="Link canarytoken"
          value={tokenChoice}
          disabled={!isAdmin || linkBusy}
          onChange={(event) => setTokenChoice(event.target.value)}
        >
          <option value="">— no linked token —</option>
          {tokens.map((token) => (
            <option key={token.id} value={token.id}>
              {token.memo || token.token_type} ({token.token_type})
            </option>
          ))}
        </select>
        <button
          className="btn btn-secondary btn-sm"
          type="button"
          disabled={!isAdmin || linkBusy || tokenChoice === (credential.linked_token_id ?? '')}
          onClick={() => applyLink(tokenChoice)}
        >
          {linkBusy ? 'Saving…' : 'Save link'}
        </button>
        {credential.linked_token_id ? (
          <button className="btn btn-ghost btn-sm" type="button" disabled={!isAdmin || linkBusy} onClick={() => applyLink('')}>
            Unlink
          </button>
        ) : null}
        {linkMessage ? <span className="note">{linkMessage}</span> : null}
      </div>
      {!isAdmin ? <p className="note">Admin role required to rotate or link credentials.</p> : null}
    </>
  )
}

function linkedBadge(row: CredentialRecord, tokensById: Map<string, TokenRecord>) {
  const id = row.linked_token_id
  if (!id) return '—'
  const token = tokensById.get(id)
  if (!token) {
    return (
      <span className="badge badge--muted" title={`linked token ${id} not found — it may have been deleted`}>
        unresolved
      </span>
    )
  }
  return <span className="badge badge--accent">{token.memo || token.token_type}</span>
}

function buildColumns(tokensById: Map<string, TokenRecord>): Column<CredentialRecord>[] {
  return [
    { header: 'created', render: (row) => when(row.created_at) },
    { header: 'path', className: 'v', render: (row) => <code>{row.path}</code> },
    { header: 'username', render: (row) => row.username },
    { header: 'memo', className: 'v', render: (row) => row.memo },
    { header: 'linked token', render: (row) => linkedBadge(row, tokensById) },
    { header: 'target', detail: true, render: (row) => row.target },
    { header: 'password', detail: true, render: (row) => <code>{row.password}</code> },
    {
      header: 'content template',
      detail: true,
      render: (row) => <code style={{ whiteSpace: 'pre-wrap' }}>{row.content_template}</code>,
    },
    { header: 'linked token id', detail: true, render: (row) => row.linked_token_id ?? '' },
    { header: 'created by', detail: true, render: (row) => row.created_by },
    { header: 'rotated by', detail: true, render: (row) => row.rotated_by ?? '' },
    { header: 'rotated at', detail: true, render: (row) => (row.rotated_at ? when(row.rotated_at) : '') },
    { header: 'id', detail: true, render: (row) => row.id },
  ]
}

export const Route = createFileRoute('/credentials')({
  loader: async () => ({ user: await getSessionUser() }),
  component: Page,
})

function Page() {
  const { user } = Route.useLoaderData()
  const isAdmin = !user || user.role === 'admin'
  const [generation, setGeneration] = useState(0)
  const [data, setData] = useState<CredentialsResponse | null>(null)
  const [tokens, setTokens] = useState<TokenRecord[]>([])

  const refresh = async () => {
    const result = await fetchCredentials()
    setData(result)
  }

  useEffect(() => {
    let cancelled = false
    fetchCredentials().then((result) => {
      if (!cancelled) setData(result)
    })
    fetchLinkableTokens().then((result) => {
      if (!cancelled) setTokens(result)
    })
    return () => {
      cancelled = true
    }
  }, [generation])

  const tokensById = useMemo(() => new Map(tokens.map((token) => [token.id, token])), [tokens])
  const columns = useMemo(() => buildColumns(tokensById), [tokensById])

  return (
    <>
      <InvestigateHeader
        label="Tools"
        title="Credentials"
        subtitle="Bait usernames and passwords planted live into honeypot filesystems via honeyfs-implant — provision, rotate, and optionally link to a canarytoken for the moment an attacker actually uses one."
        chips={data?.available ? <span className="chip">{data.credentials.length.toLocaleString('en-US')} credentials</span> : undefined}
      />
      <ProvisionForm onCreated={() => setGeneration((current) => current + 1)} />
      {data === null ? (
        <MasterDetailTable rows={null} columns={columns} rowKey={(row) => row.id} inspectorTitle="Credential details" />
      ) : !data.available ? (
        <div className="card wide">
          <p className="empty">{data.error || 'Credential storage is unavailable on this host.'}</p>
        </div>
      ) : data.credentials.length === 0 ? (
        <div className="card wide">
          <p className="empty">No credentials provisioned yet — use the form above.</p>
        </div>
      ) : (
        <MasterDetailTable
          key={generation}
          rows={data.credentials}
          columns={columns}
          rowKey={(row) => row.id}
          total={data.credentials.length}
          inspectorTitle="Credential details"
          inspectorExtra={(row) => <CredentialActions credential={row} tokens={tokens} isAdmin={isAdmin} onChanged={refresh} />}
        />
      )}
    </>
  )
}
