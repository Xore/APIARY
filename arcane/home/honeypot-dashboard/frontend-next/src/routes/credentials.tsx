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
import { ErrorStateBlock } from '../components/ErrorState'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '../components/ui/empty'
import { Field, FieldGroup, FieldLabel } from '../components/ui/field'
import { Input } from '../components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Textarea } from '../components/ui/textarea'
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
  .validator((input: { path: string; username: string; password: string; memo: string; content_template: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF — the Rust tier itself has no admin check; its
    // own doc comments say the BFF-side gate is the only one that exists.
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
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
  .validator((input: { id: string; password: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
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
  .validator((input: { id: string; token_id: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
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
  return Array.from(bytes, (b) => PASSWORD_ALPHABET[b % PASSWORD_ALPHABET.length]).join('')
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
    <Card>
      <CardHeader><CardTitle><h2>Provision a new credential</h2></CardTitle><CardDescription>
        Writes the bait file live into the honeypot's filesystem via honeyfs-implant as soon as you submit — this isn't a
        draft. Cowrie's honeyfs is the only implant target wired up today. Rotating re-implants the same path with a new
        password — the file's location never changes.
      </CardDescription></CardHeader><CardContent>
      <form
        className="space-y-4"
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
      ><FieldGroup className="grid gap-3 sm:grid-cols-2">
        <Field><FieldLabel htmlFor="credential-path">Honeyfs path</FieldLabel><Input
          id="credential-path"
          type="text"
          required
          placeholder="path — e.g. home/mwagner/.aws/credentials"
          value={path}
          onChange={(event) => setPath(event.target.value)}
          aria-label="Honeyfs path"
        /></Field>
        <Field><FieldLabel htmlFor="credential-username">Username</FieldLabel><Input
          id="credential-username"
          type="text"
          required
          placeholder="username"
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          aria-label="Username"
        /></Field>
        <Field><FieldLabel htmlFor="credential-password">Password</FieldLabel><Input
          id="credential-password"
          type="text"
          required
          placeholder="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          aria-label="Password"
        /></Field>
        <Field className="justify-end"><Button variant="outline" size="sm" type="button" onClick={() => setPassword(randomPassword())}>
          Generate
        </Button></Field>
        <Field><FieldLabel htmlFor="credential-memo">Memo</FieldLabel><Input
          id="credential-memo"
          type="text"
          required
          placeholder="memo — why this bait exists"
          value={memo}
          onChange={(event) => setMemo(event.target.value)}
          aria-label="Memo"
        /></Field>
        <Field><FieldLabel htmlFor="credential-template">Content template</FieldLabel><Textarea
          id="credential-template"
          rows={2}
          placeholder="content template (optional) — defaults to a two-line username=/password= file using {{username}}/{{password}} placeholders"
          value={template}
          onChange={(event) => setTemplate(event.target.value)}
          aria-label="Content template"
        /></Field></FieldGroup>
        <Button
          variant="secondary" size="sm"
          type="submit"
          disabled={busy || !path.trim() || !username.trim() || !password.trim() || !memo.trim()}
        >
          {busy ? 'Provisioning…' : 'Provision credential'}
        </Button>
        {message ? <span className="text-sm text-muted-foreground" role="status">{message}</span> : null}
      </form></CardContent>
    </Card>
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
      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="min-w-0 flex-1 basis-48"
          type="text"
          placeholder="new password (blank = auto-generate)"
          value={newPassword}
          onChange={(event) => setNewPassword(event.target.value)}
          disabled={!isAdmin || rotateBusy}
          aria-label="New password"
        />
        <Button variant="secondary" size="sm" type="button" disabled={!isAdmin || rotateBusy} onClick={rotate}>
          {rotateBusy ? 'Rotating…' : 'Rotate password'}
        </Button>
        {rotateMessage ? <span className="text-sm text-muted-foreground" role="status">{rotateMessage}</span> : null}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Select
          aria-label="Link canarytoken"
          value={tokenChoice || 'none'}
          disabled={!isAdmin || linkBusy}
          onValueChange={(value) => setTokenChoice(value === 'none' ? '' : value)}
        >
          <SelectTrigger className="min-w-0 flex-1 basis-48" aria-label="Link canarytoken"><SelectValue placeholder="— no linked token —" /></SelectTrigger>
          <SelectContent>
          <SelectItem value="none">— no linked token —</SelectItem>
          {tokens.map((token) => (
            <SelectItem key={token.id} value={token.id}>
              {token.memo || token.token_type} ({token.token_type})
            </SelectItem>
          ))}
          </SelectContent>
        </Select>
        <Button variant="secondary" size="sm"
          type="button"
          disabled={!isAdmin || linkBusy || tokenChoice === (credential.linked_token_id ?? '')}
          onClick={() => applyLink(tokenChoice)}
        >
          {linkBusy ? 'Saving…' : 'Save link'}
        </Button>
        {credential.linked_token_id ? (
          <Button variant="ghost" size="sm" type="button" disabled={!isAdmin || linkBusy} onClick={() => applyLink('')}>
            Unlink
          </Button>
        ) : null}
        {linkMessage ? <span className="text-sm text-muted-foreground" role="status">{linkMessage}</span> : null}
      </div>
      {!isAdmin ? <p className="text-sm text-muted-foreground">Admin role required to rotate or link credentials.</p> : null}
    </>
  )
}

function linkedBadge(row: CredentialRecord, tokensById: Map<string, TokenRecord>) {
  const id = row.linked_token_id
  if (!id) return '—'
  const token = tokensById.get(id)
  if (!token) {
    return (
      <Badge variant="secondary" title={`linked token ${id} not found — it may have been deleted`}>
        unresolved
      </Badge>
    )
  }
  return <Badge variant="outline">{token.memo || token.token_type}</Badge>
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
      render: (row) => <code className="whitespace-pre-wrap break-all">{row.content_template}</code>,
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
  // #2178: a failed credential-store read used to leave the table's opening
  // ghosts up forever -- the null result was identical to "still loading".
  const [failed, setFailed] = useState(false)

  const refresh = async () => {
    setFailed(false)
    const result = await fetchCredentials()
    if (!result) {
      setFailed(true)
      return
    }
    setData(result)
  }

  useEffect(() => {
    let cancelled = false
    setData(null)
    setFailed(false)
    fetchCredentials().then((result) => {
      if (cancelled) return
      if (!result) {
        setFailed(true)
        return
      }
      setData(result)
    })
    fetchLinkableTokens().then((result) => {
      if (!cancelled) setTokens(result ?? [])
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
        chips={data?.available ? <Badge variant="secondary">{data.credentials.length.toLocaleString('en-US')} credentials</Badge> : undefined}
      />
      <ProvisionForm onCreated={() => setGeneration((current) => current + 1)} />
      {data === null && failed ? (
        <ErrorStateBlock
          title="Credential store failed to load"
          hint="The backend request failed — provisioned bait itself is untouched; this page just can't list it right now."
          onRetry={() => setGeneration((current) => current + 1)}
        />
      ) : data === null ? (
        <MasterDetailTable rows={null} columns={columns} rowKey={(row) => row.id} inspectorTitle="Credential details" />
      ) : !data.available ? (
        <Card><CardHeader><CardTitle><h2>Credential storage unavailable</h2></CardTitle></CardHeader><CardContent><Empty><EmptyHeader><EmptyTitle>Storage unavailable</EmptyTitle><EmptyDescription>{data.error || 'Credential storage is unavailable on this host.'}</EmptyDescription></EmptyHeader></Empty></CardContent></Card>
      ) : data.credentials.length === 0 ? (
        <Card><CardHeader><CardTitle><h2>Credentials</h2></CardTitle></CardHeader><CardContent><Empty><EmptyHeader><EmptyTitle>No credentials provisioned yet</EmptyTitle><EmptyDescription>Use the form above.</EmptyDescription></EmptyHeader></Empty></CardContent></Card>
      ) : (
        <>
        <p className="text-sm text-muted-foreground">
          Newest first. Rotate plants a fresh password at the same path; linking a canarytoken is bookkeeping only —
          opening the file itself doesn&apos;t fire anything on its own unless the linked token IS that file.
        </p>
        <MasterDetailTable
          key={generation}
          rows={data.credentials}
          columns={columns}
          rowKey={(row) => row.id}
          total={data.credentials.length}
          emptyState={{
            title: 'No credentials provisioned yet',
            hint: 'Provision one above to plant it into Cowrie’s live honeyfs.',
          }}
          inspectorTitle="Credential details"
          inspectorExtra={(row) => <CredentialActions credential={row} tokens={tokens} isAdmin={isAdmin} onChanged={refresh} />}
        />
        </>
      )}
    </>
  )
}
