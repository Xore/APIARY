// Canarytokens — deployed decoy tokens (dashboard-canarytokens-v1), plus
// minting new ones against the self-hosted Canarytokens platform and
// downloading their artifacts.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useRef, useState } from 'react'
import { StoreListPage, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import { InvestigateHeader, type Column } from '../components/Investigate'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '../components/ui/empty'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '../components/ui/field'
import { Input } from '../components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Skeleton } from '../components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { pathString, type JsonRecord } from '../lib/json'
import { copyWithFlash } from '../lib/flash'
import { useLiveInterval } from '../lib/live'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'
import { Crosshair, FileText, Folder, Image, QrCode, RefreshCw } from 'lucide-react'

type TokenType = {
  token_type: string
  label: string
  description: string
  requires_upload: boolean
  supports_snippet: boolean
}

const fetchPage = createServerFn({ method: 'GET' })
  .validator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/canarytokens?offset=${data.offset}&size=25`)
  })

/** One fired-token event off /api/v1/events — the slice of EventRow this
 * tab renders (the full record rides along for honeypot.token_type/
 * manage_url, which the flat row doesn't carry). */
type FiredRow = {
  time: string
  src_ip: string
  country: string
  detail: string
  record: JsonRecord
}

type FiredPage = { total: number; rows: FiredRow[] }

const fetchFired = createServerFn({ method: 'GET' }).handler(async (): Promise<FiredPage | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  // since=365d: tokens fire rarely — the events endpoint's 10d default
  // would hide older fires the old page still showed (hp-canarytokens.js
  // loadReports read the whole in-memory event cache).
  return serviceJSON<FiredPage>('/api/v1/events?sensor=canarytokens&size=50&since=365d')
})

const fetchTypes = createServerFn({ method: 'GET' }).handler(async (): Promise<TokenType[] | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<TokenType[]>('/api/v1/canarytokens/types')
})

const createToken = createServerFn({ method: 'POST' })
  .validator(
    (input: {
      token_type: string
      memo: string
      include_text_snippet?: boolean
      text_snippet?: string
      file_base64?: string
      file_name?: string
      file_content_type?: string
    }) => input,
  )
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { serviceFetch } = await import('../lib/backend.server')
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // The lookup used to feed attribution only — an unauthenticated caller
    // could mint tokens with a blank created_by (#2123).
    if (!user) return { ok: false, error: 'Sign in required.' }
    const response = await serviceFetch('/api/v1/canarytokens', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...data, created_by: user?.username ?? '' }),
    })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

function MintForm({ onCreated, presetType, formRef }: { onCreated: () => void; presetType?: string; formRef?: React.RefObject<HTMLDivElement | null> }) {
  const [types, setTypes] = useState<TokenType[]>([])
  // #2178: a failed type-catalog read used to leave an empty dropdown --
  // indistinguishable from a platform serving zero token types.
  const [typesUnavailable, setTypesUnavailable] = useState(false)
  const [tokenType, setTokenType] = useState(presetType || 'adobe_pdf')
  const [memo, setMemo] = useState('')
  const [snippet, setSnippet] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  useEffect(() => {
    let cancelled = false
    setTypesUnavailable(false)
    fetchTypes().then((result) => {
      if (cancelled) return
      if (!result) setTypesUnavailable(true)
      else setTypes(result)
    })
    return () => {
      cancelled = true
    }
  }, [])

  // #1575's template-gallery empty state (below) preselects a type by
  // jumping in here — never on first render (that's the useState above),
  // only on a later pick, so the operator's own dropdown choice isn't
  // fought if they'd already started filling the form out.
  useEffect(() => {
    if (presetType) setTokenType(presetType)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- fire on presetType change only
  }, [presetType])

  const selected = types.find((entry) => entry.token_type === tokenType)

  return (
    <Card ref={formRef}>
      <CardHeader>
      <CardTitle><h2>Mint a new token</h2></CardTitle>
      <CardDescription>
        The artifact is generated by the self-hosted Canarytokens platform over the internal tunnel; fired events land in the
        pipeline like any other sensor.
      </CardDescription>
      </CardHeader>
      <CardContent>
      <form
        className="space-y-4"
        onSubmit={async (event) => {
          event.preventDefault()
          if (busy) return
          setBusy(true)
          setMessage('')
          try {
            let filePayload: { file_base64?: string; file_name?: string; file_content_type?: string } = {}
            if (selected?.requires_upload) {
              if (!file) {
                setMessage('This token type needs an image upload.')
                return
              }
              const buffer = await file.arrayBuffer()
              let binary = ''
              for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte)
              filePayload = { file_base64: btoa(binary), file_name: file.name, file_content_type: file.type }
            }
            const result = await createToken({
              data: {
                token_type: tokenType,
                memo,
                include_text_snippet: Boolean(selected?.supports_snippet && snippet.trim()),
                text_snippet: snippet,
                ...filePayload,
              },
            })
            if (result.ok) {
              setMemo('')
              setSnippet('')
              setFile(null)
              setMessage('Token minted.')
              onCreated()
            } else {
              setMessage(result.error || 'Creation failed.')
            }
          } finally {
            setBusy(false)
          }
        }}
      >
        <FieldGroup className="gap-4 md:grid md:grid-cols-2">
        <Field>
          <FieldLabel htmlFor="canary-token-type">Token type</FieldLabel>
          <Select value={tokenType} onValueChange={setTokenType}>
            <SelectTrigger id="canary-token-type" aria-label="Token type"><SelectValue placeholder="Select a token type" /></SelectTrigger>
            <SelectContent>{types.map((entry) => <SelectItem key={entry.token_type} value={entry.token_type}>{entry.label}</SelectItem>)}</SelectContent>
          </Select>
        </Field>
        <Field>
          <FieldLabel htmlFor="canary-memo">Memo</FieldLabel>
          <Input id="canary-memo" type="text" required placeholder="where will this token live?" value={memo} onChange={(event) => setMemo(event.target.value)} />
        </Field>
        {selected?.supports_snippet ? (
          <Field><FieldLabel htmlFor="canary-snippet">Text snippet</FieldLabel><Input id="canary-snippet" type="text" placeholder="visible text snippet (optional)" value={snippet} onChange={(event) => setSnippet(event.target.value)} /></Field>
        ) : null}
        {selected?.requires_upload ? (
          <Field><FieldLabel htmlFor="canary-image">Image upload</FieldLabel><Input id="canary-image" type="file" accept="image/*" onChange={(event) => setFile(event.target.files?.[0] ?? null)} /></Field>
        ) : null}
        </FieldGroup>
        {typesUnavailable ? (
          <FieldDescription role="alert">The token-type catalog failed to load — minting needs one of its entries. Reload to retry.</FieldDescription>
        ) : null}
        <Button variant="secondary" size="sm" type="submit" disabled={busy || !memo.trim()}>
          {busy ? 'Minting…' : 'Mint token'}
        </Button>
        {message ? <p className="text-sm text-muted-foreground" role="status">{message}</p> : null}
      </form>
      {selected ? <p className="mt-4 text-sm text-muted-foreground">{selected.description}</p> : null}
      </CardContent>
    </Card>
  )
}

const COLUMNS: Column<StoreRow>[] = [
  { header: 'created', render: (row) => when(str(row, 'created_at')) },
  { header: 'type', render: (row) => <Badge variant="secondary">{str(row, 'token_type')}</Badge> },
  { header: 'memo', className: 'v', primary: true, render: (row) => str(row, 'memo') || <span className="text-muted-foreground">(no memo)</span> },
  {
    header: 'token url',
    className: 'v',
    // #1859: a token URL has no spaces and no break opportunities, so it ran
    // straight past the card edge. `overflow-wrap: anywhere` lets it break
    // mid-string, which is what a URL needs -- it stops deciding the card's
    // width instead of being allowed to.
    //
    // A token URL exists to be pasted somewhere, so it also gets a copy
    // control rather than leaving the operator to select wrapped text
    // accurately.
    render: (row) => {
      const url = str(row, 'token_url')
      if (!url) return '—'
      return (
        <span className="flex min-w-0 items-center gap-2">
          <code className="min-w-0 break-all">{url}</code>
          <Button
            type="button"
            variant="ghost" size="sm"
            title="copy the token URL"
            onClick={(event) => {
              event.stopPropagation()
              copyWithFlash(url, 'token URL')
            }}
          >
            copy
          </Button>
        </span>
      )
    },
  },
  { header: 'hostname', detail: true, render: (row) => str(row, 'hostname') },
  { header: 'created by', detail: true, render: (row) => str(row, 'created_by') },
  { header: 'id', detail: true, render: (row) => str(row, 'id') },
  {
    header: 'artifact',
    render: (row) =>
      str(row, 'token_type') === 'web_image' ? (
        ''
      ) : (
        <a
          className="text-primary hover:underline"
          href={`/api/canarytoken/${encodeURIComponent(str(row, 'id'))}/download`}
          onClick={(event) => event.stopPropagation()}
        >
          download →
        </a>
      ),
  },
]

// Fired-tokens tab (canarytokens.html:114-133 / hp-canarytokens.js
// renderFiredRow+loadReports): every time a planted token was opened,
// scanned or triggered — newest first, with the platform's manage link.
function FiredTokens() {
  const [page, setPage] = useState<FiredPage | null>(null)
  const [error, setError] = useState('')
  const load = useCallback(async () => {
    try {
      const result = await fetchFired()
      if (result) {
        setPage(result)
        setError('')
      } else {
        setError('Fired-token history unavailable.')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Fired-token history unavailable.')
    }
  }, [])
  // #1973: the shared tick replaces the hand-rolled guarded interval —
  // same visible-tab + LIVE-paused guards, resume refetch included.
  // Leading, because unlike the routes above this tab owns its own
  // initial fetch; there is no loader to cover first paint.
  useLiveInterval(load, 60_000, { leading: true })
  const rows = page?.rows ?? null
  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-4 space-y-0">
        <div><CardTitle><h2>Fired tokens</h2></CardTitle><CardDescription>Every time a planted token was opened, scanned, or triggered — newest first.</CardDescription></div>
        <Button variant="ghost" size="sm" type="button" onClick={() => void load()}><RefreshCw />Refresh</Button>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader><TableRow>
              <TableHead>Time</TableHead><TableHead>Source IP</TableHead><TableHead>Country</TableHead><TableHead>Token type</TableHead><TableHead>Detail</TableHead><TableHead>Manage</TableHead>
          </TableRow></TableHeader>
          <TableBody>
            {/* #2178: with the in-band error showing, the placeholder row
                reads as an endless load -- drop it so the failure stands
                alone instead of under an eternally-loading table. */}
            {rows === null && !error ? (
              <TableRow><TableCell colSpan={6}><Skeleton className="h-4 w-full" aria-hidden="true" /></TableCell></TableRow>
            ) : rows === null ? null : (
              rows.map((row, index) => {
                const manageURL = pathString(row.record, 'honeypot', 'manage_url')
                const tokenType =
                  pathString(row.record, 'honeypot', 'token_type') || pathString(row.record, 'honeypot', 'channel')
                return (
                  <TableRow key={`${row.time}-${index}`}>
                    <TableCell>{formatTimestamp(row.time)}</TableCell>
                    <TableCell className="font-mono">
                      {row.src_ip ? (
                        <Link to="/investigate/ip/$ip" params={{ ip: row.src_ip }}>{row.src_ip}</Link>
                      ) : (
                        '—'
                      )}
                    </TableCell>
                    <TableCell>{row.country ? <Badge variant="outline" title={countryName(row.country)}>{row.country}</Badge> : '—'}</TableCell>
                    <TableCell>{tokenType || '—'}</TableCell>
                    <TableCell>{row.detail || pathString(row.record, 'honeypot', 'memo') || '—'}</TableCell>
                    <TableCell>
                      {manageURL ? (
                        <Button asChild variant="ghost" size="sm"><a href={manageURL} target="_blank" rel="noopener noreferrer">Manage token</a></Button>
                      ) : (
                        '—'
                      )}
                    </TableCell>
                  </TableRow>
                )
              })
            )}
          </TableBody>
        </Table>
      {rows !== null && rows.length === 0 ? (
        <Empty role="status" className="border"><EmptyHeader><EmptyTitle>No token has fired yet.</EmptyTitle></EmptyHeader></Empty>
      ) : null}
      {error ? (
        <p className="mt-4 text-sm text-destructive" role="alert">
          {error}
        </p>
      ) : null}
      </CardContent>
    </Card>
  )
}

// #1575's empty-state gallery (canarytokens.html:53-77): jump straight
// into Create with a common type preselected, instead of making a
// first-time operator pick blind from the full type dropdown.
const TEMPLATES: { type: string; title: string; desc: string; chip: string; icon: React.ComponentType<{ className?: string }> }[] = [
  {
    type: 'ms_word',
    title: 'Fake .docx',
    desc: "A real Word doc that phones home the moment it's opened.",
    chip: 'Document',
    icon: FileText,
  },
  {
    type: 'qr_code',
    title: 'QR code',
    desc: 'A PNG QR code that fires when scanned and opened.',
    chip: 'Image',
    icon: QrCode,
  },
  {
    type: 'windows_dir',
    title: 'Windows folder',
    desc: 'Fires the moment the folder opens in Explorer.',
    chip: 'Folder',
    icon: Folder,
  },
  {
    type: 'web_image',
    title: 'Web bug image',
    desc: 'An embeddable image that fires when it loads anywhere.',
    chip: 'Embed',
    icon: Image,
  },
]

function TokenGallery({ onPick }: { onPick: (type: string) => void }) {
  return (
    <Card>
      <CardContent className="pt-6">
      <Empty role="status" aria-live="polite">
          <EmptyHeader>
          <EmptyMedia variant="icon"><Crosshair /></EmptyMedia>
          <EmptyTitle>No canarytokens yet</EmptyTitle>
          <EmptyDescription>
            Plant tokens outside the honeypot and track everything that fires — nothing here re-fires a token.
          </EmptyDescription>
          </EmptyHeader>
          <div className="grid w-full grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4" role="group" aria-label="Common token types">
            {TEMPLATES.map((template) => {
              const Icon = template.icon
              return <Card key={template.type} className="relative min-w-0 overflow-hidden shadow-sm">
                <div className="pointer-events-none relative z-20 flex h-full w-full flex-col items-start gap-3 p-4 text-left">
                  <Icon className="size-6 text-muted-foreground" aria-hidden="true" />
                  <h2 className="font-semibold">{template.title}</h2>
                  <p className="flex-1 text-sm text-muted-foreground">{template.desc}</p>
                  <Badge variant="secondary">{template.chip}</Badge>
                </div>
                <Button type="button" variant="ghost" className="absolute inset-0 z-10 h-full w-full rounded-[inherit]" onClick={() => onPick(template.type)}>
                  <span className="sr-only">{template.title}</span>
                </Button>
              </Card>
            })}
          </div>
      </Empty>
      </CardContent>
    </Card>
  )
}

export const Route = createFileRoute('/canarytokens')({ component: Page })

function Page() {
  // Remount the list after a mint so the new token appears immediately.
  const [generation, setGeneration] = useState(0)
  const [tab, setTab] = useState('tokens')
  const [presetType, setPresetType] = useState<string | undefined>(undefined)
  const formRef = useRef<HTMLDivElement>(null)
  const pickTemplate = useCallback((type: string) => {
    setPresetType(type)
    formRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [])
  return (
    <>
      <Tabs value={tab} onValueChange={setTab} className="col-span-full min-w-0 space-y-4">
      <TabsList aria-label="Canarytokens sections">
        <TabsTrigger value="tokens">Tokens</TabsTrigger>
        <TabsTrigger value="fired">Fired tokens</TabsTrigger>
      </TabsList>
      <TabsContent value="tokens" className="space-y-4">
        <MintForm onCreated={() => setGeneration((current) => current + 1)} presetType={presetType} formRef={formRef} />
        <StoreListPage
          key={generation}
          fetchPage={fetchPage}
          pageSize={25}
          label="Tools"
          title="Canarytokens"
          subtitle="Deployed decoy tokens — documents, URLs and hostnames that phone home the moment an attacker touches them."
          columns={COLUMNS}
          rowKey={(row, index) => `${str(row, 'id')}-${index}`}
          emptyReplacement={<TokenGallery onPick={pickTemplate} />}
          inspectorTitle="Token details"
          chipNoun="tokens"
          layout="cards"
        />
      </TabsContent>
      <TabsContent value="fired" className="space-y-4">
        <InvestigateHeader
          label="Tools"
          title="Canarytokens"
          subtitle="What's fired — every planted token that phoned home, wherever it was opened."
        />
        <FiredTokens />
      </TabsContent>
      </Tabs>
    </>
  )
}
