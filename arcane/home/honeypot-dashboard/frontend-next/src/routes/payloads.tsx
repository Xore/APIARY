// Captured payloads — dashboard-payload-inventory-v1 as the Go page's
// project-card grid (payloads.html's "payloadrow" template, #1653):
// per-source filter chips, GitHub-verdict + family badges, byte preview,
// and the per-card "…" action menu, with View-more + skeleton-first.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { confirmAction } from '../components/ConfirmDialog'
import { InvestigateHeader } from '../components/Investigate'
import { formatTimestamp } from '../lib/time'

type PayloadRow = {
  Hash: string
  Size: number
  SizeH: string
  MtimeUTC: string
  MIME: string
  Kind: string
  Platform: string
  AnalysisPath: string
  Dynamic: boolean
  Sources: string[]
  Copies: number
  Preview: string
  PreviewTruncated: boolean
}

type Page = { total: number; rows: PayloadRow[] }

// Lucene-quoted Sources term for /api/v1/payloads' store `q` passthrough —
// the ported equivalent of payloads_data.go's per-source filter.
function sourceQuery(source: string): string {
  return `Sources:"${source.replace(/["\\]/g, '')}"`
}

const fetchPayloads = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number; source?: string }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    const filter = data.source ? `&q=${encodeURIComponent(sourceQuery(data.source))}` : ''
    return serviceJSON<Page>(`/api/v1/payloads?offset=${data.offset}&size=12${filter}`)
  })

// Per-source totals for the filter chips (payloads.html:93-96). The Go
// tier counted these during its inventory scan; here each named source
// costs one size=1 count query against the same index.
const fetchSourceCounts = createServerFn({ method: 'GET' })
  .inputValidator((input: { sources: string[] }) => input)
  .handler(async ({ data }): Promise<Record<string, number>> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const counts = await Promise.all(
      data.sources.map(async (source) => {
        const page = await serviceJSON<Page>(`/api/v1/payloads?offset=0&size=1&q=${encodeURIComponent(sourceQuery(source))}`)
        return [source, page?.total ?? 0] as const
      }),
    )
    return Object.fromEntries(counts)
  })

// GitHub-analysis verdict + family badges (payloads.html:13-15), the
// ported attachGitHubAnalysisVerdicts (payloads_data.go): one whole-store
// fetch, matched to cards by sha256 — only sha256-named captures
// (cowrie/scripts) can carry a badge, same as the Go map keyed by SHA256.
type GithubBadge = { sha256: string; label: string; family: string }

const fetchGithubVerdicts = createServerFn({ method: 'GET' }).handler(async (): Promise<GithubBadge[]> => {
  const { serviceJSON } = await import('../lib/backend.server')
  type StorePage = { total: number; rows: Record<string, unknown>[] }
  const page = await serviceJSON<StorePage>('/api/v1/store/github-analysis?offset=0&size=100')
  const badges: GithubBadge[] = []
  for (const row of page?.rows ?? []) {
    const result = (row.github_analysis ?? row) as Record<string, unknown>
    const sha256 = typeof result.sha256 === 'string' ? result.sha256.toLowerCase() : ''
    if (!sha256) continue
    const verdict = result.verdict as Record<string, unknown> | undefined
    const label =
      verdict && typeof verdict.total === 'number'
        ? `${typeof verdict.malicious === 'number' ? verdict.malicious : 0}/${verdict.total} ${typeof verdict.level === 'string' ? verdict.level : ''}`.trim()
        : typeof result.exit_status === 'string'
          ? result.exit_status
          : ''
    if (!label) continue
    badges.push({ sha256, label, family: typeof result.family === 'string' ? result.family : '' })
  }
  return badges
})

// The action menu's Publish item — same admin gate, `confirm: "publish"`
// sentinel and audit fields as payload-analysis.$hash.tsx's
// submitGithubAnalysis (kept as this route's own server fn rather than a
// cross-route import, so the two route bundles stay independent). Only
// ever called from behind confirmAction's publication dialog.
const submitGithubAnalysis = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(
      '/api/v1/github-analysis/submit',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          hash: data.hash,
          confirm: 'publish',
          actor_subject: user?.sub ?? '',
          actor_username: user?.username ?? '',
        }),
      },
      { mounted: true },
    )
    const body = await response.json().catch(() => null)
    if (response.ok && body?.queued) return { ok: true }
    return { ok: false, error: body?.error || 'GitHub-analysis submission failed.' }
  })

export const Route = createFileRoute('/payloads')({
  loader: async () => ({ first: fetchPayloads({ data: { offset: 0 } }) }),
  component: Payloads,
})

const CANONICAL_SOURCES = ['dionaea', 'cowrie', 'scripts']

// Family display bounded like Go's boundedFamily; the pivot link carries
// the full value (truncating first would let two long names collide).
function boundedFamily(family: string): string {
  return family.length > 24 ? `${family.slice(0, 24)}…` : family
}

function SkeletonCards({ count }: { count: number }) {
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <div key={`skel-${i}`} className="project-card" aria-hidden="true">
          <div className="skeleton-line" style={{ width: '60%' }} />
          <div className="skeleton-line" style={{ width: '85%' }} />
          <div className="skeleton-line" style={{ width: '40%' }} />
        </div>
      ))}
    </>
  )
}

// One payload card — payloads.html's "payloadrow": .project-card stays a
// plain, non-linking container (a payload has several distinct actions
// and HTML forbids interactive controls inside an <a>); the hash is the
// one direct link, every other action lives in the "…" menu.
function PayloadCard({ row, badge }: { row: PayloadRow; badge: GithubBadge | undefined }) {
  const publish = () =>
    confirmAction({
      title: 'Publish to Xore/honeypot?',
      description: 'This uploads the sample to the public Xore/honeypot repository and to third-party scanner APIs.',
      warning: 'This cannot be undone.',
      confirmLabel: 'Publish sample',
      onConfirm: async () => {
        const result = await submitGithubAnalysis({ data: { hash: row.Hash } })
        if (!result.ok) throw new Error(result.error || 'GitHub-analysis submission failed.')
        return 'Queued — see GitHub analysis once it completes.'
      },
    })
  return (
    <div className="project-card">
      <div className="project-card__header">
        <span className="project-card__icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
            <polyline points="14 2 14 8 20 8" />
          </svg>
        </span>
        <a className="project-card__title mono" href={`/payload-analysis/${encodeURIComponent(row.Hash)}`}>
          {row.Hash}
        </a>
        <div className="project-card__badges">
          {row.Sources.map((source) => (
            <span key={source} className="badge badge--muted">
              {source}
            </span>
          ))}
          {badge ? (
            <a className="badge badge--muted" href={`/github-analysis/${encodeURIComponent(row.Hash)}`} title="GitHub analysis verdict">
              {badge.label}
            </a>
          ) : null}
          {badge?.family ? (
            <a
              className="badge badge--muted"
              href={`/events?q=${encodeURIComponent(badge.family)}`}
              title="Scanner-attributed family (GitHub analysis) — other sessions delivering this family"
            >
              {boundedFamily(badge.family)}
            </a>
          ) : null}
        </div>
      </div>
      <p className="project-card__desc">
        <strong>{row.Kind}</strong> • {row.Platform} • {row.MIME} • {row.SizeH}
        {row.Copies > 1 ? ` • ${row.Copies} copies` : ''} •{' '}
        <span title={row.AnalysisPath}>{row.Dynamic ? 'dynamic route ready' : 'static-only route'}</span>
      </p>
      <section className="tw:mt-2" aria-label="Byte preview">
        <p className="note">
          {row.Preview
            ? `First ${row.PreviewTruncated ? `512 of ${row.SizeH}` : row.SizeH} bytes, hex/ASCII. Read only; never interpreted or executed.`
            : 'No byte preview is available for this capture.'}
        </p>
        {row.Preview ? <pre className="code hp-code-results">{row.Preview}</pre> : null}
      </section>
      <div className="project-card__meta">
        <span>{formatTimestamp(row.MtimeUTC)}</span>
        <details className="action-menu">
          <summary aria-label="Payload actions" title="Payload actions">⋮</summary>
          <div className="action-menu__popover" role="menu">
            <a className="action-menu__item" role="menuitem" href={`/payload-analysis/${encodeURIComponent(row.Hash)}`}>
              Static analysis →
            </a>
            <a
              className="action-menu__item"
              role="menuitem"
              href={`/payload-workbench/results?hash=${encodeURIComponent(row.Hash)}#workbench-builder`}
            >
              Analysis workbench →
            </a>
            <a className="action-menu__item" role="menuitem" href={`/api/payload/${encodeURIComponent(row.Hash)}/download`}>
              Download sample ↓
            </a>
            <a className="action-menu__item" role="menuitem" href={`/events?shasum=${encodeURIComponent(row.Hash)}`}>
              Related events →
            </a>
            <a
              className="action-menu__item"
              role="menuitem"
              href={`https://www.virustotal.com/gui/file/${encodeURIComponent(row.Hash)}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              VirusTotal ↗
            </a>
            <button className="action-menu__item action-menu__item--danger" role="menuitem" type="button" onClick={publish}>
              Publish to Xore/honeypot
            </button>
          </div>
        </details>
      </div>
    </div>
  )
}

function Payloads() {
  const { first } = Route.useLoaderData()
  const [rows, setRows] = useState<PayloadRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [uniqueTotal, setUniqueTotal] = useState(0)
  const [source, setSource] = useState('')
  const [counts, setCounts] = useState<Record<string, number> | null>(null)
  const [badges, setBadges] = useState<GithubBadge[]>([])
  const [loadingMore, setLoadingMore] = useState(false)

  useEffect(() => {
    let cancelled = false
    first.then((page) => {
      if (cancelled || !page) return
      setRows(page.rows)
      setTotal(page.total)
      setUniqueTotal(page.total)
      const discovered = [...new Set([...CANONICAL_SOURCES, ...page.rows.flatMap((row) => row.Sources)])]
      fetchSourceCounts({ data: { sources: discovered } }).then((result) => {
        if (!cancelled && result) setCounts(result)
      })
    })
    fetchGithubVerdicts().then((result) => {
      if (!cancelled && result) setBadges(result)
    })
    return () => {
      cancelled = true
    }
  }, [first])

  const applySource = useCallback(async (name: string) => {
    setSource(name)
    setRows(null)
    const page = await fetchPayloads({ data: { offset: 0, source: name || undefined } })
    if (page) {
      setRows(page.rows)
      setTotal(page.total)
    }
  }, [])

  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await fetchPayloads({ data: { offset: rows.length, source: source || undefined } })
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore, source])

  const badgeFor = (hash: string) => badges.find((badge) => badge.sha256 === hash.toLowerCase())
  const sourceNames = counts ? Object.keys(counts).filter((name) => counts[name] > 0) : []

  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title="Captured payloads"
        subtitle="Unified inventory of Dionaea captures, Cowrie uploads/downloads, and retained script artifacts."
        chips={
          <>
            <a className="chip" href="/">← dashboard</a>
            {source ? (
              <button className="chip" type="button" onClick={() => void applySource('')}>
                all sources
              </button>
            ) : (
              <span className="chip">all sources</span>
            )}
            {sourceNames.map((name) =>
              name === source ? (
                <span key={name} className="chip">
                  {name} {counts?.[name]}
                </span>
              ) : (
                <button key={name} className="chip" type="button" onClick={() => void applySource(name)}>
                  {name} {counts?.[name]}
                </button>
              ),
            )}
            <span className="chip">
              {(rows?.length ?? 0).toLocaleString('en-US')} loaded of {total.toLocaleString('en-US')} matching •{' '}
              {uniqueTotal.toLocaleString('en-US')} unique total
            </span>
          </>
        }
      />
      <p className="note">
        Correlated workbench runs, isolated sandbox detonations, and published GitHub scans, without losing successful
        child results when another backend fails.
      </p>
      <div className="card wide">
        <p className="note">
          ⚠ Unified inventory of Dionaea captures, Cowrie uploads/downloads, and retained shell, PowerShell, VBS,
          Python, JavaScript and other script artifacts. Files are inert on disk but <strong>hostile</strong> — handle
          only in an isolated analysis VM.
        </p>
        <div className="project-grid" id="payloads-results">
          {rows === null ? (
            <SkeletonCards count={6} />
          ) : rows.length === 0 ? (
            <p className="empty">No payloads captured yet.</p>
          ) : (
            rows.map((row) => <PayloadCard key={row.Hash} row={row} badge={badgeFor(row.Hash)} />)
          )}
          {loadingMore ? <SkeletonCards count={4} /> : null}
        </div>
        {rows !== null && rows.length < total ? (
          <div className="hp-lazy-controls" aria-live="polite">
            <span>
              {rows.length.toLocaleString('en-US')} of {total.toLocaleString('en-US')} entries
            </span>
            <button className="btn btn-secondary btn-sm" type="button" onClick={viewMore} disabled={loadingMore}>
              View more
            </button>
          </div>
        ) : null}
      </div>
    </>
  )
}
