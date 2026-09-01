// Captured payloads — dashboard-payload-inventory-v1 as the Go page's
// project-card grid (payloads.html's "payloadrow" template, #1653):
// per-source filter chips, GitHub-verdict + family badges, byte preview,
// and the per-card actions -- now the same RowActions strip every table
// row uses rather than the Go page's "…" menu (#1899) -- with View-more
// + skeleton-first.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { confirmAction } from '../components/ConfirmDialog'
import { ErrorStateBlock } from '../components/ErrorState'
import { InvestigateHeader } from '../components/Investigate'
import { RowActions, RowIcons } from '../components/RowActions'
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
  .validator((input: { offset: number; source?: string }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    const filter = data.source ? `&q=${encodeURIComponent(sourceQuery(data.source))}` : ''
    return serviceJSON<Page>(`/api/v1/payloads?offset=${data.offset}&size=12${filter}`)
  })

// Per-source filter chips (#2179): one opt-in terms agg over the whole
// inventory (`aggs=sources`) replaces both halves of the old discovery, which
// seeded chips from CANONICAL_SOURCES plus whatever the loaded page happened
// to hold — a rarer source deeper in the store was captured but had no chip,
// and was therefore unfilterable — while every chip's count cost its own
// extra size=1 round-trip. Buckets arrive exact and count-ordered straight
// from the store; `other` carries ES's sum_other_doc_count so the UI can
// still disclose "+N docs in rarer sources" if the terms size itself ever
// becomes the bound. (CANONICAL_SOURCES used to seed the chip list here; the
// whole-store census makes that seed obsolete — a source either has docs and
// its bucket shows it, or it has none and never earned a chip.)
type SourceCensus = { counts: Record<string, number>; other: number }

const fetchSourceCounts = createServerFn({ method: 'GET' }).handler(async (): Promise<SourceCensus | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  type SourcesPage = Page & { source_buckets?: { key: string; doc_count: number }[]; source_other?: number }
  const page = await serviceJSON<SourcesPage>('/api/v1/payloads?offset=0&size=1&aggs=sources')
  if (!page) return null
  const counts: Record<string, number> = {}
  for (const bucket of page.source_buckets ?? []) counts[bucket.key] = bucket.doc_count
  return { counts, other: page.source_other ?? 0 }
})

// GitHub-analysis verdict + family badges (payloads.html:13-15), the
// ported attachGitHubAnalysisVerdicts (payloads_data.go): one whole-store
// fetch, matched to cards by sha256 — only sha256-named captures
// (cowrie/scripts) can carry a badge, same as the Go map keyed by SHA256.
type GithubBadge = { sha256: string; label: string; family: string }
type VerdictScan = { badges: GithubBadge[]; scanned: number; total: number }

// #2179: the store endpoint clamps a single page to 100 rows server-side, so
// the original one-shot `size=100` request quietly shrank the badge map to
// the 100 newest analyzed samples — deeper samples rendered without their
// verdict badge, contrary to the "whole-store fetch" contract this ports
// from the Go tier. Page through to the real total instead; the ceiling
// keeps a pathological store bounded, and when it binds, the shortfall is
// disclosed next to the grid rather than silently absorbed.
const VERDICT_SCAN_CEILING = 1000

function collectBadges(rows: Record<string, unknown>[]): GithubBadge[] {
  const badges: GithubBadge[] = []
  for (const row of rows) {
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
}

const fetchGithubVerdicts = createServerFn({ method: 'GET' }).handler(async (): Promise<VerdictScan | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  type StorePage = { total: number; rows: Record<string, unknown>[] }
  let badges: GithubBadge[] = []
  let scanned = 0
  let total = 0
  for (;;) {
    const page = await serviceJSON<StorePage>(`/api/v1/store/github-analysis?offset=${scanned}&size=100`)
    if (!page) break
    total = Math.max(total, page.total)
    badges = badges.concat(collectBadges(page.rows))
    scanned += page.rows.length
    if (page.rows.length === 0 || scanned >= Math.min(page.total, VERDICT_SCAN_CEILING)) break
  }
  return { badges, scanned, total }
})

// The action menu's Publish item — same admin gate, `confirm: "publish"`
// sentinel and audit fields as payload-analysis.$hash.tsx's
// submitGithubAnalysis (kept as this route's own server fn rather than a
// cross-route import, so the two route bundles stay independent). Only
// ever called from behind confirmAction's publication dialog.
const submitGithubAnalysis = createServerFn({ method: 'POST' })
  .validator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
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

// Family display bounded like Go's boundedFamily; the pivot link carries
// the full value (truncating first would let two long names collide).
function boundedFamily(family: string): string {
  return family.length > 24 ? `${family.slice(0, 24)}…` : family
}

function SkeletonCards({ count }: { count: number }) {
  // Shape-true ghost of PayloadCard (#1967): same shells, same order --
  // icon chip + mono hash title + badge pills, one desc line, then the
  // byte-preview block (a real .hp-code-results pre so min-height 180 is
  // claimed up front instead of appearing at swap-in), then meta.
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <div key={`skel-${i}`} className="project-card" aria-hidden="true">
          <div className="project-card__header">
            <span className="project-card__icon">
              <span className="skeleton-line" style={{ display: 'block', width: 16, height: 16 }} />
            </span>
            <span className="project-card__title">
              <span className="skeleton-line" style={{ display: 'block', width: '82%' }} />
            </span>
            <div className="project-card__badges">
              <span className="skeleton-line" style={{ display: 'block', width: 56, height: 18, borderRadius: 999 }} />
              <span className="skeleton-line" style={{ display: 'block', width: 44, height: 18, borderRadius: 999 }} />
            </div>
          </div>
          <p className="project-card__desc">
            <span className="skeleton-line" style={{ display: 'block', width: '88%' }} />
          </p>
          <pre className="code hp-code-results">
            <span className="skeleton-line" style={{ display: 'block', width: '92%' }} />
            <span className="skeleton-line" style={{ display: 'block', width: '74%' }} />
            <span className="skeleton-line" style={{ display: 'block', width: '81%' }} />
          </pre>
          <div className="project-card__meta">
            <span>
              <span className="skeleton-line" style={{ display: 'block', width: 64 }} />
            </span>
            <span>
              <span className="skeleton-line" style={{ display: 'block', width: 120 }} />
            </span>
          </div>
        </div>
      ))}
    </>
  )
}

// One payload card — payloads.html's "payloadrow".
//
// The card cannot itself be an <a>: a payload has several distinct
// actions, and HTML forbids interactive controls inside an anchor. That
// reasoning was right and its conclusion was not — it left the hash text
// as the only way into a payload's analysis, so the page's primary action
// had a target a few characters wide while the rest of the card, the part
// the eye lands on, did nothing. The analysis-results grids have always
// opened on a click anywhere.
//
// #1869: a transparent .hp-card-link overlay covers the card and the real
// controls sit above it, so clicking the card opens the analysis, clicking
// a control does what the control says, and the markup stays valid. The
// hash stays a link — it is also what an operator copies, and taking that
// away to add the overlay would trade one loss for another.
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
      {/* Empty by design — it takes its accessible name from the label,
          because an unlabelled link is worse than the small target it
          replaces. */}
      <a
        className="hp-card-link"
        href={`/payload-analysis/${encodeURIComponent(row.Hash)}`}
        aria-label={`Open the analysis for payload ${row.Hash}`}
      />
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
      <section aria-label="Byte preview" className="hp-flow--tight">
        <p className="note">
          {row.Preview
            ? `First ${row.PreviewTruncated ? `512 of ${row.SizeH}` : row.SizeH} bytes, hex/ASCII. Read only; never interpreted or executed.`
            : 'No byte preview is available for this capture.'}
        </p>
        {row.Preview ? <pre className="code hp-code-results">{row.Preview}</pre> : null}
      </section>
      <div className="project-card__meta">
        <span>{formatTimestamp(row.MtimeUTC)}</span>
        {/* #1899: the same strip every table row uses, with every action
            resting on screen rather than behind a ⋮.

            The disclosure menu cost a click to find out what a payload
            could even be done with, and it was the only surface in the
            dashboard still doing that after #1868 put the strip on rows.
            A card footer has the whole card width, so there is no reason
            to collapse anything here -- hence `expanded`.

            The card title already links to the static analysis, so the
            strip leads with the workbench instead of repeating it: the
            next thing an operator does after reading a capture. Publish
            is the one action with consequences outside this machine, so
            it is marked rather than left looking like Download. */}
        <RowActions
          expanded
          actions={[
            {
              label: 'Analysis workbench',
              icon: RowIcons.workbench,
              href: `/payload-workbench/results?hash=${encodeURIComponent(row.Hash)}#workbench-builder`,
            },
            {
              label: 'Static analysis',
              icon: RowIcons.detail,
              href: `/payload-analysis/${encodeURIComponent(row.Hash)}`,
            },
            {
              label: 'Download sample',
              icon: RowIcons.download,
              href: `/api/payload/${encodeURIComponent(row.Hash)}/download`,
            },
            {
              label: 'Related events',
              icon: RowIcons.events,
              href: `/events?shasum=${encodeURIComponent(row.Hash)}`,
            },
            {
              label: 'VirusTotal',
              icon: RowIcons.openIn,
              href: `https://www.virustotal.com/gui/file/${encodeURIComponent(row.Hash)}`,
              external: true,
            },
            { label: 'Publish to Xore/honeypot', icon: RowIcons.publish, onClick: publish, danger: true },
          ]}
        />
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
  const [sourceOther, setSourceOther] = useState(0)
  const [verdictScan, setVerdictScan] = useState<VerdictScan | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  // #2178: both load paths (the streamed first page and the per-source
  // refilter) collapsed a failed fetch into "rows stay null", which renders
  // as the opening skeleton grid forever. `failed` names that state;
  // retry re-fetches page zero through the ordinary paging fn, since the
  // streamed loader promise cannot be re-run.
  const [failed, setFailed] = useState(false)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    setFailed(false)
    ;(attempt === 0 ? first : fetchPayloads({ data: { offset: 0, source: source || undefined } })).then((page) => {
      if (cancelled) return
      if (!page) {
        setFailed(true)
        return
      }
      setRows(page.rows)
      setTotal(page.total)
      if (!source) setUniqueTotal(page.total)
    })
    // #2179: the census is no longer seeded from the loaded page's rows --
    // chips come from the whole-store terms agg, independent of what page 1
    // happens to show.
    fetchSourceCounts().then((result) => {
      if (!cancelled && result) {
        setCounts(result.counts)
        setSourceOther(result.other)
      }
    })
    fetchGithubVerdicts().then((result) => {
      if (!cancelled && result) setVerdictScan(result)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned loader stream; source read at retry time only
  }, [first, attempt])

  const applySource = useCallback(async (name: string) => {
    setSource(name)
    setRows(null)
    setFailed(false)
    const page = await fetchPayloads({ data: { offset: 0, source: name || undefined } })
    if (!page) {
      setFailed(true)
      return
    }
    setRows(page.rows)
    setTotal(page.total)
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

  const badgeFor = (hash: string) => verdictScan?.badges.find((badge) => badge.sha256 === hash.toLowerCase())
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
            {sourceOther > 0 ? (
              <span className="chip">…{sourceOther.toLocaleString('en-US')} docs in rarer sources</span>
            ) : null}
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
        {/* #2179: badge coverage is whole-store after pagination; only when
            the scan ceiling binds is the shortfall disclosed here instead of
            silently rendering older captures without their badges. */}
        {verdictScan && verdictScan.scanned < verdictScan.total ? (
          <p className="note">
            Verdict badges cover the {verdictScan.scanned.toLocaleString('en-US')} most recent analyzed samples of{' '}
            {verdictScan.total.toLocaleString('en-US')} on record.
          </p>
        ) : null}
        <div className="project-grid" id="payloads-results">
          {rows === null && failed ? (
            // #2178: an outage here used to read as the opening ghosts, forever.
            <ErrorStateBlock
              title="Captured payloads failed to load"
              hint="The backend request failed — this says nothing about what has been captured."
              onRetry={() => setAttempt((n) => n + 1)}
            />
          ) : rows === null ? (
            <SkeletonCards count={12} />
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
