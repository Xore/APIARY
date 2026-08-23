// LLM analysis — llm-worker's guarded model output (llm-analysis index).
// Every judgment is AI-guessed and labeled as such, mirroring the legacy
// page's UNVERIFIED posture. The index may not exist yet (worker gated on
// GPU availability); the empty state is normal.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import { StoreListPage, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

type SemanticResult = { available: boolean; reason?: string; hits: (StoreRow & { score?: number })[] }

const semanticSearch = createServerFn({ method: 'GET' })
  .inputValidator((input: { q: string }) => input)
  .handler(async ({ data }): Promise<SemanticResult | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<SemanticResult>(`/api/v1/llm-search?q=${encodeURIComponent(data.q)}`)
  })

function SemanticSearchCard() {
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<SemanticResult | null>(null)
  const [busy, setBusy] = useState(false)
  return (
    <div className="card wide">
      <h2>Semantic search</h2>
      <p className="note">
        Free-text search over session summaries by meaning, not keywords — the query is embedded locally and matched against
        llm-worker's own vectors. Results are AI-guessed and unverified.
      </p>
      <form
        className="filters"
        onSubmit={async (event) => {
          event.preventDefault()
          if (!query.trim() || busy) return
          setBusy(true)
          try {
            setResult(await semanticSearch({ data: { q: query.trim() } }))
          } finally {
            setBusy(false)
          }
        }}
      >
        <input
          className="form-input"
          type="search"
          placeholder='e.g. "attacker installed a cryptominer via wget"'
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label="Semantic search query"
        />
        <button className="btn btn-secondary btn-sm" type="submit" disabled={busy || !query.trim()}>
          {busy ? 'Searching…' : 'Search'}
        </button>
      </form>
      {result && !result.available ? <p className="empty">{result.reason}</p> : null}
      {result?.available && result.hits.length === 0 && query ? <p className="empty">No semantic matches.</p> : null}
      {result?.available && result.hits.length > 0 ? (
        <div className="card__scroll">
          <table className="data-table">
            <thead>
              <tr><th>score</th><th>severity</th><th>summary</th><th>session</th></tr>
            </thead>
            <tbody>
              {result.hits.map((hit, index) => (
                <tr key={`${str(hit, 'analysis_id')}-${index}`}>
                  <td className="n">{typeof hit.score === 'number' ? hit.score.toFixed(3) : ''}</td>
                  <td><span className="badge badge--muted">{str(hit, 'severity')}</span></td>
                  <td className="v">{str(hit, 'summary')}</td>
                  <td className="v">
                    {str(hit, 'session_id') ? (
                      <a href={`/sessions/${encodeURIComponent(str(hit, 'session_id'))}`}>{str(hit, 'session_id').slice(0, 12)}</a>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  )
}

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/llm-analysis?offset=${data.offset}&size=25`)
  })

function severityBadge(severity: string) {
  // critical→danger, high→warning, medium→info (llm_analysis.html:58).
  const cls =
    severity === 'critical'
      ? 'badge badge--danger'
      : severity === 'high'
        ? 'badge badge--warning'
        : severity === 'medium'
          ? 'badge badge--info'
          : 'badge badge--muted'
  return <span className={cls}>{severity || 'n/a'}</span>
}

// Pivot back to the honeypot activity the analysis was generated from,
// ported from llmAnalysisDoc.EvidenceLink(): a session analysis links to
// the session's own page, a payload analysis to the payload's detail page,
// and a report (an aggregate, no single source document) has no link.
function evidenceLink(row: StoreRow) {
  const docType = str(row, 'doc_type')
  if (docType === 'session' && str(row, 'session_id')) {
    return (
      <Link to="/sessions/$id" params={{ id: str(row, 'session_id') }}>
        view source
      </Link>
    )
  }
  if (docType === 'payload' && str(row, 'payload_sha256')) {
    return (
      <Link to="/payload-analysis/$hash" params={{ hash: str(row, 'payload_sha256') }}>
        view source
      </Link>
    )
  }
  return <span className="tw:text-muted">—</span>
}

const COLUMNS: Column<StoreRow>[] = [
  { header: 'analyzed', render: (row) => when(str(row, '@timestamp')) },
  {
    header: 'doc type',
    render: (row) => (
      // The per-row trust badge (llm_analysis.html:57) — structural, on
      // every row, not left to the subtitle to disclaim.
      <>
        <span className="badge badge--info">{str(row, 'doc_type')}</span>{' '}
        <span className="badge badge--muted" title="every row on this page is generated by a local LLM, not a human analyst">
          AI-generated
        </span>
      </>
    ),
  },
  { header: 'severity (AI-guessed)', render: (row) => severityBadge(str(row, 'severity')) },
  { header: 'confidence', render: (row) => str(row, 'confidence') || <span className="tw:text-muted">—</span> },
  { header: 'intent', className: 'v', render: (row) => str(row, 'intent') },
  { header: 'summary', className: 'v', primary: true, render: (row) => str(row, 'summary') || <span className="tw:text-muted">(no summary)</span> },
  { header: 'evidence', className: 'v', render: (row) => evidenceLink(row) },
  { header: 'model', detail: true, render: (row) => str(row, 'model') },
  { header: 'source ip', detail: true, render: (row) => str(row, 'src_ip') },
  { header: 'session', detail: true, render: (row) => str(row, 'session_id') },
  {
    header: 'behaviors',
    detail: true,
    render: (row) => (Array.isArray(row.behaviors) ? (row.behaviors as string[]).join(', ') : ''),
  },
  { header: 'error', detail: true, render: (row) => str(row, 'error') },
]

export const Route = createFileRoute('/llm-analysis')({ component: Page })

function Page() {
  return (
    <>
      <SemanticSearchCard />
      <StoreListPage
      fetchPage={fetchPage}
      label="Monitor"
      title="LLM analysis"
      subtitle="Model-annotated sessions, payloads and reports — every judgment here is AI-guessed and unverified until a human confirms it."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'analysis_id')}-${index}`}
      inspectorTitle="Analysis details"
      chipNoun="analyses"
      beforeTable={
        <p className="note">
          Session summaries and payload triage from llm-worker's guarded model — every row below is AI-generated,
          attacker-influenced text and must be reviewed, not trusted as fact.
        </p>
      }
      emptyState={{
        title: 'No LLM analysis documents yet',
        hint: 'llm-worker writes one per analysed event batch.',
      }}
      layout="cards"
      />
    </>
  )
}
