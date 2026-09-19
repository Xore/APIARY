// LLM analysis — llm-worker's guarded model output (llm-analysis index).
// Every judgment is AI-guessed and labeled as such, mirroring the legacy
// page's UNVERIFIED posture. The index may not exist yet (worker gated on
// GPU availability); the empty state is normal.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import { StoreListPage, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader } from '../components/ui/card'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '../components/ui/empty'
import { Field, FieldLabel } from '../components/ui/field'
import { Input } from '../components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'

type SemanticResult = { available: boolean; reason?: string; hits: (StoreRow & { score?: number })[] }

const semanticSearch = createServerFn({ method: 'GET' })
  .validator((input: { q: string }) => input)
  .handler(async ({ data }): Promise<SemanticResult | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<SemanticResult>(`/api/v1/llm-search?q=${encodeURIComponent(data.q)}`)
  })

function SemanticSearchCard() {
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<SemanticResult | null>(null)
  // #2178: a failed search collapsed to the same null as "never run", so the
  // spinner ended and nothing at all happened on screen — the one part of
  // this route's designed escape hatch that was still unwired. The
  // available/reason channel itself now renders below; this names the
  // distinct case of the endpoint being unreachable.
  const [unreachable, setUnreachable] = useState(false)
  const [busy, setBusy] = useState(false)
  return (
    <Card className="col-span-full">
      <CardHeader><h2 className="font-semibold leading-none tracking-tight">Semantic search</h2>
      <CardDescription>
        Free-text search over session summaries by meaning, not keywords — the query is embedded locally and matched against
        llm-worker's own vectors. Results are AI-guessed and unverified.
      </CardDescription></CardHeader>
      <CardContent className="space-y-4">
      <form
        className="flex flex-col gap-3 sm:flex-row sm:items-end"
        onSubmit={async (event) => {
          event.preventDefault()
          if (!query.trim() || busy) return
          setBusy(true)
          setUnreachable(false)
          try {
            const answer = await semanticSearch({ data: { q: query.trim() } })
            if (!answer) setUnreachable(true)
            else setResult(answer)
          } finally {
            setBusy(false)
          }
        }}
      >
        <Field className="min-w-0 flex-1">
        <FieldLabel htmlFor="semantic-search-query">Semantic search query</FieldLabel>
        <Input
          id="semantic-search-query"
          type="search"
          placeholder='e.g. "attacker installed a cryptominer via wget"'
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        </Field>
        <Button variant="secondary" type="submit" disabled={busy || !query.trim()}>
          {busy ? 'Searching…' : 'Search'}
        </Button>
      </form>
      {unreachable ? (
        <Empty role="alert"><EmptyHeader><EmptyTitle>Semantic search unavailable</EmptyTitle><EmptyDescription>
          The semantic-search backend could not be reached — submitting again retries it.
        </EmptyDescription></EmptyHeader></Empty>
      ) : null}
      {result && !result.available ? <Empty><EmptyHeader><EmptyTitle>Semantic search unavailable</EmptyTitle><EmptyDescription>{result.reason}</EmptyDescription></EmptyHeader></Empty> : null}
      {result?.available && result.hits.length === 0 && query ? <Empty><EmptyHeader><EmptyTitle>No semantic matches</EmptyTitle></EmptyHeader></Empty> : null}
      {result?.available && result.hits.length > 0 ? (
          <Table>
            <TableHeader>
              <TableRow><TableHead>score</TableHead><TableHead>severity</TableHead><TableHead>summary</TableHead><TableHead>session</TableHead></TableRow>
            </TableHeader>
            <TableBody>
              {result.hits.map((hit, index) => (
                <TableRow key={`${str(hit, 'analysis_id')}-${index}`}>
                  <TableCell className="tabular-nums">{typeof hit.score === 'number' ? hit.score.toFixed(3) : ''}</TableCell>
                  <TableCell><Badge variant="secondary">{str(hit, 'severity')}</Badge></TableCell>
                  <TableCell className="max-w-md whitespace-normal">{str(hit, 'summary')}</TableCell>
                  <TableCell className="font-mono">
                    {str(hit, 'session_id') ? (
                      <a href={`/sessions/${encodeURIComponent(str(hit, 'session_id'))}`}>{str(hit, 'session_id').slice(0, 12)}</a>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
      ) : null}
      </CardContent>
    </Card>
  )
}

const fetchPage = createServerFn({ method: 'GET' })
  .validator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/llm-analysis?offset=${data.offset}&size=25`)
  })

function severityBadge(severity: string) {
  return <Badge variant={severity === 'critical' ? 'destructive' : severity === 'high' || severity === 'medium' ? 'default' : 'secondary'}>{severity || 'n/a'}</Badge>
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
  return <span className="text-muted-foreground">—</span>
}

const COLUMNS: Column<StoreRow>[] = [
  { header: 'analyzed', render: (row) => when(str(row, '@timestamp')) },
  {
    header: 'doc type',
    render: (row) => (
      // The per-row trust badge (llm_analysis.html:57) — structural, on
      // every row, not left to the subtitle to disclaim.
      <>
        <Badge>{str(row, 'doc_type')}</Badge>{' '}
        <Badge variant="secondary" title="every row on this page is generated by a local LLM, not a human analyst">
          AI-generated
        </Badge>
      </>
    ),
  },
  { header: 'severity (AI-guessed)', render: (row) => severityBadge(str(row, 'severity')) },
  { header: 'confidence', render: (row) => str(row, 'confidence') || <span className="text-muted-foreground">—</span> },
  { header: 'intent', className: 'v', render: (row) => str(row, 'intent') },
  { header: 'summary', className: 'v', primary: true, render: (row) => str(row, 'summary') || <span className="text-muted-foreground">(no summary)</span> },
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
      pageSize={25}
      label="Monitor"
      title="LLM analysis"
      subtitle="Model-annotated sessions, payloads and reports — every judgment here is AI-guessed and unverified until a human confirms it."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'analysis_id')}-${index}`}
      inspectorTitle="Analysis details"
      chipNoun="analyses"
      beforeTable={
        <p className="text-sm text-muted-foreground">
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
