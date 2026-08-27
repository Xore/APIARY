// RevDeck run detail — one binary's reverse-engineering deck walkthrough:
// Rev·Deck's own bounded, autonomous tool-calling loop against the Ghidra
// REST service, a second and independent AI aid alongside the worker's own
// AI triage. Mirrors ghidra.$sha.tsx/sandbox.$job.tsx's single-artifact
// detail shape; revdeck-analysis-v1 has no artifact store of its own (no
// report/callgraph exports like ghidra, no pcap exports like sandbox), so
// this page is the record view only. GET /api/v1/revdeck/{sha}
// (detail.rs's revdeck_run) can also surface an unconfigured-worker error
// state — exit_status: "error" with revdeck: null/absent — rendered as a
// visible error card, matching dashboard/ui/revdeck.html's own alert.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'

type Citation = { kind: string; raw: string; value: string; valid: boolean }

type RevDeckAnalysis = {
  workflow: string
  status: string
  answer: string
  steps: number | null
  tool_calls: number
  citations: { valid: Citation[]; invalid: Citation[] } | null
  warnings: string[]
}

type RevdeckRun = {
  sha256: string
  exit_status: string
  error?: string
  revdeck: RevDeckAnalysis | null
}

// #2178: serviceJSON collapsed "no RevDeck analysis exists for this hash"
// (a real 404) and "the request failed" into one null, so an outage read
// as confident absence. This union keeps the two separable; the handler
// never rejects.
type RunFetch = { state: 'run'; run: RevdeckRun } | { state: 'missing' } | { state: 'failed' }

const fetchRun = createServerFn({ method: 'GET' })
  .inputValidator((input: { sha: string }) => input)
  .handler(async ({ data }): Promise<RunFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<RevdeckRun>(`/api/v1/revdeck/${encodeURIComponent(data.sha)}`)
    if (result.ok) return { state: 'run', run: result.body }
    return result.status === 404 ? { state: 'missing' } : { state: 'failed' }
  })

export const Route = createFileRoute('/revdeck/$sha')({
  loader: async ({ params }) => ({ first: fetchRun({ data: { sha: params.sha } }) }),
  component: RevdeckDetail,
})

function CitationList({ title, citations }: { title: string; citations: Citation[] }) {
  if (!citations.length) return null
  return (
    <>
      <p className="note">{title}</p>
      <ul className="">
        {citations.map((citation, index) => (
          <li key={`${citation.raw}-${index}`}>{citation.raw}</li>
        ))}
      </ul>
    </>
  )
}

function RevDeckCard({ analysis }: { analysis: RevDeckAnalysis | null }) {
  if (!analysis) {
    return (
      <div className="card wide">
        <h2>Rev·Deck</h2>
        <p className="empty">No Rev·Deck data — see the error above.</p>
      </div>
    )
  }
  return (
    <div className="card wide">
      <h2>Rev·Deck</h2>
      <p className="note">
        Rev·Deck's own bounded, autonomous tool-calling loop against the Ghidra REST service — a second and independent AI aid
        alongside the worker's own AI triage, not a replacement for it. Every claim below is a language model's reading of
        decompiled code.
      </p>
      <div className="card__scroll">
        <table className="data-table">
          <tbody>
            <tr>
              <td>workflow</td>
              <td className="v">{analysis.workflow}</td>
            </tr>
            <tr>
              <td>status</td>
              <td className="v">
                {analysis.status}
                {analysis.status === 'max_turns'
                  ? ' — the step budget ran out before the model finished; this is its best-effort synthesis, not a completed analysis'
                  : ''}
              </td>
            </tr>
            {analysis.steps ? (
              <tr>
                <td>steps</td>
                <td className="v">{analysis.steps}</td>
              </tr>
            ) : null}
            <tr>
              <td>tool calls</td>
              <td className="v">{analysis.tool_calls}</td>
            </tr>
          </tbody>
        </table>
        {analysis.answer ? (
          <>
            <p className="note">Answer:</p>
            <p>{analysis.answer}</p>
          </>
        ) : null}
        {analysis.citations ? (
          <>
            <CitationList title="Citations:" citations={analysis.citations.valid} />
            <CitationList
              title="Citations the model referenced that could not be verified against the analysis:"
              citations={analysis.citations.invalid}
            />
          </>
        ) : null}
        {analysis.warnings.length ? (
          <>
            <p className="note">Warnings from the run:</p>
            <ul className="">
              {analysis.warnings.map((warning, index) => (
                <li key={index}>{warning}</li>
              ))}
            </ul>
          </>
        ) : null}
      </div>
    </div>
  )
}

function RevdeckDetail() {
  const { first } = Route.useLoaderData()
  const { sha } = Route.useParams()
  // #2178: `resolved ?? 'missing'` made a failed fetch assert "No RevDeck
  // analysis found" — an outage dressed up as evidence. Tri-state now:
  // null while loading, 'missing' only for the backend's own 404, and a
  // named failure with retry for everything else.
  const [fetch, setFetch] = useState<RunFetch | null>(null)
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let cancelled = false
    setFetch(null)
    ;(attempt === 0 ? first : fetchRun({ data: { sha } })).then((result) => {
      if (!cancelled) setFetch(result)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned loader stream
  }, [first, attempt])

  if (fetch?.state === 'missing') {
    return <InvestigateHeader label="Evidence" title={sha.slice(0, 24)} subtitle="No RevDeck analysis found for this hash." />
  }
  if (fetch?.state === 'failed') {
    return (
      <>
        <InvestigateHeader label="Evidence" title={sha.slice(0, 24)} subtitle="The analysis could not be loaded." />
        <ErrorStateBlock
          title="The RevDeck analysis failed to load"
          hint="The backend request failed — this says nothing about whether an analysis exists for this hash."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      </>
    )
  }
  const run: RevdeckRun | null = fetch !== null && fetch.state === 'run' ? fetch.run : null

  const failed = run !== null && run.exit_status === 'error'

  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title={`RevDeck — ${sha.slice(0, 24)}…`}
        subtitle="One binary's reverse-engineering deck walkthrough: workflow verdict, tool-call trace, and the full analysis record."
        chips={
          run ? (
            <>
              <span className={failed ? 'badge badge--danger' : 'badge badge--muted'}>exit {run.exit_status || 'n/a'}</span>
              {!failed && run.revdeck?.workflow ? <span className="badge badge--muted">{run.revdeck.workflow}</span> : null}
              {!failed && run.revdeck?.status ? <span className="chip">{run.revdeck.status}</span> : null}
              <Link className="chip" to="/payload-workbench/results" search={{ hash: sha }} hash="workbench-builder">
                unified analysis workbench →
              </Link>
              <Link className="chip" to="/ghidra/$sha" params={{ sha }}>
                Ghidra analysis →
              </Link>
              <Link className="chip" to="/payload-analysis/$hash" params={{ hash: sha }}>
                static analysis →
              </Link>
              <Link className="chip" to="/events" search={{ shasum: sha }}>
                related events →
              </Link>
              <Link className="chip" to="/revdeck">← all runs</Link>
            </>
          ) : undefined
        }
      />
      {run && failed ? (
        <div className="card wide">
          <h2>This run did not complete</h2>
          <p>
            {run.error || 'The worker reported a failure with no detail.'} Rev·Deck's answer is the entire point of a standalone
            request, so a failure here means there is nothing else on this page.
          </p>
        </div>
      ) : null}
      {run === null ? (
        <div className="card wide">
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </div>
      ) : (
        <>
          {!failed ? <RevDeckCard analysis={run.revdeck} /> : null}
          <div className="card wide">
            <h2>Raw record</h2>
            <div className="card__scroll">
              <pre className="code">{JSON.stringify(run, null, 2)}</pre>
            </div>
          </div>
        </>
      )}
    </>
  )
}
