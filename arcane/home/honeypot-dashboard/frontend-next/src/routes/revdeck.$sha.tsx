// RevDeck run detail — one binary's reverse-engineering deck walkthrough.
// Mirrors ghidra.$sha.tsx/sandbox.$job.tsx's single-artifact detail shape;
// revdeck-analysis-v1 has no artifact store (no report/callgraph exports
// like ghidra, no pcap exports like sandbox), so this page is the record
// view only. GET /api/v1/revdeck/{sha} (detail.rs's revdeck_run) can also
// surface an unconfigured-worker error state — exit_status: "error" with
// revdeck: null/absent — which must render as a visible error here rather
// than a blank page.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import type { JsonRecord } from '../lib/json'

type Run = JsonRecord

const fetchRun = createServerFn({ method: 'GET' })
  .inputValidator((input: { sha: string }) => input)
  .handler(async ({ data }): Promise<Run | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Run>(`/api/v1/revdeck/${encodeURIComponent(data.sha)}`)
  })

export const Route = createFileRoute('/revdeck/$sha')({
  loader: async ({ params }) => ({ first: fetchRun({ data: { sha: params.sha } }) }),
  component: RevdeckDetail,
})

const str = (row: Run | null, ...path: string[]): string => {
  let value: unknown = row
  for (const key of path) {
    if (typeof value !== 'object' || value === null) return ''
    value = (value as Run)[key]
  }
  return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : ''
}

function RevdeckDetail() {
  const { first } = Route.useLoaderData()
  const { sha } = Route.useParams()
  const [run, setRun] = useState<Run | null | 'missing'>(null)
  useEffect(() => {
    let cancelled = false
    first.then((result) => {
      if (!cancelled) setRun(result ?? 'missing')
    })
    return () => {
      cancelled = true
    }
  }, [first])

  if (run === 'missing') {
    return <InvestigateHeader label="Evidence" title={sha.slice(0, 24)} subtitle="No RevDeck analysis found for this hash." />
  }
  const doc = run === null ? null : run
  const exitStatus = str(doc, 'exit_status')
  const failed = exitStatus === 'error'
  const workflow = str(doc, 'revdeck', 'workflow')
  const status = str(doc, 'revdeck', 'status')

  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title={`RevDeck — ${sha.slice(0, 24)}…`}
        subtitle="One binary's reverse-engineering deck walkthrough: workflow verdict, tool-call trace, and the full analysis record."
        chips={
          doc ? (
            <>
              <span className={failed ? 'badge badge--danger' : 'badge badge--muted'}>exit {exitStatus || 'n/a'}</span>
              {!failed && workflow ? <span className="badge badge--muted">{workflow}</span> : null}
              {!failed && status ? <span className="chip">{status}</span> : null}
              <Link className="chip" to="/payload-analysis/$hash" params={{ hash: sha }}>
                payload analysis →
              </Link>
              <Link className="chip" to="/revdeck">← all runs</Link>
            </>
          ) : undefined
        }
      />
      {doc && failed ? (
        <div className="card wide">
          <h2>Error</h2>
          <p>{str(doc, 'error') || 'RevDeck produced no usable answer (worker unconfigured or the run failed before completion).'}</p>
        </div>
      ) : null}
      <div className="card wide">
        <h2>Analysis record</h2>
        {doc === null ? (
          <span className="skeleton-line" aria-hidden="true" />
        ) : (
          <div className="card__scroll">
            <pre className="code">{JSON.stringify(doc, null, 2)}</pre>
          </div>
        )}
      </div>
    </>
  )
}
