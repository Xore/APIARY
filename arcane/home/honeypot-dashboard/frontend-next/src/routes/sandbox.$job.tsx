// Sandbox detonation detail — one job's verdict, behavior record and
// exported artifacts. Submission of new jobs lands with #1612's mounted
// worker role. Live read-only VNC viewing of a currently-running
// Windows-sandbox detonation (SANDBOX_VNC_BRIDGE_WS) is a separate page,
// not this one — see sandbox.vnc.tsx.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { ArtifactList } from '../components/ArtifactList'
import type { JsonRecord } from '../lib/json'

type Run = JsonRecord

const fetchRun = createServerFn({ method: 'GET' })
  .inputValidator((input: { job: string }) => input)
  .handler(async ({ data }): Promise<Run | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Run>(`/api/v1/sandbox/${encodeURIComponent(data.job)}`)
  })

export const Route = createFileRoute('/sandbox/$job')({
  loader: async ({ params }) => ({ first: fetchRun({ data: { job: params.job } }) }),
  component: SandboxDetail,
})

const str = (row: Run | null, ...path: string[]): string => {
  let value: unknown = row
  for (const key of path) {
    if (typeof value !== 'object' || value === null) return ''
    value = (value as Run)[key]
  }
  return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : ''
}

function SandboxDetail() {
  const { first } = Route.useLoaderData()
  const { job } = Route.useParams()
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
    return <InvestigateHeader label="Evidence" title={job} subtitle="No sandbox run found for this job id." />
  }
  const doc = run === null ? null : run
  const level = str(doc, 'risk_level')
  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title={`Sandbox — ${job.slice(0, 40)}`}
        subtitle="One detonation's full behavior record: verdict, platform, and every exported artifact."
        chips={
          doc ? (
            <>
              <span
                className={
                  level === 'high' || level === 'critical'
                    ? 'badge badge--danger'
                    : level === 'medium'
                      ? 'badge badge--warning'
                      : 'badge badge--muted'
                }
              >
                {level || 'n/a'} {str(doc, 'risk_score')}
              </span>
              <span className="badge badge--muted">{str(doc, 'platform')}</span>
              <span className="chip">exit {str(doc, 'exit_status')}</span>
              {str(doc, 'file', 'hash', 'sha256') ? (
                <Link className="chip" to="/payload-analysis/$hash" params={{ hash: str(doc, 'file', 'hash', 'sha256') }}>
                  payload analysis →
                </Link>
              ) : null}
              <Link className="chip" to="/payload-workbench/results">← all results</Link>
            </>
          ) : undefined
        }
      />
      <div className="card wide">
        <h2>Exported artifacts</h2>
        <ArtifactList kind="sandbox" artifactKey={job} />
      </div>
      <div className="card wide">
        <h2>Behavior record</h2>
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
