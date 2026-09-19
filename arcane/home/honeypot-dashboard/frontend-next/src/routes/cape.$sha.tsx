// CAPE run detail — one binary's detonation in CAPE's debugger-instrumented
// Windows guest, CAPE's own second sandbox route (#322) separate from
// win11-sandbox, purpose-built for debugger-class time evasion persona
// realism alone can't defeat. Ports dashboard/ui/cape.html's "cape-detail-
// body" block: malscore/status/signature/process metrics, task identity,
// signatures, process activity (call counts, not the debugger trace
// itself — see the note on GET /api/v1/cape/{sha}), behavior summary,
// dumped payloads/configs, and the analyzer log.
import { Skeleton } from '../components/ui/skeleton'
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { Badge } from '../components/ui/badge'
import { Card, CardContent } from '../components/ui/card'
import type { Json, JsonRecord } from '../lib/json'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'

type Signature = { name: string; description: string; severity: Json }

type ReportSummary = {
  machine: string
  package: string
  route: string
  timeout: boolean
  duration: number
  malscore: number
  malstatus: string | null
  summary: Record<string, string[]>
  summary_keys: string[]
  processes: { process_id: number; process_name: string; parent_id: number; module_path: string; first_seen: string; call_count: number }[]
  total_calls: number
  payloads: JsonRecord[]
  configs: JsonRecord[]
  debug_log: string
  debug_errors: string[]
}

type CapeRun = {
  sha256: string
  requested_at: string
  started_at: string
  completed_at: string
  exit_status: string
  error?: string
  task_id: number | null
  cape_status: string
  route: string
  score: number | null
  category: string
  signatures: Signature[]
  report_summary: ReportSummary | null
}

// #2178: serviceJSON collapsed "no CAPE run exists for this hash" (a real
// 404 — a genuine answer about this sample) into the same null as "the
// request failed", so an outage read as confident absence. This union
// keeps the two separable; the handler never rejects.
type RunFetch = { state: 'run'; run: CapeRun } | { state: 'missing' } | { state: 'failed' }

const fetchRun = createServerFn({ method: 'GET' })
  .validator((input: { sha: string }) => input)
  .handler(async ({ data }): Promise<RunFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<CapeRun>(`/api/v1/cape/${encodeURIComponent(data.sha)}`)
    if (result.ok) return { state: 'run', run: result.body }
    return result.status === 404 ? { state: 'missing' } : { state: 'failed' }
  })

export const Route = createFileRoute('/cape/$sha')({
  loader: async ({ params }) => ({ first: fetchRun({ data: { sha: params.sha } }) }),
  component: CapeDetail,
})

function scoreDisplay(score: number | null): string {
  return score === null ? '0' : String(Math.round(score))
}

function ProcessActivityCard({ summary }: { summary: ReportSummary }) {
  if (!summary.processes.length) {
    return (
      <Card>
        <h2>Process activity</h2>
        <p className="empty">No process trace was recorded for this run.</p>
      </Card>
    )
  }
  return (
    <Card>
      <h2>Process activity</h2>
      <p className="text-sm text-muted-foreground">
        API call counts, not the calls themselves — CAPE recorded {summary.total_calls.toLocaleString('en-US')} calls across
        these processes combined, far too many to render on one page. The full trace is in the raw report (link above).
      </p>
      <CardContent>
        <Table className="data-table">
          <TableHeader>
            <TableRow>
              <TableHead>PID</TableHead>
              <TableHead>process</TableHead>
              <TableHead>parent PID</TableHead>
              <TableHead>first seen</TableHead>
              <TableHead>API calls</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {summary.processes.map((process, index) => (
              <TableRow key={`${process.process_id}-${index}`}>
                <TableCell className="n">{process.process_id}</TableCell>
                <TableCell className="v">{process.process_name}</TableCell>
                <TableCell className="n">{process.parent_id}</TableCell>
                <TableCell className="ago">{process.first_seen}</TableCell>
                <TableCell className="n">{process.call_count.toLocaleString('en-US')}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function CapeDetail() {
  const { first } = Route.useLoaderData()
  const { sha } = Route.useParams()
  // #2178: `resolved ?? 'missing'` made a failed fetch assert "No CAPE
  // result found" — an outage masquerading as evidence. Tri-state now:
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

  const run: CapeRun | null = fetch !== null && fetch.state === 'run' ? fetch.run : null

  if (fetch?.state === 'missing') {
    return <InvestigateHeader label="Evidence" title={sha.slice(0, 24)} subtitle="No CAPE result found for this hash." />
  }
  if (fetch?.state === 'failed') {
    return (
      <>
        <InvestigateHeader
          label="Dynamic analysis"
          title={`CAPE sandbox — ${sha.slice(0, 24)}…`}
          subtitle="The load failed before any result could be shown."
        />
        <ErrorStateBlock
          title="The CAPE result failed to load"
          hint="The backend request failed — this says nothing about whether a run exists for this hash."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      </>
    )
  }
  const failed = run !== null && run.exit_status === 'error'
  const summary = run?.report_summary ?? null

  return (
    <>
      <InvestigateHeader
        label="Dynamic analysis"
        title={`CAPE sandbox — ${sha.slice(0, 24)}…`}
        subtitle="Detonation in an isolated, debugger-instrumented Windows guest — purpose-built for debugger-class time evasion (long sleeps, rdtsc checks) that persona realism alone cannot defeat."
        chips={
          run ? (
            <>
              <Badge variant={failed ? 'destructive' : 'secondary'}>exit {run.exit_status || 'n/a'}</Badge>
              <Link className="chip" to="/payload-workbench/results" search={{ hash: sha }} hash="workbench-builder">
                unified analysis workbench →
              </Link>
              <Link className="chip" to="/payload-analysis/$hash" params={{ hash: sha }}>
                static analysis →
              </Link>
              <Link className="chip" to="/events" search={{ shasum: sha }}>
                related events →
              </Link>
              <a className="chip" href={`/api/raw-report/cape/${encodeURIComponent(sha)}`} target="_blank" rel="noopener noreferrer">
                raw report (JSON) ↓
              </a>
              <Link className="chip" to="/cape">← all runs</Link>
            </>
          ) : undefined
        }
      />
      {run === null ? (
        <Card>
          <Skeleton className="h-4 w-full" aria-hidden="true" />
          <Skeleton className="h-4 w-full" aria-hidden="true" />
        </Card>
      ) : (
        <>
          {failed ? (
            <Card>
              <h2>This run did not complete</h2>
              <p>{run.error || 'The worker reported a failure with no detail.'}</p>
            </Card>
          ) : (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card>
                  <CardContent className="p-4">
                    <div className="text-sm text-muted-foreground">Malscore</div>
                    <div className={`text-2xl font-semibold${(run.score ?? 0) > 0 ? ' text-destructive' : ''}`}>{scoreDisplay(run.score)}</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4">
                    <div className="text-sm text-muted-foreground">Task status</div>
                    <div className="text-2xl font-semibold">{run.cape_status}</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4">
                    <div className="text-sm text-muted-foreground">Signatures</div>
                    <div className="text-2xl font-semibold">{run.signatures.length}</div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4">
                    <div className="text-sm text-muted-foreground">Processes traced</div>
                    <div className="text-2xl font-semibold">{summary ? summary.processes.length : 0}</div>
                  </CardContent>
                </Card>
              </div>

              <div className="section-heading">
                <div>
                  <h2>Run identity</h2>
                  <p>What was submitted, to which guest, and how the task itself went.</p>
                </div>
              </div>
              <Card>
                <h2>Task identity</h2>
                <Table className="data-table">
                  <TableBody>
                    <TableRow>
                      <TableCell>SHA-256</TableCell>
                      <TableCell className="v">{run.sha256}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>task ID</TableCell>
                      <TableCell className="v">{run.task_id ?? '—'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>requested</TableCell>
                      <TableCell className="v">{run.requested_at}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>started</TableCell>
                      <TableCell className="v">{run.started_at}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>completed</TableCell>
                      <TableCell className="v">{run.completed_at}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>exit status</TableCell>
                      <TableCell className="v">{run.exit_status}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>CAPE task status</TableCell>
                      <TableCell className="v">{run.cape_status}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell>route</TableCell>
                      <TableCell className="v">{run.route}</TableCell>
                    </TableRow>
                    {summary ? (
                      <>
                        <TableRow>
                          <TableCell>machine</TableCell>
                          <TableCell className="v">{summary.machine}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell>package</TableCell>
                          <TableCell className="v">{summary.package}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell>duration</TableCell>
                          <TableCell className="v">
                            {summary.duration} seconds{summary.timeout ? ' (hit its own analysis timeout)' : ''}
                          </TableCell>
                        </TableRow>
                      </>
                    ) : null}
                  </TableBody>
                </Table>
              </Card>

              {run.signatures.length ? (
                <Card>
                  <h2>Signatures</h2>
                  <p className="text-sm text-muted-foreground">
                    CAPE's own behavioral signature matches — a signature firing means code matching a known pattern ran, not
                    necessarily that the sample is malicious.
                  </p>
                  <CardContent>
                    <Table className="data-table">
                      <TableHeader>
                        <TableRow>
                          <TableHead>severity</TableHead>
                          <TableHead>name</TableHead>
                          <TableHead>description</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {run.signatures.map((signature, index) => (
                          <TableRow key={`${signature.name}-${index}`}>
                            <TableCell>
                              <Badge variant="secondary">{String(signature.severity)}</Badge>
                            </TableCell>
                            <TableCell className="v">{signature.name}</TableCell>
                            <TableCell className="v">{signature.description}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              ) : null}

              {summary ? (
                <>
                  <div className="section-heading">
                    <div>
                      <h2>What ran</h2>
                      <p>Every traced process, and the API calls CAPE's debugger instrumentation recorded for each.</p>
                    </div>
                  </div>
                  <ProcessActivityCard summary={summary} />

                  {summary.summary_keys.length ? (
                    <Card>
                      <h2>Behavior summary</h2>
                      <p className="text-sm text-muted-foreground">
                        Deduplicated files, registry keys, mutexes and similar CAPE observed across every traced process. Large
                        categories (registry keys especially) are common and not by themselves a finding.
                      </p>
                      {summary.summary_keys.map((key) =>
                        summary.summary[key]?.length ? (
                          <div className="flex items-center justify-between" key={key}>
                            <span className="text-sm font-medium text-muted-foreground">{key}</span>
                            <span className="font-mono text-lg font-semibold">{summary.summary[key].length}</span>
                          </div>
                        ) : null,
                      )}
                    </Card>
                  ) : null}

                  <Card>
                    <h2>Dumped payloads &amp; extracted configuration</h2>
                    {summary.payloads.length || summary.configs.length ? (
                      <>
                        <p className="text-sm text-muted-foreground">
                          Files CAPE's own debugger-driven unpacking dumped mid-execution, and any malware configuration it
                          extracted from them — CAPE's own YARA-triggered dynamic bypass mechanism at work, not static
                          analysis.
                        </p>
                        {summary.payloads.length ? <p className="text-sm text-muted-foreground">{summary.payloads.length} payload(s) dumped.</p> : null}
                        {summary.configs.length ? <p className="text-sm text-muted-foreground">{summary.configs.length} configuration(s) extracted.</p> : null}
                      </>
                    ) : (
                      <p className="empty">CAPE's debugger did not dump any payloads or extract any malware configuration during this run.</p>
                    )}
                  </Card>

                  <Card>
                    <h2>Analyzer log</h2>
                    <p className="text-sm text-muted-foreground">
                      The in-guest analyzer's own operational log, not a per-instruction trace. See Process activity above for
                      the execution summary.
                    </p>
                    {summary.debug_errors.length ? (
                      <p className="note text-danger">{summary.debug_errors.length} analyzer error(s) were logged.</p>
                    ) : null}
                    {summary.debug_log ? (
                      <CardContent aria-label="Analyzer log output">
                        <pre className="code">{summary.debug_log}</pre>
                      </CardContent>
                    ) : (
                      <p className="empty">No analyzer log was recorded.</p>
                    )}
                  </Card>
                </>
              ) : null}
            </>
          )}
        </>
      )}
    </>
  )
}
