// CAPE run detail — one binary's detonation in CAPE's debugger-instrumented
// Windows guest, CAPE's own second sandbox route (#322) separate from
// win11-sandbox, purpose-built for debugger-class time evasion persona
// realism alone can't defeat. Ports dashboard/ui/cape.html's "cape-detail-
// body" block: malscore/status/signature/process metrics, task identity,
// signatures, process activity (call counts, not the debugger trace
// itself — see the note on GET /api/v1/cape/{sha}), behavior summary,
// dumped payloads/configs, and the analyzer log.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { InvestigateHeader } from '../components/Investigate'
import { useResolved } from '../lib/hooks'
import type { Json, JsonRecord } from '../lib/json'

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

const fetchRun = createServerFn({ method: 'GET' })
  .inputValidator((input: { sha: string }) => input)
  .handler(async ({ data }): Promise<CapeRun | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<CapeRun>(`/api/v1/cape/${encodeURIComponent(data.sha)}`)
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
      <div className="card wide">
        <h2>Process activity</h2>
        <p className="empty">No process trace was recorded for this run.</p>
      </div>
    )
  }
  return (
    <div className="card wide">
      <h2>Process activity</h2>
      <p className="note">
        API call counts, not the calls themselves — CAPE recorded {summary.total_calls.toLocaleString('en-US')} calls across
        these processes combined, far too many to render on one page. The full trace is in the raw report (link above).
      </p>
      <div className="card__scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>PID</th>
              <th>process</th>
              <th>parent PID</th>
              <th>first seen</th>
              <th>API calls</th>
            </tr>
          </thead>
          <tbody>
            {summary.processes.map((process, index) => (
              <tr key={`${process.process_id}-${index}`}>
                <td className="n">{process.process_id}</td>
                <td className="v">{process.process_name}</td>
                <td className="n">{process.parent_id}</td>
                <td className="ago">{process.first_seen}</td>
                <td className="n">{process.call_count.toLocaleString('en-US')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function CapeDetail() {
  const { first } = Route.useLoaderData()
  const { sha } = Route.useParams()
  const resolved = useResolved(first)
  const run: CapeRun | null | 'missing' = resolved === undefined ? null : resolved ?? 'missing'

  if (run === 'missing') {
    return <InvestigateHeader label="Evidence" title={sha.slice(0, 24)} subtitle="No CAPE result found for this hash." />
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
              <span className={failed ? 'badge badge--danger' : 'badge badge--muted'}>exit {run.exit_status || 'n/a'}</span>
              <Link className="chip" to="/payload-workbench/results" search={{ hash: sha }} hash="workbench-builder">
                unified analysis workbench →
              </Link>
              <Link className="chip" to="/payload-analysis/$hash" params={{ hash: sha }}>
                static analysis →
              </Link>
              <Link className="chip" to="/events" search={{ shasum: sha }}>
                related events →
              </Link>
              <a className="chip" href={`/api/v1/cape/${encodeURIComponent(sha)}/raw`} target="_blank" rel="noopener noreferrer">
                raw report (JSON) ↓
              </a>
              <Link className="chip" to="/cape">← all runs</Link>
            </>
          ) : undefined
        }
      />
      {run === null ? (
        <div className="card wide">
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </div>
      ) : (
        <>
          {failed ? (
            <div className="card wide">
              <h2>This run did not complete</h2>
              <p>{run.error || 'The worker reported a failure with no detail.'}</p>
            </div>
          ) : (
            <>
              <div className="metric-grid">
                <div className="metric">
                  <div className={`metric__value${(run.score ?? 0) > 0 ? ' text-danger' : ''}`}>{scoreDisplay(run.score)}</div>
                  <div className="metric__label">Malscore</div>
                </div>
                <div className="metric">
                  <div className="metric__value">{run.cape_status}</div>
                  <div className="metric__label">Task status</div>
                </div>
                <div className="metric">
                  <div className="metric__value">{run.signatures.length}</div>
                  <div className="metric__label">Signatures</div>
                </div>
                <div className="metric">
                  <div className="metric__value">{summary ? summary.processes.length : 0}</div>
                  <div className="metric__label">Processes traced</div>
                </div>
              </div>

              <div className="section-heading">
                <div>
                  <h2>Run identity</h2>
                  <p>What was submitted, to which guest, and how the task itself went.</p>
                </div>
              </div>
              <div className="card wide">
                <h2>Task identity</h2>
                <table className="data-table">
                  <tbody>
                    <tr>
                      <td>SHA-256</td>
                      <td className="v">{run.sha256}</td>
                    </tr>
                    <tr>
                      <td>task ID</td>
                      <td className="v">{run.task_id ?? '—'}</td>
                    </tr>
                    <tr>
                      <td>requested</td>
                      <td className="v">{run.requested_at}</td>
                    </tr>
                    <tr>
                      <td>started</td>
                      <td className="v">{run.started_at}</td>
                    </tr>
                    <tr>
                      <td>completed</td>
                      <td className="v">{run.completed_at}</td>
                    </tr>
                    <tr>
                      <td>exit status</td>
                      <td className="v">{run.exit_status}</td>
                    </tr>
                    <tr>
                      <td>CAPE task status</td>
                      <td className="v">{run.cape_status}</td>
                    </tr>
                    <tr>
                      <td>route</td>
                      <td className="v">{run.route}</td>
                    </tr>
                    {summary ? (
                      <>
                        <tr>
                          <td>machine</td>
                          <td className="v">{summary.machine}</td>
                        </tr>
                        <tr>
                          <td>package</td>
                          <td className="v">{summary.package}</td>
                        </tr>
                        <tr>
                          <td>duration</td>
                          <td className="v">
                            {summary.duration} seconds{summary.timeout ? ' (hit its own analysis timeout)' : ''}
                          </td>
                        </tr>
                      </>
                    ) : null}
                  </tbody>
                </table>
              </div>

              {run.signatures.length ? (
                <div className="card wide">
                  <h2>Signatures</h2>
                  <p className="note">
                    CAPE's own behavioral signature matches — a signature firing means code matching a known pattern ran, not
                    necessarily that the sample is malicious.
                  </p>
                  <div className="card__scroll">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>severity</th>
                          <th>name</th>
                          <th>description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {run.signatures.map((signature, index) => (
                          <tr key={`${signature.name}-${index}`}>
                            <td>
                              <span className="badge badge--muted">{String(signature.severity)}</span>
                            </td>
                            <td className="v">{signature.name}</td>
                            <td className="v">{signature.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
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
                    <div className="card wide">
                      <h2>Behavior summary</h2>
                      <p className="note">
                        Deduplicated files, registry keys, mutexes and similar CAPE observed across every traced process. Large
                        categories (registry keys especially) are common and not by themselves a finding.
                      </p>
                      {summary.summary_keys.map((key) =>
                        summary.summary[key]?.length ? (
                          <div className="card__row" key={key}>
                            <span className="card__label">{key}</span>
                            <span className="card__value card__value--mono">{summary.summary[key].length}</span>
                          </div>
                        ) : null,
                      )}
                    </div>
                  ) : null}

                  <div className="card wide">
                    <h2>Dumped payloads &amp; extracted configuration</h2>
                    {summary.payloads.length || summary.configs.length ? (
                      <>
                        <p className="note">
                          Files CAPE's own debugger-driven unpacking dumped mid-execution, and any malware configuration it
                          extracted from them — CAPE's own YARA-triggered dynamic bypass mechanism at work, not static
                          analysis.
                        </p>
                        {summary.payloads.length ? <p className="note">{summary.payloads.length} payload(s) dumped.</p> : null}
                        {summary.configs.length ? <p className="note">{summary.configs.length} configuration(s) extracted.</p> : null}
                      </>
                    ) : (
                      <p className="empty">CAPE's debugger did not dump any payloads or extract any malware configuration during this run.</p>
                    )}
                  </div>

                  <div className="card wide">
                    <h2>Analyzer log</h2>
                    <p className="note">
                      The in-guest analyzer's own operational log, not a per-instruction trace. See Process activity above for
                      the execution summary.
                    </p>
                    {summary.debug_errors.length ? (
                      <p className="note text-danger">{summary.debug_errors.length} analyzer error(s) were logged.</p>
                    ) : null}
                    {summary.debug_log ? (
                      <div className="card__scroll" aria-label="Analyzer log output">
                        <pre className="code">{summary.debug_log}</pre>
                      </div>
                    ) : (
                      <p className="empty">No analyzer log was recorded.</p>
                    )}
                  </div>
                </>
              ) : null}
            </>
          )}
        </>
      )}
    </>
  )
}
