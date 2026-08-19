// GitHub-analysis detail — one sample's publication to the public
// Xore/honeypot analysis repository and third-party scanner pipeline.
// Ports dashboard/ui/github_analysis.html's "github-analysis-detail-body"
// block: exit-status banner (dry_run/denylist_blocked/quota_exceeded/
// timeout/failed/error each read differently), detections/risk/family/
// auto-YARA metrics, and three tabs — Verdict (per-scanner results),
// Provenance (the publication record), Artifacts (auto-generated YARA
// rules + the PDF report or a JSON fallback).
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { useResolved } from '../lib/hooks'

type Scanner = { source: string; ok: boolean; positives?: number; total?: number; suspicious?: boolean; permalink?: string; error?: string }
type Verdict = { malicious: number; suspicious: number; total: number; level: string }

type GithubAnalysisRun = {
  sha256: string
  requested_at: string
  started_at?: string
  completed_at: string
  exit_status: string
  reason?: string
  daily_cap?: number
  error?: string
  commit?: string
  report_commit?: string
  run_id?: number
  run_url?: string
  sample_path?: string
  family?: string
  verdict?: Verdict
  scanners?: Scanner[]
  yara_auto_rules?: string[]
  report_pdf?: string
  requested_by: string
  view_url: string | null
}

const fetchRun = createServerFn({ method: 'GET' })
  .inputValidator((input: { sha: string }) => input)
  .handler(async ({ data }): Promise<GithubAnalysisRun | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<GithubAnalysisRun>(`/api/v1/github-analysis/${encodeURIComponent(data.sha)}`)
  })

export const Route = createFileRoute('/github-analysis/$sha')({
  loader: async ({ params }) => ({ first: fetchRun({ data: { sha: params.sha } }) }),
  component: GithubAnalysisDetail,
})

const STATUS_NOTES: Record<string, { tone: 'orange' | 'red'; render: (run: GithubAnalysisRun) => string }> = {
  dry_run: {
    tone: 'orange',
    render: () => 'Dry run. GITHUB_PUBLISH_ENABLED is not set to 1 on the host, so this request was resolved without actually publishing anything.',
  },
  denylist_blocked: {
    tone: 'red',
    render: (run) => `Blocked by the publishing denylist. ${run.reason || 'No reason was recorded.'}`,
  },
  quota_exceeded: {
    tone: 'orange',
    render: (run) =>
      `Daily publish quota exceeded. ${run.daily_cap ? `The cap is ${run.daily_cap} publications per day. ` : ''}This sample was not published; resubmit tomorrow or raise GITHUB_ANALYSIS_DAILY_CAP.`,
  },
  timeout: {
    tone: 'red',
    render: () => "Timed out waiting for the Actions run. The scanner workflow did not conclude before GITHUB_ANALYSIS_MAX_WAIT elapsed.",
  },
  failed: {
    tone: 'red',
    render: (run) => (run.run_url ? 'The Actions run did not succeed. Check the workflow run for details.' : 'The Actions run did not succeed. No run URL was recorded.'),
  },
  error: {
    tone: 'red',
    render: (run) => `Publishing failed. ${run.error || 'The publisher reported a failure with no detail.'}`,
  },
}

function scannerBadge(scanner: Scanner) {
  if (!scanner.ok) return <span className="badge badge--muted tw:text-red">failed{scanner.error ? `: ${scanner.error}` : ''}</span>
  if ((scanner.positives ?? 0) > 0) return <span className="badge badge--red">detected</span>
  if (scanner.suspicious) return <span className="badge badge--muted">suspicious</span>
  return <span className="badge badge--muted">clean</span>
}

function GithubAnalysisDetail() {
  const { first } = Route.useLoaderData()
  const { sha } = Route.useParams()
  const resolved = useResolved(first)
  const run: GithubAnalysisRun | null | 'missing' = resolved === undefined ? null : resolved ?? 'missing'
  const [tab, setTab] = useState<'verdict' | 'provenance' | 'artifacts'>('verdict')

  if (run === 'missing') {
    return <InvestigateHeader label="Evidence" title={sha.slice(0, 24)} subtitle="No GitHub-analysis result found for this hash." />
  }
  const note = run ? STATUS_NOTES[run.exit_status] : undefined

  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title={`GitHub analysis — ${sha.slice(0, 24)}…`}
        subtitle="A published sample's multi-engine scanner verdict from the public Xore/honeypot analysis repository."
        chips={
          run ? (
            <>
              <Link className="chip" to="/payload-analysis/$hash" params={{ hash: sha }}>
                static analysis →
              </Link>
              <Link className="chip" to="/events" search={{ shasum: sha }}>
                related events →
              </Link>
              {run.commit ? (
                <a className="chip" href={`https://github.com/Xore/honeypot/commit/${run.commit}`} target="_blank" rel="noopener noreferrer">
                  pushed commit ↗
                </a>
              ) : null}
              {run.run_url ? (
                <a className="chip" href={run.run_url} target="_blank" rel="noopener noreferrer">
                  Actions run ↗
                </a>
              ) : null}
              <a className="chip" href={`/api/v1/github-analysis/${encodeURIComponent(sha)}`} target="_blank" rel="noopener noreferrer">
                report ↓
              </a>
              <Link className="chip" to="/github-analysis">← all runs</Link>
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
          {note ? (
            <div className={`tw:mb-6 tw:rounded-lg tw:border tw:border-${note.tone} tw:bg-${note.tone}-subtle tw:px-4 tw:py-4${note.tone === 'red' ? ' tw:text-red' : ''}`} role={note.tone === 'red' ? 'alert' : 'status'}>
              {note.render(run)}
            </div>
          ) : null}

          <div className="tw:grid tw:grid-cols-2 tw:sm:grid-cols-4 tw:gap-3 tw:mb-6">
            <div className="metric">
              <div className={`metric__value${run.verdict?.malicious ? ' tw:text-red' : ''}`}>
                {run.verdict ? `${run.verdict.malicious} / ${run.verdict.total}` : '—'}
              </div>
              <div className="metric__label">Detections</div>
            </div>
            <div className="metric">
              <div className="metric__value metric__value--text">{run.verdict?.level || 'unscored'}</div>
              <div className="metric__label">Risk level</div>
            </div>
            <div className="metric">
              <div className="metric__value metric__value--text">{run.family || 'unknown'}</div>
              <div className="metric__label">Family</div>
            </div>
            <div className="metric">
              <div className="metric__value">{run.yara_auto_rules?.length ?? 0}</div>
              <div className="metric__label">Auto YARA rules</div>
            </div>
          </div>

          <div className="tabs" role="tablist" aria-label="GitHub analysis sections">
            {(['verdict', 'provenance', 'artifacts'] as const).map((key, index) => (
              <button
                key={key}
                className={tab === key ? 'tab active' : 'tab'}
                type="button"
                role="tab"
                aria-selected={tab === key}
                onClick={() => setTab(key)}
              >
                <span>0{index + 1}</span>
                {key[0].toUpperCase()}
                {key.slice(1)}
              </button>
            ))}
          </div>

          {tab === 'verdict' ? (
            <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5">
              <div className="section-heading">
                <div>
                  <h2>What the scanners found</h2>
                  <p>Per-scanner results from the third-party pipeline the published sample was scored against.</p>
                </div>
              </div>
              <div className="card wide">
                <h2>Scanner results</h2>
                {run.scanners?.length ? (
                  <>
                    <p className="note">A scanner that failed to run is shown as failed, not omitted — a missing row would silently understate coverage.</p>
                    <div className="card__scroll">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>scanner</th>
                            <th>result</th>
                            <th>detections</th>
                            <th>link</th>
                          </tr>
                        </thead>
                        <tbody>
                          {run.scanners.map((scanner, index) => (
                            <tr key={`${scanner.source}-${index}`}>
                              <td className="v">{scanner.source}</td>
                              <td>{scannerBadge(scanner)}</td>
                              <td className="n">{scanner.ok ? `${scanner.positives ?? 0} / ${scanner.total ?? 0}` : '—'}</td>
                              <td className="v">
                                {scanner.permalink ? (
                                  <a className="lnk" href={scanner.permalink} target="_blank" rel="noopener noreferrer">
                                    report ↗
                                  </a>
                                ) : (
                                  '—'
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                ) : (
                  <p className="empty">No scanner results are recorded for this analysis.</p>
                )}
              </div>
            </div>
          ) : null}

          {tab === 'provenance' ? (
            <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5">
              <div className="section-heading">
                <div>
                  <h2>Where this came from</h2>
                  <p>The publication that produced this result: who requested it, what was pushed, and when.</p>
                </div>
              </div>
              <div className="card wide">
                <h2>Publication record</h2>
                <div className="card__scroll">
                  <table className="data-table">
                    <tbody>
                      <tr>
                        <td>SHA-256</td>
                        <td className="v">{run.sha256}</td>
                      </tr>
                      <tr>
                        <td>requested</td>
                        <td className="v">{run.requested_at}</td>
                      </tr>
                      <tr>
                        <td>started</td>
                        <td className="v">{run.started_at || '—'}</td>
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
                        <td>requesting admin</td>
                        <td className="v">{run.requested_by || 'not recorded'}</td>
                      </tr>
                      <tr>
                        <td>pushed commit</td>
                        <td className="v">{run.commit ? <code>{run.commit}</code> : '—'}</td>
                      </tr>
                      <tr>
                        <td>sample path upstream</td>
                        <td className="v">{run.sample_path ? <code>{run.sample_path}</code> : '—'}</td>
                      </tr>
                      <tr>
                        <td>Actions run</td>
                        <td className="v">
                          {run.run_url ? (
                            <a className="lnk" href={run.run_url} target="_blank" rel="noopener noreferrer">
                              {run.run_url}
                            </a>
                          ) : (
                            '—'
                          )}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : null}

          {tab === 'artifacts' ? (
            <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5">
              <div className="section-heading">
                <div>
                  <h2>What the pipeline produced</h2>
                  <p>Auto-generated detection content and the downloadable report.</p>
                </div>
              </div>
              <div className="card wide">
                <h2>Auto-generated YARA rules</h2>
                {run.yara_auto_rules?.length ? (
                  <>
                    <p className="note">
                      {run.yara_auto_rules.length} rule file{run.yara_auto_rules.length !== 1 ? 's' : ''} in the upstream repository
                      reference this sample's hash.
                    </p>
                    <div className="card__scroll">
                      <ul className="tw:list-disc tw:pl-5">
                        {run.yara_auto_rules.map((rule) => (
                          <li key={rule}>
                            <code>{rule}</code>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </>
                ) : (
                  <p className="empty">No auto-generated YARA rules reference this sample.</p>
                )}
              </div>
              <div className="card wide">
                <h2>Report</h2>
                {run.view_url ? (
                  <>
                    <p className="note">The rendered PDF report from the upstream repository, completed {run.completed_at}.</p>
                    <a className="lnk" href={run.view_url} target="_blank" rel="noopener noreferrer">
                      view PDF report ↗
                    </a>
                  </>
                ) : (
                  <>
                    <p className="note">No PDF has been generated for this analysis yet — this downloads the JSON record instead.</p>
                    <a className="lnk" href={`/api/v1/github-analysis/${encodeURIComponent(sha)}`} target="_blank" rel="noopener noreferrer">
                      download JSON ↓
                    </a>
                  </>
                )}
              </div>
            </div>
          ) : null}
        </>
      )}
    </>
  )
}
