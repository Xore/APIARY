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
import { useEffect, useRef, useState } from 'react'
import { confirmAction } from '../components/ConfirmDialog'
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

// Re-analyze (github_analysis.html:94's /github-analysis/submit form):
// resubmits the sample for GitHub publication and scanning. Same request
// shape as payloads.tsx's submitGithubAnalysis — confirm:'publish' is the
// backend's explicit-consent gate, actor fields feed the audit log.
const resubmitAnalysis = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
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

// Report viewer (#309, hp-github-analysis.js): one application-managed
// centered overlay per page, same .modal/.pdf-viewer-modal shape as the
// reports-studio viewer. Focus moves to the close button on open, Tab
// cycles inside the dialog, Escape and backdrop clicks close, and focus
// returns to the trigger card (the caller's DOM) on unmount. The iframe is
// sandboxed — view_url is third-party content (raw.githubusercontent.com).
function ReportViewer({ url, onClose }: { url: string; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLElement>(null)
  useEffect(() => {
    const previous = document.activeElement
    closeRef.current?.focus()
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }
      if (event.key !== 'Tab' || !panelRef.current) return
      const focusables = panelRef.current.querySelectorAll<HTMLElement>('button, iframe')
      if (!focusables.length) return
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus()
    }
  }, [onClose])
  return (
    <>
      <div className="modal-backdrop open" aria-hidden="true" onClick={onClose} />
      <section className="modal pdf-viewer-modal open" role="dialog" aria-modal="true" aria-label="Report" ref={panelRef}>
        <button className="modal__close" type="button" aria-label="Close report viewer" onClick={onClose} ref={closeRef}>
          ✕
        </button>
        <h2 className="pdf-viewer-title">Report</h2>
        <iframe
          className="pdf-viewer-frame"
          title="GitHub analysis report preview"
          src={url}
          sandbox="allow-scripts allow-same-origin allow-downloads"
        />
      </section>
    </>
  )
}

function scannerBadge(scanner: Scanner) {
  if (!scanner.ok) return <span className="badge badge--muted text-danger">failed{scanner.error ? `: ${scanner.error}` : ''}</span>
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
  const [queued, setQueued] = useState(false)
  const [viewerOpen, setViewerOpen] = useState(false)

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
              <a className="chip" href={`/api/raw-report/github-analysis/${encodeURIComponent(sha)}`} target="_blank" rel="noopener noreferrer">
                report ↓
              </a>
              <Link className="chip" to="/github-analysis">← all runs</Link>
              {/* github_analysis.html:94's Re-analyze form, with its exact
                  data-hp-confirm-* publication wording — publication to the
                  public repo is irreversible, hence the danger dialog. */}
              <button
                className="btn btn-sm btn-danger"
                type="button"
                title="Resubmit this sample for GitHub publication and scanning"
                onClick={() =>
                  confirmAction({
                    title: 'Publish to Xore/honeypot?',
                    description: 'This uploads the sample to the public Xore/honeypot repository and to third-party scanner APIs.',
                    warning: 'This cannot be undone.',
                    confirmLabel: 'Publish sample',
                    onConfirm: async () => {
                      const result = await resubmitAnalysis({ data: { hash: sha } })
                      if (!result.ok) throw new Error(result.error || 'Submission failed.')
                      setQueued(true)
                      return 'Publication queued.'
                    },
                  })
                }
              >
                Re-analyze
              </button>
            </>
          ) : undefined
        }
      />
      {queued ? (
        <div className="alert alert--success" role="status">
          Publication queued. This page updates once the host-side collector resolves a result.
        </div>
      ) : null}
      {run === null ? (
        <div className="card wide">
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </div>
      ) : (
        <>
          {note ? (
            <div className={`alert alert--${note.tone === 'red' ? 'danger' : 'warning'}`} role={note.tone === 'red' ? 'alert' : 'status'}>
              {note.render(run)}
            </div>
          ) : null}

          <div className="metric-grid">
            <div className="metric">
              <div className={`metric__value${run.verdict?.malicious ? ' text-danger' : ''}`}>
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
            <div className="dashboard-panel">
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
                                  <a className="btn btn-secondary btn-sm" href={scanner.permalink} target="_blank" rel="noopener noreferrer">
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
            <div className="dashboard-panel">
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
            <div className="dashboard-panel">
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
                      <ul className="">
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
                  // github_analysis.html's Report project-card (#309): a real
                  // <button> here, so the template's hand-rolled Enter/Space
                  // handling comes for free; opens the in-page viewer modal.
                  <div className="project-grid">
                    <button type="button" className="project-card" aria-label="View PDF report" onClick={() => setViewerOpen(true)}>
                      <div className="project-card__header">
                        <span className="project-card__icon">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                            <line x1="16" y1="13" x2="8" y2="13" />
                            <line x1="16" y1="17" x2="8" y2="17" />
                          </svg>
                        </span>
                        <span className="project-card__title">PDF report</span>
                      </div>
                      <p className="project-card__desc">The rendered PDF report from the upstream repository.</p>
                      <div className="project-card__meta">
                        <span>completed {run.completed_at}</span>
                      </div>
                    </button>
                  </div>
                ) : (
                  <>
                    <p className="note">No PDF has been generated for this analysis yet — this downloads the JSON record instead.</p>
                    <a className="btn btn-ghost btn-sm" href={`/api/raw-report/github-analysis/${encodeURIComponent(sha)}`} target="_blank" rel="noopener noreferrer">
                      download JSON ↓
                    </a>
                  </>
                )}
              </div>
            </div>
          ) : null}

          {viewerOpen && run.view_url ? <ReportViewer url={run.view_url} onClose={() => setViewerOpen(false)} /> : null}
        </>
      )}
    </>
  )
}
