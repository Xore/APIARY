// Payload analysis — one captured artifact's full picture: inventory
// metadata, hex preview, static analysis, and YARA verdicts, plus the
// three operator actions that queue further work on this same artifact
// (#1608 workstream L): sandbox detonation, Ghidra decompilation, and
// GitHub-analysis publication. Static analysis itself never executes the
// payload; the actions below hand off to the sensor host's own async
// workers (sandbox_submit.rs/ghidra_submit.rs/github_analysis_submit.rs) —
// this page only ever queues a request marker, same trust boundary as
// every other mutation here.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { getSessionUser } from '../lib/auth'
import { useResolved } from '../lib/hooks'
import type { JsonRecord } from '../lib/json'

type PayloadDetail = {
  hash: string
  inventory: JsonRecord | null
  analysis: JsonRecord | null
  yara: JsonRecord[]
  size_bytes: number
  hex_preview: string[]
}

const fetchDetail = createServerFn({ method: 'GET' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<PayloadDetail | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<PayloadDetail>(`/api/v1/payloads/${encodeURIComponent(data.hash)}`)
  })

// #86 Windows golden-image staleness report — informational only.
// sandbox_submit.rs's own submit handler never consults this (it only
// checks classification + spool-dir configuration), so this page doesn't
// gate the Detonate button on it either; it just surfaces the state so a
// detonation that is likely to come back empty isn't a silent surprise.
type GoldenImageStatus = {
  configured: boolean
  built_at?: string
  age_days?: number
  checksum_written?: boolean
  checksum_verified?: boolean
  stale_monthly?: boolean
  stale_iso_eval?: boolean
  checked_at?: string
  error?: string
}

const fetchGoldenImageStatus = createServerFn({ method: 'GET' }).handler(async (): Promise<GoldenImageStatus | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<GoldenImageStatus>('/api/v1/sandbox/golden-image-status')
})

type SubmitResult = { ok: boolean; target?: string; error?: string }

// All three submissions are admin-gated at the BFF, same posture as every
// other mutation in this app (settings.tsx's runServiceAction) — the Rust
// tier's own trust boundary is the service token, so this check is the
// only one that exists.
const submitSandbox = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<SubmitResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/sandbox/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hash: data.hash }),
    })
    const body = await response.json().catch(() => null)
    if (response.ok && body?.queued) {
      return { ok: true, target: typeof body?.target === 'string' ? body.target : undefined }
    }
    return { ok: false, error: body?.error || 'Sandbox submission failed.' }
  })

const submitGhidra = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<SubmitResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/ghidra/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hash: data.hash }),
    })
    const body = await response.json().catch(() => null)
    if (response.ok && body?.queued) return { ok: true }
    return { ok: false, error: body?.error || 'Ghidra submission failed.' }
  })

// github_analysis_submit.rs refuses anything but the literal string
// "publish" in `confirm` and audits every outcome — publication is
// external and irreversible (a public repo + third-party scanners), so
// the operator must have actually confirmed in the UI before this is
// ever called; see the window.confirm in OperatorActionsCard's `publish`
// handler below (same precedent as reports.tsx's DefinitionsCard
// delete-definition flow).
const submitGithubAnalysis = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<SubmitResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/github-analysis/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        hash: data.hash,
        confirm: 'publish',
        actor_subject: user?.sub ?? '',
        actor_username: user?.username ?? '',
      }),
    })
    const body = await response.json().catch(() => null)
    if (response.ok && body?.queued) return { ok: true }
    return { ok: false, error: body?.error || 'GitHub-analysis submission failed.' }
  })

export const Route = createFileRoute('/payload-analysis/$hash')({
  loader: async ({ params }) => ({
    first: fetchDetail({ data: { hash: params.hash } }),
    golden: fetchGoldenImageStatus(),
    user: await getSessionUser(),
  }),
  component: PayloadAnalysis,
})

// Badge + note for the Detonate row, derived from golden-image-status.
// Missing/unreadable/unconfigured is not an error (see golden_image_status
// in sandbox_submit.rs) — no badge at all in that case, same "no news" as
// the legacy sandbox.html detail page shows nothing when GoldenImage is nil.
function goldenImageNote(golden: GoldenImageStatus | null): { cls: string; label: string; detail: string } | null {
  if (!golden || !golden.configured) return null
  if (golden.error) {
    return { cls: 'badge badge--danger', label: 'Golden image missing', detail: golden.error }
  }
  if (golden.stale_iso_eval) {
    return {
      cls: 'badge badge--danger',
      label: `Golden image ${golden.age_days ?? '?'}d old`,
      detail: 'The evaluation ISO it was built from has likely expired (90-day limit) — a full rebuild is due.',
    }
  }
  if (golden.stale_monthly) {
    return {
      cls: 'badge badge--warning',
      label: `Golden image ${golden.age_days ?? '?'}d old`,
      detail: 'Past the monthly rebuild cadence.',
    }
  }
  if (golden.checksum_written && !golden.checksum_verified) {
    return {
      cls: 'badge badge--muted',
      label: 'Checksum unverified',
      detail: 'Not yet verified against a live clone this build.',
    }
  }
  return null
}

function OperatorActionsCard({ hash, golden, editable }: { hash: string; golden: GoldenImageStatus | null; editable: boolean }) {
  const [sandboxBusy, setSandboxBusy] = useState(false)
  const [sandboxMessage, setSandboxMessage] = useState('')
  const [ghidraBusy, setGhidraBusy] = useState(false)
  const [ghidraMessage, setGhidraMessage] = useState('')
  const [githubBusy, setGithubBusy] = useState(false)
  const [githubMessage, setGithubMessage] = useState('')

  const detonate = async () => {
    setSandboxBusy(true)
    setSandboxMessage('')
    try {
      const result = await submitSandbox({ data: { hash } })
      setSandboxMessage(
        result.ok
          ? `Queued${result.target ? ` for the ${result.target} sandbox` : ''} — see the sandbox queue once the job starts.`
          : result.error || 'Sandbox submission failed.',
      )
    } finally {
      setSandboxBusy(false)
    }
  }

  const decompile = async () => {
    setGhidraBusy(true)
    setGhidraMessage('')
    try {
      const result = await submitGhidra({ data: { hash } })
      setGhidraMessage(result.ok ? 'Queued — see the Ghidra results once the job finishes.' : result.error || 'Ghidra submission failed.')
    } finally {
      setGhidraBusy(false)
    }
  }

  const publish = async () => {
    if (
      typeof window !== 'undefined' &&
      !window.confirm(
        'Publish this sample to the public Xore/honeypot repository and third-party scanner APIs?\n\nThis cannot be undone.',
      )
    ) {
      return
    }
    setGithubBusy(true)
    setGithubMessage('')
    try {
      const result = await submitGithubAnalysis({ data: { hash } })
      setGithubMessage(
        result.ok ? 'Queued — see GitHub analysis once it completes.' : result.error || 'GitHub-analysis submission failed.',
      )
    } finally {
      setGithubBusy(false)
    }
  }

  const goldenNote = goldenImageNote(golden)

  return (
    <div className="card wide">
      <h2>Operator actions</h2>
      <p className="note">
        Each action queues asynchronous work on the sensor host — nothing here executes inline. Results appear on the
        sandbox, Ghidra, and GitHub-analysis pages once the matching worker finishes.
      </p>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Action</th>
              <th>Notes</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="v">
                <button
                  className="btn btn-primary btn-sm"
                  type="button"
                  disabled={!editable || sandboxBusy}
                  onClick={detonate}
                >
                  {sandboxBusy ? 'Queuing…' : 'Detonate in sandbox'}
                </button>
              </td>
              <td>
                {goldenNote ? (
                  <>
                    <span className={goldenNote.cls}>{goldenNote.label}</span>{' '}
                    <span className="note">{goldenNote.detail}</span>
                  </>
                ) : (
                  <span className="note">Routes to the Windows or Linux sandbox automatically, based on classification.</span>
                )}
              </td>
              <td className="v">{sandboxMessage ? <span className="note">{sandboxMessage}</span> : '—'}</td>
            </tr>
            <tr>
              <td className="v">
                <button
                  className="btn btn-secondary btn-sm"
                  type="button"
                  disabled={!editable || ghidraBusy}
                  onClick={decompile}
                >
                  {ghidraBusy ? 'Queuing…' : 'Decompile with Ghidra'}
                </button>
              </td>
              <td>
                <span className="note">Headless decompilation — works on any sample with code in it, executes nothing.</span>
              </td>
              <td className="v">{ghidraMessage ? <span className="note">{ghidraMessage}</span> : '—'}</td>
            </tr>
            <tr>
              <td className="v">
                <button
                  className="btn btn-danger btn-sm"
                  type="button"
                  disabled={!editable || githubBusy}
                  onClick={publish}
                >
                  {githubBusy ? 'Publishing…' : 'Submit for GitHub analysis'}
                </button>
              </td>
              <td>
                <span className="note">Publishes the sample to the public Xore/honeypot repository and third-party scanners.</span>
              </td>
              <td className="v">{githubMessage ? <span className="note">{githubMessage}</span> : '—'}</td>
            </tr>
          </tbody>
        </table>
      </div>
      {!editable ? <p className="note">Admin role required to submit for analysis.</p> : null}
    </div>
  )
}

function PayloadAnalysis() {
  const { first, golden, user } = Route.useLoaderData()
  const { hash } = Route.useParams()
  const resolvedDetail = useResolved(first)
  const detail: PayloadDetail | null | 'missing' = resolvedDetail === undefined ? null : resolvedDetail ?? 'missing'
  const goldenStatus: GoldenImageStatus | null = useResolved(golden) ?? null

  // Same "no session (dev mode)" posture as settings.tsx: treat a missing
  // session as admin so local/dev runs aren't blocked, and gate on role
  // once a real session exists.
  const isAdmin = !user || user.role === 'admin'

  if (detail === 'missing') {
    return (
      <InvestigateHeader
        label="Evidence"
        title="Payload analysis"
        subtitle={`No analysis found for ${hash.slice(0, 24)}…`}
      />
    )
  }

  const inventory = detail && detail.inventory ? detail.inventory : null
  const kind = inventory && typeof inventory.Kind === 'string' ? inventory.Kind : ''

  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title="Payload analysis"
        subtitle="Static analysis of one captured artifact — metadata, bytes, strings and rule matches. The payload is never executed here."
        chips={
          detail ? (
            <>
              <span className="chip"><code>{detail.hash.slice(0, 32)}</code></span>
              {kind ? <span className="badge badge--muted">{kind}</span> : null}
              <span className="chip">{(detail.size_bytes / 1024).toFixed(1)} KB</span>
              <a
                className="chip"
                href={`https://www.virustotal.com/gui/search/${encodeURIComponent(detail.hash)}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                VirusTotal →
              </a>
              {isAdmin ? (
                <a className="chip" href={`/api/payload/${encodeURIComponent(detail.hash)}/download`}>
                  Download sample ↓
                </a>
              ) : null}
              <Link className="chip" to="/payloads">← all payloads</Link>
            </>
          ) : undefined
        }
      />
      {detail === null ? (
        <div className="card wide">
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </div>
      ) : (
        <>
          <OperatorActionsCard hash={detail.hash} golden={goldenStatus} editable={isAdmin} />
          {detail.hex_preview.length > 0 ? (
            <div className="card wide">
              <h2>Hex preview — first 512 bytes</h2>
              <div className="card__scroll">
                <pre className="code">{detail.hex_preview.join('\n')}</pre>
              </div>
            </div>
          ) : null}
          {detail.analysis ? (
            <div className="card wide">
              <h2>Static analysis</h2>
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(detail.analysis, null, 2)}</pre>
              </div>
            </div>
          ) : null}
          {detail.yara.length > 0 ? (
            <div className="card wide">
              <h2>YARA verdicts</h2>
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(detail.yara, null, 2)}</pre>
              </div>
            </div>
          ) : null}
          {inventory ? (
            <div className="card wide">
              <h2>Inventory record</h2>
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(inventory, null, 2)}</pre>
              </div>
            </div>
          ) : null}
        </>
      )}
    </>
  )
}
