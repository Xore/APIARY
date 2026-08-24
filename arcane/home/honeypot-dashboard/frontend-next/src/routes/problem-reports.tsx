// Problem reports — operator-submitted UI problem reports
// (dashboard-problem-reports-v1), with the action trail and API-call
// context in the inspector. Admin-only, matching Go's requireAdmin on
// GET /api/problem-reports — these captures can carry a DOM snapshot and
// recent API bodies, sensitive enough to keep off a regular operator's
// view even though anyone can submit one (see ProblemReportButton.tsx).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { StoreListPage, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/problem-reports?offset=${data.offset}&size=25`)
  })

const setStatus = createServerFn({ method: 'POST' })
  .inputValidator((input: { id: string; status: 'open' | 'triaged' | 'closed' }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF — the Rust tier itself has no admin check.
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/problem-reports/${encodeURIComponent(data.id)}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ status: data.status }),
    })
    if (!response.ok) return { ok: false, error: `Update failed (${response.status}).` }
    return { ok: true }
  })

const STATUS_CYCLE: Record<string, 'open' | 'triaged' | 'closed'> = { open: 'triaged', triaged: 'closed', closed: 'open' }

// The capture shape ProblemReportButton.tsx submits and problem_reports.rs
// stores (post-redaction): console_errors / network_failures as string
// lists, api_calls with request/response bodies, dom_snapshot as one big
// truncated string. Counts render in columns; full content in the inspector.
type ApiCall = { at?: string; method?: string; url?: string; status?: number; request_body?: string; response_body?: string }

function strings(row: StoreRow, key: string): string[] {
  return Array.isArray(row[key]) ? (row[key] as unknown[]).filter((entry): entry is string => typeof entry === 'string') : []
}
function apiCalls(row: StoreRow): ApiCall[] {
  return Array.isArray(row.api_calls) ? (row.api_calls as ApiCall[]) : []
}
function domSnapshot(row: StoreRow): string {
  return typeof row.dom_snapshot === 'string' ? row.dom_snapshot : ''
}

function CaptureContext({ row }: { row: StoreRow }) {
  const consoleErrors = strings(row, 'console_errors')
  const networkFailures = strings(row, 'network_failures')
  const calls = apiCalls(row)
  const snapshot = domSnapshot(row)
  return (
    <>
      {consoleErrors.length ? (
        <>
          <p className="note">Console errors ({consoleErrors.length})</p>
          <pre className="hp-md__preview">{consoleErrors.join('\n')}</pre>
        </>
      ) : null}
      {networkFailures.length ? (
        <>
          <p className="note">Network failures ({networkFailures.length})</p>
          <pre className="hp-md__preview">{networkFailures.join('\n')}</pre>
        </>
      ) : null}
      {calls.length ? (
        <>
          <p className="note">API calls ({calls.length})</p>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>at</th>
                  <th>method</th>
                  <th>url</th>
                  <th>status</th>
                  <th>request / response</th>
                </tr>
              </thead>
              <tbody>
                {calls.map((call, index) => (
                  <tr key={`${call.at}-${index}`}>
                    <td>{call.at ? when(call.at) : ''}</td>
                    <td>{call.method || ''}</td>
                    <td className="v">{call.url || ''}</td>
                    <td className="n">{typeof call.status === 'number' && call.status !== 0 ? call.status : '—'}</td>
                    <td className="v">
                      {call.request_body || call.response_body ? (
                        <details>
                          <summary className="lnk">bodies</summary>
                          {call.request_body ? <pre className="hp-md__preview">{call.request_body}</pre> : null}
                          {call.response_body ? <pre className="hp-md__preview">{call.response_body}</pre> : null}
                        </details>
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
      ) : null}
      {snapshot ? (
        <details>
          <summary className="lnk">DOM snapshot ({(snapshot.length / 1024).toFixed(0)} KB, redacted)</summary>
          <pre className="hp-md__preview">{snapshot}</pre>
        </details>
      ) : (
        <p className="note">No DOM snapshot was captured with this report.</p>
      )}
    </>
  )
}

function StatusControl({ row, onChanged }: { row: StoreRow; onChanged: () => void }) {
  const [busy, setBusy] = useState(false)
  const id = str(row, 'id')
  const current = str(row, 'status') || 'open'
  if (!id) return null
  const next = STATUS_CYCLE[current] ?? 'triaged'
  return (
    <button
      className="btn btn-secondary btn-sm"
      type="button"
      disabled={busy}
      onClick={async () => {
        setBusy(true)
        try {
          const result = await setStatus({ data: { id, status: next } })
          if (result.ok) onChanged()
        } finally {
          setBusy(false)
        }
      }}
    >
      {busy ? '…' : `Mark ${next}`}
    </button>
  )
}

const COLUMNS: Column<StoreRow>[] = [
  { header: 'submitted', render: (row) => when(str(row, 'submitted_at')) },
  {
    header: 'status',
    render: (row) => (
      <span className={str(row, 'status') === 'open' ? 'badge badge--warning' : 'badge badge--muted'}>{str(row, 'status')}</span>
    ),
  },
  { header: 'page', className: 'v', primary: true, render: (row) => str(row, 'page') || <span className="text-muted">(unknown page)</span> },
  { header: 'expected', className: 'v', render: (row) => str(row, 'expected') },
  { header: 'actual', className: 'v', render: (row) => str(row, 'actual') },
  { header: 'console', className: 'n', render: (row) => (strings(row, 'console_errors').length || '—') },
  { header: 'network', className: 'n', render: (row) => (strings(row, 'network_failures').length || '—') },
  { header: 'api calls', className: 'n', render: (row) => (apiCalls(row).length || '—') },
  { header: 'snapshot', render: (row) => (domSnapshot(row) ? <span className="badge badge--muted">DOM</span> : '—') },
  { header: 'by', detail: true, render: (row) => str(row, 'submitted_by_name') || str(row, 'submitted_by') },
  { header: 'user agent', detail: true, render: (row) => str(row, 'user_agent') },
  {
    header: 'action trail',
    detail: true,
    render: (row) =>
      Array.isArray(row.action_trail) ? <pre className="hp-md__preview">{(row.action_trail as string[]).join('\n')}</pre> : '',
  },
]

export const Route = createFileRoute('/problem-reports')({
  loader: async () => {
    const { getSessionUser } = await import('../lib/auth')
    return { user: await getSessionUser() }
  },
  component: Page,
})

function Page() {
  const { user } = Route.useLoaderData()
  // Same "no session (dev mode)" posture used everywhere else admin-gating
  // shows up in this port: treat a missing session as admin so local/dev
  // runs aren't blocked.
  const isAdmin = !user || user.role === 'admin'
  const [refreshKey, setRefreshKey] = useState(0)

  if (!isAdmin) {
    return (
      <InvestigateHeader
        label="Operations"
        title="Problem reports"
        subtitle="Admin role required to view submitted problem reports — these captures can include a DOM snapshot and recent API bodies."
      />
    )
  }

  return (
    <StoreListPage
      key={refreshKey}
      fetchPage={fetchPage}
      label="Operations"
      title="Problem reports"
      subtitle="Operator-submitted UI problem reports, with the action trail and request context captured at submit time."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'id')}-${index}`}
      inspectorTitle="Report details"
      chipNoun="reports"
      beforeTable={
        <p className="note">
          Reports submitted via the &quot;Report a problem&quot; button, newest first.
        </p>
      }
      emptyState={{
        title: 'No problem reports submitted yet',
        hint: 'Reports raised from the dashboard are collected here with their full context.',
      }}
      inspectorExtra={(row) => (
        <>
          <StatusControl row={row} onChanged={() => setRefreshKey((key) => key + 1)} />
          <CaptureContext row={row} />
        </>
      )}
      layout="cards"
    />
  )
}
