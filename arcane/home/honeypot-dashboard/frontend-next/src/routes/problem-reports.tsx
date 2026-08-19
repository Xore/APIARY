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
  { header: 'page', className: 'v', render: (row) => str(row, 'page') },
  { header: 'expected', className: 'v', render: (row) => str(row, 'expected') },
  { header: 'actual', className: 'v', render: (row) => str(row, 'actual') },
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
      inspectorExtra={(row) => <StatusControl row={row} onChanged={() => setRefreshKey((key) => key + 1)} />}
    />
  )
}
