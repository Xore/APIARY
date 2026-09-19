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
import { Badge } from '../components/ui/badge'
import { Button, buttonVariants } from '../components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'

const fetchPage = createServerFn({ method: 'GET' })
  .validator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/problem-reports?offset=${data.offset}&size=25`)
  })

const setStatus = createServerFn({ method: 'POST' })
  .validator((input: { id: string; status: 'open' | 'triaged' | 'closed' }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF — the Rust tier itself has no admin check.
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
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
          <p className="text-sm font-medium">Console errors ({consoleErrors.length})</p>
          <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">{consoleErrors.join('\n')}</pre>
        </>
      ) : null}
      {networkFailures.length ? (
        <>
          <p className="text-sm font-medium">Network failures ({networkFailures.length})</p>
          <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">{networkFailures.join('\n')}</pre>
        </>
      ) : null}
      {calls.length ? (
        <>
          <p className="text-sm font-medium">API calls ({calls.length})</p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>at</TableHead>
                  <TableHead>method</TableHead>
                  <TableHead>url</TableHead>
                  <TableHead>status</TableHead>
                  <TableHead>request / response</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {calls.map((call, index) => (
                  <TableRow key={`${call.at}-${index}`}>
                    <TableCell>{call.at ? when(call.at) : ''}</TableCell>
                    <TableCell>{call.method || ''}</TableCell>
                    <TableCell className="max-w-xs break-all">{call.url || ''}</TableCell>
                    <TableCell className="tabular-nums">{typeof call.status === 'number' && call.status !== 0 ? call.status : '—'}</TableCell>
                    <TableCell>
                      {call.request_body || call.response_body ? (
                        <details>
                          {/* #1898: was .lnk, which promises navigation --
                              this expands in place. A summary is a control
                              that acts, so it takes the quietest button
                              tone rather than link styling. */}
                          <summary className={buttonVariants({ variant: 'ghost', size: 'sm' })}>bodies</summary>
                          {call.request_body ? <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">{call.request_body}</pre> : null}
                          {call.response_body ? <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">{call.response_body}</pre> : null}
                        </details>
                      ) : (
                        '—'
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
        </>
      ) : null}
      {snapshot ? (
        <details>
          <summary className={buttonVariants({ variant: 'ghost', size: 'sm' })}>
            DOM snapshot ({(snapshot.length / 1024).toFixed(0)} KB, redacted)
          </summary>
          <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap break-all">{snapshot}</pre>
        </details>
      ) : (
        <p className="text-sm text-muted-foreground">No DOM snapshot was captured with this report.</p>
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
    <Button
      variant="secondary"
      size="sm"
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
    </Button>
  )
}

const COLUMNS: Column<StoreRow>[] = [
  { header: 'submitted', render: (row) => when(str(row, 'submitted_at')) },
  {
    header: 'status',
    render: (row) => (
      <Badge variant={str(row, 'status') === 'open' ? 'default' : 'secondary'}>{str(row, 'status')}</Badge>
    ),
  },
  { header: 'page', className: 'v', primary: true, render: (row) => str(row, 'page') || <span className="text-muted-foreground">(unknown page)</span> },
  { header: 'expected', className: 'v', render: (row) => str(row, 'expected') },
  { header: 'actual', className: 'v', render: (row) => str(row, 'actual') },
  { header: 'console', className: 'n', render: (row) => (strings(row, 'console_errors').length || '—') },
  { header: 'network', className: 'n', render: (row) => (strings(row, 'network_failures').length || '—') },
  { header: 'api calls', className: 'n', render: (row) => (apiCalls(row).length || '—') },
  { header: 'snapshot', render: (row) => (domSnapshot(row) ? <Badge variant="secondary">DOM</Badge> : '—') },
  { header: 'by', detail: true, render: (row) => str(row, 'submitted_by_name') || str(row, 'submitted_by') },
  { header: 'user agent', detail: true, render: (row) => str(row, 'user_agent') },
  {
    header: 'action trail',
    detail: true,
    render: (row) =>
      Array.isArray(row.action_trail) ? <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 font-mono text-xs whitespace-pre-wrap">{JSON.stringify(row.action_trail, null, 2)}</pre> : '',
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
  // UI-side gate only — the server functions behind these controls fail
  // closed on both session and role (#2123); dev mode gets its fixture
  // operator from getSessionUser's OIDC_DISABLED branch, not from here.
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
      pageSize={25}
      label="Operations"
      title="Problem reports"
      subtitle="Operator-submitted UI problem reports, with the action trail and request context captured at submit time."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'id')}-${index}`}
      inspectorTitle="Report details"
      chipNoun="reports"
      beforeTable={
        <p className="text-sm text-muted-foreground">
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
