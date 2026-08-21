// Dead letters — pipeline documents that failed classification
// (dead-letter-honeypot). Empty is the healthy state. Ports
// dashboard/ui/dead_letters.html: a free-text Lucene query box (elastic.go's
// deadLetters) plus an admin-gated "purge shown" destructive action
// (purgeDeadLetters) scoped to that same query — never a silently broader
// unfiltered set unless the query box is empty.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { confirmAction } from '../components/ConfirmDialog'
import { InvestigateHeader, MasterDetailTable } from '../components/Investigate'
import { str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number; q: string }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const params = new URLSearchParams({ offset: String(data.offset), size: '25' })
    if (data.q.trim()) params.set('q', data.q.trim())
    return serviceJSON<StorePage>(`/api/v1/store/dead-letters?${params.toString()}`)
  })

const purgeDeadLetters = createServerFn({ method: 'POST' })
  .inputValidator((input: { q: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; deleted?: number; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF — the Rust tier itself has no admin check.
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const params = new URLSearchParams()
    if (data.q.trim()) params.set('q', data.q.trim())
    const response = await serviceFetch(`/api/v1/store/dead-letters?${params.toString()}`, { method: 'DELETE' })
    if (!response.ok) return { ok: false, error: `Purge failed (${response.status}).` }
    const body = (await response.json().catch(() => ({}))) as { deleted?: number }
    return { ok: true, deleted: body.deleted ?? 0 }
  })

const COLUMNS: Column<StoreRow>[] = [
  { header: 'time', render: (row) => when(str(row, '@timestamp')) },
  { header: 'reason', className: 'v', render: (row) => str(row, 'reason') || str(row, 'error') },
  { header: 'source', className: 'v', render: (row) => str(row, 'logset') || str(row, 'pipeline') },
]

export const Route = createFileRoute('/dead-letters')({
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

  const [rows, setRows] = useState<StoreRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  const [queryInput, setQueryInput] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [purging, setPurging] = useState(false)
  const [message, setMessage] = useState('')

  const load = useCallback((q: string) => {
    setRows(null)
    fetchPage({ data: { offset: 0, q } }).then((page) => {
      setRows(page?.rows ?? [])
      setTotal(page?.total ?? 0)
    })
  }, [])

  useEffect(() => {
    load(appliedQuery)
  }, [load, appliedQuery])

  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await fetchPage({ data: { offset: rows.length, q: appliedQuery } })
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore, appliedQuery])

  const runSearch = () => setAppliedQuery(queryInput)

  const purge = () => {
    const q = queryInput.trim()
    const scope = q ? `matching "${q}"` : 'every retained dead letter (no query is set)'
    // Themed confirm (hp-modals contract) instead of window.confirm —
    // a destructive delete states its exact scope before running (#1653).
    confirmAction({
      title: 'Purge dead letters?',
      description: 'Removes the retained un-ingestable records from Elasticsearch so the backlog count resets.',
      warning: `Permanently deletes ${scope}. This cannot be undone.`,
      confirmLabel: 'Purge',
      onConfirm: () => void doPurge(q),
    })
  }

  const doPurge = async (q: string) => {
    setPurging(true)
    setMessage('')
    try {
      const result = await purgeDeadLetters({ data: { q } })
      if (result.ok) {
        setMessage(`${result.deleted ?? 0} dead letter${result.deleted === 1 ? '' : 's'} purged.`)
        load(appliedQuery)
      } else {
        setMessage(result.error || 'Purge failed.')
      }
    } finally {
      setPurging(false)
    }
  }

  return (
    <>
      <InvestigateHeader
        label="Operations"
        title="Dead letters"
        subtitle="Documents Elasticsearch rejected, with their original error and field shape for remediation. An empty list is the healthy state."
        chips={
          <>
            <span className="chip">{total.toLocaleString('en-US')} documents</span>
            <input
              className="search"
              placeholder="optional Elasticsearch query"
              aria-label="Dead-letter query"
              value={queryInput}
              onChange={(event) => setQueryInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') runSearch()
              }}
            />
            <button className="copy" type="button" onClick={runSearch}>
              search
            </button>
            {isAdmin ? (
              <button className="btn btn-sm btn-danger" type="button" onClick={purge} disabled={purging}>
                {purging ? 'purging…' : 'purge shown'}
              </button>
            ) : null}
          </>
        }
      />
      {message ? (
        <p className="note" role="status" aria-live="polite">
          {message}
        </p>
      ) : null}
      <MasterDetailTable
        rows={rows}
        columns={COLUMNS}
        rowKey={(_, index) => String(index)}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Dead letter"
      />
    </>
  )
}
