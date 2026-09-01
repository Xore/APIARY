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
import { ErrorStateBlock } from '../components/ErrorState'
import { str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

const fetchPage = createServerFn({ method: 'GET' })
  .validator((input: { offset: number; q: string }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const params = new URLSearchParams({ offset: String(data.offset), size: '25' })
    if (data.q.trim()) params.set('q', data.q.trim())
    return serviceJSON<StorePage>(`/api/v1/store/dead-letters?${params.toString()}`)
  })

const purgeDeadLetters = createServerFn({ method: 'POST' })
  .validator((input: { q: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; deleted?: number; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF — the Rust tier itself has no admin check.
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
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
  // UI-side gate only — the server functions behind these buttons fail
  // closed on both session and role (#2123); dev mode gets its fixture
  // operator from getSessionUser's OIDC_DISABLED branch, not from here.
  const isAdmin = !user || user.role === 'admin'

  const [rows, setRows] = useState<StoreRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  const [queryInput, setQueryInput] = useState('')
  const [appliedQuery, setAppliedQuery] = useState('')
  const [purging, setPurging] = useState(false)
  const [message, setMessage] = useState('')
  // #2178: `page?.rows ?? []` made a failed store read indistinguishable
  // from an empty backlog -- exactly the quiet-this-page-calls-healthy that
  // must never be manufactured. Tri-state instead.
  const [failed, setFailed] = useState(false)

  const load = useCallback((q: string) => {
    setRows(null)
    setFailed(false)
    fetchPage({ data: { offset: 0, q } })
      .then((page) => {
        if (!page) {
          setFailed(true)
          return
        }
        setRows(page.rows)
        setTotal(page.total)
      })
      .catch(() => setFailed(true))
  }, [])

  useEffect(() => {
    load(appliedQuery)
  }, [load, appliedQuery])

  const retryLoad = useCallback(() => load(appliedQuery), [load, appliedQuery])

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
            <span className="chip">{failed ? 'load failed' : `${total.toLocaleString('en-US')} documents`}</span>
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
      {failed ? (
        /* #2178: this page's own copy says an empty list is the healthy
           state -- which is precisely why a failed read must not render
           as one. */
        <ErrorStateBlock
          title="Dead letters failed to load"
          hint="The store read failed — nothing here is cached."
          onRetry={retryLoad}
        />
      ) : (
        <MasterDetailTable
          rows={rows}
          columns={COLUMNS}
          rowKey={(_, index) => String(index)}
          emptyState={{
            title: 'No dead letters recorded',
            hint: 'Events that could not be parsed or indexed land here — an empty list is the healthy state.',
          }}
          total={total}
          onViewMore={viewMore}
          loadingMore={loadingMore}
          inspectorTitle="Dead letter"
        />
      )}
    </>
  )
}
