// Event history — free-text raw search over the full event archive
// (the legacy /history page's ES q= passthrough), with a JSON export of
// the current result scope.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useRef, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import type { JsonRecord } from '../lib/json'

type EventRow = {
  time: string
  sensor: string
  src_ip: string
  country: string
  port: string
  proto: string
  detail: string
  session: string
  record: JsonRecord
}

type Page = { total: number; offset: number; rows: EventRow[] }

const fetchHistory = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number; q: string }) => input)
  .handler(async ({ data }): Promise<Page | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const query = data.q ? `&q=${encodeURIComponent(data.q)}` : ''
    return serviceJSON<Page>(`/api/v1/events?offset=${data.offset}&size=50&since=90d${query}`)
  })

export const Route = createFileRoute('/history')({
  loader: async () => ({ first: fetchHistory({ data: { offset: 0, q: '' } }) }),
  component: History,
})

const COLUMNS: Column<EventRow>[] = [
  { header: 'time', render: (row) => row.time.replace('T', ' ').slice(0, 19) },
  { header: 'sensor', render: (row) => <span className="badge badge--muted">{row.sensor}</span> },
  { header: 'source ip', className: 'v', render: (row) => row.src_ip },
  { header: 'port', className: 'n', render: (row) => (row.port ? `:${row.port}` : '') },
  { header: 'detail', className: 'v', render: (row) => row.detail || row.proto },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row.record, null, 2)}</pre>,
  },
]

function History() {
  const { first } = Route.useLoaderData()
  const [rows, setRows] = useState<EventRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  const [query, setQuery] = useState('')
  const activeQuery = useRef('')

  useEffect(() => {
    let cancelled = false
    first.then((page) => {
      if (cancelled || !page) return
      setRows(page.rows)
      setTotal(page.total)
    })
    return () => {
      cancelled = true
    }
  }, [first])

  const search = useCallback(async (q: string) => {
    activeQuery.current = q
    setRows(null)
    const page = await fetchHistory({ data: { offset: 0, q } })
    if (activeQuery.current !== q) return // superseded by a newer search
    setRows(page ? page.rows : [])
    setTotal(page ? page.total : 0)
  }, [])

  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await fetchHistory({ data: { offset: rows.length, q: activeQuery.current } })
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore])

  const exportJSON = useCallback(() => {
    if (!rows) return
    const blob = new Blob([JSON.stringify(rows.map((row) => row.record), null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'honeypot-history.json'
    link.click()
    URL.revokeObjectURL(url)
  }, [rows])

  return (
    <>
      <InvestigateHeader
        label="Operations"
        title="Event history"
        subtitle="Raw search across the full event archive — Lucene query syntax, 90-day window, exportable."
        chips={<span className="chip">{total.toLocaleString('en-US')} matches</span>}
      />
      <form
        className="filters"
        onSubmit={(event) => {
          event.preventDefault()
          void search(query)
        }}
      >
        <input
          className="input"
          type="search"
          placeholder='Lucene query — e.g. source.ip:1.2.3.4 AND honeypot.event:login'
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          aria-label="History search query"
        />
        <button className="btn btn-secondary btn-sm" type="submit">
          Search
        </button>
        <button className="btn btn-secondary btn-sm" type="button" onClick={exportJSON} disabled={!rows || rows.length === 0}>
          Export JSON
        </button>
      </form>
      <MasterDetailTable
        rows={rows}
        columns={COLUMNS}
        rowKey={(row, index) => `${row.time}-${index}`}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Archived event"
      />
    </>
  )
}
