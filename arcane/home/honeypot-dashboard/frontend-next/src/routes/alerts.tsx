// Alerts — dashboard-alert-state-v1 (the notifier's own state store:
// counts, first/last seen, acknowledge flags).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'

type AlertRow = {
  Key: string
  Message: string
  Link: string
  FirstSeen: string
  LastSeen: string
  Count: number
  Acknowledged: boolean
}

type Page = { total: number; rows: AlertRow[] }

const fetchAlerts = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/alerts?offset=${data.offset}&size=25`)
  })

export const Route = createFileRoute('/alerts')({
  loader: async () => ({ first: fetchAlerts({ data: { offset: 0 } }) }),
  component: Alerts,
})

const COLUMNS: Column<AlertRow>[] = [
  {
    header: 'state',
    render: (row) =>
      row.Acknowledged ? <span className="badge badge--muted">acked</span> : <span className="badge badge--warning">open</span>,
  },
  { header: 'alert', className: 'v', render: (row) => row.Message },
  { header: 'count', className: 'n', render: (row) => row.Count.toLocaleString('en-US') },
  { header: 'last seen', render: (row) => row.LastSeen.replace('T', ' ').slice(0, 19) },
  { header: 'first seen', detail: true, render: (row) => row.FirstSeen.replace('T', ' ').slice(0, 19) },
  { header: 'key', detail: true, render: (row) => row.Key },
  {
    header: 'links',
    detail: true,
    render: (row) =>
      row.Link ? (
        <a className="lnk" href={row.Link}>
          investigate →
        </a>
      ) : null,
  },
]

function Alerts() {
  const { first } = Route.useLoaderData()
  const [rows, setRows] = useState<AlertRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
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
  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await fetchAlerts({ data: { offset: rows.length } })
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore])
  return (
    <>
      <InvestigateHeader
        label="Operations"
        title="Alerts"
        subtitle="Everything the notifier has raised — campaign scores, YARA hits, pipeline problems — with acknowledge state."
        chips={<span className="chip">{total.toLocaleString('en-US')} alerts</span>}
      />
      <MasterDetailTable
        rows={rows}
        columns={COLUMNS}
        rowKey={(row) => row.Key}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Alert details"
      />
    </>
  )
}
