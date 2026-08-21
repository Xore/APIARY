// Alerts — dashboard-alert-state-v1 (the notifier's own state store:
// counts, first/last seen, acknowledge flags).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { usePaginatedList } from '../lib/hooks'
import { formatTimestamp } from '../lib/time'

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

const acknowledgeAlert = createServerFn({ method: 'POST' })
  .inputValidator((input: { key: string; ack: boolean }) => input)
  .handler(async ({ data }): Promise<boolean> => {
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/alerts/${encodeURIComponent(data.key)}/ack`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ack: data.ack }),
    })
    return response.ok
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
  { header: 'last seen', render: (row) => formatTimestamp(row.LastSeen) },
  { header: 'first seen', detail: true, render: (row) => formatTimestamp(row.FirstSeen) },
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
  const { rows, setRows, total, loadingMore, viewMore } = usePaginatedList(first, (offset) => fetchAlerts({ data: { offset } }))
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
        inspectorExtra={(row) => (
          <button
            className="btn btn-secondary btn-sm"
            type="button"
            onClick={async () => {
              const ok = await acknowledgeAlert({ data: { key: row.Key, ack: !row.Acknowledged } })
              if (ok) {
                setRows((current) =>
                  current
                    ? current.map((candidate) =>
                        candidate.Key === row.Key ? { ...candidate, Acknowledged: !row.Acknowledged } : candidate,
                      )
                    : current,
                )
              }
            }}
          >
            {row.Acknowledged ? 'Reopen alert' : 'Acknowledge alert'}
          </button>
        )}
      />
    </>
  )
}
