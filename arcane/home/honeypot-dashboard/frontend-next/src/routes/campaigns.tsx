// Correlated campaigns — compact core columns; ports/sensors detail in the
// click-open inspector (investigate-consistency rules).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'

type CampaignRow = {
  network: string
  events: number
  unique_ips: number
  sensors: string[]
  ports: string[]
  first: string
  last: string
}

const fetchCampaigns = createServerFn({ method: 'GET' }).handler(async () => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<{ rows: CampaignRow[] }>('/api/v1/campaigns?size=100')
})

export const Route = createFileRoute('/campaigns')({
  loader: async () => ({ page: fetchCampaigns() }),
  component: Campaigns,
})

const COLUMNS: Column<CampaignRow>[] = [
  { header: 'network', className: 'v', render: (row) => row.network },
  { header: 'events', className: 'n', render: (row) => row.events.toLocaleString('en-US') },
  { header: 'ips', className: 'n', render: (row) => row.unique_ips.toLocaleString('en-US') },
  { header: 'sensors', className: 'v', render: (row) => row.sensors.slice(0, 5).join(' ') + (row.sensors.length > 5 ? ` +${row.sensors.length - 5}` : '') },
  { header: 'all sensors', detail: true, render: (row) => row.sensors.join(' ') },
  { header: 'ports', detail: true, render: (row) => row.ports.join(' ') },
  { header: 'first', detail: true, render: (row) => row.first.replace('T', ' ').slice(0, 19) },
  { header: 'last', render: (row) => row.last.replace('T', ' ').slice(11, 19) },
]

function Campaigns() {
  const { page } = Route.useLoaderData()
  const [rows, setRows] = useState<CampaignRow[] | null>(null)
  useEffect(() => {
    let cancelled = false
    page.then((result) => {
      if (!cancelled && result) setRows(result.rows)
    })
    return () => {
      cancelled = true
    }
  }, [page])
  return (
    <>
      <InvestigateHeader
        label="Correlation"
        title="Correlated campaigns"
        subtitle="Related source networks grouped across sensors over a rolling 7-day window."
        chips={<span className="chip">{rows ? `${rows.length} active networks` : '…'}</span>}
      />
      <MasterDetailTable rows={rows} columns={COLUMNS} rowKey={(row) => row.network} />
    </>
  )
}
