// Attacker identities — attackers-v1 store (the identity worker's durable
// entities), shared master-detail kit; credentials/IPs are pane detail.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'

type AttackerRow = {
  id: string
  ips: string[]
  fingerprints: string[]
  payloads: string[]
  credentials: string[]
  sensors: string[]
  events: number
  first: string
  last: string
}

type Page = { total: number; rows: AttackerRow[] }

const fetchAttackers = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/attackers?offset=${data.offset}&size=25`)
  })

export const Route = createFileRoute('/attackers')({
  loader: async () => ({ first: fetchAttackers({ data: { offset: 0 } }) }),
  component: Attackers,
})

const COLUMNS: Column<AttackerRow>[] = [
  { header: 'entity', className: 'v', render: (row) => row.id.slice(0, 8) },
  { header: 'ips', className: 'n', render: (row) => row.ips.length.toLocaleString('en-US') },
  { header: 'events', className: 'n', render: (row) => row.events.toLocaleString('en-US') },
  {
    header: 'sensors',
    className: 'v',
    render: (row) => (
      <>
        {row.sensors.map((sensor) => (
          <span key={sensor} className="badge badge--muted">
            {sensor}
          </span>
        ))}
      </>
    ),
  },
  { header: 'first', detail: true, render: (row) => row.first.replace('T', ' ').slice(0, 19) },
  { header: 'last', render: (row) => row.last.replace('T', ' ').slice(0, 19) },
  { header: 'member IPs', detail: true, render: (row) => row.ips.join(' ') },
  { header: 'credentials', detail: true, render: (row) => row.credentials.slice(0, 40).join(', ') },
  { header: 'fingerprints', detail: true, render: (row) => row.fingerprints.join(' ') },
]

function Attackers() {
  const { first } = Route.useLoaderData()
  const [rows, setRows] = useState<AttackerRow[] | null>(null)
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
      const page = await fetchAttackers({ data: { offset: rows.length } })
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore])
  return (
    <>
      <InvestigateHeader
        label="Correlation"
        title="Attacker identities"
        subtitle="Durable entities merged across IP churn by shared fingerprint, payload, and credential signals."
        chips={<span className="chip">{total.toLocaleString('en-US')} identities</span>}
      />
      <MasterDetailTable
        rows={rows}
        columns={COLUMNS}
        rowKey={(row) => row.id}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Identity details"
      />
    </>
  )
}
