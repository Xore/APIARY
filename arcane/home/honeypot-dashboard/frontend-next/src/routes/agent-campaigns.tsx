// Agent campaigns — agent-intrusion-worker's correlated AI-agent activity.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, str, num, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/agent-campaigns?offset=${data.offset}&size=25`)
  })

const COLUMNS: Column<StoreRow>[] = [
  { header: 'detected', render: (row) => when(str(row, '@timestamp')) },
  {
    header: 'severity',
    render: (row) => (
      <span className={str(row, 'severity') === 'high' ? 'badge badge--danger' : 'badge badge--warning'}>{str(row, 'severity')}</span>
    ),
  },
  { header: 'campaign', className: 'v', render: (row) => str(row, 'campaign_id') },
  {
    header: 'categories',
    className: 'v',
    render: (row) => (Array.isArray(row.matched_categories) ? (row.matched_categories as string[]).join(' ') : ''),
  },
  { header: 'events', className: 'n', render: (row) => num(row, 'event_count').toLocaleString('en-US') },
  { header: 'window', detail: true, render: (row) => `${when(str(row, 'start'))} → ${when(str(row, 'end'))}` },
  {
    header: 'identifiers',
    detail: true,
    render: (row) => (Array.isArray(row.correlation_identifiers) ? (row.correlation_identifiers as string[]).join(', ') : ''),
  },
]

export const Route = createFileRoute('/agent-campaigns')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      label="Monitor"
      title="Agent campaigns"
      subtitle="Correlated AI-agent intrusion activity — encoded egress, tool-use fingerprints, and cross-sensor automation patterns."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'campaign_id')}-${index}`}
      inspectorTitle="Campaign details"
      chipNoun="campaigns"
    />
  )
}
