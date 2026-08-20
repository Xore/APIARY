// Auth-failure events — Keycloak login failures against the dashboard's
// own realm (auth-failure-events store).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, str, when, type StorePage } from '../components/StoreList'
import type { Column } from '../components/Investigate'
import type { StoreRow } from '../components/StoreList'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/auth-events?offset=${data.offset}&size=25`)
  })

const COLUMNS: Column<StoreRow>[] = [
  { header: 'time', render: (row) => when(str(row, '@timestamp')) },
  { header: 'type', render: (row) => <span className="badge badge--warning">{str(row, 'type')}</span> },
  { header: 'ip', className: 'v', render: (row) => str(row, 'ip_address') },
  { header: 'error', className: 'v', render: (row) => str(row, 'error') },
  { header: 'realm', detail: true, render: (row) => str(row, 'realm') },
  { header: 'client', detail: true, render: (row) => str(row, 'client_id') },
  { header: 'user', detail: true, render: (row) => str(row, 'user_id') },
]

export const Route = createFileRoute('/auth-events')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      label="Monitor"
      title="Auth-failure events"
      subtitle="Failed logins against the dashboard's own Keycloak realm — the watchers watching the watchers."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'event_id')}-${index}`}
      inspectorTitle="Event details"
      chipNoun="events"
    />
  )
}
