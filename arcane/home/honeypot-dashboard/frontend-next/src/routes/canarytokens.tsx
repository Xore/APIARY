// Canarytokens — deployed decoy tokens (dashboard-canarytokens-v1).
// Management actions (mint/delete) join the operations slice with the
// settings modal; this page is the monitoring view.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/canarytokens?offset=${data.offset}&size=25`)
  })

const COLUMNS: Column<StoreRow>[] = [
  { header: 'created', render: (row) => when(str(row, 'created_at')) },
  { header: 'type', render: (row) => <span className="badge badge--muted">{str(row, 'token_type')}</span> },
  { header: 'memo', className: 'v', render: (row) => str(row, 'memo') },
  { header: 'token url', className: 'v', render: (row) => <code>{str(row, 'token_url')}</code> },
  { header: 'hostname', detail: true, render: (row) => str(row, 'hostname') },
  { header: 'created by', detail: true, render: (row) => str(row, 'created_by') },
  { header: 'id', detail: true, render: (row) => str(row, 'id') },
]

export const Route = createFileRoute('/canarytokens')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      label="Tools"
      title="Canarytokens"
      subtitle="Deployed decoy tokens — documents, URLs and hostnames that phone home the moment an attacker touches them."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'id')}-${index}`}
      inspectorTitle="Token details"
      chipNoun="tokens"
    />
  )
}
