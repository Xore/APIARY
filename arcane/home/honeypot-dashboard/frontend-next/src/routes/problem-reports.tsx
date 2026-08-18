// Problem reports — operator-submitted UI problem reports
// (dashboard-problem-reports-v1), with the action trail and API-call
// context in the inspector.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/problem-reports?offset=${data.offset}&size=25`)
  })

const COLUMNS: Column<StoreRow>[] = [
  { header: 'submitted', render: (row) => when(str(row, 'submitted_at')) },
  {
    header: 'status',
    render: (row) => (
      <span className={str(row, 'status') === 'open' ? 'badge badge--warning' : 'badge badge--muted'}>{str(row, 'status')}</span>
    ),
  },
  { header: 'page', className: 'v', render: (row) => str(row, 'page') },
  { header: 'expected', className: 'v', render: (row) => str(row, 'expected') },
  { header: 'actual', className: 'v', render: (row) => str(row, 'actual') },
  { header: 'by', detail: true, render: (row) => str(row, 'submitted_by') },
  { header: 'user agent', detail: true, render: (row) => str(row, 'user_agent') },
  {
    header: 'action trail',
    detail: true,
    render: (row) =>
      Array.isArray(row.action_trail) ? <pre className="hp-md__preview">{(row.action_trail as string[]).join('\n')}</pre> : '',
  },
]

export const Route = createFileRoute('/problem-reports')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      label="Operations"
      title="Problem reports"
      subtitle="Operator-submitted UI problem reports, with the action trail and request context captured at submit time."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'id')}-${index}`}
      inspectorTitle="Report details"
      chipNoun="reports"
    />
  )
}
