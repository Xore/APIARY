// LLM analysis — llm-worker's guarded model output (llm-analysis index).
// Every judgment is AI-guessed and labeled as such, mirroring the legacy
// page's UNVERIFIED posture. The index may not exist yet (worker gated on
// GPU availability); the empty state is normal.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/llm-analysis?offset=${data.offset}&size=25`)
  })

function severityBadge(severity: string) {
  const cls =
    severity === 'high' || severity === 'critical'
      ? 'badge badge--danger'
      : severity === 'medium'
        ? 'badge badge--warning'
        : 'badge badge--muted'
  return <span className={cls}>{severity || 'n/a'}</span>
}

const COLUMNS: Column<StoreRow>[] = [
  { header: 'analyzed', render: (row) => when(str(row, '@timestamp')) },
  { header: 'doc type', render: (row) => <span className="badge badge--muted">{str(row, 'doc_type')}</span> },
  { header: 'severity (AI-guessed)', render: (row) => severityBadge(str(row, 'severity')) },
  { header: 'intent', className: 'v', render: (row) => str(row, 'intent') },
  { header: 'summary', className: 'v', render: (row) => str(row, 'summary') },
  { header: 'model', detail: true, render: (row) => str(row, 'model') },
  { header: 'source ip', detail: true, render: (row) => str(row, 'src_ip') },
  { header: 'session', detail: true, render: (row) => str(row, 'session_id') },
  {
    header: 'behaviors',
    detail: true,
    render: (row) => (Array.isArray(row.behaviors) ? (row.behaviors as string[]).join(', ') : ''),
  },
  { header: 'error', detail: true, render: (row) => str(row, 'error') },
]

export const Route = createFileRoute('/llm-analysis')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      label="Monitor"
      title="LLM analysis"
      subtitle="Model-annotated sessions, payloads and reports — every judgment here is AI-guessed and unverified until a human confirms it."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'analysis_id')}-${index}`}
      inspectorTitle="Analysis details"
      chipNoun="analyses"
    />
  )
}
