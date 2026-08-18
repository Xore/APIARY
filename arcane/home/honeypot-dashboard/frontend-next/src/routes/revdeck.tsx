// RevDeck — reverse-engineering deck runs (revdeck-analysis-v1). The
// empty state is normal until the ghidra-worker's drain produces output.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/revdeck?offset=${data.offset}&size=25`)
  })

const COLUMNS: Column<StoreRow>[] = [
  { header: 'analyzed', render: (row) => when(str(row, '@timestamp')) },
  { header: 'exit', render: (row) => <span className="badge badge--muted">{str(row, 'exit_status')}</span> },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row, null, 2)}</pre>,
  },
]

export const Route = createFileRoute('/revdeck')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      label="Evidence"
      title="RevDeck"
      subtitle="Reverse-engineering deck runs — deep binary walkthroughs produced by the ghidra worker's drain queue."
      columns={COLUMNS}
      rowKey={(_, index) => String(index)}
      inspectorTitle="RevDeck run"
      chipNoun="runs"
    />
  )
}
