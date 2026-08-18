// Dead letters — pipeline documents that failed classification
// (dead-letter-honeypot). Empty is the healthy state.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/dead-letters?offset=${data.offset}&size=25`)
  })

const COLUMNS: Column<StoreRow>[] = [
  { header: 'time', render: (row) => when(str(row, '@timestamp')) },
  { header: 'reason', className: 'v', render: (row) => str(row, 'reason') || str(row, 'error') },
  { header: 'source', className: 'v', render: (row) => str(row, 'logset') || str(row, 'pipeline') },
]

export const Route = createFileRoute('/dead-letters')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      label="Operations"
      title="Dead letters"
      subtitle="Documents the pipeline could not classify — an empty list is the healthy state."
      columns={COLUMNS}
      rowKey={(_, index) => String(index)}
      inspectorTitle="Dead letter"
      chipNoun="documents"
    />
  )
}
