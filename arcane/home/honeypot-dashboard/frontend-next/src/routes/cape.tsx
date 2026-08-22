// CAPE — advanced sandbox detonations (cape-analysis-v1). Empty until
// the CAPE host worker is deployed; submissions land with #1612.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, sha256Of, str, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/cape?offset=${data.offset}&size=25`)
  })

const COLUMNS: Column<StoreRow>[] = [
  { header: 'analyzed', render: (row) => when(str(row, '@timestamp')) },
  { header: 'status', render: (row) => <span className="badge badge--muted">{str(row, 'status') || str(row, 'exit_status')}</span> },
  {
    header: 'detail',
    className: 'v',
    primary: true,
    render: (row) => {
      const sha = sha256Of(row)
      return sha ? (
        <Link className="lnk" to="/cape/$sha" params={{ sha }}>
          {sha.slice(0, 16)} — full result →
        </Link>
      ) : (
        <span className="tw:text-muted">no source hash</span>
      )
    },
  },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row, null, 2)}</pre>,
  },
]

export const Route = createFileRoute('/cape')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      label="Evidence"
      title="CAPE"
      subtitle="CAPE sandbox detonations — config-extraction runs for payloads that warrant the heavier analysis pipeline."
      columns={COLUMNS}
      rowKey={(_, index) => String(index)}
      inspectorTitle="CAPE run"
      chipNoun="runs"
      layout="cards"
    />
  )
}
