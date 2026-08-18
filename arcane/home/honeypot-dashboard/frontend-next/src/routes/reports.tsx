// Reports studio — generated PDF reports and the report definitions
// behind them. Generation itself stays with the reporter until the
// worker port (#1610) moves it into this tier; every finished report is
// viewable here.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'

type StoreRow = Record<string, unknown>
type Page = { total: number; rows: StoreRow[] }

const fetchGenerated = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<Page | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/store/generated-reports?offset=${data.offset}&size=25`)
  })

const fetchDefinitions = createServerFn({ method: 'GET' }).handler(async (): Promise<Page | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<Page>('/api/v1/store/report-definitions?size=25')
})

export const Route = createFileRoute('/reports')({
  loader: async () => ({ generated: fetchGenerated({ data: { offset: 0 } }), definitions: fetchDefinitions() }),
  component: Reports,
})

const str = (row: StoreRow, key: string): string => (typeof row[key] === 'string' ? (row[key] as string) : '')
const num = (row: StoreRow, key: string): number => (typeof row[key] === 'number' ? (row[key] as number) : 0)

const COLUMNS: Column<StoreRow>[] = [
  { header: 'created', render: (row) => str(row, 'created_at').replace('T', ' ').slice(0, 19) },
  { header: 'title', className: 'v', render: (row) => str(row, 'title') || str(row, 'name') },
  { header: 'template', render: (row) => <span className="badge badge--muted">{str(row, 'template')}</span> },
  { header: 'origin', render: (row) => str(row, 'origin') },
  { header: 'size', className: 'n', render: (row) => `${(num(row, 'size_bytes') / 1024).toFixed(0)} KB` },
  {
    header: 'pdf',
    render: (row) => (
      <a
        className="lnk"
        href={`/api/report/${encodeURIComponent(str(row, 'id'))}/pdf`}
        target="_blank"
        rel="noopener noreferrer"
        onClick={(event) => event.stopPropagation()}
      >
        open PDF →
      </a>
    ),
  },
]

function Reports() {
  const data = Route.useLoaderData()
  const [generated, setGenerated] = useState<Page | null>(null)
  const [definitions, setDefinitions] = useState<Page | null>(null)
  useEffect(() => {
    let cancelled = false
    data.generated.then((page) => {
      if (!cancelled && page) setGenerated(page)
    })
    data.definitions.then((page) => {
      if (!cancelled && page) setDefinitions(page)
    })
    return () => {
      cancelled = true
    }
  }, [data])
  return (
    <>
      <InvestigateHeader
        label="Reports"
        title="Reports studio"
        subtitle="Finished PDF reports and the definitions that produce them — scheduled and on-demand runs land here."
        chips={<span className="chip">{(generated?.total ?? 0).toLocaleString('en-US')} generated reports</span>}
      />
      <MasterDetailTable
        rows={generated ? generated.rows : null}
        columns={COLUMNS}
        rowKey={(row, index) => `${str(row, 'id')}-${index}`}
        inspectorTitle="Report details"
      />
      <div className="card wide">
        <h2>Report definitions</h2>
        {definitions === null ? (
          <span className="skeleton-line" aria-hidden="true" />
        ) : definitions.rows.length === 0 ? (
          <p className="empty">No report definitions yet.</p>
        ) : (
          <pre className="code">{JSON.stringify(definitions.rows, null, 2)}</pre>
        )}
        <p className="note">
          Definitions drive the scheduler; editing and on-demand generation move into this tier with the worker port (#1610).
        </p>
      </div>
    </>
  )
}
