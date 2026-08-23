// Executed commands — the events pipeline filtered to honeypot.event=
// "command"; the full record rides the inspector.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { usePaginatedList } from '../lib/hooks'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'

type EventRow = {
  time: string
  sensor: string
  src_ip: string
  country: string
  port: string
  proto: string
  detail: string
  session: string
  record: JsonRecord
}

type Page = { total: number; offset: number; rows: EventRow[] }

const fetchCommands = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<Page | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/events?kind=command&offset=${data.offset}&size=25`)
  })

export const Route = createFileRoute('/commands')({
  loader: async () => ({ first: fetchCommands({ data: { offset: 0 } }) }),
  component: Commands,
})

function commandText(record: JsonRecord): string {
  const hp = record.honeypot as JsonRecord | undefined
  for (const key of ['input', 'command', 'data', 'message']) {
    const value = hp?.[key]
    if (typeof value === 'string' && value) return value
  }
  return ''
}

const COLUMNS: Column<EventRow>[] = [
  { header: 'seen', render: (row) => formatTimestamp(row.time) },
  { header: 'sensor', render: (row) => <span className="badge badge--muted">{row.sensor}</span> },
  { header: 'source ip', className: 'v', render: (row) => row.src_ip },
  { header: 'command', className: 'v', render: (row) => <code>{commandText(row.record) || row.detail}</code> },
  { header: 'session', detail: true, render: (row) => row.session },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row.record, null, 2)}</pre>,
  },
]

function Commands() {
  const { first } = Route.useLoaderData()
  const { rows, total, loadingMore, viewMore } = usePaginatedList(first, (offset) => fetchCommands({ data: { offset } }))
  return (
    <>
      <InvestigateHeader
        label="Attacker behavior"
        title="Executed commands"
        subtitle="Every shell command attackers typed into interactive honeypots, newest first."
        chips={
          <>
            <span className="chip">{total.toLocaleString('en-US')} commands</span>
            <a className="chip" title="Download every executed command as CSV" href="/api/export/commands.csv">
              ⇩ CSV
            </a>
          </>
        }
      />
      <p className="note">
        Shell commands captured during interactive honeypot sessions, deduplicated across sources.
      </p>
      <MasterDetailTable
        rows={rows}
        columns={COLUMNS}
        rowKey={(row, index) => `${row.time}-${index}`}
        detailHref={(row) => (row.src_ip ? `/investigate/ip/${encodeURIComponent(row.src_ip)}` : undefined)}
        emptyState={{
          title: 'No commands captured yet',
          hint: 'Cowrie records these as attackers type in a shell session.',
        }}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Command details"
      />
    </>
  )
}
