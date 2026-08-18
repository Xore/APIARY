// Session recordings — cowrie-ttylog-v1; the inspector will grow the
// terminal-output preview once the replay decode endpoint lands (the cast
// bytes live in the store as ttylog_base64).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'

type RecordingRow = {
  shasum: string
  size_bytes: number
  imported_at: string
}

type Page = { total: number; rows: RecordingRow[] }

const fetchRecordings = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/recordings?offset=${data.offset}&size=25`)
  })

export const Route = createFileRoute('/recordings')({
  loader: async () => ({ first: fetchRecordings({ data: { offset: 0 } }) }),
  component: Recordings,
})

const COLUMNS: Column<RecordingRow>[] = [
  { header: 'imported', render: (row) => row.imported_at.replace('T', ' ').slice(0, 19) },
  { header: 'recording', className: 'v', render: (row) => row.shasum },
  { header: 'size', className: 'n', render: (row) => `${(row.size_bytes / 1024).toFixed(1)} KB` },
]

function Recordings() {
  const { first } = Route.useLoaderData()
  const [rows, setRows] = useState<RecordingRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  useEffect(() => {
    let cancelled = false
    first.then((page) => {
      if (cancelled || !page) return
      setRows(page.rows)
      setTotal(page.total)
    })
    return () => {
      cancelled = true
    }
  }, [first])
  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await fetchRecordings({ data: { offset: rows.length } })
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore])
  return (
    <>
      <InvestigateHeader
        label="Attacker behavior"
        title="Session recordings"
        subtitle="Replayable cowrie TTY sessions — every keystroke and screen output an attacker's interactive shell produced, in order."
        chips={<span className="chip">{total.toLocaleString('en-US')} recordings</span>}
      />
      <MasterDetailTable
        rows={rows}
        columns={COLUMNS}
        rowKey={(row) => row.shasum}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Recording details"
      />
    </>
  )
}
