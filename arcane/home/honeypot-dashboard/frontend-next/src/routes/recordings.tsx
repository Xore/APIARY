// Session recordings — cowrie-ttylog-v1. The inspector fetches the
// decoded replay (frames + terminal transcript) lazily when a row opens.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { formatTimestamp } from '../lib/time'

type RecordingRow = {
  shasum: string
  size_bytes: number
  imported_at: string
}

type Page = { total: number; rows: RecordingRow[] }

type Replay = {
  shasum: string
  frames: number
  duration_seconds: number
  transcript: string
}

const fetchRecordings = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/recordings?offset=${data.offset}&size=25`)
  })

const fetchReplay = createServerFn({ method: 'GET' })
  .inputValidator((input: { shasum: string }) => input)
  .handler(async ({ data }): Promise<Replay | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Replay>(`/api/v1/recordings/${encodeURIComponent(data.shasum)}`)
  })

// Control bytes the transcript view drops so raw ANSI/VT sequences don't
// litter the plain text (a real player lands with the workbench round).
function plainTranscript(transcript: string): string {
  // eslint-disable-next-line no-control-regex
  return transcript
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '') // CSI sequences (colors, cursor)
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?/g, '') // OSC (window title)
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '') // stray control bytes
}

function ReplayPane({ shasum }: { shasum: string }) {
  const [replay, setReplay] = useState<Replay | null | 'loading'>('loading')
  useEffect(() => {
    let cancelled = false
    setReplay('loading')
    fetchReplay({ data: { shasum } }).then(
      (result) => {
        if (!cancelled) setReplay(result)
      },
      () => {
        if (!cancelled) setReplay(null)
      },
    )
    return () => {
      cancelled = true
    }
  }, [shasum])
  if (replay === 'loading') return <span className="skeleton-line" aria-hidden="true" />
  if (!replay) return <p className="subtitle">Replay unavailable for this recording.</p>
  return (
    <>
      <p className="subtitle">
        {replay.frames.toLocaleString('en-US')} frames · {replay.duration_seconds.toFixed(1)}s of terminal time ·{' '}
        <a className="lnk" href={`/tty-replay/${encodeURIComponent(shasum)}`}>
          open replay page →
        </a>
      </p>
      <pre className="hp-md__preview">{plainTranscript(replay.transcript)}</pre>
    </>
  )
}

export const Route = createFileRoute('/recordings')({
  loader: async () => ({ first: fetchRecordings({ data: { offset: 0 } }) }),
  component: Recordings,
})

const COLUMNS: Column<RecordingRow>[] = [
  { header: 'imported', render: (row) => formatTimestamp(row.imported_at) },
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
        inspectorExtra={(row) => <ReplayPane shasum={row.shasum} />}
      />
    </>
  )
}
