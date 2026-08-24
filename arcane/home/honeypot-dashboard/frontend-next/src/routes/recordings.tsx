// Session recordings — one row per recorded cowrie session
// (`cowrie.log.closed`), matching recordings.html's own unit. The inspector
// fetches the decoded replay (frames + terminal transcript) lazily when a row
// opens, keyed by the recording's sha256.
//
// #1716: this listed one row per *recording* until the content-addressing of
// `cowrie-ttylog-v1` made that untenable — 111,845 sessions collapse into 171
// recordings, so "the source IP of this recording" had no single answer and
// the column showed an arbitrary one. Everything rendered below is native to
// the close event, so there is no join and no per-row lookup.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'

type RecordingRow = {
  /** When the session closed. */
  when: string
  /** Empty when enrichment left the tunnel address here (#1714) — rendered
   * as an em dash rather than as a source that never attacked anything. */
  src_ip: string
  country: string
  session: string
  /** sha256 of the recording's bytes. Many sessions share one — bot traffic
   * is repetitive and the ttylog store is content-addressed — which is why
   * this list is keyed on the session and the replay pane on the shasum. */
  shasum: string
  size_bytes: number
  duration_ms: number
}

type Page = { total: number; rows: RecordingRow[] }

type Replay = {
  shasum: string
  frames: number
  duration_seconds: number
  transcript: string
}

const fetchRecordings = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number; ip?: string }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    const ip = data.ip ? `&ip=${encodeURIComponent(data.ip)}` : ''
    return serviceJSON<Page>(`/api/v1/recordings?offset=${data.offset}&size=25${ip}`)
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

function ReplayPane({ row }: { row: RecordingRow }) {
  const [replay, setReplay] = useState<Replay | null | 'loading'>('loading')
  useEffect(() => {
    let cancelled = false
    setReplay('loading')
    fetchReplay({ data: { shasum: row.shasum } }).then(
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
  }, [row.shasum])
  if (replay === 'loading') return <span className="skeleton-line" aria-hidden="true" />
  if (!replay) return <p className="subtitle">Replay unavailable for this recording.</p>
  return (
    <>
      {/* #1716: attribution comes from the row's own close event. It used to
          be fetched here by shasum, which had the same flaw the list did —
          many sessions share one recording, so the lookup returned whichever
          one ES happened to answer with. */}
      <p className="subtitle">
        {row.src_ip ? (
          <a
            className="lnk"
            href={`/investigate/ip/${encodeURIComponent(row.src_ip)}`}
            title={`attacker profile for ${row.src_ip}`}
          >
            {row.src_ip}
          </a>
        ) : (
          'unattributed'
        )}
        {row.country ? (
          <>
            {' '}
            <span className="badge badge--info" title={countryName(row.country)}>
              {row.country}
            </span>
          </>
        ) : null}
        {row.session ? (
          <>
            {' · '}
            <a
              className="lnk sess"
              href={`/sessions/${encodeURIComponent(row.session)}`}
              title="full chronological session replay"
            >
              session {row.session}
            </a>
          </>
        ) : null}
      </p>
      <p className="subtitle">
        {replay.frames.toLocaleString('en-US')} frames · {replay.duration_seconds.toFixed(1)}s of terminal time ·{' '}
        <a className="btn btn-secondary btn-sm" href={`/tty-replay/${encodeURIComponent(row.shasum)}`}>
          open replay page →
        </a>
      </p>
      <pre className="hp-md__preview">{plainTranscript(replay.transcript)}</pre>
    </>
  )
}

export const Route = createFileRoute('/recordings')({
  // #1716: `?ip=` has always been linked here from the per-IP profile; the
  // list only gained a source column it could filter on now.
  validateSearch: (search: Record<string, unknown>) => ({
    ip: typeof search.ip === 'string' && search.ip ? search.ip : undefined,
  }),
  loaderDeps: ({ search }) => ({ ip: search.ip }),
  loader: async ({ deps }) => ({ first: fetchRecordings({ data: { offset: 0, ip: deps.ip } }) }),
  component: Recordings,
})

const COLUMNS: Column<RecordingRow>[] = [
  { header: 'closed', render: (row) => formatTimestamp(row.when) },
  // #1716: every value below belongs to this one session, not to whichever
  // session happened to be picked for a shared recording.
  { header: 'source', className: 'v', render: (row) => row.src_ip || '—' },
  {
    header: 'country',
    render: (row) => (row.country ? <span title={countryName(row.country)}>{row.country}</span> : '—'),
  },
  { header: 'session', className: 'v', render: (row) => row.session || '—' },
  { header: 'size', className: 'n', render: (row) => `${(row.size_bytes / 1024).toFixed(1)} KB` },
  {
    header: 'duration',
    className: 'n',
    render: (row) => (row.duration_ms ? `${(row.duration_ms / 1000).toFixed(1)}s` : '—'),
  },
  { header: 'recording', detail: true, className: 'v', render: (row) => <code>{row.shasum}</code> },
]

function Recordings() {
  const { first } = Route.useLoaderData()
  const { ip } = Route.useSearch()
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
      const page = await fetchRecordings({ data: { offset: rows.length, ip } })
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore, ip])
  return (
    <>
      <InvestigateHeader
        label="Attacker behavior"
        title="Session recordings"
        subtitle="Replayable cowrie TTY sessions — every keystroke and screen output an attacker's interactive shell produced, in order. One row per session; sessions that ran identical commands share one recording."
        chips={
          <>
            <span className="chip">{total.toLocaleString('en-US')} recorded sessions</span>
            {ip ? <span className="badge badge--info">source {ip}</span> : null}
          </>
        }
      />
      <MasterDetailTable
        rows={rows}
        columns={COLUMNS}
        // #1716: NOT the shasum — thousands of sessions share one recording,
        // so keying on it collides. The session id is this row's own identity.
        rowKey={(row, i) => `${row.session || 'anon'}-${row.when}-${i}`}
        detailHref={(row) => `/tty-replay/${encodeURIComponent(row.shasum)}`}
        emptyState={{
          title: 'No session recordings captured yet',
          hint: 'Cowrie writes one per interactive shell session.',
        }}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Recording details"
        inspectorExtra={(row) => <ReplayPane row={row} />}
      />
    </>
  )
}
