// Session recordings — cowrie-ttylog-v1. The inspector fetches the
// decoded replay (frames + terminal transcript) lazily when a row opens.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'

type RecordingRow = {
  shasum: string
  size_bytes: number
  imported_at: string
  // #1691: denormalized onto the document at import time by
  // es_importer.rs's ttylog_attribution, so the list can show attribution
  // without an per-row events lookup. Absent on recordings imported before
  // that landed and never backfilled, and on any recording whose session
  // produced no connect event — both render as an em dash.
  src_ip?: string
  country?: string
  session?: string
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

/** Who produced a recording. recordings.html:30-37 listed source IP,
 * country and session per row, read off the Go tier's in-memory
 * cowrie.log.closed events.
 *
 * Since #1691 that attribution is denormalized onto the cowrie-ttylog-v1
 * document at import time, so the list renders it directly. This lazy
 * per-row lookup stays as the fallback for documents that predate the
 * change and were not backfilled: the closed event's honeypot.shasum IS
 * the recording's shasum (events.rs:99-102), so one filtered
 * /api/v1/events lookup recovers it. since=365d — the events default
 * (10d) would drop attribution for older recordings the list still
 * shows. */
type Provenance = { src_ip: string; country: string; session: string }

const fetchProvenance = createServerFn({ method: 'GET' })
  .inputValidator((input: { shasum: string }) => input)
  .handler(async ({ data }): Promise<Provenance | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const page = await serviceJSON<{ rows: Provenance[] }>(
      `/api/v1/events?kind=cowrie.log.closed&shasum=${encodeURIComponent(data.shasum)}&size=1&since=365d`,
    )
    const row = page?.rows?.[0]
    return row ? { src_ip: row.src_ip, country: row.country, session: row.session } : null
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
  const [who, setWho] = useState<Provenance | null | 'loading'>('loading')
  useEffect(() => {
    let cancelled = false
    setReplay('loading')
    setWho('loading')
    fetchReplay({ data: { shasum } }).then(
      (result) => {
        if (!cancelled) setReplay(result)
      },
      () => {
        if (!cancelled) setReplay(null)
      },
    )
    fetchProvenance({ data: { shasum } }).then(
      (result) => {
        if (!cancelled) setWho(result)
      },
      () => {
        if (!cancelled) setWho(null)
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
      {who === 'loading' ? (
        <span className="skeleton-line" aria-hidden="true" />
      ) : who ? (
        <p className="subtitle">
          {who.src_ip ? (
            <a className="lnk" href={`/investigate/ip/${encodeURIComponent(who.src_ip)}`} title={`attacker profile for ${who.src_ip}`}>
              {who.src_ip}
            </a>
          ) : (
            'unattributed'
          )}
          {who.country ? <> <span className="badge badge--info" title={countryName(who.country)}>{who.country}</span></> : null}
          {who.session ? (
            <>
              {' · '}
              <a className="lnk sess" href={`/sessions/${encodeURIComponent(who.session)}`} title="full chronological session replay">
                session {who.session}
              </a>
            </>
          ) : null}
        </p>
      ) : (
        <p className="subtitle">No cowrie.log.closed event still references this recording — attribution unavailable.</p>
      )}
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
  // #1691: restores recordings.html:30-37's inline attribution.
  { header: 'source', className: 'v', render: (row) => row.src_ip || '—' },
  { header: 'country', render: (row) => (row.country ? <span title={countryName(row.country)}>{row.country}</span> : '—') },
  { header: 'session', className: 'v', render: (row) => row.session || '—' },
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
        detailHref={(row) => `/tty-replay/${encodeURIComponent(row.shasum)}`}
        emptyState={{
          title: 'No session recordings captured yet',
          hint: 'Cowrie writes one per interactive shell session.',
        }}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Recording details"
        inspectorExtra={(row) => <ReplayPane shasum={row.shasum} />}
      />
    </>
  )
}
