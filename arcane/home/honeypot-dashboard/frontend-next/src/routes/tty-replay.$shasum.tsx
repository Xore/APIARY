// TTY replay — the shareable deep link for one Cowrie recording, ported
// from ui/tty_replay.html + hp-tty-replay.js. Two tabs (#1268 "ask 2"):
// Playback with play/pause/restart/seek/speed controls, and Attacker
// replay — the recording source IP's whole profile, not just this one
// session.
//
// Playback tradeoff: the Go tier rendered through the vendored xterm.js
// terminal emulator (#1282) with per-frame timing off the ttylog. This
// port cannot add npm dependencies (lockfile policy), and the Rust replay
// endpoint (replay.rs) serves an aggregate transcript, not timed frames —
// so playback is a timed progressive reveal of the stripped transcript,
// paced across the recording's real duration. Genuinely exotic escape
// sequences still round-trip via the events pipeline's .cast tooling.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useMemo, useRef, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { Tabs, TabPanel } from '../components/Tabs'
import { useResolved } from '../lib/hooks'
import { formatTimestamp } from '../lib/time'

type Replay = {
  shasum: string
  size_bytes: number
  imported_at: string
  frames: number
  duration_seconds: number
  transcript: string
}

type Kv = { key: string; count: number }

type ProfileEvent = { time: string; sensor: string; detail: string; proto: string }

type IpProfile = {
  ip: string
  total: number
  country: string
  asn: string
  sensors: Kv[]
  commands: Kv[]
  credentials: Kv[]
  sessions: Kv[]
  techniques: Kv[]
  events: ProfileEvent[]
}

const fetchReplay = createServerFn({ method: 'GET' })
  .inputValidator((input: { shasum: string }) => input)
  .handler(async ({ data }): Promise<Replay | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Replay>(`/api/v1/recordings/${encodeURIComponent(data.shasum)}`)
  })

/** The recording's source IP, recovered the same way /recordings joins
 * attribution: the cowrie.log.closed event whose honeypot.shasum is this
 * recording's shasum (events.rs:99-102). since=365d — the 10d events
 * default would lose attribution for older recordings. */
const fetchSourceIp = createServerFn({ method: 'GET' })
  .inputValidator((input: { shasum: string }) => input)
  .handler(async ({ data }): Promise<string> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const page = await serviceJSON<{ rows: { src_ip: string }[] }>(
      `/api/v1/events?kind=cowrie.log.closed&shasum=${encodeURIComponent(data.shasum)}&size=1&since=365d`,
    )
    return page?.rows?.[0]?.src_ip ?? ''
  })

const fetchProfile = createServerFn({ method: 'GET' })
  .inputValidator((input: { ip: string }) => input)
  .handler(async ({ data }): Promise<IpProfile | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<IpProfile>(`/api/v1/investigate/ip/${encodeURIComponent(data.ip)}`)
  })

export const Route = createFileRoute('/tty-replay/$shasum')({
  loader: async ({ params }) => ({ first: fetchReplay({ data: { shasum: params.shasum } }) }),
  component: TtyReplay,
})

function plainTranscript(transcript: string): string {
  // eslint-disable-next-line no-control-regex
  return transcript
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '')
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?/g, '')
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '')
}

// Playback controls (tty_replay.html's #tty-viewer + hp-tty-replay.js's
// play/restart/seek/speed wiring), driving a character-position cursor
// over the stripped transcript instead of a frame index.
function Playback({ replay }: { replay: Replay }) {
  const text = useMemo(() => plainTranscript(replay.transcript), [replay.transcript])
  const total = text.length
  const [pos, setPos] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const termRef = useRef<HTMLDivElement>(null)

  // Pace the reveal over the recording's real duration, clamped: the old
  // player capped each inter-frame gap at 3s (hp-tty-replay.js
  // scheduleNext) so an idle session never stalled playback for minutes —
  // a whole-playback clamp is this pacing model's equivalent.
  const playSeconds = Math.min(Math.max(replay.duration_seconds, 2), 120)

  useEffect(() => {
    if (!playing || total === 0) return
    const stepMs = 80
    const perTick = Math.max(1, Math.round((total / playSeconds) * (stepMs / 1000) * speed))
    const timer = setInterval(() => {
      setPos((current) => Math.min(total, current + perTick))
    }, stepMs)
    return () => clearInterval(timer)
  }, [playing, speed, total, playSeconds])

  useEffect(() => {
    if (playing && pos >= total) setPlaying(false)
  }, [playing, pos, total])

  // Follow the output like a live terminal would.
  useEffect(() => {
    const el = termRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [pos])

  if (total === 0) {
    return (
      <div className="card wide">
        <div className="hp-tty-status" role="status">
          This recording has no replayable output. The terminal is empty.
        </div>
      </div>
    )
  }

  const label = playing ? 'Pause' : pos >= total ? 'Replay' : pos > 0 ? 'Resume' : 'Play'

  return (
    <div className="card wide">
      <div className="hp-tty-controls">
        <button
          className="btn btn-sm btn-primary"
          type="button"
          onClick={() => {
            if (playing) {
              setPlaying(false)
              return
            }
            if (pos >= total) setPos(0)
            setPlaying(true)
          }}
        >
          {label}
        </button>
        <button
          className="btn btn-sm btn-secondary"
          type="button"
          onClick={() => {
            setPlaying(false)
            setPos(0)
          }}
        >
          Restart
        </button>
        <input
          type="range"
          min={0}
          max={total}
          value={pos}
          aria-label="Seek within the recording"
          onChange={(event) => {
            setPlaying(false)
            setPos(Number(event.target.value))
          }}
        />
        <label>
          speed{' '}
          <select value={speed} onChange={(event) => setSpeed(Number(event.target.value))}>
            <option value={1}>1×</option>
            <option value={2}>2×</option>
            <option value={4}>4×</option>
            <option value={0.5}>0.5×</option>
          </select>
        </label>
      </div>
      <div className="hp-tty-status" role="status">
        {replay.frames.toLocaleString('en-US')} frame(s), {replay.size_bytes.toLocaleString('en-US')} bytes recorded ·{' '}
        {replay.duration_seconds.toFixed(1)}s of terminal time.
      </div>
      <div
        ref={termRef}
        className="hp-tty-term"
        aria-label="Terminal playback"
        style={{ maxHeight: 480, overflowY: 'auto' }}
      >
        {text.slice(0, pos)}
      </div>
      {/* The reveal is a playback affordance — the whole transcript stays
          one disclosure away, no scrubbing to the end required. */}
      <details className="tw:mt-3">
        <summary>Full transcript</summary>
        <pre className="code">{text}</pre>
      </details>
    </div>
  )
}

function MiniTable({ title, rows, linkTo }: { title: string; rows: Kv[]; linkTo?: (key: string) => string }) {
  if (rows.length === 0) return null
  return (
    <div className="card half">
      <h2>{title}</h2>
      <div className="card__scroll">
        <table className="data-table">
          <tbody>
            {rows.map((row) => (
              <tr key={row.key}>
                <td className="n">{row.count.toLocaleString('en-US')}</td>
                <td className="v">{linkTo ? <a href={linkTo(row.key)}>{row.key}</a> : row.key}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// Attacker replay (tty_replay.html panel-attacker): the source IP's
// profile — KPIs, behavior tables, MITRE chips, and the chronological
// timeline — loaded lazily on first tab activation. The old page's
// single-point Leaflet map and payload-observation KPI aren't in
// /api/v1/investigate/ip's profile; everything else is.
function AttackerTab({ shasum }: { shasum: string }) {
  const [state, setState] = useState<'loading' | 'none' | { ip: string; profile: IpProfile | null }>('loading')
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const ip = await fetchSourceIp({ data: { shasum } })
        if (cancelled) return
        if (!ip) {
          setState('none')
          return
        }
        const profile = await fetchProfile({ data: { ip } })
        if (!cancelled) setState({ ip, profile })
      } catch {
        if (!cancelled) setState('none')
      }
    })()
    return () => {
      cancelled = true
    }
  }, [shasum])

  if (state === 'loading') return <span className="skeleton-line" aria-hidden="true" />
  if (state === 'none' || !state.profile) {
    return (
      <p className="empty">
        No indexed event still references this recording's source IP — either it aged out of the events window, or the
        recording predates this dashboard's own tracking. Attacker context isn't available for this one, but{' '}
        <a className="lnk" href="/recordings">
          other recordings
        </a>{' '}
        may still have it.
      </p>
    )
  }

  const { ip, profile } = state
  return (
    <>
      <div className="overview-header">
        <div>
          <div className="label-section">Attacker profile</div>
          <h2>
            <a className="lnk" href={`/investigate/ip/${encodeURIComponent(ip)}`}>
              {ip}
            </a>
          </h2>
          <p className="subtitle">
            {profile.country || 'unknown origin'}
            {profile.asn ? ` • ${profile.asn}` : ''} — everything this source IP has done, not just this one session.
          </p>
        </div>
      </div>

      <div className="tw:grid tw:grid-cols-2 tw:sm:grid-cols-3 tw:gap-3 tw:mb-6">
        <div className="metric">
          <div className="metric__value">{profile.total.toLocaleString('en-US')}</div>
          <div className="metric__label">Events</div>
        </div>
        <div className="metric">
          <div className="metric__value">{profile.sessions.length.toLocaleString('en-US')}</div>
          <div className="metric__label">Sessions</div>
        </div>
        <div className="metric">
          <div className="metric__value">{profile.commands.length.toLocaleString('en-US')}</div>
          <div className="metric__label">Distinct commands</div>
        </div>
      </div>

      {profile.techniques.length > 0 ? (
        <div className="filters">
          {profile.techniques.map((technique) => (
            <a
              className="chip"
              key={technique.key}
              href={`https://attack.mitre.org/techniques/${technique.key.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
            >
              {technique.key} × {technique.count.toLocaleString('en-US')}
            </a>
          ))}
        </div>
      ) : null}

      <MiniTable title="Commands" rows={profile.commands} />
      <MiniTable title="Credentials tried" rows={profile.credentials} />
      <MiniTable title="Sensors" rows={profile.sensors} />
      <MiniTable title="Sessions" rows={profile.sessions} linkTo={(key) => `/sessions/${encodeURIComponent(key)}`} />

      {profile.events.length > 0 ? (
        <div className="card wide">
          <h2>Session timeline</h2>
          <p className="note">Chronological, oldest to newest.</p>
          <div className="card__scroll timeline-track">
            {[...profile.events].reverse().map((event, index) => (
              <div className="timeline-block" key={`${event.time}-${index}`}>
                <div className="timeline-block__meta">
                  {formatTimestamp(event.time)} • {event.sensor}
                </div>
                <div>{event.detail || event.proto}</div>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </>
  )
}

function TtyReplay() {
  const { first } = Route.useLoaderData()
  const { shasum } = Route.useParams()
  const resolved = useResolved(first)
  const replay: Replay | null | 'missing' = resolved === undefined ? null : resolved ?? 'missing'
  const [tab, setTab] = useState('playback')

  if (replay === 'missing') {
    return <InvestigateHeader label="Attacker behavior" title={shasum} subtitle="No recording found for this id." />
  }

  return (
    <>
      <InvestigateHeader
        label="Cowrie TTY session recording"
        title={shasum.slice(0, 40)}
        subtitle="Replayed from the session's Elasticsearch mirror, not read off disk — timed playback of the decoded transcript."
        chips={
          replay ? (
            <>
              <span className="chip">{replay.frames.toLocaleString('en-US')} frames</span>
              <span className="chip">{replay.duration_seconds.toFixed(1)}s terminal time</span>
              <span className="chip">{(replay.size_bytes / 1024).toFixed(1)} KB</span>
              <Link className="chip" to="/recordings">← all recordings</Link>
            </>
          ) : undefined
        }
      />
      <Tabs
        tabs={[
          { id: 'playback', label: 'Playback' },
          { id: 'attacker', label: 'Attacker replay' },
        ]}
        active={tab}
        onSelect={setTab}
        label="TTY session views"
        idPrefix="tty"
      />
      <TabPanel id="playback" active={tab} idPrefix="tty" className="dashboard-panel">
        {replay === null ? (
          <div className="card wide">
            <span className="skeleton-line" aria-hidden="true" />
            <span className="skeleton-line" aria-hidden="true" />
          </div>
        ) : (
          <Playback replay={replay} />
        )}
      </TabPanel>
      <TabPanel id="attacker" active={tab} idPrefix="tty" className="dashboard-panel">
        {/* Lazily mounted — the profile lookup doesn't run until the tab
            is first opened (hp-tty-replay.js initialized its map the same
            way, on first reveal). */}
        {tab === 'attacker' ? <AttackerTab shasum={shasum} /> : null}
      </TabPanel>
    </>
  )
}
