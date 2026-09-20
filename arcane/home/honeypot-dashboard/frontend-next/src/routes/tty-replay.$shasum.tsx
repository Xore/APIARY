// TTY replay — the shareable deep link for one Cowrie recording, ported
// from ui/tty_replay.html + hp-tty-replay.js. Two tabs (#1268 "ask 2"):
// Playback with play/pause/restart/seek/speed controls, and Attacker
// replay — the recording source IP's whole profile, not just this one
// session.
//
// #1682: playback now goes through a real terminal emulator (@xterm/xterm)
// again, same as the Go tier's vendored xterm.js. replay.rs's Replay
// struct already carried `ttylog_base64` ("raw base64 rides along for a
// future in-browser player" — its own doc comment) even before this
// landed; the earlier plain-text progressive-reveal fallback existed only
// because nothing on the frontend consumed that field yet, not because
// the raw frames were unavailable. Cowrie's own binary ttylog framing
// (TTYSTRUCT = "<iLiiLL": op i32, tty u32 unused, length i32, direction
// i32, sec u32, usec u32, then `length` bytes of data for OP_WRITE) is
// decoded client-side into individually-timed frames — mirrors
// replay.rs's own decode() exactly (OP_WRITE + DIR_OUTPUT only, same
// byte content as `transcript`), just kept as a frame list instead of one
// concatenated string so each frame can be `term.write()`'d with real
// timing instead of revealed character-by-character.
import { Skeleton } from '../components/ui/skeleton'
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Label } from '../components/ui/label'
import { Card, CardContent, CardDescription } from '../components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Table, TableBody, TableCell, TableRow } from '../components/ui/table'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs'
import { formatTimestamp } from '../lib/time'
import { xtermTheme } from '../lib/xtermTheme'
import { useAppearanceKey } from '../lib/prefs'


type Replay = {
  shasum: string
  size_bytes: number
  imported_at: string
  frames: number
  duration_seconds: number
  transcript: string
  ttylog_base64: string
}

type TtyFrame = { timestamp: number; data: Uint8Array }

const TTY_OP_WRITE = 3
const TTY_DIR_OUTPUT = 2
const TTY_HEADER_BYTES = 24

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

/** Mirrors replay.rs's decode(): same header layout, same OP_WRITE +
 * DIR_OUTPUT filter, so the frame bytes concatenate to exactly
 * `replay.transcript` — just kept as individually-timestamped frames. */
function parseTtyLog(bytes: Uint8Array): TtyFrame[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const frames: TtyFrame[] = []
  let cursor = 0
  while (cursor + TTY_HEADER_BYTES <= bytes.length) {
    const op = view.getInt32(cursor, true)
    const length = view.getInt32(cursor + 8, true)
    const direction = view.getInt32(cursor + 12, true)
    const sec = view.getUint32(cursor + 16, true)
    const usec = view.getUint32(cursor + 20, true)
    cursor += TTY_HEADER_BYTES
    if (length < 0 || cursor + length > bytes.length) break
    if (op === TTY_OP_WRITE && direction === TTY_DIR_OUTPUT) {
      frames.push({ timestamp: sec + usec / 1_000_000, data: bytes.slice(cursor, cursor + length) })
    }
    cursor += length
  }
  return frames
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

// #2178: serviceJSON collapsed "no recording has this id" (a real 404)
// and "the request failed" into one null, so an outage read as "No
// recording found for this id." — a confident negative about evidence.
// Tri-state now; the handler never rejects.
type ReplayFetch = { state: 'replay'; replay: Replay } | { state: 'missing' } | { state: 'failed' }

const fetchReplay = createServerFn({ method: 'GET' })
  .validator((input: { shasum: string }) => input)
  .handler(async ({ data }): Promise<ReplayFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<Replay>(`/api/v1/recordings/${encodeURIComponent(data.shasum)}`)
    if (result.ok) return { state: 'replay', replay: result.body }
    return result.status === 404 ? { state: 'missing' } : { state: 'failed' }
  })

/** The recording's source IP, recovered the same way /recordings joins
 * attribution: the cowrie.log.closed event whose honeypot.shasum is this
 * recording's shasum (events.rs:99-102). since=365d — the 10d events
 * default would lose attribution for older recordings.
 *
 * #2178: this used to return plain string, where '' meant BOTH "no indexed
 * event references this recording anymore" AND "the attribution query
 * itself failed" — an outage collapsed into confident absence about
 * evidence. Tri-state now; never rejects. */
type SourceIpFetch = { state: 'ip'; ip: string } | { state: 'none' } | { state: 'failed' }

const fetchSourceIp = createServerFn({ method: 'GET' })
  .validator((input: { shasum: string }) => input)
  .handler(async ({ data }): Promise<SourceIpFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<{ rows?: { src_ip: string }[] }>(
      `/api/v1/events?kind=cowrie.log.closed&shasum=${encodeURIComponent(data.shasum)}&size=1&since=365d`,
    )
    if (!result.ok) {
      // A 404 from the events search reads as "nothing matched"; every
      // other failure means the pipeline itself is down.
      return result.status === 404 ? { state: 'none' } : { state: 'failed' }
    }
    const ip = result.body.rows?.[0]?.src_ip ?? ''
    return ip ? { state: 'ip', ip } : { state: 'none' }
  })

// #2178: null here also overloaded "the operator profile genuinely isn't
// there" (404) with "the profile request failed". Tri-state like the rest
// of this file; never rejects.
type ProfileFetch = { state: 'profile'; profile: IpProfile } | { state: 'absent' } | { state: 'failed' }

const fetchProfile = createServerFn({ method: 'GET' })
  .validator((input: { ip: string }) => input)
  .handler(async ({ data }): Promise<ProfileFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<IpProfile>(`/api/v1/investigate/ip/${encodeURIComponent(data.ip)}`)
    if (result.ok) return { state: 'profile', profile: result.body }
    return result.status === 404 ? { state: 'absent' } : { state: 'failed' }
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
// play/restart/seek/speed wiring) driving a real terminal emulator.
// Frame-indexed rather than character-indexed: seeking resets the
// terminal and replays every frame up to the target synchronously (no
// per-frame delay), the same fast-forward-by-replay approach asciinema's
// own player uses, since xterm has no "undo a write" primitive.
function TerminalPlayback({ replay }: { replay: Replay }) {
  const frames = useMemo(() => {
    if (!replay.ttylog_base64) return []
    try {
      return parseTtyLog(base64ToBytes(replay.ttylog_base64))
    } catch {
      return []
    }
  }, [replay.ttylog_base64])

  const text = useMemo(() => plainTranscript(replay.transcript), [replay.transcript])
  const total = frames.length

  const containerRef = useRef<HTMLDivElement & { __xoreTerminal?: import('@xterm/xterm').Terminal }>(null)
  const termRef = useRef<import('@xterm/xterm').Terminal | null>(null)
  const appearance = useAppearanceKey()

  // #1757: xterm swaps its theme in place, so an appearance change costs
  // neither a remount nor a re-parse of the recording.
  useEffect(() => {
    const term = termRef.current
    if (term) term.options.theme = xtermTheme()
  }, [appearance])
  const fitRef = useRef<import('@xterm/addon-fit').FitAddon | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const indexRef = useRef(0)
  const speedRef = useRef(1)
  const [index, setIndex] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)

  useEffect(() => {
    indexRef.current = index
  }, [index])
  useEffect(() => {
    speedRef.current = speed
  }, [speed])

  // Mount the terminal once frames are known — a stable instance survives
  // play/pause/seek; only restart() ever calls term.reset().
  useEffect(() => {
    const container = containerRef.current
    if (!container || total === 0) return
    let disposed = false
    ;(async () => {
      const [{ Terminal }, { FitAddon }] = await Promise.all([
        import('@xterm/xterm'),
        import('@xterm/addon-fit'),
        import('@xterm/xterm/css/xterm.css'),
      ])
      if (disposed) return
      const term = new Terminal({
        convertEol: true,
        cols: 80,
        rows: 24,
        disableStdin: true,
        fontSize: 13,
        scrollback: 5000,
        theme: xtermTheme(),
      })
      const fit = new FitAddon()
      term.loadAddon(fit)
      term.open(container)
      fit.fit()
      container.__xoreTerminal = term
      termRef.current = term
      fitRef.current = fit
    })()
    const onResize = () => fitRef.current?.fit()
    window.addEventListener('resize', onResize)
    return () => {
      disposed = true
      window.removeEventListener('resize', onResize)
      if (timerRef.current) clearTimeout(timerRef.current)
      termRef.current?.dispose()
      delete container.__xoreTerminal
      termRef.current = null
      fitRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- frames identity is stable per replay
  }, [total])

  const writeUpTo = useCallback(
    (target: number) => {
      const term = termRef.current
      if (!term) return
      term.reset()
      for (let i = 0; i < target; i++) term.write(frames[i].data)
      setIndex(target)
    },
    [frames],
  )

  const scheduleNext = useCallback(() => {
    const term = termRef.current
    if (!term) return
    const i = indexRef.current
    if (i >= frames.length) {
      setPlaying(false)
      return
    }
    const frame = frames[i]
    term.write(frame.data)
    const next = i + 1
    setIndex(next)
    if (next >= frames.length) {
      setPlaying(false)
      return
    }
    // Same idle cap the earlier reveal-based player used: an inter-frame
    // gap longer than 3s (an attacker who walked away mid-session) never
    // stalls playback for minutes.
    const gap = Math.min(Math.max(0, frames[next].timestamp - frame.timestamp), 3)
    timerRef.current = setTimeout(scheduleNext, (gap * 1000) / speedRef.current)
  }, [frames])

  useEffect(() => {
    if (!playing) return
    scheduleNext()
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- scheduleNext re-chains itself via indexRef
  }, [playing])

  if (total === 0) {
    return (
      <Card>
        <CardDescription role="status">
          This recording has no replayable output. The terminal is empty.
        </CardDescription>
      </Card>
    )
  }

  const label = playing ? 'Pause' : index >= total ? 'Replay' : index > 0 ? 'Resume' : 'Play'

  return (
    <Card>
      <div className="my-3 flex flex-wrap items-center gap-4 [&_input[type=range]]:min-w-40 [&_input[type=range]]:flex-[1_1_260px]">
        <Button
          variant="default"
          size="sm"
          type="button"
          onClick={() => {
            if (playing) {
              setPlaying(false)
              return
            }
            if (index >= total) writeUpTo(0)
            setPlaying(true)
          }}
        >
          {label}
        </Button>
        <Button
          variant="secondary"
          size="sm"
          type="button"
          onClick={() => {
            setPlaying(false)
            writeUpTo(0)
          }}
        >
          Restart
        </Button>
        <Input
          type="range"
          min={0}
          max={total}
          value={index}
          aria-label="Seek within the recording"
          onChange={(event) => {
            setPlaying(false)
            writeUpTo(Number(event.target.value))
          }}
        />
        <Label>
          speed{' '}
          <Select value={String(speed)} onValueChange={(value) => setSpeed(Number(value))}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="1">1×</SelectItem>
              <SelectItem value="2">2×</SelectItem>
              <SelectItem value="4">4×</SelectItem>
              <SelectItem value="0.5">0.5×</SelectItem>
            </SelectContent>
          </Select>
        </Label>
      </div>
      <CardDescription role="status">
        {replay.frames.toLocaleString('en-US')} frame(s), {replay.size_bytes.toLocaleString('en-US')} bytes recorded ·{' '}
        {replay.duration_seconds.toFixed(1)}s of terminal time.
      </CardDescription>
      <div ref={containerRef} className="min-h-[420px] overflow-x-auto whitespace-pre rounded-lg border border-border bg-[var(--terminal-bg)] p-4 font-mono text-sm leading-[1.35] text-[var(--terminal-fg)]" aria-label="Terminal playback" />
      {/* The whole transcript stays one disclosure away, searchable/
          copyable, no scrubbing to the end required. */}
      <details className="hp-flow">
        <summary>Full transcript</summary>
        <pre className="code">{text}</pre>
      </details>
    </Card>
  )
}

function MiniTable({ title, rows, linkTo }: { title: string; rows: Kv[]; linkTo?: (key: string) => string }) {
  if (rows.length === 0) return null
  return (
    <Card className="sm:w-1/2 w-full">
      <h2>{title}</h2>
      <CardContent>
        <Table className="data-table">
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.key}>
                <TableCell className="n">{row.count.toLocaleString('en-US')}</TableCell>
                <TableCell className="v">{linkTo ? <a href={linkTo(row.key)}>{row.key}</a> : row.key}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

// Attacker replay (tty_replay.html panel-attacker): the source IP's
// profile — KPIs, behavior tables, MITRE chips, and the chronological
// timeline — loaded lazily on first tab activation. The old page's
// single-point Leaflet map and payload-observation KPI aren't in
// /api/v1/investigate/ip's profile; everything else is.
function AttackerTab({ shasum }: { shasum: string }) {
  // #2178: three distinct dead ends — the attribution query failing, the
  // recording genuinely unreferenced by any indexed event, and the profile
  // request failing after a good ip — all landed in the same "No indexed
  // event still references this recording's source IP" paragraph, so an
  // outage asserted nothing was known. Each state now speaks for itself.
  const [state, setState] = useState<
    'loading' | 'none' | 'failed' | { ip: string; profile: IpProfile | null }
  >('loading')
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let cancelled = false
    setState('loading')
    ;(async () => {
      try {
        const source = await fetchSourceIp({ data: { shasum } })
        if (cancelled) return
        if (source.state === 'failed') {
          setState('failed')
          return
        }
        if (source.state === 'none') {
          setState('none')
          return
        }
        const profile = await fetchProfile({ data: { ip: source.ip } })
        if (!cancelled) {
          if (profile.state === 'failed') setState('failed')
          else if (profile.state === 'absent') setState({ ip: source.ip, profile: null })
          else setState({ ip: source.ip, profile: profile.profile })
        }
      } catch {
        // Handlers don't reject by construction; this backstop maps any
        // surprise to "unknown", not to "no attacker context exists".
        if (!cancelled) setState('failed')
      }
    })()
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- re-runs on attempt bump only
  }, [shasum, attempt])

  if (state === 'loading') return <Skeleton className="h-4 w-full" aria-hidden="true" />
  if (state === 'failed') {
    return (
      <ErrorStateBlock
        title="Attacker context failed to load"
        hint="The backend request failed — this says nothing about whether attacker context exists for this recording."
        onRetry={() => setAttempt((n) => n + 1)}
      />
    )
  }
  if (state === 'none') {
    return (
      <p className="empty">
        No indexed event still references this recording's source IP — either it aged out of the events window, or the
        recording predates this dashboard's own tracking. Attacker context isn't available for this one, but{' '}
        <Link className="lnk" to="/recordings" search={() => ({ ip: undefined })}>
          other recordings
        </Link>{' '}
        may still have it.
      </p>
    )
  }

  const { ip, profile } = state
  if (!profile) {
    // #2178 split from the catch-all above: we KNOW the source ip; only
    // its profile is unavailable — so name the ip instead of implying the
    // whole trail vanished.
    return (
      <p className="empty">
        This recording's source IP is <code>{ip}</code>, but its indexed attacker profile isn't available right now —
        open{' '}
        <Link className="lnk" to="/investigate/ip/$ip" params={{ ip }}>
          its profile page
        </Link>{' '}
        directly.
      </p>
    )
  }
  return (
    <>
      <div className="overview-header">
        <div>
          <div className="text-base font-semibold">Attacker profile</div>
          <h2>
            <Link className="lnk" to="/investigate/ip/$ip" params={{ ip }}>
              {ip}
            </Link>
          </h2>
          <CardDescription>
            {profile.country || 'unknown origin'}
            {profile.asn ? ` • ${profile.asn}` : ''} — everything this source IP has done, not just this one session.
          </CardDescription>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="text-sm text-muted-foreground">Events</div>
            <div className="text-2xl font-semibold">{profile.total.toLocaleString('en-US')}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-sm text-muted-foreground">Sessions</div>
            <div className="text-2xl font-semibold">{profile.sessions.length.toLocaleString('en-US')}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-sm text-muted-foreground">Distinct commands</div>
            <div className="text-2xl font-semibold">{profile.commands.length.toLocaleString('en-US')}</div>
          </CardContent>
        </Card>
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
        <Card>
          <h2>Session timeline</h2>
          <p className="text-sm text-muted-foreground">Chronological, oldest to newest.</p>
          <CardContent className="timeline-track">
            {[...profile.events].reverse().map((event, index) => (
              <div className="timeline-block" key={`${event.time}-${index}`}>
                <div className="timeline-block__meta">
                  {formatTimestamp(event.time)} • {event.sensor}
                </div>
                <div>{event.detail || event.proto}</div>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}
    </>
  )
}

function TtyReplay() {
  const { first } = Route.useLoaderData()
  const { shasum } = Route.useParams()
  // #2178: `resolved ?? 'missing'` made a failed fetch assert "No
  // recording found for this id." — an outage dressed as absence of
  // evidence. Tri-state now: null while loading, 'missing' only for the
  // backend's own 404, 'failed' named with a retry.
  const [fetch, setFetch] = useState<ReplayFetch | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [tab, setTab] = useState('playback')
  useEffect(() => {
    let cancelled = false
    setFetch(null)
    ;(attempt === 0 ? first : fetchReplay({ data: { shasum } })).then((result) => {
      if (!cancelled) setFetch(result)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned loader stream
  }, [first, attempt])

  if (fetch?.state === 'missing') {
    return <InvestigateHeader label="Attacker behavior" title={shasum} subtitle="No recording found for this id." />
  }
  if (fetch?.state === 'failed') {
    return (
      <>
        <InvestigateHeader label="Attacker behavior" title={shasum} subtitle="The recording could not be loaded." />
        <ErrorStateBlock
          title="This recording failed to load"
          hint="The backend request failed — this says nothing about whether a recording exists for this id."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      </>
    )
  }

  const replay: Replay | null = fetch !== null && fetch.state === 'replay' ? fetch.replay : null

  return (
    <>
      <InvestigateHeader
        label="Cowrie TTY session recording"
        title={shasum.slice(0, 40)}
        subtitle="Replayed from the session's Elasticsearch mirror, not read off disk — real terminal playback, timed off the recording's own frames."
        chips={
          replay ? (
            <>
              <span className="chip">{replay.frames.toLocaleString('en-US')} frames</span>
              <span className="chip">{replay.duration_seconds.toFixed(1)}s terminal time</span>
              <span className="chip">{(replay.size_bytes / 1024).toFixed(1)} KB</span>
              <Link className="chip" to="/recordings" search={{ ip: undefined }}>← all recordings</Link>
            </>
          ) : undefined
        }
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="playback">Playback</TabsTrigger>
          <TabsTrigger value="attacker">Attacker replay</TabsTrigger>
        </TabsList>
        <TabsContent value="playback">
          {replay === null ? (
            <Card>
              <CardContent className="p-6">
                <Skeleton className="h-4 w-full" aria-hidden="true" />
                <Skeleton className="h-4 w-full" aria-hidden="true" />
              </CardContent>
            </Card>
          ) : (
            <TerminalPlayback replay={replay} />
          )}
        </TabsContent>
        <TabsContent value="attacker">
          <Card>
            <CardContent className="p-6">
              {/* Lazily mounted — the profile lookup doesn't run until the tab
                  is first opened (hp-tty-replay.js initialized its map the same
                  way, on first reveal). */}
              {tab === 'attacker' ? <AttackerTab shasum={shasum} /> : null}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </>
  )
}
