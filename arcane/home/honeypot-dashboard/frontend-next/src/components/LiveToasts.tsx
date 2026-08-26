// Shell-wide operational toasts (#1900).
//
// This used to announce arriving events -- "N new honeypot events", the
// port of hp-app.js showLiveToast. On a fleet this size that is a
// notification that fires forever and says nothing: events arriving is the
// normal state, the LIVE badge already says the stream is up, and a toast
// that is always present is one an operator learns to ignore. Which is the
// real cost -- it trained the eye to dismiss the corner of the screen
// where actual problems would appear.
//
// So the trigger moved from "something happened" to "something is wrong".
// Conditions worth interrupting for, from /api/v1/source-health, the same
// endpoint the source-health page renders:
//
//   * a sensor stopped reporting (STALE, its own >1h threshold)
//   * ingestion stalled or fell behind
//   * the Elasticsearch cluster went yellow or red
//   * the Filebeat pipeline became unreachable
//   * documents started landing in the dead-letter index
//
// Edge-triggered, not level-triggered. A condition raises one toast when it
// becomes true and one when it clears; an outage that lasts all afternoon
// does not re-announce itself every minute. That distinction is the whole
// point -- a repeating alert is the same "always present, therefore
// ignored" failure the event toast had, wearing a more serious label.
//
// Recovery is reported too, because an operator who saw the outage needs to
// know it ended without going to look. Those are the only toasts that will
// appear on a healthy fleet, and only after something was wrong.
import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useLiveInterval } from '../lib/live'
import { pullLiveToastPrefs, type LiveToastPrefs } from '../lib/prefs'

type Severity = 'warning' | 'danger' | 'success'

type Toast = {
  id: number
  /** Stable per condition, so a toast can be traced back to what raised it. */
  key: string
  message: string
  severity: Severity
  to: string
}

/** One thing that can be wrong, as the health endpoint describes it. */
type Condition = { key: string; message: string; severity: Severity; to: string }

type SensorHealth = { sensor: string; state: string; last_seen: string }
type SourceHealth = {
  cluster_status?: string
  sensors?: SensorHealth[]
  ingest?: { state?: string; age_seconds?: number }
  pipeline?: { state?: string }
  dead_letters?: number
}

const DEFAULT_PREFS: LiveToastPrefs = { enabled: true, intervalSeconds: 60 }
const TOAST_MS = 12000

// Health conditions move on the order of minutes -- a sensor is STALE after
// an hour without traffic, ingestion after fifteen. Polling faster than
// this cannot make a toast arrive meaningfully sooner and only adds
// requests, so the operator's toast cadence sets a floor rather than the
// interval: it is a preference about notification frequency, and this is
// not a stream any more.
const MIN_POLL_MS = 60_000

// The backend is not reachable from the browser -- everything goes through
// the server tier, the same way pullLiveToastPrefs does. LiveToasts is
// mounted in AppShell rather than by a route, so it has no loader of its
// own and this is its only way to read the health document.
const fetchSourceHealth = createServerFn({ method: 'GET' }).handler(
  async (): Promise<SourceHealth | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<SourceHealth>('/api/v1/source-health')
  },
)

/** Reads the health document as a set of conditions that are true right now. */
export function conditionsFrom(health: SourceHealth): Condition[] {
  const conditions: Condition[] = []

  for (const sensor of health.sensors ?? []) {
    if (sensor.state === 'STALE') {
      conditions.push({
        key: `sensor:${sensor.sensor}`,
        message: `${sensor.sensor} stopped reporting`,
        severity: 'warning',
        to: '/source-health',
      })
    }
  }

  const ingest = health.ingest?.state
  if (ingest === 'stale') {
    conditions.push({
      key: 'ingest',
      // The 45-hour blackout in #1767 is what this exists for: nothing on
      // screen said ingestion had stopped, because a loopback healthcheck
      // kept the freshness figure looking alive.
      message: 'Ingestion has stalled — no new events are being indexed',
      severity: 'danger',
      to: '/source-health',
    })
  } else if (ingest === 'delayed') {
    conditions.push({
      key: 'ingest',
      message: 'Ingestion is falling behind',
      severity: 'warning',
      to: '/source-health',
    })
  }

  // Red only. Yellow is the steady state of this deployment, not a
  // problem: Elasticsearch runs on one node, so replica shards can never
  // be assigned and the cluster is permanently yellow -- measured live,
  // 408 active shards and 16 unassigned with number_of_nodes = 1.
  //
  // Alerting on it would recreate exactly what this component was changed
  // to stop doing. It would fire on essentially every session, for a
  // condition no operator can act on, and teach the eye to dismiss the
  // corner of the screen where a red cluster would appear.
  //
  // The source-health page still shows the colour, which is the right
  // place for a standing fact. If this cluster ever gains a second node,
  // yellow becomes meaningful again and belongs back here.
  if ((health.cluster_status ?? '').toLowerCase() === 'red') {
    conditions.push({
      key: 'cluster',
      message: 'Elasticsearch cluster is red — shards are unavailable',
      severity: 'danger',
      to: '/source-health',
    })
  }

  const pipeline = health.pipeline?.state
  if (pipeline === 'unreachable') {
    conditions.push({
      key: 'pipeline',
      message: 'Filebeat is unreachable',
      severity: 'danger',
      to: '/source-health',
    })
  }

  if ((health.dead_letters ?? 0) > 0) {
    conditions.push({
      key: 'dead-letters',
      message: `${health.dead_letters} document${health.dead_letters === 1 ? '' : 's'} rejected by Elasticsearch`,
      severity: 'warning',
      to: '/dead-letters',
    })
  }

  return conditions
}

/** What changed between two observations: newly true, and newly resolved. */
export function transitions(
  previous: Map<string, Condition>,
  current: Condition[],
): { raised: Condition[]; cleared: Condition[] } {
  const now = new Map(current.map((condition) => [condition.key, condition]))
  const raised = current.filter((condition) => {
    const before = previous.get(condition.key)
    // A condition that changes severity (delayed -> stalled) is news again;
    // one that merely persists is not.
    return !before || before.severity !== condition.severity
  })
  const cleared = [...previous.values()].filter((condition) => !now.has(condition.key))
  return { raised, cleared }
}

export function LiveToasts() {
  const [toasts, setToasts] = useState<Toast[]>([])
  const [prefs, setPrefs] = useState<LiveToastPrefs>(DEFAULT_PREFS)
  const known = useRef<Map<string, Condition>>(new Map())
  const primed = useRef(false)
  const nextId = useRef(0)

  useEffect(() => {
    let cancelled = false
    pullLiveToastPrefs().then((result) => {
      if (!cancelled) setPrefs(result)
    })
    return () => {
      cancelled = true
    }
  }, [])

  // #1973: this was a hand-rolled setInterval plus a bare `void poll()` --
  // no visibility guard, no LIVE-paused guard -- so a background tab kept
  // querying source-health forever and could toast "sensor went stale"
  // against data the rest of the shell had agreed not to refresh. The
  // shared tick owns the cadence now.
  //
  // `alive` covers the async tail: a poll already in flight when the
  // component unmounts must not raise toasts afterwards.
  const alive = useRef(true)
  useEffect(() => {
    return () => {
      alive.current = false
    }
  }, [])

  const show = useCallback((condition: Condition, message: string, severity: Severity) => {
    const id = nextId.current++
    setToasts((current) => [...current, { id, key: condition.key, message, severity, to: condition.to }])
    setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), TOAST_MS)
  }, [])

  const poll = useCallback(async () => {
    let health: SourceHealth | null
    try {
      health = await fetchSourceHealth()
    } catch {
      // The dashboard's own backend being unreachable is not something to
      // toast about -- the page would already be failing to load, and a
      // toast raised from a failed call would fire on every transient
      // blip during a deploy.
      return
    }
    if (!alive.current || !health) return

    const current = conditionsFrom(health)
    const { raised, cleared } = transitions(known.current, current)

    // The first poll establishes what is already true rather than
    // announcing it. Opening the dashboard during a known outage should
    // not fire a toast per stale sensor -- the source-health page is
    // where that belongs, and the toast is for changes since you looked.
    if (primed.current) {
      for (const condition of raised) show(condition, condition.message, condition.severity)
      for (const condition of cleared) show(condition, `Resolved: ${condition.message}`, 'success')
    }
    primed.current = true
    known.current = new Map(current.map((condition) => [condition.key, condition]))
  }, [show])

  // Deliberately not scoped to a route: an outage is worth knowing about
  // on every page, including /events. The old toast was suppressed there
  // because the arriving rows were themselves the notification -- but a
  // sensor that stopped reporting shows up as rows that never arrive,
  // which is exactly what nobody notices.
  useLiveInterval(poll, Math.max(MIN_POLL_MS, prefs.intervalSeconds * 1000), {
    leading: true,
    enabled: prefs.enabled,
  })

  if (toasts.length === 0) return null
  return (
    <div className="hp-toast-stack">
      {toasts.map((toast) => (
        <Link key={toast.id} className={`toast hp-toast toast--${toast.severity}`} to={toast.to}>
          {toast.message}
        </Link>
      ))}
    </div>
  )
}
