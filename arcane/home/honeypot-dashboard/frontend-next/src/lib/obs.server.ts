// Serving-tier observability for the BFF (#1972) — the Node-side counterpart
// of backend-service's src/obs.rs, sized to this tier's realities:
//
//   - Requests are counted/timed where the 'request' middleware can see
//     them (start.ts wraps its pipeline with recordBffRequest); per-status
//     detail lives on the Rust tier's counter where statuses are cheap to
//     observe reliably — here they'd require h3 response hooks that don't
//     exist yet on every path type.
//   - Shed events become a counter (bff_sheds_total{reason}) instead of
//     invisible-by-design 503s (#1616: "nothing records how often").
//   - Outbound Rust-tier calls land as bff_backend_calls_total{result} so
//     a degradation shows WHICH failure class dried up first.
//   - OIDC outcomes are NAMED events (#1972 item 4): login started,
//     completed, and failed each increment one counter and write one JSONL
//     line, so the #1942-style question "how often is this failing and
//     since when" stops needing stdout archaeology.
//   - Durable line: same deal as the Rust tier — DASHBOARD_BFF_LOG_FILE on
//     the filebeat-tailed mount, one ECS-ish JSON object per line, size-capped
//     with the same rename-rotation shape as obs.rs's rotate_if_oversized
//     (#2826 — this sink shipped without it, unbounded by construction while
//     the Rust tier's twin was already capped at 2 x MAX_SINK_BYTES, #2468).
//
// A /metrics route (routes/metrics.ts) renders these in Prometheus text;
// exposition format kept deliberately parallel to the Rust tier's.
import { appendFile, rename, stat, unlink } from 'node:fs/promises'
import { monitorEventLoopDelay } from 'node:perf_hooks'

// Mirrors obs.rs's MAX_SINK_BYTES exactly: one live generation + one retired
// `.1` bounds the sink at 25 MiB + <=25 MiB on disk. This tier logs far less
// than the Rust tier (named OIDC events only, not every request), so this
// cap is reached far more slowly in practice -- but "slowly" is not "never",
// which is the whole defect this closes.
const MAX_SINK_BYTES = 25 * 1024 * 1024

export function rotatedPath(path: string): string {
  return `${path}.1`
}

/** Same shape as backend-service's audit::rotate_if_oversized: rename the
 * live file aside as `<path>.1` (dropping any previous `.1`) once it exceeds
 * the cap, then let the caller's append re-create the live file fresh. A
 * missing file or a failed stat/rename/unlink is silently a no-op -- shipping
 * logs must never take the BFF down with it, same rule obs.rs's own comment
 * states for its rotate call. */
export async function rotateIfOversized(path: string, maxBytes: number): Promise<void> {
  try {
    const meta = await stat(path)
    if (meta.size <= maxBytes) return
  } catch {
    return
  }
  const rotated = rotatedPath(path)
  try {
    await unlink(rotated)
  } catch {
    /* no previous generation to drop */
  }
  try {
    await rename(path, rotated)
  } catch {
    /* rotation failed: next append just keeps growing the live file */
  }
}

// Counters. Bounded label values only — reasons/results/names come from our
// own call sites, never from request bytes.
const counters = new Map<string, number>()

function inc(name: string): void {
  counters.set(name, (counters.get(name) ?? 0) + 1)
}

// Metrics-scoped event-loop sampler. Deliberately a SECOND instance rather
// than an import from backpressure.server.ts: that module will call this
// one's recordShed() on its shed paths, and the gauge belongs to metrics
// semantics, not admission control. Two 20ms-resolution samplers per
// process cost nothing measurable.
const lagMonitor = monitorEventLoopDelay({ resolution: 20 })
lagMonitor.enable()

/** p99 event-loop delay over the rolling window, in whole ms. */
export function eventLoopLagP99(): number {
  return lagMonitor.percentile(99) / 1e6
}

let totalDurationMs = 0

export function recordBffRequest(durationMs: number): void {
  inc('bff_requests_total')
  totalDurationMs += durationMs
}

export function recordShed(reason: 'queue-full' | 'event-loop-lag'): void {
  inc(`bff_sheds_total{reason="${reason}"}`)
}

export function recordBackendCall(result: string): void {
  // result ∈ ok | http_<status> | network_error | timeout — closed set of
  // shapes produced by backend.server.ts's wrapper below.
  inc(`bff_backend_calls_total{result="${result}"}`)
}

/** One lookup, one outcome — the outermost layer that answered (or "miss"
 * when it fell through to a live fetch), never both, so hit-rates sum to 1.
 * Redis hits on top of in-process misses count as redis, not as a process
 * miss AND a redis hit. */
export function recordCacheLookup(layer: 'in_process' | 'redis' | 'miss'): void {
  inc(`bff_payload_cache_total{result="${layer}"}`)
}

export function recordNamedEvent(name: string, fields: Record<string, unknown> = {}): void {
  // Name shape owned by callers (auth_login_started/…_completed/…_failed);
  // logged names stay sanitized so request-derived strings never become
  // label values.
  const safe = /^[\w.-]{1,64}$/.test(name) ? name : 'unnamed_event'
  inc(`bff_named_events_total{name="${safe}"}`)
  void appendNamedEventLine(safe, fields)
}

// obs.rs holds a tokio Mutex across the whole rotate->open->write sequence and
// its comment says why: an await between them "lets tokio's lazy file
// lifecycle interleave or defer them across tasks (measured in the tests
// below)". The same hazard is real here and worse, because recordNamedEvent
// fires this off without awaiting: two events crossing the cap concurrently
// both see an oversized file, and the second one's unlink deletes the retired
// generation the first just renamed aside -- leaving zero generations instead
// of one. A single-slot promise chain is Node's equivalent of that mutex.
// Writes never reject (writeNamedEventLine swallows its own errors), so the
// tail can never poison the chain.
let sinkTail: Promise<void> = Promise.resolve()

function appendNamedEventLine(name: string, fields: Record<string, unknown>): Promise<void> {
  sinkTail = sinkTail.then(() => writeNamedEventLine(name, fields))
  return sinkTail
}

/** Awaits every named-event line queued so far. Tests need it because
 * recordNamedEvent is deliberately fire-and-forget; nothing in the serving
 * path calls it. */
export function flushNamedEventSink(): Promise<void> {
  return sinkTail
}

async function writeNamedEventLine(name: string, fields: Record<string, unknown>): Promise<void> {
  const file = logFile()
  if (!file) return
  try {
    await rotateIfOversized(file, MAX_SINK_BYTES)
    await appendFile(
      file,
      `${JSON.stringify({
        '@timestamp': new Date().toISOString(),
        'event.category': 'dashboard_app',
        service: 'dashboard-bff',
        level: name.endsWith('failed') ? 'error' : 'info',
        'event.action': name,
        ...fields,
      })}\n`,
    )
  } catch {
    /* durable sink unavailable: counters above still carry the signal */
  }
}

function logFile(): string {
  return process.env.DASHBOARD_BFF_LOG_FILE ?? ''
}

/// Prometheus text. Duration gauge exposes the mean-of-accumulated mean —
/// sum/count split gives scrapers rate()-able halves like the Rust tier's.
export function renderMetrics(): string {
  const out: string[] = []
  out.push('# HELP bff_requests_total HTTP requests served by this tier.')
  out.push('# TYPE bff_requests_total counter')
  out.push(`bff_requests_total ${counters.get('bff_requests_total') ?? 0}`)
  out.push('# HELP bff_request_duration_seconds_sum Sum of served-request wall time.')
  out.push('# TYPE bff_request_duration_seconds_sum counter')
  out.push('# UNIT bff_request_duration_seconds seconds')
  out.push(`bff_request_duration_seconds_sum ${(totalDurationMs / 1000).toFixed(6)}`)
  out.push('# HELP bff_sheds_total Load shed by the admission limiter (#1616).')
  out.push('# TYPE bff_sheds_total counter')
  for (const [name, value] of sortedCounterEntries()) {
    if (name.startsWith('bff_sheds_total')) out.push(`${name} ${value}`)
  }
  out.push('# HELP bff_backend_calls_total Calls into the Rust tier by outcome.')
  out.push('# TYPE bff_backend_calls_total counter')
  for (const [name, value] of sortedCounterEntries()) {
    if (name.startsWith('bff_backend_calls_total')) out.push(`${name} ${value}`)
  }
  out.push('# HELP bff_payload_cache_total Payload-cache lookups by hit/miss.')
  out.push('# TYPE bff_payload_cache_total counter')
  for (const [name, value] of sortedCounterEntries()) {
    if (name.startsWith('bff_payload_cache_total')) out.push(`${name} ${value}`)
  }
  out.push('# HELP bff_named_events_total Named application events (OIDC outcomes etc.).')
  out.push('# TYPE bff_named_events_total counter')
  for (const [name, value] of sortedCounterEntries()) {
    if (name.startsWith('bff_named_events_total')) out.push(`${name} ${value}`)
  }
  out.push('# HELP bff_event_loop_lag_p99_seconds p99 event-loop delay.')
  out.push('# TYPE bff_event_loop_lag_p99_seconds gauge')
  out.push('# UNIT bff_event_loop_lag_p99_seconds seconds')
  out.push(`bff_event_loop_lag_p99_seconds ${(eventLoopLagP99() / 1000).toFixed(6)}`)
  return `${out.join('\n')}\n`

  function sortedCounterEntries(): Array<[string, number]> {
    return [...counters.entries()].sort(([a], [b]) => (a < b ? -1 : 1))
  }
}
