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
//     the filebeat-tailed mount, one ECS-ish JSON object per line.
//
// A /metrics route (routes/metrics.ts) renders these in Prometheus text;
// exposition format kept deliberately parallel to the Rust tier's.
import { appendFile } from 'node:fs/promises'
import { monitorEventLoopDelay } from 'node:perf_hooks'

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
  appendNamedEventLine(safe, fields)
}

async function appendNamedEventLine(name: string, fields: Record<string, unknown>): Promise<void> {
  if (!logFile()) return
  try {
    await appendFile(
      logFile(),
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
