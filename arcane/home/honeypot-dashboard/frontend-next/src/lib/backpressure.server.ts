// BFF backpressure (#1616): the hard requirement is that this tier never
// gets overwhelmed, since it carries no compose resource limit (see
// compose.yml's dashboard-next comment) and scales by adding replicas, not
// by being throttled from outside. Two primitives:
//
//   - ConcurrencyLimiter: bounded-queue admission control. `maxConcurrent`
//     run at once; up to `maxQueue` more wait; anything past that (or any
//     request while the event loop is already lagging) is shed immediately
//     instead of piling up memory/sockets behind a growing queue.
//   - eventLoopLagMs(): sampled via perf_hooks so admission can shed load
//     the process is visibly struggling with, even under the concurrency
//     cap (GC pressure, a slow synchronous JSON pass, etc).
//
// Used two ways: backend.server.ts wraps the Rust-tier fan-out in one
// shared limiter (the "bounded queue for fan-out to the Rust tier"), and
// the byte-streaming proxy routes (SSE, PDF, artifact, canarytoken) each
// take their own limiter instance (the "per-route concurrency caps") since
// those hold a socket/file-descriptor for the life of the stream, not just
// for one request/response cycle.
import { monitorEventLoopDelay } from 'node:perf_hooks'

const elMonitor = monitorEventLoopDelay({ resolution: 20 })
elMonitor.enable()

/** Number(process.env[name]) with a fallback — guards the compose
 * convention of `${VAR:-}` (empty string, not unset) for every tunable
 * this module and its callers read, so an unset override can never
 * silently parse to 0 (e.g. a concurrency cap of 0 that admits nothing). */
export function envInt(name: string, fallback: number): number {
  const raw = process.env[name]
  return raw ? Number(raw) || fallback : fallback
}

/** p99 event-loop delay over the monitor's rolling window, in whole ms. */
export function eventLoopLagMs(): number {
  return elMonitor.percentile(99) / 1e6
}

const EVENT_LOOP_LAG_SHED_MS = envInt('BFF_EVENT_LOOP_SHED_MS', 250)

export class Overloaded extends Error {
  constructor(public readonly reason: 'queue-full' | 'event-loop-lag') {
    super(`shedding load: ${reason}`)
  }
}

export class ConcurrencyLimiter {
  private active = 0
  private readonly waiters: Array<() => void> = []

  constructor(
    private readonly maxConcurrent: number,
    private readonly maxQueue: number = 0,
  ) {}

  /** Resolves with a release function once admitted, or throws Overloaded. */
  async acquire(): Promise<() => void> {
    if (eventLoopLagMs() > EVENT_LOOP_LAG_SHED_MS) throw new Overloaded('event-loop-lag')
    if (this.active >= this.maxConcurrent) {
      if (this.waiters.length >= this.maxQueue) throw new Overloaded('queue-full')
      await new Promise<void>((resolve) => this.waiters.push(resolve))
    }
    this.active++
    let released = false
    return () => {
      if (released) return
      released = true
      this.active--
      const next = this.waiters.shift()
      if (next) next()
    }
  }

  /** Runs fn under the limiter; propagates Overloaded to the caller instead
   * of running fn when shed. */
  async run<T>(fn: () => Promise<T>): Promise<T> {
    const release = await this.acquire()
    try {
      return await fn()
    } finally {
      release()
    }
  }
}

export function overloadedResponse(err: Overloaded): Response {
  return new Response(err.reason === 'event-loop-lag' ? 'bff overloaded' : 'bff at capacity', {
    status: 503,
    headers: { 'retry-after': '1' },
  })
}

/** Shared acquire-limiter/fetch-upstream/release-and-stream sequence behind
 * every byte-streaming proxy route (artifact/canarytoken/export/payload/
 * report/live). Callers keep their own pre-limiter validation (allowlist,
 * hash format, admin role) and only supply the upstream URL, the success
 * response's headers (computed from the upstream response), and the
 * unavailable-case message — with an optional fixed status for routes like
 * live.ts's SSE proxy that don't forward upstream.status. */
export async function limitedStreamProxy(
  request: Request,
  limiter: ConcurrencyLimiter,
  url: string,
  headersFor: (upstream: Response) => HeadersInit,
  unavailable: { message: string; status?: number },
): Promise<Response> {
  let release: () => void
  try {
    release = await limiter.acquire()
  } catch (err) {
    if (err instanceof Overloaded) return overloadedResponse(err)
    throw err
  }
  const upstream = await fetch(url, {
    headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' },
    signal: request.signal,
  }).catch((err) => {
    release()
    throw err
  })
  if (!upstream.ok || !upstream.body) {
    release()
    return new Response(unavailable.message, { status: unavailable.status ?? upstream.status })
  }
  return new Response(releaseOnFinish(upstream.body, release), { status: 200, headers: headersFor(upstream) })
}

/** Wraps a proxied upstream body so a route-level limiter slot (acquired
 * for the life of a stream, not just one request/response cycle — SSE,
 * PDF/artifact downloads) is released exactly once: when the stream ends
 * normally, errors, or the client disconnects (Response bodies call
 * cancel() on abort). Without this, a limiter guarding a streamed route
 * would leak its slot on every request and converge on permanent 503s. */
export function releaseOnFinish(body: ReadableStream<Uint8Array>, release: () => void): ReadableStream<Uint8Array> {
  const reader = body.getReader()
  let released = false
  const finish = () => {
    if (released) return
    released = true
    release()
  }
  return new ReadableStream({
    async pull(controller) {
      try {
        const { done, value } = await reader.read()
        if (done) {
          controller.close()
          finish()
          return
        }
        controller.enqueue(value)
      } catch (err) {
        controller.error(err)
        finish()
      }
    },
    cancel(reason) {
      finish()
      return reader.cancel(reason)
    },
  })
}
