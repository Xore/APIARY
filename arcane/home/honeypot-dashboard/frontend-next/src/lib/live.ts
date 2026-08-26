// Shared live-refresh state — the port of hp-app.js's window.HoneypotLive
// (:152-185): one paused switch over every refresh path, plus connection
// health as the single global indicator (#210 — no per-page pill). Pages
// with polling or SSE subscribe via useLiveState()/isLivePaused() and
// report their connection health back with setConnectionHealthy().
// Paused persists in localStorage under the Go shell's own key
// ("hp-live-paused"), so the choice survives reloads and follows the
// operator across tiers during the transition.
import { useEffect, useSyncExternalStore } from 'react'

type LiveState = { paused: boolean; connectionHealthy: boolean }

const PAUSED_KEY = 'hp-live-paused'

let state: LiveState = { paused: false, connectionHealthy: true }
const listeners = new Set<() => void>()

// localStorage is read lazily on the client (never during SSR) — the
// first useLiveState() mount hydrates it via restorePaused().
let restored = false
export function restorePaused() {
  if (restored || typeof window === 'undefined') return
  restored = true
  try {
    if (localStorage.getItem(PAUSED_KEY) === '1') set({ paused: true })
  } catch {
    /* storage unavailable */
  }
}

function set(next: Partial<LiveState>) {
  state = { ...state, ...next }
  for (const listener of listeners) listener()
}

export function isLivePaused(): boolean {
  return state.paused
}

export function toggleLive() {
  set({ paused: !state.paused })
  try {
    localStorage.setItem(PAUSED_KEY, state.paused ? '1' : '0')
  } catch {
    /* storage unavailable */
  }
  syncStream()
  if (!state.paused) {
    // Resuming shows current data rather than whatever went stale while
    // updates were suppressed — pages listen for this to refetch now.
    window.dispatchEvent(new CustomEvent('hp-live-resumed'))
  }
}

// ── Shared SSE stream — one connection for the whole shell (#1564: the
// Go dashboard deliberately kept a single EventSource so navigating never
// tears one down and opens another; hp-app.js:1967-1986). Consumers
// subscribe; the stream exists while at least one subscriber is mounted
// and LIVE isn't paused, and its open/error state feeds the topbar's
// stalled indicator.
type LiveEventHandler = (data: string) => void
const streamHandlers = new Set<LiveEventHandler>()
let stream: EventSource | null = null

function syncStream() {
  if (typeof window === 'undefined' || typeof EventSource === 'undefined') return
  const wanted = streamHandlers.size > 0 && !state.paused
  if (wanted && !stream) {
    stream = new EventSource('/api/live')
    stream.addEventListener('open', () => setConnectionHealthy(true))
    stream.addEventListener('error', () => setConnectionHealthy(false))
    stream.addEventListener('event', (event) => {
      for (const handler of streamHandlers) handler((event as MessageEvent).data)
    })
  } else if (!wanted && stream) {
    stream.close()
    stream = null
    // Closing on purpose (pause/unmount) is not a connection failure.
    setConnectionHealthy(true)
  }
}

/** Subscribe to live event frames. Returns the unsubscribe function. */
export function subscribeLiveEvents(handler: LiveEventHandler): () => void {
  streamHandlers.add(handler)
  syncStream()
  return () => {
    streamHandlers.delete(handler)
    syncStream()
  }
}

/** SSE/poll owners report their connection health here. */
export function setConnectionHealthy(healthy: boolean) {
  if (state.connectionHealthy !== healthy) set({ connectionHealthy: healthy })
}

const getSnapshot = () => state
const serverSnapshot: LiveState = { paused: false, connectionHealthy: true }

export function useLiveState(): LiveState {
  useEffect(restorePaused, [])
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    getSnapshot,
    () => serverSnapshot,
  )
}

/**
 * The shell's one polling discipline (#1973): run `fn` on an interval,
 * but only while the tab is visible AND the shared LIVE switch isn't
 * paused — plus one catch-up call the moment live resumes. Before this
 * existed the guarded tick was hand-rolled three times (overview,
 * source-health, canarytokens) and skipped entirely twice: the Topbar
 * alert-badge polled through hidden tabs, and LiveToasts polled through
 * both, toasting "sensor went stale" against data the rest of the UI had
 * agreed not to refresh — the exact split-brain the switch exists to
 * prevent.
 *
 * `fn` must be referentially stable where it matters (wrap in useCallback);
 * the effect resubscribes when it, `ms`, or `enabled` change. `leading`
 * fires `fn` once at mount/effect-start, preserving the "first paint
 * fetches now" behavior of the call sites that relied on it (the ones
 * whose route loaders already fetch leave it off to avoid doubling the
 * request). `enabled: false` tears the interval down entirely, for
 * consumers whose polling is preference-gated.
 */
export function useLiveInterval(
  fn: () => void,
  ms: number,
  options: { leading?: boolean; enabled?: boolean } = {},
) {
  const { leading = false, enabled = true } = options
  useEffect(() => {
    if (!enabled) return
    if (leading) fn()
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible' && !isLivePaused()) fn()
    }, ms)
    // Resuming after a pause shows current data rather than whatever went
    // stale while updates were suppressed.
    window.addEventListener('hp-live-resumed', fn)
    return () => {
      clearInterval(timer)
      window.removeEventListener('hp-live-resumed', fn)
    }
  }, [fn, ms, enabled, leading])
}
