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
  if (!state.paused) {
    // Resuming shows current data rather than whatever went stale while
    // updates were suppressed — pages listen for this to refetch now.
    window.dispatchEvent(new CustomEvent('hp-live-resumed'))
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
