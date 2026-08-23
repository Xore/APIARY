// Shell-wide "new events" toasts — the port of hp-app.js showLiveToast
// (:429-442) + the shared-stream trigger (:1978-1984): while the operator
// is anywhere but the events explorer, arriving live events surface as a
// stacked, clickable toast ("N new honeypot events" → /events) that
// removes itself after 8s. Suppressed while LIVE is paused (the shared
// stream is closed then anyway) and on /events, where the rows themselves
// stream in. Batches arrivals per the operator's configured cadence
// (#1684 — a fixed 3s batch fired constantly on a busy sensor) so a burst
// is one toast with a count, not a toast per event.
import { useEffect, useRef, useState } from 'react'
import { Link, useRouterState } from '@tanstack/react-router'
import { subscribeLiveEvents } from '../lib/live'
import { pullLiveToastPrefs, type LiveToastPrefs } from '../lib/prefs'

type Toast = { id: number; count: number }

const DEFAULT_PREFS: LiveToastPrefs = { enabled: true, intervalSeconds: 3 }
const TOAST_MS = 8000

export function LiveToasts() {
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  const [toasts, setToasts] = useState<Toast[]>([])
  const [prefs, setPrefs] = useState<LiveToastPrefs>(DEFAULT_PREFS)
  const pending = useRef(0)
  const nextId = useRef(0)
  const onEvents = pathname === '/events'

  useEffect(() => {
    let cancelled = false
    pullLiveToastPrefs().then((result) => {
      if (!cancelled) setPrefs(result)
    })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    if (onEvents || !prefs.enabled) return
    const unsubscribe = subscribeLiveEvents(() => {
      pending.current += 1
    })
    const flush = setInterval(
      () => {
        if (pending.current === 0) return
        const count = pending.current
        pending.current = 0
        const id = nextId.current++
        setToasts((current) => [...current, { id, count }])
        setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), TOAST_MS)
      },
      Math.max(1, prefs.intervalSeconds) * 1000,
    )
    return () => {
      unsubscribe()
      clearInterval(flush)
      pending.current = 0
    }
  }, [onEvents, prefs])

  if (toasts.length === 0) return null
  return (
    <div className="hp-toast-stack">
      {toasts.map((toast) => (
        <Link key={toast.id} className="toast hp-toast" to="/events">
          {toast.count} new honeypot event{toast.count === 1 ? '' : 's'}
        </Link>
      ))}
    </div>
  )
}
