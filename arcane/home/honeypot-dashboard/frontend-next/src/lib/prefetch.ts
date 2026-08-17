// Predictive prefetching (per Xore, #1608): the app anticipates the likely
// next click and warms that route — loader and server payload — before it
// happens. Two layers:
//   1. intent preload (router-level, hover/touch) — already on via
//      defaultPreload: 'intent';
//   2. this module: after each navigation settles, the top predicted next
//      routes for the current page are preloaded during idle time, so the
//      server functions behind them run and the BFF's short-TTL payload
//      cache is hot when the click lands.
// Toggleable (hard requirement): localStorage 'hp-prefetch' = 'off'
// disables layer 2 with one click in settings; default is on.
import { useRouter, useRouterState } from '@tanstack/react-router'
import { useEffect } from 'react'

/** Where operators actually go next, seeded from the dashboard's own
 * navigation structure (sidebar neighbors + observed investigation flow:
 * overview → events → sources; campaigns/clusters ↔ attackers). */
const PREDICTIONS: Record<string, string[]> = {
  '/': ['/events', '/ips', '/alerts'],
  '/events': ['/ips', '/campaigns', '/recordings'],
  '/ips': ['/events', '/campaigns', '/attackers'],
  '/campaigns': ['/clusters', '/attackers', '/kill-chain'],
  '/clusters': ['/attackers', '/campaigns', '/events'],
  '/attackers': ['/kill-chain', '/events', '/clusters'],
  '/kill-chain': ['/commands', '/campaigns'],
  '/commands': ['/recordings', '/events'],
  '/sensors': ['/recordings', '/events'],
  '/recordings': ['/events', '/commands'],
  '/alerts': ['/events', '/source-health'],
  '/source-health': ['/history', '/alerts'],
  '/payloads': ['/payload-workbench/results', '/events'],
}

export function prefetchEnabled(): boolean {
  try {
    return localStorage.getItem('hp-prefetch') !== 'off'
  } catch {
    return true
  }
}

export function setPrefetchEnabled(on: boolean) {
  try {
    if (on) localStorage.removeItem('hp-prefetch')
    else localStorage.setItem('hp-prefetch', 'off')
  } catch {
    /* storage unavailable */
  }
}

export function usePredictivePrefetch() {
  const router = useRouter()
  const pathname = useRouterState({ select: (s) => s.location.pathname })
  useEffect(() => {
    if (!prefetchEnabled()) return
    const targets = PREDICTIONS[pathname]
    if (!targets?.length) return
    const idle =
      'requestIdleCallback' in window
        ? (fn: () => void) => (window as Window & { requestIdleCallback: (fn: () => void, opts?: { timeout: number }) => number }).requestIdleCallback(fn, { timeout: 2000 })
        : (fn: () => void) => window.setTimeout(fn, 350)
    let cancelled = false
    idle(() => {
      if (cancelled) return
      for (const to of targets) {
        router.preloadRoute({ to }).catch(() => {
          /* prediction misses are free */
        })
      }
    })
    return () => {
      cancelled = true
    }
  }, [router, pathname])
}
