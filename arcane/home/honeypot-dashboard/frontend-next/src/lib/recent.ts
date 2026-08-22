// "Recent investigations" — the port of hp-app.js's localStorage-backed
// last-5 list (:2151-2220, design-refresh pick 12B): the operator's last
// few investigation targets, rendered in the sidebar under a "Recent"
// label. Same storage key AND entry shape ({kind, value}) as the Go
// shell, so the list follows the operator across tiers during the
// transition — and hrefs are BUILT from an explicit kind switch at render
// time, never stored, so a poisoned localStorage entry is structurally
// incapable of producing a javascript: URL or off-site redirect (the Go
// tier's own CodeQL js/xss hardening, kept identical here).
import { useSyncExternalStore } from 'react'

export type RecentKind = 'ip' | 'session' | 'payload' | 'events-ip'
export type RecentEntry = { kind: RecentKind; value: string }

const KEY = 'hp-recent-investigations'
const MAX = 5
const listeners = new Set<() => void>()
let cache: RecentEntry[] | null = null

export function hrefForRecent(entry: RecentEntry): string | null {
  switch (entry.kind) {
    case 'ip':
      return '/investigate/ip/' + encodeURIComponent(entry.value)
    case 'session':
      return '/sessions/' + encodeURIComponent(entry.value)
    case 'payload':
      return '/payload-analysis/' + encodeURIComponent(entry.value)
    case 'events-ip':
      return '/events?ip=' + encodeURIComponent(entry.value)
    default:
      return null
  }
}

export function labelForRecent(entry: RecentEntry): string {
  if (entry.kind === 'session') return 'session ' + entry.value.slice(0, 12)
  if (entry.kind === 'payload') return entry.value.slice(0, 16) + '…'
  return entry.value
}

function safeEntry(entry: unknown): entry is RecentEntry {
  const candidate = entry as RecentEntry
  return (
    !!candidate &&
    typeof candidate.value === 'string' &&
    candidate.value.length > 0 &&
    candidate.value.length <= 128 &&
    hrefForRecent(candidate) !== null
  )
}

function read(): RecentEntry[] {
  if (cache) return cache
  try {
    const parsed = JSON.parse(localStorage.getItem(KEY) || '[]')
    cache = Array.isArray(parsed) ? parsed.filter(safeEntry).slice(0, MAX) : []
  } catch {
    cache = []
  }
  return cache
}

function write(list: RecentEntry[]) {
  cache = list.slice(0, MAX).map((entry) => ({ kind: entry.kind, value: entry.value }))
  try {
    localStorage.setItem(KEY, JSON.stringify(cache))
  } catch {
    /* storage unavailable — the in-memory list still renders */
  }
  for (const listener of listeners) listener()
}

/** Entity page detection, same patterns as the Go shell — called from the
 * shell on every navigation so individual routes need no wiring. */
export function recordRecentFromLocation(pathname: string, search: string) {
  let match: RegExpMatchArray | null
  let entry: RecentEntry | null = null
  if ((match = pathname.match(/^\/investigate\/ip\/([^/]+)$/))) {
    entry = { kind: 'ip', value: decodeURIComponent(match[1]) }
  } else if ((match = pathname.match(/^\/sessions\/([^/]+)$/))) {
    entry = { kind: 'session', value: decodeURIComponent(match[1]) }
  } else if ((match = pathname.match(/^\/payload-analysis\/([^/]+)$/))) {
    entry = { kind: 'payload', value: decodeURIComponent(match[1]) }
  } else if (pathname === '/events') {
    const ip = new URLSearchParams(search).get('ip')
    if (ip) entry = { kind: 'events-ip', value: ip }
  }
  if (!entry || !safeEntry(entry)) return
  const current = entry
  write([current, ...read().filter((item) => item.kind !== current.kind || item.value !== current.value)])
}

const EMPTY: RecentEntry[] = []

export function useRecentInvestigations(): RecentEntry[] {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    read,
    () => EMPTY,
  )
}
