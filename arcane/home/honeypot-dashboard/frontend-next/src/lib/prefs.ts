// Appearance state shared with the legacy tier during the transition: same
// localStorage keys and data attributes as the Go dashboard, so theme and
// palette follow the operator across both UIs until cutover.
//
// Theme also write-throughs to the real server-side per-operator
// preference store (backend-service/src/preferences.rs's GET/PUT
// /api/v1/preferences) — instant local apply (data attribute +
// localStorage) always happens first and never waits on the network; the
// server sync is fire-and-forget on top of it, so a slow or failed
// request never blocks or reverts what's already on screen. Palette is
// deliberately NOT synced: preferences.rs's PreferencesPatch excludes
// `palette` (matching the Go tier's own patch struct — a `deny_unknown_
// fields` PUT with `palette` set would simply error), so it stays
// localStorage-only, same as before.
import { useSyncExternalStore } from 'react'
import { createServerFn } from '@tanstack/react-start'

export type ThemeMode = 'system' | 'dark' | 'light'

const listeners = new Set<() => void>()

function emit() {
  for (const listener of listeners) listener()
}

// Pushes one theme value to the server preference store. Best-effort: no
// settings record exists yet for a brand-new operator (PUT 404s until a
// GET has run once), so this falls back to a GET (which creates the
// projection with compiled defaults) and retries the PUT once. Any
// failure (offline, dev mode with no session, backend unreachable) is
// swallowed — this is a write-through on top of the local apply, never a
// gate on it.
const pushThemePreference = createServerFn({ method: 'POST' })
  .inputValidator((input: { theme: ThemeMode }) => input)
  .handler(async ({ data }): Promise<void> => {
    const { getSessionUser } = await import('./auth')
    const user = await getSessionUser()
    if (!user) return
    const { serviceFetch } = await import('./backend.server')
    const body = JSON.stringify({ subject: user.sub, username: user.username, patch: { theme: data.theme } })
    const put = () =>
      serviceFetch('/api/v1/preferences', { method: 'PUT', headers: { 'content-type': 'application/json' }, body })
    try {
      const first = await put()
      if (first.status === 404) {
        const params = new URLSearchParams({ subject: user.sub, username: user.username, role: user.role })
        await serviceFetch(`/api/v1/preferences?${params.toString()}`)
        await put()
      }
    } catch {
      /* best-effort; the local apply already happened */
    }
  })

// Reads the operator's server-synced theme, if any, and reconciles this
// device to it (e.g. another device changed it since). Called from
// settings.tsx on mount — never on every page, since that's out of this
// module's edit scope for __root.tsx's pre-hydration boot script.
const fetchThemePreference = createServerFn({ method: 'GET' }).handler(async (): Promise<ThemeMode | null> => {
  const { getSessionUser } = await import('./auth')
  const user = await getSessionUser()
  if (!user) return null
  const { serviceJSON } = await import('./backend.server')
  const params = new URLSearchParams({ subject: user.sub, username: user.username, role: user.role })
  const result = await serviceJSON<{ preferences?: { theme?: string } }>(`/api/v1/preferences?${params.toString()}`)
  const theme = result?.preferences?.theme
  return theme === 'dark' || theme === 'light' || theme === 'system' ? theme : null
})

export async function pullServerTheme(): Promise<void> {
  try {
    const theme = await fetchThemePreference()
    if (theme && theme !== getThemeMode()) applyTheme(theme, { sync: false })
  } catch {
    /* best-effort */
  }
}

export function getThemeMode(): ThemeMode {
  if (typeof document === 'undefined') return 'system'
  const t = document.documentElement.dataset.theme
  return t === 'dark' || t === 'light' ? t : 'system'
}

export function cycleTheme() {
  const order: ThemeMode[] = ['system', 'dark', 'light']
  const next = order[(order.indexOf(getThemeMode()) + 1) % order.length]
  applyTheme(next)
}

export function applyTheme(mode: ThemeMode, options?: { sync?: boolean }) {
  try {
    if (mode === 'system') {
      delete document.documentElement.dataset.theme
      localStorage.removeItem('hp-theme')
    } else {
      document.documentElement.dataset.theme = mode
      localStorage.setItem('hp-theme', mode)
    }
  } catch {
    /* storage unavailable */
  }
  emit()
  // Instant local apply above is already done and visible; the server
  // write-through happens after, fire-and-forget (options.sync === false
  // is used by pullServerTheme itself, to avoid immediately re-pushing
  // the value it just pulled).
  if (options?.sync !== false && typeof window !== 'undefined') {
    void pushThemePreference({ data: { theme: mode } }).catch(() => {})
  }
}

export function applyPalette(palette: string) {
  try {
    if (palette && palette !== 'claude') {
      document.documentElement.dataset.hpPalette = palette
      localStorage.setItem('hp-palette', palette)
    } else {
      delete document.documentElement.dataset.hpPalette
      localStorage.removeItem('hp-palette')
    }
  } catch {
    /* storage unavailable */
  }
  emit()
}

export function useThemeMode(): ThemeMode {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    getThemeMode,
    () => 'system',
  )
}
