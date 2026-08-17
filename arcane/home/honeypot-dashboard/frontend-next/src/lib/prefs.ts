// Appearance state shared with the legacy tier during the transition: same
// localStorage keys and data attributes as the Go dashboard, so theme and
// palette follow the operator across both UIs until cutover.
import { useSyncExternalStore } from 'react'

export type ThemeMode = 'system' | 'dark' | 'light'

const listeners = new Set<() => void>()

function emit() {
  for (const listener of listeners) listener()
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

export function applyTheme(mode: ThemeMode) {
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
