// Appearance state shared with the legacy tier during the transition: same
// localStorage keys and data attributes as the Go dashboard, so theme and
// palette follow the operator across both UIs until cutover.
//
// Both axes write through to the real server-side per-operator preference
// store (backend-service/src/preferences.rs's GET/PUT /api/v1/preferences).
// Instant local apply (data attribute + localStorage) always happens first
// and never waits on the network; the server sync is fire-and-forget on top
// of it, so a slow or failed request never blocks or reverts what is already
// on screen.
//
// Both are also read back, by pullAppearance() from the root route's mount.
// Until #1755 only the mode was -- the palette was pushed on every change,
// stored faithfully, and never consulted, so it silently did not follow the
// operator between devices. This header used to say palette "syncs the same
// way", which was true of the write and of nothing else.
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
const pushAppearancePreference = createServerFn({ method: 'POST' })
  .inputValidator((input: { theme?: ThemeMode; palette?: string }) => input)
  .handler(async ({ data }): Promise<void> => {
    const { getSessionUser } = await import('./auth')
    const user = await getSessionUser()
    if (!user) return
    const { serviceFetch } = await import('./backend.server')
    const patch: Record<string, string> = {}
    if (data.theme) patch.theme = data.theme
    if (data.palette !== undefined) patch.palette = data.palette
    const body = JSON.stringify({ subject: user.sub, username: user.username, patch })
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

export type Appearance = { mode: ThemeMode | null; theme: string | null }

// Reads the operator's server-synced appearance and reconciles this device to
// it -- another device changed it, or this one has never seen it.
//
// #1755: this used to read only `preferences.theme` and was typed
// `Promise<ThemeMode | null>`, so the palette was write-only server state.
// applyPalette() pushed it on every change and preferences.rs stored it
// faithfully, and nothing anywhere read it back. An operator picked `ocean`
// on one machine, opened the dashboard on another, and got `claude` -- no
// error, no sign the preference existed. The module header claimed palette
// "syncs the same way"; accepting the write is half of syncing.
const fetchAppearance = createServerFn({ method: 'GET' }).handler(async (): Promise<Appearance> => {
  const { getSessionUser } = await import('./auth')
  const user = await getSessionUser()
  if (!user) return { mode: null, theme: null }
  const { serviceJSON } = await import('./backend.server')
  const params = new URLSearchParams({ subject: user.sub, username: user.username, role: user.role })
  const result = await serviceJSON<{ preferences?: { theme?: string; palette?: string } }>(
    `/api/v1/preferences?${params.toString()}`,
  )
  const mode = result?.preferences?.theme
  const theme = result?.preferences?.palette
  return {
    mode: mode === 'dark' || mode === 'light' || mode === 'system' ? mode : null,
    // Shape-checked, not matched against the themes this build knows about.
    // The server applies the same rule (preferences.rs::theme_name); a name
    // it accepted must not be dropped here, or a theme vendored after this
    // bundle was built would be unreachable on every device but the one that
    // picked it.
    theme: typeof theme === 'string' && isThemeName(theme) ? theme : null,
  }
})

/// Reconcile this device to the operator's stored appearance.
///
/// Both axes, and neither re-pushed: `sync: false` on each apply, or pulling
/// a value would immediately write it back and every page load would cost a
/// PUT.
export async function pullAppearance(): Promise<void> {
  // Arm the event bridges here as well as from useAppearanceKey's subscribe:
  // the root route mounts everywhere (routes/__root.tsx), but a page that
  // renders no subscriber never reaches that registration path -- settings,
  // where themes are actually changed, has none. Arming is idempotent, the
  // listeners cost one entry each for the life of the document, and both
  // functions guard non-window contexts themselves.
  watchOsTheme()
  watchCrossTabAppearance()
  try {
    const { mode, theme } = await fetchAppearance()
    if (mode && mode !== getThemeMode()) applyTheme(mode, { sync: false })
    if (theme && theme !== getThemeName()) applyPalette(theme, { sync: false })
  } catch {
    /* best-effort */
  }
}


// theme.css carries `.hp-theme-switching, .hp-theme-switching * { transition:
// none !important; }` and, until now, nothing in this tier ever applied it --
// the rule was dead code and the bug it was written for was live (#1761).
//
// The bug: the stylesheet has dozens of `transition` declarations, many on
// `color` and `background`. Change every token at once and each property
// interpolates independently, so text and the surface behind it cross at
// different rates and the page renders unreadable intermediate frames --
// black ink on a dark ground for a few hundred milliseconds.
//
// Suppress transitions, change the attributes, re-enable on the next frame.
// Two nested rAF calls rather than one: the first fires *before* the pending
// style change is painted, so removing the class there would re-enable
// transitions in time for them to run. The second fires after that paint,
// which is the point where there is nothing left to animate.
//
// Reading offsetHeight in between forces the style recalculation to happen
// while the class is still on, rather than being batched with its removal --
// without that, a browser is free to coalesce the whole sequence and animate
// anyway.
//
// `prefers-reduced-motion` does not cover this: theme.css's blanket
// suppressions only apply when the OS setting is on.
//
// Not used by the pre-paint boot script in __root.tsx, deliberately: on first
// paint there is no previous state to transition from.
function withoutTransitions(change: () => void) {
  // Colours resolved for the old appearance are now wrong (#1853).
  void import('./cssVar').then((m) => m.resetCssVarCache())
  if (typeof document === 'undefined') {
    change()
    return
  }
  const root = document.documentElement
  root.classList.add('hp-theme-switching')
  change()
  // Force the new values to be resolved while suppression is still active.
  void root.offsetHeight
  const release = () => root.classList.remove('hp-theme-switching')
  if (typeof requestAnimationFrame === 'function') {
    requestAnimationFrame(() => requestAnimationFrame(release))
  } else {
    release()
  }
}

/** Mirror the current appearance into the first-paint cookie (#1833).
 *
 *  Read from the DOM rather than from the caller's argument, so this
 *  records what was actually applied and cannot drift from it. `system` is
 *  resolved to a concrete mode here because the server has no
 *  prefers-color-scheme to evaluate, and a cookie saying "system" would
 *  leave it with nothing to emit -- which is the case this exists to fix.
 *
 *  Best-effort and last: localStorage and the server preference remain the
 *  source of truth, so a blocked cookie costs one repaint on a new device
 *  and nothing else. */
function syncAppearanceCookie(): void {
  if (typeof document === 'undefined') return
  void import('./appearanceCookie').then(({ writeAppearanceCookie, resolveMode }) => {
    const stored = document.documentElement.dataset.theme
    const mode = stored === 'light' || stored === 'dark' ? stored : 'system'
    writeAppearanceCookie({
      mode: resolveMode(mode),
      theme: document.documentElement.dataset.hpTheme || null,
    })
  })
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
  withoutTransitions(() => {
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
  })
  syncAppearanceCookie()
  emit()
  // Instant local apply above is already done and visible; the server
  // write-through happens after, fire-and-forget (options.sync === false
  // is used by pullAppearance itself, to avoid immediately re-pushing
  // the value it just pulled).
  if (options?.sync !== false && typeof window !== 'undefined') {
    void pushAppearancePreference({ data: { theme: mode } }).catch(() => {})
  }
}

// A theme name is an identifier. Same rule as the pre-paint boot script in
// __root.tsx and as the server (preferences.rs::theme_name), so a name cannot
// be accepted at one layer and rejected at another.
//
// Checked by shape rather than against the nine themes we ship: a theme is
// CSS in the vendored stylesheet, and vendoring a new one must be enough to
// make it selectable. A name this does not match is not applied, and an
// unrecognised-but-well-formed one is applied and simply matches no rule --
// the page falls back to default tokens rather than losing the choice.
const THEME_NAME = /^[a-z][a-z0-9-]{2,31}$/

export function isThemeName(value: string): boolean {
  return THEME_NAME.test(value)
}

/// The theme this document is currently showing.
export function getThemeName(): string {
  if (typeof document === 'undefined') return 'claude'
  return document.documentElement.dataset.hpTheme || 'claude'
}

export function applyPalette(palette: string, options?: { sync?: boolean }) {
  // Empty means "back to the default", which is a real choice and not a
  // malformed value.
  const name = palette || 'claude'
  if (palette && !isThemeName(name)) return
  // The larger of the two swaps since Xore/theme#104: a theme now moves the
  // ground, the sidebar, every surface, every border and the whole text ramp
  // at once, which is the maximal case for the flashing #1761 describes.
  withoutTransitions(() => {
    try {
      // Set unconditionally, including for claude. The attribute used to be
      // deleted for the default on the grounds that :root already carries
      // those tokens -- true for rendering, but it left the DOM unable to
      // answer "which theme is this?", which the gallery picker (#1758) and
      // the server reconcile (#1755) both need. Upstream's selector list
      // names claude explicitly, so setting it changes nothing visually.
      document.documentElement.dataset.hpTheme = name
      document.documentElement.dataset.hpPalette = name
      localStorage.setItem('hp-palette', name)
    } catch {
      /* storage unavailable */
    }
  })
  syncAppearanceCookie()
  emit()
  // Same write-through as theme: "" stores as claude-equivalent default
  // server-side (the Go domain accepts "" as claude).
  if (options?.sync !== false && typeof window !== 'undefined') {
    void pushAppearancePreference({ data: { palette: name } }).catch(() => {})
  }
}

export type LiveToastPrefs = { enabled: boolean; intervalSeconds: number }

// #1684: the "N new honeypot events" toast used to fire on a hardcoded 3s
// batch regardless of volume. Read the operator's saved cadence the same
// best-effort way pullAppearance does — LiveToasts.tsx has no loader of
// its own (it's mounted unconditionally in AppShell, not a route), so this
// is its only way to see the server-side preference.
const fetchLiveToastPrefs = createServerFn({ method: 'GET' }).handler(async (): Promise<LiveToastPrefs> => {
  const { getSessionUser } = await import('./auth')
  const user = await getSessionUser()
  if (!user) return { enabled: true, intervalSeconds: 60 }
  const { serviceJSON } = await import('./backend.server')
  const params = new URLSearchParams({ subject: user.sub, username: user.username, role: user.role })
  const result = await serviceJSON<{
    preferences?: { live_toasts?: boolean; live_toast_interval_seconds?: number }
  }>(`/api/v1/preferences?${params.toString()}`)
  const prefs = result?.preferences
  return {
    enabled: prefs?.live_toasts ?? true,
    intervalSeconds: prefs?.live_toast_interval_seconds ?? 60,
  }
})

export async function pullLiveToastPrefs(): Promise<LiveToastPrefs> {
  try {
    return await fetchLiveToastPrefs()
  } catch {
    return { enabled: true, intervalSeconds: 60 }
  }
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

// While the mode is `system` the rendered colours follow the OS, and nothing
// in this module is involved -- no attribute changes, so no emit() fires.
// A canvas that repaints on appearance changes would therefore keep the old
// colours when someone flips their OS to dark, which looks exactly like the
// bug #1757 is about. Bridge that into the same store.
//
// Registered once, lazily, and never torn down: it costs one listener for
// the life of the document and there is no point at which the answer stops
// mattering.
let osThemeWatched = false
function watchOsTheme() {
  if (osThemeWatched || typeof window === 'undefined' || !window.matchMedia) return
  osThemeWatched = true
  const query = window.matchMedia('(prefers-color-scheme: dark)')
  const onChange = () => {
    if (getThemeMode() === 'system') emit()
  }
  if (typeof query.addEventListener === 'function') query.addEventListener('change', onChange)
  else if (typeof query.addListener === 'function') query.addListener(onChange)
}

// #2138: both appliers write through to localStorage, and every other tab of
// this origin boots from those same keys — but nothing told those tabs that a
// key changed underneath them, so appearance changes crossed tabs only by
// accident of reload: switch the theme in one tab and every other one kept
// its old colours until a full page load.
//
// Bridge the `storage` event into the appliers themselves (rather than poking
// attributes directly), so every reactive surface hears about it the same way
// it hears about local toggles: they emit(), sync the cookie, and skip
// re-writing what already matches. Storage events never fire in the tab that
// wrote them and not on no-op writes either, so this cannot echo back or ping-
// pong between tabs; upstream shipped the identical shape in theme.js
// (#129/#130) with the same reasoning.
//
// `sync: false` is pullAppearance's rule applied here: the writing tab already
// pushed the new value to the server preference store, so re-pushing from each
// open tab would put N-1 redundant PUTs behind every toggle.
//
// Registered once, lazily, from useAppearanceKey's subscribe and again from
// pullAppearance() -- whichever a given page reaches first; one listener for
// the life of the document and there is no point at which the answer stops
// mattering. The subscribe path alone left chartless pages unarmed.
let crossTabWatched = false
function watchCrossTabAppearance() {
  if (crossTabWatched || typeof window === 'undefined') return
  crossTabWatched = true
  window.addEventListener('storage', (event) => {
    // A whole-area clear reports key null: both keys are gone at once, so
    // both axes fall back to their defaults together. (The appliers never
    // clear() themselves -- writes are remove/set on one key at a time --
    // so null only ever comes from an outside hand.)
    if (event.key === null) {
      if (getThemeMode() !== 'system') applyTheme('system', { sync: false })
      if (getThemeName() !== 'claude') applyPalette('', { sync: false })
      return
    }
    if (event.key === 'hp-theme') {
      // Same closed-shape read the boot script (#1754) makes: light/dark are
      // real choices, everything else -- including the key being gone --
      // reads as absent, and absent has meant `system` all along.
      const mode = event.newValue === 'dark' || event.newValue === 'light' ? event.newValue : 'system'
      if (mode !== getThemeMode()) applyTheme(mode, { sync: false })
    } else if (event.key === 'hp-palette') {
      // Well-formed names apply verbatim (open-ended identifiers, same rule
      // as fetchAppearance); a removed key -- or anything not shaped like a
      // name -- falls back to the default through applyPalette's
      // empty-string path, the way absent reads as the default elsewhere.
      const next = event.newValue !== null && isThemeName(event.newValue) ? event.newValue : ''
      if (next !== getThemeName()) applyPalette(next, { sync: false })
    }
  })
}

/// One value that changes whenever anything about the rendered appearance
/// does: the mode, the theme name, or the OS preference while in `system`.
///
/// For canvas-rendered surfaces -- ECharts, the graphs, xterm -- which
/// resolve CSS custom properties into pixels once and cannot re-resolve them
/// on their own. Put it in an effect's dependency array and repaint.
///
/// Returns a string rather than an object so React's Object.is comparison in
/// useSyncExternalStore sees an unchanged value as unchanged; returning a
/// fresh object each call would re-render forever.
export function useAppearanceKey(): string {
  return useSyncExternalStore(
    (listener) => {
      watchOsTheme()
      watchCrossTabAppearance()
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => `${getThemeMode()}:${getThemeName()}`,
    () => 'system:claude',
  )
}
