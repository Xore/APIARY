// The appearance cookie (#1833) — the first cookie in this stack.
//
// Theme delivery depended entirely on localStorage, which is per-device by
// definition, so a cold load on a new machine could not render the
// operator's theme no matter how the client code was arranged. The server
// knows the answer — beforeLoad has the session and the preference is in
// Elasticsearch — and had no way to act on it before first paint.
//
// A cookie is the only channel that reaches the server on the request that
// renders the document. This one carries display preference and nothing
// else: no identity, no token, nothing that grants anything. It is written
// alongside the localStorage write and the server PUT rather than instead
// of them, so blocking it degrades to exactly today's behaviour — correct
// theme, one repaint — rather than to a broken one.
//
// `system` is resolved to a concrete light/dark before it is stored. The
// server cannot evaluate prefers-color-scheme, so storing the literal
// "system" would leave it with nothing to emit, which is the case this
// exists to fix. The client re-resolves on change, so the cookie is a
// first-paint hint and never the source of truth.

export const APPEARANCE_COOKIE = 'hp_appearance'

/** How long the hint survives. Long, because it is a preference and not a
 *  session: an operator who returns to a machine after a month should not
 *  get a flash of the default ground for having been away. */
const MAX_AGE_SECONDS = 60 * 60 * 24 * 365

export type Appearance = {
  /** Concrete light/dark — never the literal "system". */
  mode: 'light' | 'dark' | null
  /** The named theme (claude, slate, …). */
  theme: string | null
}

/** The same shape rule the boot script and preferences.rs::theme_name use.
 *  Deliberately a shape and not a list of the themes shipped today: a theme
 *  is CSS in the vendored stylesheet, so a new one must work the moment it
 *  is vendored. */
const THEME_NAME = /^[a-z][a-z0-9-]{2,31}$/

/** Parse the cookie value. Anything unrecognised yields null rather than a
 *  guess — a wrong ground painted confidently is worse than the default. */
export function parseAppearance(raw: string | undefined | null): Appearance {
  const empty: Appearance = { mode: null, theme: null }
  if (!raw) return empty
  // `mode:theme`, either side optionally empty.
  const [modePart = '', themePart = ''] = raw.split(':')
  return {
    mode: modePart === 'light' || modePart === 'dark' ? modePart : null,
    theme: THEME_NAME.test(themePart) ? themePart : null,
  }
}

export function serialiseAppearance(appearance: Appearance): string {
  const mode = appearance.mode === 'light' || appearance.mode === 'dark' ? appearance.mode : ''
  const theme = appearance.theme && THEME_NAME.test(appearance.theme) ? appearance.theme : ''
  return `${mode}:${theme}`
}

/** Pull the appearance cookie out of a raw Cookie header. */
export function readAppearanceCookie(header: string | undefined | null): Appearance {
  if (!header) return { mode: null, theme: null }
  for (const part of header.split(';')) {
    const trimmed = part.trim()
    if (!trimmed.startsWith(`${APPEARANCE_COOKIE}=`)) continue
    const value = trimmed.slice(APPEARANCE_COOKIE.length + 1)
    try {
      return parseAppearance(decodeURIComponent(value))
    } catch {
      return parseAppearance(value)
    }
  }
  return { mode: null, theme: null }
}

/** Write the cookie from the browser.
 *
 *  Not `Secure` unconditionally: the dashboard is reached over plain HTTP
 *  on the internal address during development, and a Secure cookie is
 *  silently dropped there — which would make this fail exactly where it is
 *  hardest to notice. `Lax` because nothing about a display preference
 *  needs to survive a cross-site POST. */
export function writeAppearanceCookie(appearance: Appearance): void {
  if (typeof document === 'undefined') return
  const value = encodeURIComponent(serialiseAppearance(appearance))
  const secure = typeof location !== 'undefined' && location.protocol === 'https:' ? '; Secure' : ''
  try {
    document.cookie = `${APPEARANCE_COOKIE}=${value}; Path=/; Max-Age=${MAX_AGE_SECONDS}; SameSite=Lax${secure}`
  } catch {
    /* cookies blocked — localStorage and the server PUT still carry it */
  }
}

/** Resolve `system` against the device, so the cookie carries something
 *  the server can actually emit. */
export function resolveMode(mode: 'light' | 'dark' | 'system'): 'light' | 'dark' | null {
  if (mode === 'light' || mode === 'dark') return mode
  if (typeof matchMedia !== 'function') return null
  try {
    return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  } catch {
    return null
  }
}
