// Viewer-local timestamp rendering — the port of hp-app.js's data-hp-utc
// conversion (#282: raw UTC strings shown to operators in other zones).
// Same resolution rules as applyTimeDisplay (hp-app.js:1705-1760):
//  - tz "browser" defers to the browser's own zone (Intl default),
//  - tz "utc" keeps UTC, anything else is an explicit IANA zone;
//  - clock "h12" renders `h:mm:ss AM/PM`, default is zero-padded 24h;
//  - output keeps the server's "YYYY-MM-DD HH:MM:SS" shape via en-CA
//    formatToParts, regardless of browser locale.
// Preferences ride localStorage mirrors (hp-tz / hp-clock) written by the
// settings page, so this stays synchronous and usable in table cells.

export type TimePrefs = { tz: string; clock: 'h24' | 'h12' }

export function readTimePrefs(): TimePrefs {
  if (typeof window === 'undefined') return { tz: 'utc', clock: 'h24' }
  try {
    const tz = localStorage.getItem('hp-tz') || 'utc'
    const clock = localStorage.getItem('hp-clock') === 'h12' ? 'h12' : 'h24'
    return { tz, clock }
  } catch {
    return { tz: 'utc', clock: 'h24' }
  }
}

export function writeTimePrefs(prefs: Partial<TimePrefs>) {
  try {
    if (prefs.tz !== undefined) localStorage.setItem('hp-tz', prefs.tz)
    if (prefs.clock !== undefined) localStorage.setItem('hp-clock', prefs.clock)
  } catch {
    /* storage unavailable */
  }
}

/** "2026-08-21T14:03:22.123Z" → "2026-08-21 14:03:22" in the viewer's
 * resolved zone/clock. Falls back to the raw UTC slice on any parse or
 * zone failure — never throws in a render path. */
export function formatTimestamp(iso: string | undefined | null, prefs?: TimePrefs): string {
  if (!iso) return ''
  const fallback = iso.replace('T', ' ').slice(0, 19)
  const { tz, clock } = prefs ?? readTimePrefs()
  const hour12 = clock === 'h12'
  if ((tz === 'utc' || !tz) && !hour12) return fallback
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return fallback
  const options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }
  // "browser" leaves timeZone unset (Intl defaults to the host zone);
  // everything else must be explicit — omitting it for "utc" would also
  // fall back to the browser zone, reintroducing #282.
  if (tz && tz !== 'browser') options.timeZone = tz === 'utc' ? 'UTC' : tz
  let parts: Intl.DateTimeFormatPart[]
  try {
    parts = new Intl.DateTimeFormat('en-CA', options).formatToParts(date)
  } catch {
    return fallback // invalid IANA zone name
  }
  const get = (type: string) => parts.find((part) => part.type === type)?.value ?? ''
  const hour24 = Number(get('hour'))
  const base = `${get('year')}-${get('month')}-${get('day')}`
  if (!hour12) return `${base} ${get('hour')}:${get('minute')}:${get('second')}`
  const meridiem = hour24 >= 12 ? 'PM' : 'AM'
  const displayHour = hour24 % 12 === 0 ? 12 : hour24 % 12
  return `${base} ${displayHour}:${get('minute')}:${get('second')} ${meridiem}`
}
