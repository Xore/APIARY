// #3326: the appearance cookie is the one channel that reaches the server
// before first paint, and both of its halves are total functions over
// attacker-writable input — on a shared machine anyone can write the cookie,
// and the theme half is interpolated into an attribute selector on <html>.
//
// The literals in appearanceCookie.test.ts answer "does parseAppearance
// ('dark:slate') work". They cannot answer the question that actually decides
// whether the pair is safe, which is a statement about a domain no finite list
// of cases enumerates: is `serialise ∘ parse` the identity on *every*
// well-formed value, and can *any* byte sequence make either half emit
// something the other layer would refuse?
//
// A note on what this file is and is not: a deterministic test, not a search.
// The seed is pinned and the run count is small, so `npm test` — and every PR —
// sees the same cases every time and a red run is a red run forever rather than
// a coin flip. The nightly raises both (FC_SEED=random, FC_NUM_RUNS) to look for
// cases the pinned set does not contain; a counterexample found there is worth
// adding to a generator below, which is the whole point of running it at all.
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import {
  APPEARANCE_COOKIE,
  parseAppearance,
  readAppearanceCookie,
  serialiseAppearance,
  type Appearance as CookieAppearance,
} from './appearanceCookie'
// The same shape rule, from the other layer. appearanceCookie.ts and prefs.ts
// each keep their own copy of it and both say in comments that they must stay
// in step; a comment cannot be mutated and cannot fail. Importing the applier's
// copy here is what turns "they must agree" into something a test can check.
import { isThemeName } from './prefs'

/** fast-check reads no environment of its own, so the pilot's knobs are ours.
 *  `random` means "pick one, this run" — fast-check's own default is
 *  `Date.now()`, so omitting the seed is exactly that. */
const seed = process.env.FC_SEED
const PARAMS: fc.Parameters<unknown> = {
  numRuns: Number(process.env.FC_NUM_RUNS ?? 100),
  ...(seed && seed !== 'random' ? { seed: Number(seed) } : {}),
}

// The shape appearanceCookie.ts enforces, as a generator rather than as a regex
// restated from it: a lowercase letter, then 2..31 of [a-z0-9-]. A generator
// built from the rule cannot drift from the rule the way a copied literal can,
// and it produces names at both ends of the length bound, which is where an
// off-by-one in the bound would show.
const THEME_TAIL = 'abcdefghijklmnopqrstuvwxyz0123456789-'.split('')
const THEME_HEAD = 'abcdefghijklmnopqrstuvwxyz'.split('')
const themeName = fc
  .tuple(
    fc.constantFrom(...THEME_HEAD),
    fc.array(fc.constantFrom(...THEME_TAIL), { minLength: 2, maxLength: 31 }),
  )
  .map(([head, tail]) => head + tail.join(''))

/** The closed set the cookie type admits. `system` is deliberately not among
 *  the generated modes even though the wider codebase uses it: the type cannot
 *  express it, and a generator that never produces it is a second, executable
 *  statement of why. */
const cookieMode = fc.constantFrom<CookieAppearance['mode']>('light', 'dark', null)

const wellFormed = fc.record<CookieAppearance>({
  mode: cookieMode,
  theme: fc.option(themeName, { nil: null }),
})

/** The two segments a hostile writer, a stale build, or a plain bug could put on
 *  the wire. Near-misses of the accepted values, not a spread of random text:
 *  `system` is six specific characters, and a generator that draws it from a
 *  100k-symbol alphabet never produces it, however many runs it does. */
const modeSegment = fc.constantFrom(
  // accepted
  'light',
  'dark',
  // the value this cookie exists to keep off the wire (#1833) — the server has
  // no prefers-color-scheme to resolve it
  'system',
  // case, spacing and near-spellings: a reader that stops comparing exactly
  // would accept any of these
  'System',
  'LIGHT',
  'Dark',
  ' light',
  'dark ',
  'lightd',
  'ight',
  // empty and non-values
  '',
  ' ',
  'auto',
  'none',
  '0',
  'true',
  'null',
  // a second colon, so the mode and theme segments get swapped around
  'light:dark',
)

const themeSegment = fc.oneof(
  { weight: 3, arbitrary: themeName },
  {
    weight: 2,
    arbitrary: fc.constantFrom(
      // one character short of, and one over, the length bound — the drift a
      // copy of the regex can acquire without either file's tests noticing
      'ab',
      'a'.repeat(32),
      'a'.repeat(33),
      // shape broken in each of the ways the rule names
      'Ab',
      'CLAUDE',
      '9claude',
      '-claude',
      '_claude',
      'claudé',
      'claude ',
      ' clude',
      'claude\t',
      'claude\n',
      // outright hostile: the value goes into an attribute selector
      '"><script>',
      'claude" onload="x',
      "claude';--",
      'claude&x',
      // separators that mean something to a header parser
      'claude;path=/',
      'claude=1',
      'claude%zz',
      'claude%2F',
      'claude dark',
      // empty
      '',
    ),
  },
)

/** A whole cookie value, drawn mostly from values built out of the format's
 *  own alphabet. The uniform-random tail is kept — unknown junk has to be
 *  handled too — but it is not what the interesting cases come from. */
const cookieValue = fc.oneof(
  { weight: 3, arbitrary: fc.tuple(modeSegment, themeSegment).map(([m, t]) => `${m}:${t}`) },
  { weight: 2, arbitrary: modeSegment },
  { weight: 1, arbitrary: fc.string() },
)

describe('appearance cookie round-trip properties (#3326)', () => {
  it('serialise ∘ parse is the identity on every well-formed appearance', () => {
    // The brief's ask, and the one the hand-written round-trip case cannot
    // generalise: it asserts `dark:slate` specifically. This says no
    // combination of the three modes and the two absent halves is special.
    fc.assert(
      fc.property(wellFormed, (appearance) => {
        expect(parseAppearance(serialiseAppearance(appearance))).toEqual(appearance)
      }),
      PARAMS,
    )
  })

  it('reduces any cookie value to a fixed point in one pass', () => {
    // Not implied by the round-trip above, which only ranges over values this
    // module itself produced: whatever an attacker or a stale build put in the
    // jar, one serialise∘parse is a canonical value, and a second changes
    // nothing. The cookie layer therefore cannot oscillate between two
    // spellings of the same appearance — which is what would show up as a
    // theme that visibly changes and changes back.
    fc.assert(
      fc.property(cookieValue, (raw) => {
        const once = serialiseAppearance(parseAppearance(raw))
        expect(serialiseAppearance(parseAppearance(once))).toBe(once)
      }),
      PARAMS,
    )
  })

  it('writes only what the server can act on', () => {
    // A property about serialise's *output*, which the round-trip cannot see:
    // parse is forgiving by design, so a serialiser that emitted `system:` for
    // the system preference would still round-trip — and the cookie would carry
    // the one value the server has no way to resolve, which is the entire
    // reason this cookie resolves its mode before writing it (#1833).
    fc.assert(
      fc.property(wellFormed, (appearance) => {
        const [mode, theme] = serialiseAppearance(appearance).split(':')
        expect(mode === '' || mode === 'light' || mode === 'dark').toBe(true)
        expect(theme === '' || isThemeName(theme)).toBe(true)
      }),
      PARAMS,
    )
  })

  it('never yields a theme the applier would refuse', () => {
    // The security invariant, over input rather than over the values this
    // module is willing to write. A theme that survived here would land in an
    // attribute selector unescaped, and the two shape rules are two copies of
    // one rule in two files that nothing keeps in step.
    fc.assert(
      fc.property(cookieValue, (raw) => {
        const { theme } = parseAppearance(raw)
        if (theme !== null) expect(isThemeName(theme)).toBe(true)
      }),
      PARAMS,
    )
  })

  it('never yields a mode the server cannot emit', () => {
    // The reason `system` is resolved to a concrete light/dark before the
    // cookie is written (#1833): the server has no prefers-color-scheme to
    // evaluate, and a cookie carrying "system" leaves it with nothing to emit.
    // Stated as a property over the input space so it survives a reader that
    // stops comparing `mode` exactly — which the hand-written case, asserting
    // only the literal 'system', would not.
    fc.assert(
      fc.property(cookieValue, (raw) => {
        const { mode } = parseAppearance(raw)
        expect(mode === null || mode === 'light' || mode === 'dark').toBe(true)
      }),
      PARAMS,
    )
  })

  it('accepts each segment verbatim or not at all', () => {
    // The two properties above say the *result* is in range; this one says the
    // result is the segment that was actually written, character for character.
    // Without it a reader that normalised on the way through — lowercasing
    // 'LIGHT' to 'light', trimming a space — would satisfy every other property
    // here while quietly turning a guess into an answer, which is the one thing
    // the module's own comment rules out ("a wrong ground painted confidently is
    // worse than the default").
    fc.assert(
      fc.property(cookieValue, (raw) => {
        const [modeSegment = '', themeSegment = ''] = raw.split(':')
        const parsed = parseAppearance(raw)
        if (parsed.mode !== null) expect(modeSegment).toBe(parsed.mode)
        if (parsed.theme !== null) expect(themeSegment).toBe(parsed.theme)
      }),
      PARAMS,
    )
  })

  it('reads back out of a Cookie header exactly what it parses out of the value', () => {
    // The third path into the same function, and the one with the most
    // machinery: split the header, find our name (and not a longer one ending
    // in it), then decodeURIComponent. encodeURIComponent escapes every `%`, so
    // the decode cannot throw for a value this module wrote — and the catch
    // branch exists for values it did not. Driving arbitrary values through
    // both arms is what keeps the composition honest.
    fc.assert(
      fc.property(cookieValue, (raw) => {
        const header = `${APPEARANCE_COOKIE}=${encodeURIComponent(raw)}`
        expect(readAppearanceCookie(header)).toEqual(parseAppearance(raw))
      }),
      PARAMS,
    )
  })

  it('is not displaced by a longer cookie name that ends in ours', () => {
    // The same scan, with a decoy that shares the suffix. Kept as its own
    // property because it is the one failure that returns *a* confident answer
    // rather than none: another cookie's value, painted as this one's theme.
    fc.assert(
      fc.property(cookieValue, (raw) => {
        const header = `not_${APPEARANCE_COOKIE}=${encodeURIComponent(raw)}`
        expect(readAppearanceCookie(header)).toEqual({ mode: null, theme: null })
      }),
      PARAMS,
    )
  })
})
