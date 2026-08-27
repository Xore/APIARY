// Named with a leading "-" so TanStack's route generator skips it: without
// the prefix it scans this file for a Route export, finds none, and warns on
// every dev-server start (routeFileIgnorePrefix, see the generator's own
// message). vitest still collects it -- its include is src/**/*.test.ts.
// A route file that has children is a layout, and a layout that redirects
// is an infinite loop.
//
// This is the shape that broke every sensor page on a cold load. `sensors.tsx`
// looked like a page — it had no component, only a `beforeLoad` that sent
// /sensors to the busiest sensor. But TanStack's file convention nests
// `sensors.$sensor` under any `sensors` route that exists, so it was the
// detail page's *parent*: loading /sensors/cowrie entered the parent,
// which redirected to /sensors/cowrie, which entered the parent again.
//
// Nothing caught it. It typechecks, it builds, and a client-side
// transition inside an already-loaded app does not re-enter the parent the
// same way — so it survives desktop clicking and fails on a deep link, a
// refresh, or a phone opening a fresh document.
//
// The rule is mechanical, so it is checked mechanically rather than
// remembered: if `X.tsx` and any `X.<child>.tsx` both exist, `X.tsx` is a
// layout and must not redirect. Put the redirect in `X.index.tsx`, which
// is a leaf and has no children to drag with it.
//
// #2127 is the other half of the same trap. A layout that doesn't
// redirect but declares a `component` and never renders `<Outlet/>`
// swallows its children entirely — /cape/$sha, /github-analysis/$sha and
// /revdeck/$sha each server-rendered their parent list forever, which
// read as "the worker isn't producing yet" because every one of these
// lists announces that emptiness is normal. Same mechanical rule, second
// clause: a component-ful parent must reference Outlet, or it has no
// children at all.
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROUTES = dirname(fileURLToPath(import.meta.url))

/** Route modules, by their file-convention name: "sensors.$sensor", "index". */
function routeNames(): string[] {
  return readdirSync(ROUTES)
    .filter((f) => f.endsWith('.tsx') || f.endsWith('.ts'))
    .filter((f) => !f.endsWith('.test.ts') && !f.endsWith('.test.tsx'))
    .map((f) => f.replace(/\.tsx?$/, ''))
}

/** The routes that own children, and are therefore layouts. */
function layoutRoutes(names: string[]): string[] {
  return names.filter((name) => {
    // ".index" is a leaf by definition; it cannot parent anything.
    if (name.endsWith('.index')) return false
    return names.some((other) => other !== name && other.startsWith(`${name}.`))
  })
}

describe('route shape', () => {
  it('no layout route redirects', () => {
    const names = routeNames()
    const offenders: string[] = []

    for (const layout of layoutRoutes(names)) {
      const source = readFileSync(join(ROUTES, `${layout}.tsx`), 'utf8')
      // `redirect` imported from the router and thrown, as opposed to the
      // word appearing in a comment or a URL parameter named redirect.
      if (/\bthrow\s+redirect\s*\(/.test(source)) {
        offenders.push(layout)
      }
    }

    expect(
      offenders,
      `${offenders.join(', ')} has child routes and throws a redirect, so loading any child ` +
        `re-enters it forever. Move the redirect into ${offenders[0] ?? 'X'}.index.tsx.`,
    ).toEqual([])
  })

  it('recognises the shape that caused the outage', () => {
    // Guards the guard: if layoutRoutes stopped identifying parents, the
    // test above would pass by finding nothing to check.
    expect(layoutRoutes(['sensors', 'sensors.$sensor', 'events'])).toEqual(['sensors'])
    expect(layoutRoutes(['sensors.index', 'sensors.$sensor'])).toEqual([])
  })

  it('no component-ful layout swallows its children', () => {
    // #2127's half of the trap. A parent whose Route declares a component
    // renders ONLY that component; children mount exclusively through an
    // <Outlet/> inside it. Without one, every child URL re-renders the
    // parent — and when that parent is a list whose empty state is normal,
    // the swallow masquerades as a deployment status.
    const names = routeNames()
    const offenders: string[] = []

    for (const layout of layoutRoutes(names)) {
      const source = readFileSync(join(ROUTES, `${layout}.tsx`), 'utf8')
      if (/component\s*:/.test(source) && !source.includes('Outlet')) {
        offenders.push(layout)
      }
    }

    expect(
      offenders,
      `${offenders.join(', ')} declares a component but never renders <Outlet/>, so its ` +
        `child routes can never mount — each child URL silently re-renders the parent. ` +
        `Render <Outlet/> in ${offenders[0] ?? 'X'}.tsx, or (the repo's usual answer) move ` +
        `the page into X.index.tsx and delete the parent.`,
    ).toEqual([])
  })

  it('recognises the swallowing shape too', () => {
    // Guards the guard for the #2127 clause.
    const swallows = (source: string) => /component\s*:/.test(source) && !source.includes('Outlet')
    expect(swallows("createFileRoute('/cape')({ component: Page })")).toBe(true)
    expect(swallows("createFileRoute('/x')({ component: () => <><Outlet/></> })")).toBe(false)
    expect(swallows("import { Outlet } from '@tanstack/react-router'\ncreateFileRoute('/x')({})")).toBe(false)
  })

  it('sensors is a leaf pair, not a layout with a child', () => {
    // The specific regression. /sensors must be an index route.
    const names = routeNames()
    expect(names).toContain('sensors.index')
    expect(names).not.toContain('sensors')
  })

  it('cape, github-analysis and revdeck are leaf pairs', () => {
    // The specific regression of #2127: all three detail routes hung off a
    // component-ful list and never mounted once.
    const names = routeNames()
    for (const family of ['cape', 'github-analysis', 'revdeck']) {
      expect(names).toContain(`${family}.index`)
      expect(names).not.toContain(family)
      expect(names).toContain(`${family}.$sha`)
    }
  })
})

// ---------------------------------------------------------------------------
// #2178's settled-error discipline. Every site in that census shipped as the
// same shape: a module renders loading ghosts (`SkeletonRows`,
// `SkeletonCards`, `.skeleton-line`) while carrying no vocabulary anywhere
// for what happens when the load fails -- because serviceJSON collapses
// settled-null into "still loading", those ghosts render forever, or hand
// off to an empty state that asserts absence during an outage. Phases 1-3
// named a failure state in every such module; this keeps it named.
//
// Mechanical rule: any routes/components module that renders a ghost
// primitive must also reference ErrorStateBlock or a failed/load-failed
// channel somewhere in the file. The one legitimate exception is the
// primitive-defining host itself (Investigate.tsx exports SkeletonRows but
// loads no data of its own).
// ---------------------------------------------------------------------------

const COMPONENTS = join(dirname(ROUTES), 'components')

const RENDERS_GHOST = /<SkeletonRows\b|<SkeletonCards\b|skeleton-line/
const FAILURE_VOCABULARY = /ErrorStateBlock|\bfailed\b|[Ll]oad [Ff]ailed/
const DEFINES_PRIMITIVE = /export function Skeleton(Rows|Cards)/

describe('settled-error discipline (#2178)', () => {
  /** modules under routes/ and components/, recursive, tests excluded */
  function tsxSources(): { name: string; source: string }[] {
    const out: { name: string; source: string }[] = []
    const walk = (root: string): void => {
      for (const entry of readdirSync(root, { withFileTypes: true })) {
        if (entry.name.endsWith('.test.ts') || entry.name.endsWith('.test.tsx')) continue
        const full = join(root, entry.name)
        if (entry.isDirectory()) walk(full)
        else if (entry.name.endsWith('.tsx')) out.push({ name: full, source: readFileSync(full, 'utf8') })
      }
    }
    walk(ROUTES)
    walk(COMPONENTS)
    return out
  }

  it('every ghost-rendering module can name a failure', () => {
    const offenders = tsxSources()
      .filter((file) => RENDERS_GHOST.test(file.source))
      .filter((file) => !FAILURE_VOCABULARY.test(file.source))
      // The component library hosting the primitives legitimately carries no
      // error copy: it renders ghosts for whoever feeds it.
      .filter((file) => !DEFINES_PRIMITIVE.test(file.source))
      .map((file) => file.name)

    expect(
      offenders,
      `${offenders.join(', ')} renders loading ghosts but never says what a failed load looks like. With ` +
        `serviceJSON collapsing settled errors into null, that module renders its ghosts forever -- or asserts ` +
        `absence through an empty state during an outage (#2178). Give the load an explicit failed/error channel ` +
        `rendered through ErrorStateBlock (routes/*$*.tsx detail trio and routes/commands.tsx are the local idioms).`,
    ).toEqual([])
  })

  it('recognises the shapes', () => {
    // Guards the guard: each classification half must actually classify.
    expect(RENDERS_GHOST.test('{rows === null ? <SkeletonRows count={4}/> : null}')).toBe(true)
    expect(RENDERS_GHOST.test("import { SkeletonRows } from './Investigate'")).toBe(false)
    expect(FAILURE_VOCABULARY.test('const { failed, retry } = useServerQuery()')).toBe(true)
    expect(FAILURE_VOCABULARY.test('usePaginatedList(first, fetchMore) sets Failed via setFailed')).toBe(false)
    expect(FAILURE_VOCABULARY.test('<ErrorStateBlock title="failed to load"/>')).toBe(true)
    expect(FAILURE_VOCABULARY.test('const [rows, setRows] = useState(null)')).toBe(false)
    expect(DEFINES_PRIMITIVE.test('export function SkeletonRows({ count }: { count: number }) {')).toBe(true)
    expect(DEFINES_PRIMITIVE.test("<SkeletonRows count={12} cols={6} wide={[2, 4]} stub={[5]} />")).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// #2311's admin write-path contract, guarded mechanically like the rest of
// this file. The bug these pins keep closed: fetchAdminData collapsed
// partly-dead loads into an all-defaults AdminConfig — maintenance off,
// empty roster, and worst of all `revision: 0`, which as the next save's
// If-Match baseline could only 409 against the real doc, blaming "another
// session" when the client had invented the precondition itself. Four
// mechanical facts have to stay true together:
//
//   1. the load fails WHOLE (any dead leg → null, nothing manufactured),
//   2. both settling paths (initial fetch, conflict-driven reload) NAME the
//      failure instead of silently ignoring it,
//   3. every admin pane parks behind the failure state rather than mounting
//      editable cards from nothing,
//   4. If-Match is minted only from a revision parameter its caller actually
//      received from a real load — never a constant placeholder.
// ---------------------------------------------------------------------------

describe('settings admin write-path (#2311)', () => {
  const settingsSource = readFileSync(join(ROUTES, 'settings.tsx'), 'utf8')

  /** The fail-whole gate fetchAdminData must apply before touching defaults. */
  const FAILS_WHOLE = /if \(!config \|\| !roster \|\| !reports\) return null/

  /** How each PUT server fn mints its If-Match header (single expression). */
  const IF_MATCH_SITES = /'if-match':\s*([^,}\n]+)/g

  /** The only acceptable minting expression, from the save call's input. */
  const MINTED_FROM_INPUT = 'String(data.revision)'

  /** Collect every top-level Pane chunk by id, including nested markup. */
  function paneChunks(source: string): Map<string, string> {
    const chunks = new Map<string, string>()
    const opener = /<Pane id="([a-z-]+)">/g
    let match: RegExpExecArray | null
    while ((match = opener.exec(source))) {
      const close = source.indexOf('</Pane>', match.index)
      chunks.set(match[1], close === -1 ? source.slice(match.index) : source.slice(match.index, close))
    }
    return chunks
  }

  it('fetchAdminData fails whole before anything can manufacture defaults', () => {
    expect(FAILS_WHOLE.test(settingsSource)).toBe(true)
    // And the gate sits between the legs resolving and the defaults object
    // being built — reordering either side recreates the bug.
    const handlerStart = settingsSource.indexOf('createServerFn({ method: \'GET\' }).handler(async (): Promise<AdminConfig | null>')
    const gateAt = settingsSource.search(FAILS_WHOLE)
    const defaultsAt = settingsSource.indexOf('revision: config?.revision ?? 0')
    expect(gateAt > handlerStart).toBe(true)
    expect(gateAt < defaultsAt).toBe(true)
  })

  it('recognises the fail-whole gate shape', () => {
    expect(FAILS_WHOLE.test('return { revision: config?.revision ?? 0 }')).toBe(false)
    expect(FAILS_WHOLE.test('if (!config || !roster || !reports) return null')).toBe(true)
  })

  it('both settling paths name the failure instead of ignoring settled-null', () => {
    // Initial mount + reloadAdminConfig — one count per site; dropping
    // either leaves the operator parked on skeletons-forever again.
    const named = [...settingsSource.matchAll(/setAdminFailed\(true\)/g)].length
    expect(named).toBeGreaterThanOrEqual(2)
  })

  it('every admin pane parks behind the failure state', () => {
    const panes = paneChunks(settingsSource)
    // The five surfaces #2311 found rendering fabricated content during an
    // outage: four editable config cards plus the users roster.
    const adminPanes = ['branding', 'report-presets', 'behavior', 'honeypot', 'users']
    const parked: string[] = []
    for (const id of adminPanes) {
      const chunk = panes.get(id)
      if (!chunk || !chunk.includes('adminFailed ?') || !chunk.includes('adminData ?')) parked.push(id)
    }
    expect(
      parked,
      `${parked.join(', ')} does not gate on both a loaded config and the named failure — ` +
        `with serviceJSON collapsing outages to null, it either rides a skeleton forever ` +
        `or saves from synthetic state (#2311): {adminData ? <Card/> : adminFailed ? <failure/> : loadingCard}`,
    ).toEqual([])
  })

  it('recognises the parked-pane shape too', () => {
    const chunk = paneChunks(`<Pane id="probe">{x ? <C/> : loadingCard}</Pane><Pane id="ok">{y ? <D/> : adminFailed ? fail : loadingCard}</Pane>`)
    expect(chunk.get('probe')).not.toContain('adminFailed ?')
    expect(chunk.get('ok')).toContain('adminFailed ?')
  })

  it('If-Match is minted from the save input\'s loaded revision, never a placeholder', () => {
    // savePresentation + saveConfigSection are exactly two PUT sites, and
    // every If-Match value in the file must be built from the revision the
    // caller actually passed in — a constant or `?? 0` fallback here is the
    // #2311 precondition-invention bug reappearing somewhere new.
    const minted = [...settingsSource.matchAll(IF_MATCH_SITES)].map((m) => m[1].trim())
    expect(minted).toHaveLength(2)
    expect(new Set(minted)).toEqual(new Set([MINTED_FROM_INPUT]))
  })

  it('recognises the If-Match shapes', () => {
    const values = (source: string) =>
      [...source.matchAll(/'if-match':\s*([^,}\n]+)/g)].map((m) => m[1].trim())
    expect(values("headers: { 'if-match': String(data.revision), body: v }")).toEqual(['String(data.revision)'])
    expect(values("headers: { 'content-type': 'application/json', 'if-match': String(revision ?? 0) }")).toEqual([
      'String(revision ?? 0)',
    ])
    expect(values("headers: { 'if-match': '0' },")).toEqual(["'0'"])
  })
})
