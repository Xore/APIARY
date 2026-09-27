#!/usr/bin/env node
// #3318: fail when a test-shaped file exists that no configured runner collects.
//
// The failure this exists to catch is silent. A test file is named like a test
// file, sits next to the code it covers, and asserts real behaviour -- and
// nothing runs it. It is worse than no test at all, because the file is the
// evidence: a reader, and every future coverage number, counts it as a test
// that guards the module. The usual way in is a move, not a mistake. Somebody
// puts a spec next to a route, or a test in a directory the include globs do
// not reach, and the suite stays green because the file was never collected.
//
// So the check is the other direction from "is the suite passing": it asks what
// the runners would actually collect, and compares that against what is on
// disk. Both halves come from the runners themselves -- `vitest list
// --filesOnly` and `playwright test --list` -- rather than from a second
// implementation of their glob semantics here. A hand-rolled matcher against
// vitest.config.ts's include globs would agree with vitest until the day it
// did not, and the day it did not would be the day it reported a healthy tree
// over a test that had stopped running.
//
// Two runners, because two runners own .ts/.spec.ts in this package:
// vitest's include globs (src/**) and Playwright's testDir (e2e/). Asking only
// vitest would flag e2e/dashboard.spec.ts, which Playwright does collect --
// and the fix for that would be a suppression list, which is how these guards
// rot. This asks the honest question instead: is any configured runner
// collecting it?
//
// Deliberately .ts/.tsx only. `e2e/fake-backend.test.mjs` is a node:test file
// and no configured runner collects it either, but that is a pre-existing
// finding about a different runner in a different tier, and widening this
// check to .mjs would turn a new gate into a permanently red one on day one.
// See the PR for #3318.
//
// Usage: node scripts/test-discovery-guard.mjs   (exit 0 = every test-shaped
//                                                 file is collected)
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join, relative, resolve, sep } from 'node:path'

const PACKAGE_ROOT = resolve(import.meta.dirname, '..')

// Not walked at all. These hold dependencies, build output and reports --
// nothing a test lives in, and node_modules alone is large enough that walking
// it would dominate the run.
const SKIP_DIRS = new Set([
  '.git', '.nitro', '.output', '.stryker-tmp', '.tanstack',
  'coverage', 'dist', 'node_modules', 'playwright-report', 'public', 'reports', 'test-results',
])

// What "looks like a test" means. .ts/.tsx, both suffixes, both the .test and
// the .spec infix -- which is why the canary proof below is a .spec.ts, not a
// .test.ts: the globs under test name both, and a guard that only knew one of
// them would have passed a file placed to dodge it.
const TEST_SHAPED = /(^|[\\/])[^\\/]+\.(test|spec)\.(ts|tsx)$/

function toPosix(p) {
  return sep === '/' ? p : p.split(sep).join('/')
}

function relativeToRoot(absolute) {
  return toPosix(relative(PACKAGE_ROOT, absolute))
}

function walk(dir, found = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue
      walk(join(dir, entry.name), found)
    } else if (entry.isFile() && TEST_SHAPED.test(entry.name)) {
      found.push(relativeToRoot(join(dir, entry.name)))
    }
  }
  return found
}

function isFile(relPath) {
  try {
    return statSync(resolve(PACKAGE_ROOT, relPath)).isFile()
  } catch {
    return false
  }
}

function run(label, cliArgs, parse, env = process.env) {
  const result = spawnSync(process.execPath, cliArgs, {
    cwd: PACKAGE_ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env,
  })
  if (result.error) {
    console.error(`test-discovery: cannot run the ${label} collector: ${result.error.message}`)
    console.error('  run `npm ci` first -- the guard asks the real runners, it does not reimplement them')
    process.exit(2)
  }
  if (result.status !== 0) {
    // A collector that failed is not a collector that found nothing. Treating
    // it as the latter would make this guard pass on the exact runs where it
    // could not see anything.
    console.error(`test-discovery: the ${label} collector exited ${result.status}`)
    if (result.stderr.trim()) console.error(result.stderr.trim().split('\n').map((l) => `  ${l}`).join('\n'))
    process.exit(2)
  }
  return parse(result.stdout)
}

// vitest prints one collected file per line, package-relative and posix. Lines
// that are not existing files are dropped: `--list` imports each test module to
// collect it, and a module that prints on import must not be able to inject a
// line that makes an unrun file look collected.
function collectVitest() {
  const files = run('vitest', [join(PACKAGE_ROOT, 'node_modules/vitest/vitest.mjs'), 'list', '--filesOnly'], (stdout) =>
    stdout.split('\n').map((l) => l.trim()).filter(Boolean),
  )
  return { runner: 'vitest', command: 'vitest list --filesOnly', files: files.filter(isFile) }
}

// Playwright's json reporter nests specs under suites; a suite and a spec each
// carry the file they live in, and a spec with no cases in it still has a
// suite entry -- so both are collected, or a file whose only test was skipped
// would look unrun.
//
// The report is read from a FILE, not from stdout, and that is not tidiness.
// Playwright's collection imports every file its testMatch reaches -- including
// e2e/fake-backend.test.mjs, which is a node:test module -- and importing it
// makes node's own runner write a TAP banner to stdout, ahead of the JSON.
// Verified in the node:22-alpine image this gate runs on: `playwright test
// --list --reporter=json 2>&1` opens with "TAP version 13". PLAYWRIGHT_JSON_OUTPUT_NAME
// puts the report in a file, where nothing else can interleave with it.
function collectPlaywright() {
  const dir = mkdtempSync(join(tmpdir(), 'test-discovery-'))
  const reportPath = join(dir, 'playwright-list.json')
  try {
    run('playwright', [join(PACKAGE_ROOT, 'node_modules/@playwright/test/cli.js'), 'test', '--list', '--reporter=json'], () => null, {
      ...process.env,
      PLAYWRIGHT_JSON_OUTPUT_NAME: reportPath,
    })
    if (!isFile(reportPath)) {
      console.error(`test-discovery: the playwright collector wrote no report at ${reportPath}`)
      process.exit(2)
    }
    let doc
    try {
      doc = JSON.parse(readFileSync(reportPath, 'utf8'))
    } catch (err) {
      console.error(`test-discovery: cannot read the playwright collector's report: ${err.message}`)
      process.exit(2)
    }
    const files = new Set()
    const walkSuites = (suites) => {
      for (const suite of suites ?? []) {
        if (suite.file) files.add(toPosix(suite.file))
        for (const spec of suite.specs ?? []) {
          if (spec.file) files.add(toPosix(spec.file))
        }
        walkSuites(suite.suites)
      }
    }
    walkSuites(doc.suites)
    const root = doc.config?.rootDir
    const base = root ? relative(PACKAGE_ROOT, resolve(root)) : ''
    return {
      runner: 'playwright',
      command: 'playwright test --list --reporter=json',
      files: [...files].map((f) => toPosix(join(base, f))),
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

const onDisk = walk(PACKAGE_ROOT).sort()
const collectors = [collectVitest(), collectPlaywright()]
const collected = new Set(collectors.flatMap((c) => c.files))
const unrun = onDisk.filter((f) => !collected.has(f))

for (const c of collectors) {
  console.log(`test-discovery: ${c.runner} collects ${c.files.length} file(s) (${c.command})`)
}
console.log(`test-discovery: ${onDisk.length} test-shaped .ts/.tsx file(s) under ${relative(PACKAGE_ROOT, PACKAGE_ROOT) || '.'}/`)

if (unrun.length) {
  console.error('')
  console.error(`::error::${unrun.length} test file(s) exist that no configured runner collects (#3318):`)
  for (const f of unrun) console.error(`  - ${f}`)
  console.error('')
  console.error('vitest collects src/** per its include globs (vitest.config.ts); playwright collects')
  console.error('its own testDir (playwright.config.ts, currently e2e/). A test in neither is not')
  console.error('running, and a coverage number counts it as though it were. Either:')
  console.error('  - move it somewhere the runner that should own it collects from, or')
  console.error('  - delete it, if it was never meant to run.')
  process.exit(1)
}

console.log('test-discovery: every test-shaped file is collected. No silently-unrun tests.')
