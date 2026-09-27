#!/usr/bin/env node
// #3318: the non-regression ratchet for this tier's line and branch coverage.
//
// Why this is a separate script and not vitest's own `coverage.thresholds`:
// a threshold in the config is a number somebody typed, and typing it is how a
// gate gets set to whatever would make it green. The number this file checks
// against lives in coverage-baseline.json, which is committed, which is a
// generated measurement rather than a claim, and whose only way to change is
// `npm run coverage:baseline` -- a diff a reviewer can see. There is no
// autoUpdate path here on purpose: vitest's `thresholds.autoUpdate` would
// rewrite the very file the check reads, which is a check that can rewrite
// itself, which is not a check.
//
// What it asserts, and why each half exists:
//
//   1. lines.pct and branches.pct must not drop more than
//      tolerance.pctPoints below the baseline. This is the issue's actual
//      contract -- "fails when coverage drops beyond a small tolerance" -- and
//      it is the half that fires when a change ADDS untested source: this
//      package's src/ files average 58 lines, so one percentage point of a
//      7359-line denominator is ~74 lines, about 1.3 average files. A PR
//      landing a new route does not fail on this; a PR landing several does,
//      which is worth a conversation rather than silence.
//
//   2. covered lines and covered branches must not drop by ANY amount
//      (tolerance.coveredCount is 0). This is the half that fires when a
//      change REMOVES tested behaviour, and it is why the ratchet cannot be
//      gamed by the obvious move: deleting an untested source file shrinks the
//      denominator and makes pct go UP, which half 1 alone would wave through.
//      Comparing raw covered counts cannot be gamed that way.
//
// Both are computed from covered/total in coverage-summary.json rather than
// from its `pct` field, which istanbul rounds to 2 decimals -- a rounding
// artefact of 0.01pp is noise next to a 1.0pp tolerance, but the raw counts
// are the measurement and the percentage is derived from it, so that is the
// order the arithmetic goes in.
//
// Usage:
//   node scripts/coverage-ratchet.mjs            check (default). Exits 1 on a
//                                                regression, 0 otherwise.
//   node scripts/coverage-ratchet.mjs --update   rewrite coverage-baseline.json
//                                                from the current measurement.
//                                                Deliberate, and a visible diff.
//
// Reads the last `npm run test:coverage` report by default; --summary <file>
// points it elsewhere, which is what makes the failure paths testable without
// a coverage run.
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

const PACKAGE_ROOT = resolve(import.meta.dirname, '..')
const SUMMARY_PATH = 'coverage/coverage-summary.json'
const BASELINE_PATH = 'coverage-baseline.json'

// The two metrics the issue names. statements and functions are recorded in
// the baseline as context and are NOT gated: the contract is line and branch
// coverage, and adding a gate nobody agreed to is how a ratchet stops being
// the thing that was asked for.
const GATED = ['lines', 'branches']
// For the file-path note only -- the summary's keys are relative to whichever
// directory the report was written from, which differs between a local run and
// a container mount, so nothing downstream may key off them.
const RECORDED = [...GATED, 'statements', 'functions']

function parseArgs(argv) {
  const opts = { update: false, summary: SUMMARY_PATH }
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--update') opts.update = true
    else if (argv[i] === '--summary') {
      const value = argv[i + 1]
      if (!value) {
        console.error('coverage-ratchet: --summary needs a file path')
        process.exit(2)
      }
      opts.summary = value
      i += 1
    } else {
      console.error(`coverage-ratchet: unknown argument: ${argv[i]}`)
      process.exit(2)
    }
  }
  return opts
}

function readJson(path, what) {
  const full = resolve(PACKAGE_ROOT, path)
  let raw
  try {
    raw = readFileSync(full, 'utf8')
  } catch {
    // A missing measurement is a failure, not a pass. Silently passing here
    // would make the whole gate conditional on a report that may not exist.
    console.error(`coverage-ratchet: cannot read the ${what} at ${full}`)
    console.error(`  run \`npm run test:coverage\` first (it writes ${SUMMARY_PATH})`)
    process.exit(2)
  }
  try {
    return JSON.parse(raw)
  } catch (err) {
    console.error(`coverage-ratchet: ${full} is not valid JSON: ${err.message}`)
    process.exit(2)
  }
}

// The one case where "absent" is not an error: bootstrapping the very first
// baseline. Everything else treats an absent baseline as a failure, because a
// check with no baseline to compare against is a check that never fires.
function readBaselineIfPresent() {
  if (!existsSync(resolve(PACKAGE_ROOT, BASELINE_PATH))) return null
  return readJson(BASELINE_PATH, 'baseline')
}

function fileCount(summary) {
  return Object.keys(summary).filter((k) => k !== 'total').length
}

function measure(summary) {
  const totals = {}
  for (const metric of RECORDED) {
    const t = summary.total?.[metric]
    if (!t || !Number.isFinite(t.total) || !Number.isFinite(t.covered)) {
      console.error(`coverage-ratchet: coverage-summary.json has no usable total.${metric}`)
      console.error('  if the file was hand-edited, regenerate it: npm run test:coverage')
      process.exit(2)
    }
    totals[metric] = { covered: t.covered, total: t.total, pct: round(100 * t.covered / t.total) }
  }
  return totals
}

function round(pct) {
  return Math.round(pct * 1e4) / 1e4
}

function describeRuntime() {
  let vitest = 'unknown'
  try {
    vitest = JSON.parse(readFileSync(resolve(PACKAGE_ROOT, 'node_modules/vitest/package.json'), 'utf8')).version
  } catch {
    // Not installed (someone ran this outside an install). Not fatal on its
    // own -- the node line below is the one that changes the numbers.
  }
  let coverage = 'unknown'
  try {
    coverage = JSON.parse(readFileSync(resolve(PACKAGE_ROOT, 'node_modules/@vitest/coverage-v8/package.json'), 'utf8')).version
  } catch {
    // as above
  }
  return { node: process.version, vitest, coverageProvider: `@vitest/coverage-v8 ${coverage}` }
}

function validateBaseline(baseline) {
  const problems = []
  for (const key of ['recordedAt', 'measuredWith', 'tolerance', 'totals', 'files']) {
    if (baseline?.[key] === undefined) problems.push(`missing "${key}"`)
  }
  for (const metric of GATED) {
    if (!baseline?.totals?.[metric]) {
      problems.push(`missing "totals.${metric}"`)
      continue
    }
    for (const field of ['covered', 'total', 'pct']) {
      if (!Number.isFinite(baseline.totals[metric][field])) problems.push(`"totals.${metric}.${field}" is not a number`)
    }
  }
  if (!Number.isFinite(baseline?.tolerance?.pctPoints)) problems.push('missing "tolerance.pctPoints"')
  if (!Number.isFinite(baseline?.tolerance?.coveredCount)) problems.push('missing "tolerance.coveredCount"')
  if (problems.length) {
    console.error('coverage-ratchet: coverage-baseline.json is not a usable baseline:')
    for (const p of problems) console.error(`  - ${p}`)
    console.error('  regenerate it deliberately and commit the result:')
    console.error('    npm run test:coverage && npm run coverage:baseline')
    process.exit(2)
  }
}

function writeBaseline(summary) {
  const totals = measure(summary)
  const doc = {
    // JSON has no comments, so the contract lives in the one key every JSON
    // reader tolerates. It is a string because a value nobody reads is a
    // value nobody maintains.
    about:
      'Generated measurement, not a target. Do not hand-edit these numbers and do not ' +
      'regenerate them to make a red run green -- coverage-baseline.json exists so that ' +
      'coverage cannot fall without a commit that says it did. Update only via ' +
      '`npm run coverage:baseline`, in a commit whose diff shows the change.',
    recordedAt: new Date().toISOString(),
    measuredWith: {
      ...describeRuntime(),
      // Stated because it decides the denominator: v8 coverage counts are a
      // property of the Node that ran the tests, so a Node major bump can move
      // these numbers with no source change at all.
      note: 'measured on the runtime the image ships (node:22-alpine), which is the runtime CI runs',
    },
    scope: 'src/**/*.{ts,tsx} minus *.test.*, *.spec.*, *.d.ts and src/routeTree.gen.ts (vitest.config.ts coverage.include/exclude)',
    tolerance: {
      // Percentage points, lines and branches. 1.0pp of this denominator is
      // ~74 lines, about 1.3 of src/'s average 58-line file: one new route does
      // not trip it, a batch of them does.
      pctPoints: 1.0,
      // Raw covered lines/branches allowed to disappear. Zero on purpose --
      // this is the half that catches deleted tested behaviour, and it is
      // immune to the "delete an untested file to raise the percentage" move.
      // A PR that legitimately removes covered code updates this file in the
      // same commit; that is the intended cost.
      coveredCount: 0,
    },
    // Repeated here, on the artifact a reviewer actually reads in the diff.
    // The same reasoning is in scripts/coverage-ratchet.mjs next to the code
    // that enforces it; a baseline nobody can interpret is a baseline nobody
    // will notice being edited by hand.
    toleranceWhy: {
      pctPoints:
        'percentage points of lines/branches. This is the half that fires when a change ADDS untested ' +
        'source. 1.0pp of a 7359-line denominator is ~74 lines, about 1.3 of src/\'s average 58-line file.',
      coveredCount:
        'raw covered lines/branches allowed to disappear; 0 is deliberate. This is the half that fires ' +
        'when a change REMOVES tested behaviour, and comparing raw counts cannot be satisfied by deleting ' +
        'an untested file to shrink the denominator.',
    },
    files: fileCount(summary),
    totals,
  }
  const target = resolve(PACKAGE_ROOT, BASELINE_PATH)
  writeFileSync(target, `${JSON.stringify(doc, null, 2)}\n`, 'utf8')
  console.log(`coverage-ratchet: wrote ${target}`)
  for (const metric of GATED) {
    const t = totals[metric]
    console.log(`  ${metric.padEnd(9)} ${t.covered}/${t.total} = ${t.pct}%`)
  }
  console.log('  this is now the floor. Commit it deliberately -- it is the record of what the')
  console.log('  suite covers today, not a claim about what it ought to cover.')
}

function check(opts) {
  const summary = readJson(opts.summary, 'coverage summary')
  const baseline = readJson(BASELINE_PATH, 'baseline')
  validateBaseline(baseline)
  const totals = measure(summary)
  const files = fileCount(summary)
  const now = describeRuntime()
  const then = baseline.measuredWith ?? {}

  // A note, not a failure. A Node major bump changes v8's counters, and the
  // first thing a reader needs is that fact rather than a percentage that
  // moved for a reason that has nothing to do with their diff.
  if (then.node && now.node !== then.node) {
    console.log(`coverage-ratchet: NOTE runtime differs from the baseline -- baseline ${then.node}, now ${now.node}.`)
    console.log('  A Node major can change v8 coverage counts with no source change; if this fails,')
    console.log('  check the runtime before assuming the diff caused it.')
  }
  if (then.vitest && now.vitest !== then.vitest) {
    console.log(`coverage-ratchet: NOTE vitest differs from the baseline -- baseline ${then.vitest}, now ${now.vitest}.`)
  }
  if (typeof baseline.files === 'number' && baseline.files !== files) {
    console.log(`coverage-ratchet: NOTE scope changed -- baseline covers ${baseline.files} files, this run ${files}.`)
    console.log('  A file entering or leaving src/ moves the denominator on its own; judge that diff, not this number.')
  }

  const failures = []
  console.log(`coverage-ratchet: ${files} files under src/ (baseline ${baseline.files})`)
  for (const metric of GATED) {
    const got = totals[metric]
    const want = baseline.totals[metric]
    const dropPct = want.pct - got.pct
    const dropCovered = want.covered - got.covered
    const pctOk = dropPct <= baseline.tolerance.pctPoints + 1e-9
    const coveredOk = dropCovered <= baseline.tolerance.coveredCount
    const mark = pctOk && coveredOk ? 'ok  ' : 'FAIL'
    console.log(
      `  ${mark} ${metric.padEnd(9)} ${got.pct}% (${got.covered}/${got.total})` +
      `  baseline ${want.pct}% (${want.covered}/${want.total})` +
      `  drop ${round(dropPct)}pp / ${dropCovered} covered`,
    )
    if (!pctOk) {
      failures.push(
        `${metric} coverage fell ${round(dropPct)}pp, past the ${baseline.tolerance.pctPoints}pp tolerance ` +
        `(${got.pct}% now, ${want.pct}% in coverage-baseline.json)`,
      )
    }
    if (!coveredOk) {
      failures.push(
        `${metric} lost ${dropCovered} covered ${metric === 'lines' ? 'line' : 'branch'}(es) with no tolerance allowed ` +
        `(${got.covered} now, ${want.covered} in coverage-baseline.json)`,
      )
    }
  }

  if (failures.length) {
    console.error('')
    console.error('::error::coverage regression (#3318) -- this tier collects no other evidence that tested behaviour still runs:')
    for (const f of failures) console.error(`  - ${f}`)
    console.error('')
    console.error('This is a non-regression floor, not a target. To move it on purpose -- having first')
    console.error('established that the drop is intended rather than a lost test -- run:')
    console.error('  npm run test:coverage && npm run coverage:baseline')
    console.error('and commit coverage-baseline.json in the same commit as the change that caused the drop.')
    process.exit(1)
  }
  console.log('coverage-ratchet: no regression. The baseline is a floor, not a target -- raising it is a separate, deliberate commit.')
}

const opts = parseArgs(process.argv.slice(2))
if (opts.update) {
  // --update still reads the baseline first, so an update cannot silently
  // replace something that was not a usable baseline (a hand-written one, a
  // truncated one, a half-merged one) without the shape check noticing.
  const existing = readBaselineIfPresent()
  if (existing) validateBaseline(existing)
  else console.log('coverage-ratchet: no coverage-baseline.json yet -- bootstrapping the first one.')
  writeBaseline(readJson(opts.summary, 'coverage summary'))
} else {
  check(opts)
}
