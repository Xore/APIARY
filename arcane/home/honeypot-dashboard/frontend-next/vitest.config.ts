// #1831: the unit-test harness this tier never had.
//
// A separate config from vite.config.ts on purpose. That one loads
// nitro() and tanstackStart(), which build a server and a route tree —
// machinery a unit test neither needs nor should wait for, and which
// makes the run fail for reasons unrelated to the code under test.
//
// jsdom rather than node because the logic worth testing here is the
// logic types cannot express, and almost all of it touches the DOM:
// attribute ordering across animation frames, a boot script that runs
// before hydration, colour resolution that requires a real computed
// style. `tsc --noEmit` and `vite build` were the only checks this tier
// had, and neither can see behaviour.
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { defineConfig } from 'vitest/config'

// #3319: machine-readable results, kept opt-in by the environment rather
// than by CI. CI_ARTIFACTS_DIR is the only thing that switches this on, so
// the same `npm test` a developer runs locally, and the one deploy.yml and
// any other caller runs, keep vitest's plain console output and write no
// file. Emitting a report is not a claim the run passed -- the exit code
// still is -- it is evidence a reader can diff after the fact.
const artifactsDir = process.env.CI_ARTIFACTS_DIR
if (artifactsDir) mkdirSync(artifactsDir, { recursive: true })

export default defineConfig({
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    // The route tree is generated; nothing in it is worth asserting, and
    // importing it drags in every route module.
    exclude: ['node_modules/**', '.output/**', 'src/routeTree.gen.ts'],
    restoreMocks: true,
    // `default` stays first so the console output CI has always had is
    // unchanged; the junit reporter is additive and goes to its own file
    // (both keys verified against vitest 4.1.11, the version package.json
    // pins).
    ...(artifactsDir
      ? {
          reporters: ['default', 'junit'] as const,
          outputFile: { junit: join(artifactsDir, 'frontend-next-unit-junit.xml') },
        }
      : {}),

    // #3318: coverage over src/, and the input to the CI ratchet that reads
    // coverage-summary.json. The report is written to coverage/, which
    // .gitignore keeps out of the tree -- same reasoning as the Playwright
    // run artifacts and the Stryker output already ignored there.
    //
    // No `thresholds` block, deliberately. A threshold inside vitest is a
    // constant this file owns, so editing it down is a one-line silent
    // regression; the ratchet instead compares a *measured* summary against a
    // committed baseline (scripts/check-frontend-next-coverage.py), which
    // cannot be adjusted without a visible diff to coverage-baseline.json.
    coverage: {
      // v8 is the provider that instruments the same runtime the tests
      // execute in, so there is no babel/istanbul transform whose own
      // version becomes a second thing to pin.
      provider: 'v8',
      // src/ only, per the issue. Nothing outside it is this tier's own code:
      // e2e/ is Playwright's and is measured by a different job, and the
      // server/ directory is BFF build output, not what `npm test` runs.
      include: ['src/**'],
      // Everything src/ except the test files themselves and the generated
      // route tree.
      //
      // The test files are not a rounding error in this number: a test file
      // executes every line it contains, so leaving `src/**/*.test.ts` in the
      // include would add thousands of near-100% lines and report a figure
      // that says more about how much test code exists than about how much
      // source is exercised. They are excluded for the same reason the build
      // never bundles them: they are not shipped code.
      //
      // src/routeTree.gen.ts is the one file in src/ that is generated rather
      // than written (the tanstackStart() vite plugin emits it on every
      // build), it is already excluded from the test run above, and its
      // currency is gated by a different check entirely -- the "Generated
      // route tree is current" step in quality.yml diffs it after a build.
      // Left in the denominator, every route anyone adds would lower the
      // percentage without a single tested behaviour having changed, which is
      // a ratchet that cries wolf rather than one that holds a line. It is
      // named here, in the open, with the reason attached, rather than
      // quietly dropped somewhere nobody reads.
      exclude: [
        'src/**/*.test.ts',
        'src/**/*.test.tsx',
        'src/routeTree.gen.ts',
      ],
      // json-summary is the machine-readable half the ratchet reads; text is
      // the console table, so a developer running `npm run test:coverage`
      // sees the same numbers CI gates on; html is the browsable report the
      // CI artifact upload publishes.
      reporter: ['text', 'json-summary', 'html'],
      reportsDirectory: 'coverage',
      // Untouched files count too (`all` is vitest 4's default and is stated
      // here because it is the difference between "the code the tests reach"
      // and "the code that exists"). A file with no test at all reporting 0%
      // is the drop the ratchet exists to notice.
      all: true,
    },
  },
})
