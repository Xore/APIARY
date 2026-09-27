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
    // #3318: the tier had no coverage number at all, so nothing here could
    // tell a change that deleted tested behaviour from one that did not.
    //
    // Not `enabled: true` on purpose: coverage instruments every module it
    // loads and writes a report tree to disk, and `npm test` is the command
    // deploy.yml, the README and a developer's own loop all run. It stays
    // uninstrumented and report-free. `npm run test:coverage` -- the one
    // command that turns this on -- is what CI and the ratchet use.
    //
    // `include` is the whole point: the scope is src/ and only src/. Not the
    // tests themselves (they are 100% covered by construction and would
    // inflate every total), not the configs or scripts, not e2e/, and not
    // node_modules. What is left is the code the dashboard actually ships,
    // which is the only thing a coverage number should be about.
    coverage: {
      provider: 'v8',
      reportsDirectory: 'coverage',
      // json-summary is what scripts/coverage-ratchet.mjs reads; lcovonly is
      // what a reviewer loads into an external coverage viewer; text is what
      // the CI log shows. `lcov` rather than `lcovonly` would also emit the
      // self-contained html report, and that is 5.9MB of per-file assets on a
      // run that uploads its coverage to a 7-day artifact -- so it is
      // deliberately not the one that generates it.
      reporter: ['text', 'json-summary', 'lcovonly'],
      include: ['src/**/*.ts', 'src/**/*.tsx'],
      exclude: [
        // The tests, the type-only declaration, and the generated route tree
        // -- the same three exclusions the test-level `exclude` above already
        // reasons about, so "what counts as source" is one list, not two that
        // can disagree. Written out rather than inherited: vitest 4 dropped
        // its coverage `exclude` defaults (coverageConfigDefaults.exclude is
        // now []), so there is nothing to spread.
        '**/*.test.ts',
        '**/*.test.tsx',
        '**/*.spec.ts',
        '**/*.spec.tsx',
        '**/__tests__/**',
        '**/*.d.ts',
        'src/routeTree.gen.ts',
      ],
    },
  },
})
