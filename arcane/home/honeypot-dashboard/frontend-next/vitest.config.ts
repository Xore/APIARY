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
  },
})
