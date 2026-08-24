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
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    // The route tree is generated; nothing in it is worth asserting, and
    // importing it drags in every route module.
    exclude: ['node_modules/**', '.output/**', 'src/routeTree.gen.ts'],
    restoreMocks: true,
  },
})
