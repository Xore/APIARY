import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { defineConfig, devices, type ReporterDescription } from "@playwright/test";

const externalBaseURL = process.env.DASHBOARD_E2E_BASE_URL;

// #3319: the JUnit reporter, opt-in via CI_ARTIFACTS_DIR exactly like the
// vitest config's, so a developer's `npm run test:browser` and any other
// caller keep the console reporters and write no report file. The `github`
// and `html` reporters are not replaced -- junit is inserted between them,
// so inline PR annotations and the browsable report survive alongside it.
// `html` in particular is not redundant: it is what a human opens to read a
// trace, and `trace: "retain-on-failure"` below is only worth setting while
// somebody can actually get at the result.
function ciReporters(): ReporterDescription[] {
  const reporters: ReporterDescription[] = [["github"], ["html", { open: "never" }]];
  const dir = process.env.CI_ARTIFACTS_DIR;
  if (dir) {
    mkdirSync(dir, { recursive: true });
    reporters.splice(1, 0, ["junit", { outputFile: join(dir, "playwright-junit.xml") }]);
  }
  return reporters;
}

// #2034: the slimmed port of the Go tier's 90-case browser matrix (#60, PR
// #146 -- deleted with the Go dashboard at #1628/#1659). Sized to survive:
// theme x viewport shell smoke over the sidebar route set from
// lib/nav.ts (the same registry the sidebar renders, so a new route joins
// the sweep automatically), the modal core (command palette open/type/
// Escape), and role-aware action visibility on /credentials. The stack is
// fully hermetic: fixture redis sessions + shape-correct fake backend via
// e2e/start-dashboard.mjs, against the BUILT production server output.
export default defineConfig({
  testDir: "./e2e",
  outputDir: "./test-results",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  // One shared dashboard/redis/fake-backend fixture server (started once by
  // the webServer block below, not per-worker) -- workers just run
  // different tests concurrently against that one server.
  fullyParallel: true,
  workers: process.env.CI ? 4 : undefined,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? ciReporters() : "list",
  use: {
    baseURL: externalBaseURL || "http://127.0.0.1:18080",
    ...devices["Desktop Chrome"],
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: externalBaseURL
    ? undefined
    : {
        command: "node e2e/start-dashboard.mjs",
        url: "http://127.0.0.1:18080/healthz",
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
});
