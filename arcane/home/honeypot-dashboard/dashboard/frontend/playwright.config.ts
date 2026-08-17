import { defineConfig, devices } from "@playwright/test";

const externalBaseURL = process.env.DASHBOARD_E2E_BASE_URL;

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./test-results",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  // Single spec file, one shared dashboard/Redis/fake-OIDC fixture server
  // (started once by the webServer block below, not per-worker) -- workers
  // just run different tests concurrently against that one server, so this
  // is safe to parallelize. ubuntu-latest runners ship 4 vCPUs.
  fullyParallel: true,
  workers: process.env.CI ? 4 : undefined,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
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
