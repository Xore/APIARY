import { spawn } from "node:child_process";
import { join } from "node:path";

import { startFakeBackend } from "./fake-backend.mjs";
import { startFakeRedis } from "./fake-redis.mjs";
import { seedFixtureSessions } from "./fixture-session.mjs";

// Composes the whole hermetic tier for the browser matrix, mirroring the
// webServer role the Go suite's start-dashboard.mjs played:
//
//   fake redis  <- OIDC_SESSION_REDIS_URL   (fixture sessions live here)
//   fake backend <- BACKEND_URL             (/api/v1/* shape-correct JSON)
//   built BFF    <- node .output/server/index.mjs on :18080
//
// The BFF must already be BUILT (`npm run build`) -- this harness exercises
// the production server output, not the dev server, so what the matrix sees
// is what ships. Exits nonzero if the stack fails to come up; SIGTERM/SIGINT
// tear everything down so Playwright's webServer lifecycle stays clean.

const ROOT = process.cwd();
const PORT = Number(process.env.DASHBOARD_E2E_PORT ?? 18080);

const children = new Set();
let shuttingDown = false;

function spawnChild(label, command, args, env = {}) {
  const child = spawn(command, args, {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.add(child);
  const forward = (stream, level) => {
    stream.on("data", (chunk) => {
      for (const line of chunk.toString().split("\n")) {
        if (line.trim()) console.error(`[${label}] ${line}`);
      }
    });
  };
  forward(child.stdout, "log");
  forward(child.stderr, "err");
  child.once("exit", (code) => {
    children.delete(child);
    if (!shuttingDown && code !== 0 && code !== null) {
      console.error(`[${label}] exited early with code ${code}`);
      process.exit(1);
    }
  });
  return child;
}

function teardown() {
  shuttingDown = true;
  for (const child of children) child.kill("SIGTERM");
  process.exit(0);
}
process.on("SIGTERM", teardown);
process.on("SIGINT", teardown);

// No build step here by design: the harness runs the already-built
// production output. CI builds right before invoking Playwright; locally,
// `npm run build && npm run test:browser`.

console.error("[harness] starting fake redis...");
const redis = await startFakeRedis();
await seedFixtureSessions(redis.url);
console.error(`[harness] redis ready at ${redis.url}`);

console.error("[harness] starting fake backend...");
const backend = await startFakeBackend(Number(process.env.DASHBOARD_E2E_BACKEND_PORT ?? 18081));
console.error(`[harness] fake backend at ${backend.url}`);

console.error("[harness] starting dashboard BFF...");
spawnChild("bff", process.execPath, [join(ROOT, ".output/server/index.mjs")], {
  PORT: String(PORT),
  HOST: "127.0.0.1",
  // Sessions resolve from the fixture redis first; OIDC_DISABLED=1 is the
  // cookie-less admin fallback so unseeded contexts still navigate as an
  // operator. Production never sets either of these two vars together.
  // #2183's SERVICE_TOKEN gate refuses tokenless boots without this exact
  // dev override -- the e2e harness is that sanctioned context (same opt-in
  // the port-tests harness sets). Setting it here keeps production-parity:
  // a real token in CI would still break auth, so this stays override-only.
  APIARY_ALLOW_UNAUTH_DEV: "1",
  OIDC_DISABLED: "1",
  OIDC_SESSION_REDIS_URL: redis.url,
  BACKEND_URL: backend.url,
});

async function waitForHealth(deadlineMs = 60_000) {
  const deadline = Date.now() + deadlineMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/healthz`);
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`dashboard did not become healthy on :${PORT} within ${deadlineMs}ms`);
}

await waitForHealth();
console.error("[harness] READY");
// Stays up servicing requests until Playwright's webServer lifecycle
// signals us; redis and the fake backend are children of this process, so
// they cannot outlive it.
