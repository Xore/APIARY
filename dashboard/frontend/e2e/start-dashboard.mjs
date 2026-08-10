import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { startFakeElasticsearch } from "./fake-elasticsearch.mjs";
import { startFakeOIDCIssuer } from "./fake-oidc-issuer.mjs";
import { startFakeRedis } from "./fake-redis.mjs";
import { seedFixtureSession } from "./fixture-session.mjs";

// #405 follow-up: Payload Workbench (and alerts/reports/payload-inventory/
// static-analysis before it) are Elasticsearch-only with no local-disk
// fallback, so the e2e dashboard needs *some* ES to talk to -- a real
// cluster is too heavy for this fixture, so this points it at an in-memory
// stand-in that speaks just enough of the doc CRUD API to round-trip.
const fakeES = await startFakeElasticsearch();
// #1034: main.go's newOIDCAuth() does live OIDC discovery and requires a
// reachable session store at startup, unconditionally -- see the two fixture
// modules for why each is shaped the way it is.
const fakeOIDC = await startFakeOIDCIssuer();
const fakeRedis = await startFakeRedis();
// Pre-authenticate: dashboard.spec.ts sets the matching cookie on every
// browser context instead of driving a real login round trip. See
// fixture-session.mjs for why.
await seedFixtureSession(fakeRedis.url);

const root = mkdtempSync(join(tmpdir(), "honeypot-dashboard-e2e-"));
const logs = join(root, "logs");
const state = join(root, "state");
const payloads = join(root, "payloads");
mkdirSync(join(logs, "cowrie"), { recursive: true });
mkdirSync(state, { recursive: true });
mkdirSync(payloads, { recursive: true });

const now = Date.now();
const events = Array.from({ length: 60 }, (_, index) => ({
  timestamp: new Date(now - index * 60_000).toISOString(),
  eventid: index % 3 === 0 ? "cowrie.command.input" : "cowrie.login.failed",
  src_ip: `203.0.113.${(index % 40) + 1}`,
  dst_port: 22,
  username: "root",
  password: `fixture-${index}`,
  input: index % 3 === 0 ? `uname -a # ${index}` : undefined,
  session: `browser-session-${String(index).padStart(2, "0")}`,
}));
// #1103: cowrie reads Elasticsearch exclusively now, no local-file fallback
// -- seed the fake ES with these same events instead of only writing the
// local file. The local file is still written too: rebuild()'s directory
// walk still discovers "cowrie" as a sensor to query in ES that way (see
// dashboard/aggregate.go's own comment on why), even though its content is
// never read once discovered.
fakeES.seedSensorEvents("cowrie", events);
writeFileSync(join(logs, "cowrie", "cowrie.json"), `${events.map((e) => JSON.stringify(e)).join("\n")}\n`);
writeFileSync(join(payloads, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), "#!/bin/sh\ncurl http://example.invalid/fixture\n");

const stateFile = (name) => join(state, name);
const child = spawn("go", ["run", "."], {
  cwd: resolve(".."),
  env: {
    ...process.env,
    LISTEN_ADDR: "127.0.0.1:18080",
    LOG_DIR: logs,
    SCRIPT_PAYLOAD_DIR: stateFile("script-payloads"),
    EXPECTED_SENSORS: "cowrie,dionaea,conpot,suricata",
    INTELLIGENCE_STATE_FILE: stateFile("intelligence.json"),
    DASHBOARD_CONFIG_FILE: stateFile("config.json"),
    DASHBOARD_USERS_FILE: stateFile("users.json"),
    DASHBOARD_AUDIT_FILE: stateFile("audit.jsonl"),
    DASHBOARD_CONFIG_HISTORY_FILE: stateFile("config-history.jsonl"),
    DASHBOARD_REPORTS_FILE: stateFile("reports.json"),
    PAYLOAD_DIRS: payloads,
    ELASTICSEARCH_URL: fakeES.url,
    OIDC_ISSUER_URL: fakeOIDC.url,
    OIDC_EXTERNAL_URL: "http://127.0.0.1:18080",
    // Fixture-only secret, well above the 32-char minimum oidc_auth.go
    // enforces -- never a real client secret, this issuer doesn't
    // authenticate anything.
    OIDC_CLIENT_SECRET: "e2e-fixture-secret-not-a-real-credential-0000",
    OIDC_SESSION_REDIS_URL: fakeRedis.url,
  },
  stdio: "inherit",
});

let stopping = false;
const stop = () => {
  if (stopping) return;
  stopping = true;
  child.kill();
  fakeES.close();
  fakeOIDC.close();
  fakeRedis.close();
  rmSync(root, { recursive: true, force: true });
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
process.on("exit", () => {
  fakeES.close();
  fakeOIDC.close();
  fakeRedis.close();
  rmSync(root, { recursive: true, force: true });
});
child.on("exit", (code, signal) => {
  fakeES.close();
  fakeOIDC.close();
  fakeRedis.close();
  rmSync(root, { recursive: true, force: true });
  if (!stopping && code !== 0) {
    process.exitCode = code ?? (signal ? 1 : 0);
  }
});
