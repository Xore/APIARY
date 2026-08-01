import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawn } from "node:child_process";

const root = mkdtempSync(join(tmpdir(), "honeypot-dashboard-e2e-"));
const logs = join(root, "logs");
const state = join(root, "state");
mkdirSync(join(logs, "cowrie"), { recursive: true });
mkdirSync(state, { recursive: true });

const now = Date.now();
const events = Array.from({ length: 60 }, (_, index) => JSON.stringify({
  timestamp: new Date(now - index * 60_000).toISOString(),
  eventid: index % 3 === 0 ? "cowrie.command.input" : "cowrie.login.failed",
  src_ip: `203.0.113.${(index % 40) + 1}`,
  dst_port: 22,
  username: "root",
  password: `fixture-${index}`,
  input: index % 3 === 0 ? `uname -a # ${index}` : undefined,
  session: `browser-session-${String(index).padStart(2, "0")}`,
})).join("\n");
writeFileSync(join(logs, "cowrie", "cowrie.json"), `${events}\n`);

const stateFile = (name) => join(state, name);
const child = spawn("go", ["run", "."], {
  cwd: resolve(".."),
  env: {
    ...process.env,
    LISTEN_ADDR: "127.0.0.1:18080",
    LOG_DIR: logs,
    SCRIPT_PAYLOAD_DIR: stateFile("script-payloads"),
    EXPECTED_SENSORS: "cowrie,dionaea,conpot,suricata",
    ALERT_STATE_FILE: stateFile("alerts.json"),
    INTELLIGENCE_STATE_FILE: stateFile("intelligence.json"),
    DASHBOARD_CONFIG_FILE: stateFile("config.json"),
    DASHBOARD_USERS_FILE: stateFile("users.json"),
    DASHBOARD_AUDIT_FILE: stateFile("audit.jsonl"),
    DASHBOARD_CONFIG_HISTORY_FILE: stateFile("config-history.jsonl"),
    DASHBOARD_REPORTS_FILE: stateFile("reports.json"),
    DASHBOARD_REPORTS_DIR: stateFile("reports"),
  },
  stdio: "inherit",
});

let stopping = false;
const stop = () => {
  if (stopping) return;
  stopping = true;
  child.kill();
  rmSync(root, { recursive: true, force: true });
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
process.on("exit", () => rmSync(root, { recursive: true, force: true }));
child.on("exit", (code, signal) => {
  rmSync(root, { recursive: true, force: true });
  if (!stopping && code !== 0) {
    process.exitCode = code ?? (signal ? 1 : 0);
  }
});
