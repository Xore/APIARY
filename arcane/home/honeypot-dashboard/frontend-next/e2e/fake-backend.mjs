import { createServer } from "node:http";

// The one seam the frontend actually reads data through is BACKEND_URL
// (lib/backend.server.ts), so this fixture stands in for the Rust tier and
// answers /api/v1/* with shape-correct, contentful JSON. Shapes mirror what
// the frontend's own types expect -- lib/backend.server.ts's serviceJSON
// collapses every failure mode to null, which pages render as an empty or
// retry state, so a wrong shape here would silently test the fallback path
// instead of the page. Endpoints not named below get a generic answer
// ({rows:[], total:0} for the store family, {} otherwise): enough for shell-
// level smoke on the long-tail routes without fixture-maintaining all 114.
//
// Deliberately no auth surface: production browser traffic never talks to
// BACKEND_URL directly, the BFF server functions do it server-side.

const NOW = "2026-08-26T12:00:00Z";

const kv = (key, count) => ({ key, count, link: "/" });

const dashboard = {
  protocols: [kv("ssh", 412), kv("http", 233)],
  top_ports: [kv("22", 401), kv("80", 220)],
  countries: [kv("CN", 180), kv("US", 95)],
  asns: [kv("AS4134 CHINANET", 88), kv("AS14061 DIGITALOCEAN", 41)],
  providers: [kv("digitalocean", 51)],
  top_ips: [kv("203.0.113.7", 120), kv("198.51.100.9", 64)],
  top_paths: [kv("/admin.php", 45), kv("/cgi-bin/luci", 30)],
  top_creds: [kv("root / admin", 77), kv("admin / 123456", 52)],
  top_commands: [kv("uname -a", 34), kv("cat /proc/cpuinfo", 21)],
  clients: [kv("SSH-2.0-libssh_0.8.0", 66)],
  fingerprints: [kv("mirai", 40), kv("gpon", 18)],
  alerts: [kv("et-open: scan", 12)],
  alert_cats: [kv("recon", 20), kv("exploit", 8)],
  payloads: [
    { shasum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", download: "/dl/e3b0c4", count: 14, link: "/payloads?shasum=e3b0c4", vt: "" },
  ],
  logins: 512,
  heatmap: [
    { sensor: "citrix", cells: [{ label: "00h", count: 3, pct: 10 }, { label: "01h", count: 5, pct: 30 }] },
    { sensor: "cowrie", cells: [{ label: "00h", count: 8, pct: 80 }, { label: "01h", count: 2, pct: 10 }] },
  ],
  map_points: [
    { city: "Shanghai", country: "CN", lat: 31.23, lon: 121.47, events: 190, ips: 33, url: "/" },
    { city: "Amsterdam", country: "NL", lat: 52.37, lon: 4.9, events: 44, ips: 7, url: "/" },
  ],
  sensors: [
    { name: "citrix", count: 551, last_seen: NOW, state: "up" },
    { name: "cowrie", count: 1102, last_seen: NOW, state: "up" },
    { name: "dionaea", count: 221, last_seen: "2026-08-25T09:00:00Z", state: "stale" },
  ],
};

const eventRow = (n) => ({
  id: `e2e-event-${n}`,
  time: NOW,
  sensor: ["citrix", "cowrie", "dnp3"][n % 3],
  src_ip: `203.0.113.${n + 1}`,
  country: "CN",
  port: "22",
  detail: n === 0 ? "login attempt root/admin" : `session activity ${n}`,
  proto: "tcp",
  session: `sess-${n}`,
  // Detail-pane pivot groups extracted server-side by events.rs; empty
  // string = absent. The /events page reads row.pivots.<field> directly
  // when rendering the detail pane, so the object must exist.
  pivots: {
    persona: "", site: "", asset: "", fingerprint: "", fingerprint_kind: "",
    command: n === 1 ? "uname -a" : "", user: "", pass: "", path: "",
    shasum: "", asn: "", org: "", provider: "", alert: "", category: "",
    tty_replay: "", ics_severity: "", payload_class: "",
  },
  record: { "@timestamp": NOW, sensor: { name: "cowrie" }, source: { ip: `203.0.113.${n + 1}`, geo: { country_iso_code: "CN" } }, honeypot: { kind: "cowrie.log.opened", session_id: `sess-${n}` } },
});

// Aggregate/investigate endpoints. These pages are typed against the Rust
// backend's exact serde output, so every field a column renders must be
// present or hydration throws on undefined.
const attackPage = {
  total: 1,
  rows: [
    {
      id: "att-1",
      ips: ["203.0.113.7"],
      fingerprints: ["mirai"],
      payloads: [],
      credentials: ["root/admin"],
      sensors: ["citrix", "cowrie"],
      events: 342,
      first: NOW,
      last: NOW,
      updated: NOW,
      verdicts: ["mirai"],
      techniques: [],
    },
  ],
};

const campaignRow = {
  cidr: "203.0.113.0/24",
  score: 42,
  events: 190,
  unique_ips: 12,
  sensors: ["citrix"],
  ports: ["22", "8089"],
  creds: 5,
  payloads: 1,
  alerts: 3,
  providers: ["digitalocean"],
  fingerprints: 4,
  explanation: "shared session pivots across sensors",
  first: NOW,
  last: NOW,
};

const clusterPage = {
  total: 1,
  rows: [{ kind: "ja4", value: "t13d1516h8_8daaf6fa27fa_4a44ad6c72f5", sources: 33, events: 291, sensors: ["citrix"] }],
};

const sourceRow = {
  ip: "203.0.113.7",
  country: "CN",
  events: 120,
  logins: 64,
  sessions: 31,
  sensors: ["citrix", "cowrie"],
  first: NOW,
  last: NOW,
};

/** Minimal handler table; keys are matched by startsWith after the query
 *  string is split off, first match wins, then the catch-all. */
function route(pathname) {
  if (pathname === "/api/v1/config") {
    return { payload: { presentation: { dashboard_title: "APIARY", dashboard_subtitle: "browser-e2e deployment", banner_text: "", footer_text: "" } } };
  }
  if (pathname === "/api/v1/overview/kpis") {
    return { total: 4242, last24h: 321, previous24h: 291, change24h: "+10.3%", unique_ips: 87, hourly: Array.from({ length: 24 }, (_, h) => 5 + ((h * 7) % 19)), logins: 512, ready: true };
  }
  if (pathname === "/api/v1/overview/dashboard") return dashboard;
  if (pathname === "/api/v1/events") {
    return { total: 1337, offset: 0, rows: [eventRow(0), eventRow(1), eventRow(2)], fingerprint_ips: null };
  }
  if (pathname === "/api/v1/filter-values") {
    return { sensors: ["citrix", "cowrie"], countries: ["CN", "NL"], protos: ["tcp"], ports: ["22", "8089"], kinds: [] };
  }
  if (pathname === "/api/v1/attackers") {
    return { total: attackPage.total, rows: attackPage.rows.slice(0) };
  }
  if (pathname === "/api/v1/campaigns") {
    return { total: 1, rows: [campaignRow] };
  }
  if (pathname === "/api/v1/clusters") {
    return { total: clusterPage.total, rows: clusterPage.rows.slice(0) };
  }
  if (pathname === "/api/v1/sources") {
    return { total_unique: 87, rows: [sourceRow] };
  }
  if (pathname === "/api/v1/recordings") {
    // RecordingRow keyed on session; the replay pane fetches /recordings/<sha>
    // separately and is not part of the shell sweep.
    return {
      total: 1,
      rows: [
        { when: NOW, src_ip: "203.0.113.7", country: "CN", session: "sess-7", shasum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", size_bytes: 4096, duration_ms: 12000 },
      ],
    };
  }
  if (pathname.startsWith("/api/v1/sensors/catalog")) {
    // SensorSummary consumed by /sensors index + the $sensor tab rail.
    return { sensors: [{ sensor: "citrix", events: 551, last_seen: NOW }, { sensor: "cowrie", events: 1102, last_seen: NOW }] };
  }
  if (/^\/api\/v1\/sensors\/[^/]+\/overview$/.test(pathname)) {
    const sensor = decodeURIComponent(pathname.split("/")[4]);
    return {
      sensor,
      window: "7d",
      events: 551,
      unique_sources: 12,
      first_seen: NOW,
      last_seen: NOW,
      hourly: Array.from({ length: 24 }, (_, h) => 5 + ((h * 3) % 11)),
      top_sources: [{ key: "203.0.113.7", count: 120 }],
      top_countries: [{ key: "CN", count: 180 }],
      top_lists: [{ label: "commands", rows: [{ key: "uname -a", count: 34 }] }],
      measures: [{ label: "logins", total: 64, max: 24, unit: "" }],
    };
  }
  if (/^\/api\/v1\/sensors\/[^/]+\/events$/.test(pathname)) {
    // SensorEventRow: the page's protocol table calls meaningfulFields(
    // row.fields), so fields must always be an object.
    const sensor = decodeURIComponent(pathname.split("/")[4]);
    return {
      sensor,
      total: 2,
      rows: [
        { id: `se-0`, when: NOW, src_ip: "203.0.113.7", src_port: 44322, dst_port: 22, fields: { honeypot: { kind: "cowrie.log.opened" }, message: "login attempt" } },
        { id: `se-1`, when: NOW, src_ip: "203.0.113.8", src_port: 51234, dst_port: 8089, fields: { honeypot: { kind: "citrix.request" }, path: "/vpn/index.html" } },
      ],
    };
  }
  if (pathname === "/api/v1/sensors") {
    // CuratedSensorViews' SensorDetail; only the three per-protocol arrays.
    return { mailoney: [], http_requests: [], tanner: [] };
  }
  if (pathname === "/api/v1/payloads") {
    // Payload rows keep the Go-tier capitalized serde names.
    return {
      total: 1,
      offset: 0,
      rows: [
        {
          Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          Size: 0,
          SizeH: "0 B",
          MtimeUTC: NOW,
          MIME: "text/plain",
          Kind: "script",
          Platform: "",
          AnalysisPath: "",
          Dynamic: false,
          Sources: ["cowrie"],
          Copies: 1,
          Preview: "uname -a",
          PreviewTruncated: false,
        },
      ],
    };
  }
  if (pathname === "/api/v1/credentials") {
    // lib/routes/credentials.tsx expects {available, credentials:[...]}.
    return {
      available: true,
      credentials: [
        {
          id: "cred-1",
          target: "edge-router",
          path: "/admin",
          username: "root",
          password: "e2e-secret",
          content_template: "",
          memo: "router-root",
          created_by: "e2e",
          created_at: NOW,
        },
      ],
    };
  }
  if (pathname === "/api/v1/canarytokens/types") {
    // TokenType list the create-form select is built from.
    return [{ token_type: "http", label: "HTTP", description: "web token", requires_upload: false, supports_snippet: false }];
  }
  if (pathname === "/api/v1/canarytokens") return { tokens: [] };
  if (pathname === "/api/v1/alerts") {
    return { total: 1, offset: 0, rows: [{ id: "alert-1", time: NOW, sensor: "citrix", signature: "test alert", severity: "high", record: {} }], fingerprint_ips: null };
  }
  if (pathname === "/api/v1/source-health") {
    // Full SourceHealth — the page renders cluster/yara/runtime/ingest/
    // pipeline blocks straight off this object.
    return {
      cluster_status: "green",
      total_documents: 4_420_000,
      sensors: [
        { sensor: "citrix", documents: 551_000, last_seen: NOW, state: "ACTIVE" },
        { sensor: "cowrie", documents: 1_102_000, last_seen: NOW, state: "ACTIVE" },
        { sensor: "dionaea", documents: 221_000, last_seen: "2026-08-25T09:00:00Z", state: "STALE" },
      ],
      yara: { enabled: true, last_scan: NOW, rules_sha256: "e3b0c4", samples: 88, matched: 3, errors: 0 },
      runtime: { uptime_seconds: 86_400, rss_bytes: 268_435_456, vm_bytes: 536_870_912 },
      ingest: { state: "running", last_ingest: NOW, age_seconds: 3, recent_dead_letters: 0 },
      dead_letters: 0,
      unattributed_24h: 17,
      pipeline: { state: "running", acked: 1000, failed: 0, dropped: 2, active: 12, decode_failures: 1 },
    };
  }
  if (pathname === "/api/v1/services") {
    return {
      available: true,
      services: [
        { name: "honeypot-dashboard", state: "running", health: "healthy" },
        { name: "ml-worker", state: "running", health: "" },
      ],
    };
  }
  if (pathname === "/api/v1/topology") {
    const sensorRow = (sensor) => ({
      sensor,
      stack: "home",
      containers: [`${sensor}-app`, `${sensor}-sidecar`],
      ingress: ["traefik"],
      hostnames: ["apiary.example.invalid"],
      ports: [{ proto: "tcp", public: 2222, host: 22, proxy: true }],
      raw_index: `honeypot-${sensor}`,
    });
    return {
      generated_at: NOW,
      sensors: [sensorRow("citrix"), sensorRow("cowrie"), sensorRow("dnp3")],
      stacks: [
        { stack: "home", containers: [{ name: "citrix-app", adapter_visible: true }, { name: "cowrie-app", adapter_visible: true }, { name: "dnp3-app", adapter_visible: false }] },
      ],
    };
  }
  if (pathname === "/api/v1/ml-health") return [];
  if (pathname === "/api/v1/ml-anomalies/acks") return {};
  if (pathname.startsWith("/api/v1/store/")) return { rows: [], total: 0 };
  if (pathname === "/api/v1/search") return { results: [] };
  return {};
}

export function startFakeBackend(port) {
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const body = JSON.stringify(route(url.pathname));
    res.writeHead(200, { "content-type": "application/json" });
    res.end(body);
  });
  return new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    // Port zero keeps the harness collision-free; callers that pass a port
    // get a stable URL for Playwright's webServer handshake instead.
    if (port) {
      server.listen(port, "127.0.0.1", () => resolvePromise({ url: `http://127.0.0.1:${port}`, close: () => server.close() }));
    } else {
      server.listen(0, "127.0.0.1", () => resolvePromise({ url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() }));
    }
  });
}
