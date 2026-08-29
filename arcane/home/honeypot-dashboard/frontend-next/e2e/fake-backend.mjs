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
// The bare {} tail is not silent (#2507): it logs once per unrecognized
// path so a new page's fixture gap shows up in harness output instead of
// passing unnoticed as empty-state coverage.
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

// --- reports studio (#2507) ----------------------------------------------
// Mirrors backend-service reports_store.rs / reports_api.rs: the template
// catalog (report_template_catalog()), the element catalog
// (REPORT_ELEMENT_CATALOG), one serde ReportDefinition, and one
// GeneratedReportMeta row. Before these handlers existed the bare catch-all
// answered {} and /reports exercised only its empty/error render paths --
// the exact fixture gap that shipped #2480's DefinitionsCard crash past
// every pre-#2480 sweep (they timed out before reaching the route).

// [id, name, description, title, window, elements, kind] -- kind "" is the
// generic renderer; sandbox/payload/ghidra name the artifact-referenced one.
const reportTemplates = [
  ["executive", "Executive report", "Management-ready summary of the observation window: headline metrics, assessment, findings, and recommendations.", "Honeypot Executive Security Report", "24h", ["cover", "metrics", "assessment", "findings", "recommendations", "top_sources", "top_countries", "parameters"], ""],
  ["security", "Full security report", "Complete defensive picture: every metric, ranking, operational alert, and a bounded evidence appendix.", "Honeypot Security Operations Report", "24h", ["cover", "metrics", "assessment", "findings", "recommendations", "top_sensors", "top_sources", "top_signatures", "top_asns", "top_countries", "top_ports", "operational_alerts", "event_appendix", "parameters"], ""],
  ["threat", "Threat landscape", "Who and what is attacking: signatures, autonomous systems, countries, and targeted ports over a longer window.", "Honeypot Threat Landscape Report", "7d", ["cover", "metrics", "top_signatures", "top_asns", "top_countries", "top_ports", "findings", "parameters"], ""],
  ["incident", "Incident investigation", "Scoped deep-dive for one IP, session, network, or signature with operational alerts and an extended event appendix.", "Honeypot Incident Investigation Report", "24h", ["cover", "metrics", "assessment", "findings", "recommendations", "operational_alerts", "event_appendix", "parameters"], ""],
  ["sensors", "Sensor and collection health", "Collection coverage and operational state: sensor volumes plus open operational alerts.", "Honeypot Sensor and Collection Health Report", "24h", ["cover", "metrics", "top_sensors", "operational_alerts", "parameters"], ""],
  ["sandbox", "Sandbox analysis", "Dynamic-analysis report for one sandbox job: assessment, process / socket / network evidence, and ATT&CK mapping.", "Sandbox Dynamic Analysis Report", "", [], "sandbox"],
  ["payload", "Payload analysis", "Static/dynamic analysis report for one captured payload: classification, IOCs, YARA, sandbox runs, and any GitHub-analysis verdict.", "Payload Analysis Report", "", [], "payload"],
  ["ghidra", "Ghidra static analysis", "Headless-decompilation report for one captured payload: functions, strings, imports, capa capabilities, FLOSS-deobfuscated strings, fuzzy hashes, and structural (lief) info.", "Ghidra Static Analysis Report", "", [], "ghidra"],
  ["custom", "Custom report", "Blank canvas: pick every element, the scope, the theme, and the branding yourself.", "Honeypot Custom Report", "", ["cover", "metrics", "parameters"], ""],
].map(([id, name, description, title, window, elements, kind]) => ({
  id,
  name,
  description,
  title,
  theme: "dark",
  window,
  elements,
  sandbox: kind === "sandbox",
  payload: kind === "payload",
  ghidra: kind === "ghidra",
}));

// [id, label, description] -- report_pdf.rs's ELEMENT_* literals.
const reportElements = [
  ["cover", "Cover", "Title, scope, author, observed window, and classification line"],
  ["metrics", "Metric grid", "Headline counts: events, sources, alerts, logins, payloads, sessions, risk rating"],
  ["assessment", "Assessment", "Deterministic triage score explanation and rating"],
  ["findings", "Key findings", "Derived findings from the matching telemetry"],
  ["recommendations", "Recommended actions", "Derived defensive next steps"],
  ["top_sensors", "Top sensors", "Sensor volume ranking"],
  ["top_sources", "Top source addresses", "Source IP volume ranking"],
  ["top_signatures", "Top alert signatures", "IDS / honeypot signature ranking"],
  ["top_asns", "Top autonomous systems", "ASN / organization ranking"],
  ["top_countries", "Top countries", "Country ranking (contextual GeoIP lead only)"],
  ["top_ports", "Top destination ports", "Targeted port ranking"],
  ["operational_alerts", "Operational alerts", "Dashboard operational alert state matching the scope"],
  ["event_appendix", "Event appendix", "Representative newest matching event records (bounded)"],
  ["parameters", "Parameters and limitations", "Applied filters, data source, and evidentiary limitations"],
].map(([id, label, description]) => ({ id, label, description }));

const reportDefinition = {
  id: "def-e2e-1",
  name: "Daily executive digest",
  template: "executive",
  theme: "dark",
  branding: {
    title: "APIARY Executive Security Report",
    author: "e2e",
    header_left: "APIARY",
    header_right: "browser-e2e deployment",
    footer_left: "hermetic fixture",
    classification: "UNCLASSIFIED // e2e",
  },
  scope: {
    window: "24h",
    ip: "",
    network: "",
    sensor: "",
    port: "",
    signature: "",
    country: "",
    asn: "",
    text: "",
    type: "",
    session: "",
    job: "",
    hash: "",
  },
  elements: ["cover", "metrics", "parameters"],
  appendix_limit: 200,
  schedule: { enabled: true, frequency: "daily", hour: 6, minute: 0, weekday: 0, month_day: 1, last_run_at: NOW, next_run_at: NOW },
  created: NOW,
  updated: NOW,
};

// GeneratedReportMeta -- what the generated-reports grid's columns read.
const generatedReport = {
  id: "rep-e2e-1",
  definition_id: "def-e2e-1",
  name: "daily-executive-digest",
  template: "executive",
  theme: "dark",
  title: "APIARY Executive Security Report",
  size_bytes: 153_600,
  created_at: NOW,
  origin: "manual",
};

// gpu_queue.rs's GpuJob list -- a real array ({} here used to be a wrong
// shape, not just an empty one: the loader hands it to an array-typed card).
const gpuJob = {
  job_id: "gpu-e2e-1",
  job_type: "ghidra",
  ref: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  model: "qwen3:14b",
  estimated_vram_mib: 20480,
  status: "queued",
  requested_at: NOW,
  started_at: "",
  finished_at: "",
  abort_requested: false,
  error: "",
  attempts: 0,
};

/** Paths that already answered the bare {} catch-all -- logged once each. */
const catchAllWarned = new Set();

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
  if (pathname === "/api/v1/reports/templates") {
    // Reports studio wizard catalog (#2507): the template gallery and the
    // element picker both render straight off this response.
    return { templates: reportTemplates, elements: reportElements };
  }
  if (pathname === "/api/v1/reports/definitions") {
    // The Library's saved-definitions table; a body without its documented
    // array once crashed this page (#2480), so the shape is load-bearing.
    return { definitions: [reportDefinition] };
  }
  if (pathname.startsWith("/api/v1/store/generated-reports")) {
    // Specific leg ahead of the generic store catch-all so the
    // generated-reports grid exercises a real GeneratedReportMeta row.
    return { total: 1, rows: [generatedReport] };
  }
  if (pathname === "/api/v1/gpu-queue") {
    // gpu_queue.rs::list returns a bare array; /payload-workbench/results
    // loads it into an array-typed card on mount.
    return [gpuJob];
  }
  if (pathname === "/api/v1/ml-anomalies/stats") {
    // detail.rs::ml_anomaly_stats -- the Open (all time) tile's backlog.
    return { total: 34, open: 9 };
  }
  if (pathname.startsWith("/api/v1/charts/kill-chain-sankey")) {
    // The four chart payloads below are what /kill-chain and /ml-anomalies
    // fetch on mount through the /api/chart/{name} BFF proxy (#2507); the
    // catch-all's {} used to drop every one into EChart's empty/error state.
    // Same {nodes, links} envelope as the topology flow graph.
    return {
      nodes: [
        { name: "Recon" },
        { name: "Initial Access" },
        { name: "Execution" },
        { name: "Persistence" },
        { name: "Lateral Movement" },
        { name: "Impact" },
      ],
      links: [
        { source: "Recon", target: "Initial Access" },
        { source: "Initial Access", target: "Execution" },
        { source: "Execution", target: "Persistence" },
        { source: "Execution", target: "Lateral Movement" },
        { source: "Lateral Movement", target: "Impact" },
      ],
    };
  }
  if (pathname.startsWith("/api/v1/charts/attck-coverage")) {
    // Heatmap cell grid: {tactic_idx, technique_idx, count} triples.
    return {
      tactics: ["Recon", "Execution", "Persistence"],
      techniques: ["T1595", "T1059", "T1505"],
      cells: [
        { tactic_idx: 0, technique_idx: 0, count: 40 },
        { tactic_idx: 1, technique_idx: 1, count: 12 },
        { tactic_idx: 2, technique_idx: 2, count: 3 },
      ],
    };
  }
  if (pathname.startsWith("/api/v1/charts/campaign-timeline")) {
    // Per-CIDR Gantt rows; the client encodes [index, start_ms, end_ms, score].
    const startMs = Date.parse("2026-08-26T10:00:00Z");
    return [
      { cidr: "203.0.113.0/24", start_ms: startMs, end_ms: startMs + 3_600_000, score: 42, events: 190 },
      { cidr: "198.51.100.0/24", start_ms: startMs + 1_800_000, end_ms: startMs + 7_200_000, score: 17, events: 64 },
    ];
  }
  if (pathname.startsWith("/api/v1/charts/ml-anomaly-scores")) {
    // Scatter series: [{name, points:[{time, value}]}].
    return [
      {
        name: "203.0.113.7",
        points: [
          { time: "2026-08-26T10:00:00Z", value: 0.62 },
          { time: "2026-08-26T11:00:00Z", value: 0.81 },
        ],
      },
    ];
  }
  if (pathname.startsWith("/api/v1/preferences")) {
    // preferences.rs::get envelope -- {preferences, revision}. The root
    // route's appearance reconcile reads preferences.theme/palette off it.
    return { preferences: { theme: "dark", palette: "claude" }, revision: 1 };
  }
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
    return { generated_at: NOW, sensors: topologySensors(), stacks: topologyStacks(), flow: flowGraph() };
  }
  if (pathname === "/api/v1/ml-health") return [];
  if (pathname === "/api/v1/ml-anomalies/acks") return {};
  if (pathname.startsWith("/api/v1/store/")) return { rows: [], total: 0 };
  if (pathname === "/api/v1/search") return { results: [] };
  if (pathname === "/api/v1/live") {
    // STUB pending the live-shared-poller workstream (4b9cae88/bf8d4740:
    // "serve the live feed from one shared poller per process", "coalesce
    // live-tail frames"). routes/api/live.ts proxies this path straight
    // through as an SSE body (limitedStreamProxy forces the response's
    // content-type/headers regardless of what's returned here), so the
    // exact frame format isn't exercised by this fixture either way --
    // this just needs to stop answering the bare {} catch-all (#2542)
    // without pinning a real-backend contract that workstream is still
    // reshaping. Replace with a shape-correct frame/envelope once it lands.
    return { entries: [], cursor: null };
  }
  // #2507: an unrecognized /api/v1/* path used to answer {} invisibly, so
  // every new page silently inherited fallback coverage and its smoke test
  // verified little more than the skeleton. Say so, once per path, so a
  // fixture gap is visible in harness output instead of silent.
  if (!catchAllWarned.has(pathname)) {
    catchAllWarned.add(pathname);
    console.error(`[fake-backend] ${pathname} answered the bare {} catch-all`);
  }
  return {};
}

// --- /api/v1/topology ----------------------------------------------------
// The response carries data.flow, which routes/api/topology.flow.ts proxies
// to the "How a byte flows" sankey; without it that route 502s and the
// matrix silently covers only the error state. flowGraph mirrors
// backend-service src/topology.rs's flow_graph() -- same node names, same
// layers, same edges -- so interaction tests run against the real DAG's
// density (~90 nodes, layers 0-6), the exact thing the zoom/pan/drag
// affordances of #2130 exist for.

const TOPOLOGY_SENSORS = [
  ["cowrie", ["portbridge"]],
  ["endlessh", ["portbridge"]],
  ["beelzebub", ["portbridge"]],
  ["mailoney", ["portbridge"]],
  ["dionaea", ["portbridge"]],
  ["multipot", ["portbridge"]],
  ["conpot", ["portbridge"]],
  ["conpot-s7-1200", ["portbridge"]],
  ["conpot-s7-1500", ["portbridge"]],
  ["conpot-iec104", ["portbridge"]],
  ["conpot-guardian", ["portbridge"]],
  ["conpot-kamstrup", ["portbridge"]],
  ["dnp3", ["portbridge"]],
  ["dicompot", ["portbridge"]],
  ["dns-honeypot", ["portbridge"]],
  ["citrix-honeypot", ["portbridge"]],
  ["cisco-asa-honeypot", ["portbridge"]],
  ["rdp-honeypot", ["portbridge"]],
  ["http-honeypot", ["traefik", "portbridge"]],
  ["api-honeypot", ["portbridge"]],
  ["galah", ["traefik", "portbridge"]],
  ["hellpot", ["traefik", "portbridge"]],
  // wordpot retired from the fleet (#2381) -- not a fake sensor any more.
  ["snare", ["traefik"]],
  ["sentrypeer", ["portbridge"]],
  ["elasticpot", ["portbridge"]],
  ["canarytokens", ["tunnel-only", "traefik"]],
];

const INGRESS_LABELS = {
  traefik: "VPS Traefik (:443 hostnames)",
  portbridge: "VPS portbridge (raw ports)",
  "tunnel-only": "WireGuard tunnel only",
};

const VPS_PRODUCERS = [
  "suricata IDS (VPS)",
  "zeek (VPS)",
  "zeek-proxy (relay side)",
  "huginn JA4T sidecar",
  "Traefik access log (VPS)",
];

const RAW_INDEX_NODES = [
  "honeypot-v2-*",
  "suricata-v2-*",
  "portbridge-v2-*",
  "zeek-v1-*",
  "zeek-proxy-v1-*",
  "huginn-v1-*",
  "traefik-v1-*",
  "cowrie-ttylog-v1",
  "dionaea-incidents-v1",
  "mailoney-mail-v1",
  "extracted-files-v1",
];

const WORKER_LOOPS = [
  // [worker, reads, writes, surfaces] -- PIPELINES.md §2 verbatim.
  ["attacker-identity-worker", ["honeypot-v2-*", "ghidra-analysis-v1", "sandbox-analysis-v1", "github-analysis-v1", "cape-analysis-v1", "revdeck-analysis-v1"], ["attackers-v1"], ["/attackers · overview · graphs"]],
  ["correlator-worker", ["honeypot-v2-*", "suricata-v2-*"], ["campaigns-v1", "attacker-clusters-v1"], ["/campaigns", "/clusters · kill-chain"]],
  ["agent-intrusion loop", ["honeypot-v2-*", "suricata-v2-*"], ["agent-intrusion-campaigns"], ["/agent-campaigns"]],
  ["zeek-proxy-attribution", ["zeek-v1-*", "portbridge-v2-*"], ["attributed flows (enriched docs)"], ["/sessions · /events"]],
  ["ml-worker", ["suricata-v2-*", "zeek-v1-*"], ["ml-anomalies"], ["/ml-anomalies"]],
  ["llm-worker", ["payload stores", "honeypot-v2-*"], ["llm-analysis"], ["/llm-analysis"]],
  ["es-results-importer", ["result spools (root-owned)"], ["ghidra-analysis-v1", "sandbox-analysis-v1", "github-analysis-v1", "cape-analysis-v1", "revdeck-analysis-v1"], ["/payload-workbench/results"]],
  ["yara scanner", ["payload stores"], ["yara-analysis-v1"], ["/investigate · charts"]],
  ["payload-inventory-worker", ["payload stores"], ["dashboard-payload-inventory-v1", "dashboard-payload-bytes-v1"], ["/payloads · charts"]],
  ["alert-notifier loop", ["attackers-v1", "campaigns-v1", "agent-intrusion-campaigns"], ["dashboard-alert-state-v1"], ["/alerts"]],
  ["canarytokens-adapter", ["canarytokens"], ["dashboard-canarytokens-v1"], ["/canarytokens · settings pane"]],
  ["reporter", ["dashboard state (backend indices)"], ["reporter-metrics-v1"], ["/settings stats"]],
];

const DEAD_LETTERS = ["ES non-indexable policy", "dead-letter-honeypot", "/dead-letters"];

function flowGraph() {
  const nodes = [];
  const seen = new Set();
  const declare = (name, layer) => {
    if (!seen.has(name)) {
      seen.add(name);
      nodes.push({ name, layer });
    }
  };
  const links = [];
  const link = (source, target) => links.push({ source, target });

  for (const label of Object.values(INGRESS_LABELS)) declare(label, 0);
  for (const [sensor] of TOPOLOGY_SENSORS) declare(sensor, 1);
  for (const producer of VPS_PRODUCERS) declare(producer, 1);
  declare("portbridge conn-log (VPS)", 1);
  declare("Filebeat", 2);
  declare("payload stores", 2);
  declare("result spools (root-owned)", 3);
  declare("dashboard state (backend indices)", 3);
  for (const family of RAW_INDEX_NODES) declare(family, 3);
  declare("dashboard-canarytokens-v1", 5);
  for (const [worker, , writes, surfaces] of WORKER_LOOPS) {
    declare(worker, 4);
    writes.forEach((w) => declare(w, 5));
    surfaces.forEach((s) => declare(s, 6));
  }
  DEAD_LETTERS.forEach((name, i) => declare(name, 4 + i));

  for (const [sensor, ingresses] of TOPOLOGY_SENSORS)
    for (const via of ingresses) link(INGRESS_LABELS[via], sensor);
  link("VPS portbridge (raw ports)", "portbridge conn-log (VPS)");
  for (const [sensor] of TOPOLOGY_SENSORS) {
    if (sensor !== "canarytokens") link(sensor, "Filebeat");
  }
  for (const captor of ["cowrie", "dionaea"]) link(captor, "payload stores");
  for (const producer of VPS_PRODUCERS) link(producer, "Filebeat");
  for (const family of RAW_INDEX_NODES) link("Filebeat", family);

  for (const [worker, reads, writes, surfaces] of WORKER_LOOPS) {
    reads.forEach((r) => link(r, worker));
    writes.forEach((w) => link(worker, w));
    for (const surface of surfaces) for (const w of writes) link(w, surface);
  }
  for (const verdict of ["ghidra-analysis-v1", "sandbox-analysis-v1", "github-analysis-v1", "cape-analysis-v1", "revdeck-analysis-v1"])
    link(verdict, "attacker-identity-worker");

  const [dlWorker, dlIndex, dlPage] = DEAD_LETTERS;
  link("honeypot-v2-*", dlWorker);
  link(dlWorker, dlIndex);
  link(dlIndex, dlPage);

  return { nodes, links };
}

function topologySensors() {
  return TOPOLOGY_SENSORS.map(([sensor]) => ({
    sensor,
    stack: "home",
    containers: [`${sensor}-app`, `${sensor}-sidecar`],
    ingress: ["traefik"],
    hostnames: ["apiary.example.invalid"],
    ports: [{ proto: "tcp", public: 2222, host: 22, proxy: true }],
    raw_index: `honeypot-${sensor}`,
  }));
}

function topologyStacks() {
  return [
    {
      stack: "home",
      containers: TOPOLOGY_SENSORS.slice(0, 6).map(([sensor], i) => ({ name: `${sensor}-app`, adapter_visible: i % 2 === 0 })),
    },
  ];
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
