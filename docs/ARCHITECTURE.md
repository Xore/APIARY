# System architecture and data flow

[← back to README](../README.md)

This section describes the active implementation across the home server's
Dockge stacks and the VPS Compose file, plus pieces that are real but live
outside ordinary Compose services: the Ghidra static analysis pipeline
(`analysis/ghidra/`, its own Dockge stack plus a host systemd worker —
genuinely deployed, see "Captured payload lifecycle and static analysis"
below) and the Linux KVM sandbox (root-owned host worker described below).

`sandbox/windows/` is past the planning stage but not fully wired up: the
golden image builds reliably and boots (Sysmon, PowerShell logging, FakeNet,
Regshot, and the living-persona daemon all confirmed working against a live
guest — see #47, #290, #358), and it can be driven manually via
`kvm_manage.sh`/`orchestrate/run_sample.py`. What's still missing is the
automated intake path: no host-side worker config or systemd units are
installed yet, so the dashboard's Windows submission path has nothing to
hand a request to, and #53's end-to-end smoke test (dashboard submit →
Windows sandbox report) hasn't run. Until that's wired up, Windows samples
still take the static-only/Wine-in-Linux-guest path the sandbox section below
describes, not the native Windows 11 guest — see that directory's own
`IMPLEMENTATION_PLAN.md` for current status. TANNER containers are
web-request emulators, not malware detonation sandboxes.

**The home side is not one deployment unit.** [#258](https://github.com/Xore/APIARY/issues/258)
split what used to be a single `docker-compose.yml` into 12 independently
deployed Dockge stacks — each with its own compose file
(`docker-compose.<name>.yml`) and its own start/stop/update lifecycle. The
root `docker-compose.yml` is now a deliberate empty marker; nothing runs
`docker compose up` against it any more. The diagrams below draw those stack
boundaries explicitly rather than one "home server" box, because that
boundary is where independent deployment, restart, and failure actually
happen.

## Deployment and trust boundaries

```mermaid
flowchart LR
  attacker["Untrusted internet client"]

  subgraph vps["Public VPS"]
    direction TB
    suricata["Suricata<br/>IDS + EVE + rotating PCAP"]
    traefik["Traefik<br/>TLS routing"]
    auth["Xore/auth-backend<br/>forward-auth SSO"]
    httpBridges["socat HTTP bridges<br/>dashboard, Kibana, EveBox,<br/>Arkime, TANNER, Rev·Deck,<br/>web honeypots"]
    portbridge["portbridge<br/>raw TCP/UDP forwarding<br/>optional PROXY v1"]
    connlog[("portbridge connection log")]
  end

  wg["WireGuard tunnel"]

  subgraph home["Home server — 18 independent Dockge stacks (#258)"]
    direction TB
    subgraph initStack["honeypot-init"]
      initJobs["Bootstrap one-shot jobs"]
    end
    subgraph sensorStacks["Sensor stacks — one Dockge stack each, each its own isolated network (#235)"]
      direction LR
      cowrieStack["honeypot-cowrie"]
      dionaeaStack["honeypot-dionaea<br/>+ tftp-relay"]
      conpotStack["honeypot-conpot"]
      dnp3Stack["honeypot-dnp3"]
      httpStack["honeypot-http"]
      multipotStack["honeypot-multipot"]
      dicompotStack["honeypot-dicompot"]
      dnsHoneypotStack["honeypot-dns-honeypot"]
      citrixStack["honeypot-citrix"]
      ciscoAsaStack["honeypot-cisco-asa"]
      rdpStack["honeypot-rdp"]
      endlesshStack["honeypot-endlessh"]
    end
    subgraph tannerStack["honeypot-tanner"]
      tannerSvcs["SNARE + TANNER analyzer/API/web<br/>+ nested Docker + Redis"]
    end
    subgraph elkStack["honeypot-elk"]
      elkSvcs["Filebeat, Elasticsearch,<br/>Kibana, EveBox, Arkime"]
    end
    subgraph dashboardStack["honeypot-dashboard"]
      dashboardSvc["Dashboard + results-importer<br/>+ services-adapter"]
    end
    subgraph payloadStack["honeypot-payload-analysis"]
      payloadSvcs["payload-dedupe + YARA"]
    end
    subgraph utilStack["honeypot-utilities"]
      utilSvcs["autoheal + log-maintenance<br/>+ reporter"]
    end
    hostSandbox["Root-owned host services<br/>Linux + Windows sandbox, Ghidra —<br/>systemd + libvirt/KVM, not Dockge stacks"]
  end

  attacker -->|"all public traffic is observed"| suricata
  attacker -->|"HTTPS"| traefik
  traefik -->|"forward-auth check"| auth
  auth -->|"identity headers or reject"| traefik
  traefik -->|"decoy HTTP and protected UIs"| httpBridges
  attacker -->|"raw sensor ports"| portbridge
  portbridge --> connlog
  httpBridges --> wg
  portbridge --> wg
  wg --> sensorStacks
  wg --> tannerStack
  wg --> elkStack
  wg --> dashboardStack
  sensorStacks -->|"logs + captured artifacts<br/>via shared host paths"| elkStack
  sensorStacks -->|"logs + captured artifacts<br/>via shared host paths"| dashboardStack
  tannerStack -->|"logs via shared host paths"| elkStack
  tannerStack -->|"logs via shared host paths"| dashboardStack
  payloadStack -.->|"hashes + results"| dashboardStack
  dashboardStack -.->|"hash-only request spool"| hostSandbox
  suricata -.->|"read-only SSHFS logs over WireGuard"| elkStack
  suricata -.->|"read-only SSHFS logs over WireGuard"| dashboardStack
```

Stacks are deployed independently, but not network- or filesystem-isolated
from each other the way the VPS/home boundary is: most share the `honeynet`
Docker network by name and the same host bind-mounted `logs/`/state
directories, which is how a sensor stack's events reach `honeypot-elk` and
`honeypot-dashboard` without a direct network call between them. Independent
deployment means each stack can be updated, restarted, or fail without
taking the others down — not that they can't see each other's data.

The VPS is the only internet-facing layer. Suricata sees traffic before it
enters WireGuard, so IDS records and PCAPs retain the original network view.
Traefik handles HTTPS routes and delegates authentication for investigation
UIs to the separately deployed `Xore/auth-backend`. Raw protocols pass through
`portbridge`; targets that understand HAProxy PROXY v1 receive the original
client address in-band, while the connection log lets the dashboard recover
source attribution for PROXY-unaware sensors.

The `httpBridges` box above collapses six otherwise-identical
Cloudflare → Traefik → forward-auth → `socat-hp-*` → WireGuard chains into
one node — see
["The forward-auth bridge, generically"](CGNAT-DEPLOYMENT.md#the-forward-auth-bridge-generically)
in the deployment guide for the per-request sequence every investigation UI
(dashboard, Kibana, TANNER, EveBox, Arkime, Rev·Deck) shares.

Home container ports bind to `HP_BIND` (normally the home WireGuard address),
not to every host interface. The root Compose network `honeynet` carries the
trusted analysis/management plane (Elasticsearch, Kibana, Filebeat, the
dashboard, EveBox, Arkime) — not the honeypots themselves. Each honeypot has
its own single-member network instead ([#235](https://github.com/Xore/APIARY/issues/235)),
so a compromise of one has no network path to another; `tftp-relay` shares
`dionaea_net` with `dionaea` since it actually depends on and forwards
traffic to it, the one real exception. TANNER additionally uses
`tanner_local`, which contains its Redis, API, PHP emulator, and disposable
nested Docker daemon. That daemon is deliberately not the homeserver Docker
socket.

## Home container interaction map

```mermaid
flowchart TB
  subgraph honeypotInit["honeypot-init — separate Dockge stack (#111, #258)"]
    direction TB
    persona["persona-apply<br/>validate/apply personas"]
    loginit["log-init<br/>create host log paths"]
    esinit["elasticsearch-setup<br/>templates, pipelines, ILM"]
    kibanainit["honeypot-kibana-setup<br/>data views + dashboards"]
    arkinit["arkime-init<br/>Arkime schema + user"]
    snareclone["snare-clone<br/>persona pages onto snare-pages"]
    persona --> loginit
  end

  initMarkers[("state/init-markers/<br/>*.done completion files")]
  loginit --> initMarkers
  esinit --> initMarkers
  arkinit --> initMarkers
  snareclone --> initMarkers

  subgraph sensorGroup["Sensor stacks — one Dockge stack each (#258), each its own isolated network (#235)"]
    direction LR
    subgraph cowrieStackG["honeypot-cowrie"]
      cowrie["Cowrie"]
    end
    subgraph multipotStackG["honeypot-multipot"]
      multipot["multipot"]
    end
    subgraph httpStackG["honeypot-http"]
      http["HTTP + API honeypots"]
    end
    subgraph dionaeaStackG["honeypot-dionaea"]
      dionaea["Dionaea"]
      tftp["TFTP relay"]
    end
    subgraph conpotStackG["honeypot-conpot"]
      conpot["Conpot personas"]
    end
    subgraph dnp3StackG["honeypot-dnp3"]
      dnp3["DNP3"]
    end
  end

  subgraph tannerGroup["honeypot-tanner — TANNER application-emulation boundary"]
    snare["SNARE"]
    tanner["TANNER analyzer"]
    tannerapi["TANNER API"]
    tannerweb["TANNER web UI"]
    phpox["PHP sandbox emulator"]
    tannerdocker["nested Docker daemon"]
    redis["TANNER Redis"]
  end

  logs[("Host logs<br/>JSON/JSONL")]
  payloads[("Captured payload stores<br/>Cowrie + Dionaea + inline scripts")]
  dashboardState[("dashboard-state")]
  yaraResults[("yara-results")]

  subgraph elkStackG["honeypot-elk"]
    es[("Elasticsearch")]
    filebeat["Filebeat"]
    kibana["Kibana"]
    evebox["EveBox"]
    pcapSync["PCAP sync"]
    arkCapture["Arkime capture"]
    arkViewer["Arkime viewer"]
  end

  subgraph dashboardStackG["honeypot-dashboard"]
    dashboard["Live dashboard"]
  end

  subgraph utilStackG["honeypot-utilities"]
    maintenance["log-maintenance<br/>bounded text-log rotation"]
  end

  initMarkers -.->|"entrypoint polls log-init.done"| sensorGroup
  initMarkers -.->|"entrypoint polls log-init.done"| maintenance
  initMarkers -.->|"entrypoint polls snare-clone.done<br/>+ log-init.done"| snare
  tftp --> dionaea

  cowrie --> logs
  multipot --> logs
  http --> logs
  dionaea --> logs
  conpot --> logs
  dnp3 --> logs
  tanner --> logs

  cowrie --> payloads
  dionaea --> payloads
  dashboard -->|"retains inert inline scripts"| dashboardState
  dashboardState --> payloads

  snare --> tanner
  tanner --> tannerapi
  tanner --> phpox
  tanner --> tannerdocker
  tanner --> redis
  tannerweb --> tannerapi
  tannerapi --> redis

  logs --> filebeat
  initMarkers -.->|"entrypoint polls elasticsearch-setup.done"| filebeat
  filebeat --> es
  es --> kibana
  kibanainit -.->|"configures via API,<br/>no ordering dependency"| kibana

  logs -->|"every sensor except multipot"| dashboard
  payloads --> dashboard
  dashboardState --> dashboard
  yaraResults --> dashboard
  dashboard --> es
  es -.->|"multipot events, ES-sourced (#403, #238)"| dashboard
  dashboard -.->|"health only"| filebeat

  es --> evebox
  initMarkers -.->|"entrypoint polls arkime-init.done<br/>+ log-init.done"| evebox

  logs -->|"closed VPS PCAP files"| pcapSync
  pcapSync --> arkCapture
  initMarkers -.->|"entrypoint polls arkime-init.done"| arkCapture
  arkCapture --> es
  es --> arkViewer
  pcapSync --> arkViewer
```

Most sensors write append-only JSON logs under the host `logs/` tree. The
dashboard reads bounded tails of those files for low-latency live operations,
while Filebeat maintains durable offsets and ships the same evidence to
Elasticsearch for historical search. These are complementary paths: the live
dashboard can remain useful during an Elasticsearch interruption, and the
Elasticsearch archive outlives the dashboard's bounded in-memory window.

multipot is the one exception (#403): the dashboard never reads its log file
directly, only Elasticsearch (`events_es.go`'s `loadSensorEventsES`, queried
by `sensor` against `honeypot-v2-*` on every rebuild cycle, merged into the
same `s.events` pipeline every file-based sensor's events go through). This
was made a prerequisite for #238's new protocol handlers (POP3, IMAP, SOCKS5,
HL7/MLLP, ADB — all added directly to multipot rather than vendoring five
separate third-party images) so they show up in the normal Event Explorer
without the dashboard reading their log file at all. multipot still writes
its log file exactly as before, purely for Filebeat to pick up — the
dashboard's own read path is what changed. Every other sensor, including
http-honeypot's deepened WordPress bait (readme.html version fingerprinting,
xmlrpc.php, vulnerable-plugin readme.txt endpoints — also #238), is unaffected
and stays file-based.

`honeypot-init` runs first among the 18 stacks, and every other one depends
on its output without a Compose-level dependency — Compose's
`depends_on: condition: service_completed_successfully` can't reach across a
stack boundary, [#258](https://github.com/Xore/APIARY/issues/258)'s
split notwithstanding. Its one-shot jobs write a `<job>.done` marker file to
a shared `state/init-markers/` directory on success; every dependent
container across every other stack polls for that file at container
entrypoint (`until [ -f /markers/<job>.done ]; do sleep 3; done`) instead.
`log-init` also prepares host log paths before sensors start, and
`log-maintenance` (in `honeypot-utilities`, one of the marker-waiting
services, not a bootstrap job itself) rotates only the human-readable logs
that are safe to copy-truncate; structured streams tailed by Filebeat are
preserved. `honeypot-kibana-setup` is the one job with no dependents
anywhere: nothing waits on its marker because nothing needs to.

## Event ingestion and network analysis

```mermaid
flowchart LR
  traffic["Attacker traffic"]
  sensorEvents["Sensor JSON events"]
  vpsEve["VPS Suricata eve.json"]
  vpsPcap["VPS rotating PCAP"]
  portLog["VPS portbridge log"]
  sshfs["Read-only SSHFS mounts"]
  filebeat["Filebeat<br/>filestream registry"]
  live["Dashboard parser<br/>bounded file tails<br/>(all sensors except multipot)"]
  esRead["Dashboard ES read<br/>multipot only (#403)"]
  normalize["Normalization + GeoIP +<br/>source-IP correlation"]
  es[("Elasticsearch")]
  dlq[("dead-letter-honeypot")]
  kibana["Kibana"]
  evebox["EveBox"]
  sync["pcap-sync<br/>skip open/newest file"]
  arkime["Arkime capture"]
  viewer["Arkime viewer"]

  traffic --> sensorEvents
  traffic --> vpsEve
  traffic --> vpsPcap
  traffic --> portLog

  vpsEve --> sshfs
  vpsPcap --> sshfs
  portLog --> sshfs

  sensorEvents --> filebeat
  sshfs --> filebeat
  filebeat -->|"honeypot-v2-* and suricata-v2-*"| es
  filebeat -->|"non-indexable original event"| dlq
  es --> kibana

  sensorEvents --> live
  sshfs --> live
  live --> normalize
  es -->|"query by sensor"| esRead
  esRead --> normalize
  portLog --> normalize

  es --> evebox

  sshfs --> sync
  sync -->|"local close-write event"| arkime
  arkime -->|"session metadata"| es
  sync -->|"packet files"| viewer
  es --> viewer
```

The analysis layers serve different purposes:

| Layer | Input | Output | Primary use |
|---|---|---|---|
| Dashboard live parser | recent sensor/EVE/portbridge file tails (every sensor except multipot) | normalized in-memory snapshot, alerts, campaigns, exports | immediate operations and cross-sensor pivots |
| Dashboard ES read (#403) | `honeypot-v2-*`, queried by sensor — multipot only | same normalized snapshot as the file parser, merged in | multipot events (POP3/IMAP/SOCKS5/HL7/ADB, #238) without a dashboard file read |
| Filebeat | durable JSON filestreams | versioned Elasticsearch indices/data streams | complete historical indexing with restart-safe offsets |
| Elasticsearch setup | templates and pipelines | flattened heterogeneous sensor fields, GeoIP, ILM, dead-letter fallback | mapping safety and retention |
| Kibana | Elasticsearch | saved searches, visualizations, archive investigations | long-range analysis |
| Suricata | public-interface packets | signatures, protocol events, flows, rotating PCAP | IDS and network evidence |
| EveBox | the `suricata-v2-*` indices | alert-focused UI over Elasticsearch | fast Suricata triage |
| Arkime | closed PCAP files | indexed sessions plus retained packet files | full-packet search and payload inspection |
| Dashboard correlation (see "Correlation and enrichment" below) | normalized events and portbridge metadata | attacker profiles, sessions, clusters, campaigns, ATT&CK context | evidence-led behavioral investigation |

`pcap-sync` exists because remote SSHFS writes do not produce usable local
inotify events: it skips the newest file because Suricata may still be writing
it, then copies closed files locally so Arkime receives the `IN_CLOSE_WRITE`
event it expects.

EveBox needs no such sidecar. It queries the `suricata-v2-*` indices Filebeat
already writes, so it holds no copy of the event data and nothing to outgrow.

## Elasticsearch ingest pipeline

`geoip-honeypot` (`analysis/elasticsearch-setup.sh`, set as `honeypot-v2-*`'s
`index.default_pipeline`) is the one ingest pipeline every honeypot/Suricata/
portbridge document passes through before it's indexed. It runs as an ordered
list of processors — each one reads/writes `ctx` in place, and every
processor is `ignore_failure: true` so one enrichment failing (a missing
GeoIP database, a malformed field) never blocks indexing the underlying
event.

```mermaid
flowchart TD
  doc["Raw Filebeat document<br/>honeypot.* / suricata.eve.* / portbridge.*"]
  main["1. Main enrichment script<br/>event.sensor, source/destination.ip+port,<br/>network.protocol, user.name, process.command_line,<br/>url.path, file.hash.sha256, event.category, ot.persona<br/>+ suricata/portbridge field promotion"]
  geo1["2-3. GeoIP: suricata.eve.src_ip<br/>→ source.geo, source.as"]
  geo2["4. GeoIP: suricata.eve.dest_ip<br/>→ destination.geo"]
  geo3["5-6. GeoIP: honeypot.src_ip<br/>→ source.geo, source.as"]
  geo4["7-8. GeoIP: portbridge.src_ip<br/>→ source.geo, source.as"]
  dionaea["9. Dionaea incident hash extraction (#354)<br/>plain string scan for sha256/md5 in raw message<br/>(no regex -- disabled by default in Painless)"]
  nettype["10. Network-type classification<br/>source.as.organization_name → scanner/cloud/hosting"]
  log4shell["11. Log4Shell detection (#238, #416)<br/>deobfuscate Log4j lookup evasion, flag event.log4shell<br/>ported from Log4Pot's deobfuscator.py, depth/length-bounded"]
  indexed[("honeypot-v2-*<br/>index.default_pipeline: geoip-honeypot")]

  doc --> main
  main --> geo1 --> geo2 --> geo3 --> geo4
  geo4 --> dionaea
  dionaea --> nettype
  nettype --> log4shell
  log4shell --> indexed
```

Each numbered step corresponds directly to one processor in
`geoip-honeypot`'s `processors` array (same order, same file) — this diagram
is not an approximation of the pipeline, it's a 1:1 map of it. Notably:

- Steps 2-8 run unconditionally on every document; each is a no-op
  (`ignore_missing: true`) when its source field isn't present, so a
  Suricata document only ever gets steps 2-4 populated and a honeypot/
  portbridge document only ever gets steps 5-8.
- No processor here performs geoip lookups against `source.as`/`destination`
  fields that don't apply to it (dead branches are `ignore_missing`, not
  `ignore_failure`-masked errors).
- Step 11 (Log4Shell) runs last and reads whichever `honeypot.*` fields step
  1 already normalized in, not the raw pre-enrichment document — it doesn't
  need its own copy of field-name knowledge per sensor, just the same
  `honeypot.*` flattened map every sensor already writes into.
- None of these processors make outbound network calls (the geoip ones read
  local `GeoLite2-*.mmdb` files, not a lookup service) — enrichment happens
  entirely on data already inside the document.

## Correlation and enrichment

Enrichment adds signal to a single event as it's ingested — GeoIP, an OS
guess, a protocol fingerprint. Correlation is a separate, later step: given
one IP, hash, or shared attribute, find every other record that shares it.
Nothing here is eager. Enrichment happens once per event at ingest time;
correlation only runs when an analyst drills into a specific IP, CIDR, hash,
or cluster — the dashboard's list views never pay for a correlation query
just to render a row.

```mermaid
flowchart TB
  subgraph sources["Raw signal sources"]
    direction LR
    cowrieKex["Cowrie: SSH KEX negotiation<br/>-> HASSH (MD5)"]
    cowrieBanner["Cowrie: SSH client banner<br/>e.g. SSH-2.0-OpenSSH_7.9"]
    suricataTLS["Suricata: TLS ClientHello<br/>-> JA3 / JA4"]
    httpUA["HTTP honeypots:<br/>User-Agent, x-ja3/x-ja4 headers"]
    p0fSock(("p0f API socket<br/>VPS, network_mode: host"))
    geoMMDB[("GeoLite2 City/ASN MMDB<br/>+ local threat-CIDR list")]
  end

  subgraph vpsEnrich["VPS — per-connection, at portbridge"]
    portbridge["portbridge"]
    portbridge -->|"query over Unix socket,<br/>300ms timeout"| p0fSock
    p0fSock -->|"OS guess only —<br/>uptime/distance/NAT discarded"| portbridge
  end
  portbridge -->|"'os' field in conn-log JSON"| connlog[("portbridge connection log<br/>SSHFS to home")]

  subgraph esEnrich["Elasticsearch ingest pipeline (geoip-honeypot)"]
    esPipeline["3 index templates:<br/>honeypot-*, suricata-*, portbridge-*"]
    esPipeline --> esGeo["writes source.geo,<br/>source.as, destination.geo"]
  end

  subgraph dashEnrich["Dashboard live parser — per rebuild cycle"]
    classify["classify() —<br/>extract fingerprint + fingerKind<br/>per event"]
    viaMap["portbridge via-map join —<br/>recover real attacker IP,<br/>p0f OS as fallback fingerprint<br/>when no HASSH/JA3/UA"]
    localGeo["dashboard/geoip.go —<br/>local MMDB lookup on the<br/>real (post-join) IP"]
    classify --> viaMap --> localGeo
  end

  cowrieKex --> classify
  cowrieBanner --> classify
  suricataTLS --> classify
  httpUA --> classify
  connlog --> viaMap
  connlog -->|"Filebeat tails live file only"| esPipeline
  geoMMDB --> esEnrich
  geoMMDB --> localGeo

  subgraph correlate["On-demand correlation (drill-in only)"]
    direction LR
    ipCorr["IP / CIDR correlation<br/>ip_correlation.go"]
    hashCorr["Hash correlation<br/>hash_correlation.go"]
    clusterCorr["Cluster correlation<br/>intelligence.go"]
  end

  analyst(["Analyst drills into<br/>an IP, CIDR, hash, or cluster"])
  analyst -.->|"bounded ES query,<br/>independent of the live view above"| ipCorr
  esGeo -.-> ipCorr
  analyst -.-> hashCorr
  analyst -.-> clusterCorr
  classify -.->|"fingerprint value"| clusterCorr
  ipCorr -.->|"shared fingerprint / payload /<br/>ASN / provider-class"| clusterCorr
  hashCorr -.->|"Ghidra + sandbox + GitHub-analysis<br/>results, plus ES sightings"| payloadsPage["/payloads,<br/>workbench banner"]
  ipCorr --> ipPage["/investigate/ip/*,<br/>/investigate/cidr/*"]
  clusterCorr --> clusterPage["/clusters,<br/>/investigate/cluster/*"]
```

**p0f runs on the VPS, not at home, and only an OS guess survives.** It has
to run there: `portbridge` terminates every TCP connection and re-establishes
its own toward the sensor, so a p0f instance running at home would only ever
fingerprint portbridge's own outbound connections, never the attacker's.
Suricata and p0f both open raw sockets on the VPS's public interface and the
kernel copies packets to each independently. p0f runs in **API mode** — there
is no p0f log file anywhere — and `portbridge` queries its Unix socket once
per connection with a 300ms timeout. The full p0f response carries uptime,
NAT detection, link type, and distance in hops, but `portbridge` keeps only
the OS name/flavor string (e.g. `"Linux 3.11 and newer"`) and discards the
rest; a failed or inconclusive query is silently an empty string, never an
error that could block the connection. That OS guess becomes the `"os"`
field of the portbridge connection-log record traveling home over SSHFS —
the only place p0f data exists once it leaves the VPS.

**Protocol fingerprints are read, not computed, by this stack.** HASSH (an
MD5 of the SSH client's offered key-exchange/encryption/MAC/compression
algorithms, in order) is computed by Cowrie itself from the `cowrie.client.kex`
event and just read into `ev.fingerprint`; the SSH client version banner
(`cowrie.client.version`, e.g. `SSH-2.0-OpenSSH_7.9`) is a second, independent
SSH-side signal. JA3/JA4 (hashes of a TLS ClientHello's version, cipher list,
extensions, and curves) come from Suricata's `eve.json` `tls.ja3`/`tls.ja4`
fields, or from `x-ja3`/`x-ja4` HTTP headers where an upstream proxy already
computed them. All four fingerprint kinds — HASSH, SSH client banner, JA3/JA4,
and HTTP User-Agent — are normalized into the same `(fingerprint, fingerKind)`
pair by the dashboard's `classify()`, which is what lets cluster correlation
group "these 6 source IPs all presented the identical HASSH" the same way it
groups shared payload hashes or shared ASNs. p0f's OS string is deliberately
a **fallback fingerprint**, used only when a connection produced none of the
above (a scanner that never completes a real protocol handshake still gets a
fingerprint-shaped signal to correlate on).

**GeoIP runs twice, independently, against the same MMDB files** — not one
feeding the other. The Elasticsearch `geoip-honeypot` ingest pipeline enriches
every document across all three index templates (`honeypot-*`, `suricata-*`,
`portbridge-*`) as it's indexed, writing ECS `source.geo`/`source.as`/
`destination.geo`; this is what backs Kibana's maps. The dashboard's live
parser does its own local lookup (`dashboard/geoip.go`, no external API —
the home server has no egress) against the same `GeoLite2-City`/`GeoLite2-ASN`
MMDBs, plus a locally-refreshed threat-CIDR list for provider/scanner
classification. The dashboard's lookup happens **after** the portbridge
real-IP join, so it enriches the actual attacker address, never the tunnel
peer.

**Correlation is three separate, purpose-built queries, not one engine:**

- **IP/CIDR correlation** (`dashboard/ip_correlation.go`) answers "what else
  has this address (or CIDR) done": one bounded Elasticsearch query
  (≤200-500 records) across `honeypot-*`, `suricata-*`, and `portbridge-*`
  on drill-in, summarized into a sensor breakdown, tunnel-OS guesses, and a
  record list. Never run for list-page rows — only `/investigate/ip/{ip}`
  and `/investigate/cidr/{cidr}`.
- **Hash correlation** (`dashboard/hash_correlation.go`) answers "is this
  payload already known": checks Ghidra results, sandbox results, GitHub
  code-search results, and an Elasticsearch sighting count, all keyed by
  SHA-256 — plus MD5 as a second identifier, because Dionaea's own on-disk
  naming is MD5, not SHA-256, and a SHA-256-only search would silently miss
  every Dionaea capture. Purely advisory: surfaced as a "known elsewhere"
  card on `/payloads` and the workbench, never blocks a submission.
- **Cluster correlation** (`dashboard/intelligence.go`) answers "what
  connects these attacks": groups source IPs that share one of four
  attribute kinds — fingerprint (HASSH/JA3/JA4/UA/p0f-OS), payload hash,
  ASN, or threat-intel provider class — keeping only groups with 2 or more
  distinct source IPs. `/clusters` lists them; drilling into one re-runs IP
  correlation across every member IP, deliberately unfiltered by the list
  view's date/sensor bounds.

None of this claims attacker identity. A shared HASSH means two connections
used the same SSH client software, not the same operator; a shared ASN means
the same network, not the same actor. Correlation output is meant to compress
investigation effort, not to be the verdict itself — see "Analysis result
interpretation" below for how this stack keeps that distinction explicit
throughout.

## Captured payload lifecycle and static analysis

```mermaid
flowchart TB
  attacker["Attacker upload, download,<br/>or inline script"]
  cowrie["Cowrie transfers"]
  dionaea["Dionaea binaries"]
  dashboardCapture["Dashboard inline-script capture"]
  cowrieStore[("logs/cowrie/downloads")]
  dionaeaStore[("dionaea-lib/binaries")]
  scriptStore[("dashboard-state/script-payloads")]
  dedupe["payload-dedupe<br/>SHA-256 + same-filesystem hard links"]
  yara["YARA sidecar<br/>networkless, read-only, non-executing"]
  yaraOut[("yara-results/results.json")]
  invIndex[("Elasticsearch<br/>dashboard-payload-inventory-v1")]
  inventory["Dashboard payload inventory<br/>hash merge + source labels<br/>(read from ES, no local fallback -- #483)"]
  staticCache[("Elasticsearch<br/>dashboard-static-analysis-v1<br/>content-hash keyed, immutable")]
  staticRules["Built-in static classification<br/>MIME, type, platform, strings,<br/>entropy and deterministic rules"]
  analyst["Authenticated analyst"]
  workbench["Payload workbench —<br/>/payload-workbench/{sha256}<br/>up to 5 analyzers per run,<br/>fixed 7-analyzer registry"]

  attacker --> cowrie
  attacker --> dionaea
  attacker --> dashboardCapture
  cowrie --> cowrieStore
  dionaea --> dionaeaStore
  dashboardCapture -->|"SHA-256-named inert artifact"| scriptStore

  cowrieStore --> dedupe
  dionaeaStore --> dedupe
  scriptStore --> dedupe

  cowrieStore --> yara
  dionaeaStore --> yara
  scriptStore --> yara
  yara --> yaraOut

  cowrieStore -->|"periodic scan"| invIndex
  dionaeaStore -->|"periodic scan"| invIndex
  scriptStore -->|"periodic scan"| invIndex
  yaraOut --> invIndex
  invIndex --> inventory
  inventory --> staticRules
  staticRules -.->|"cache get/put,<br/>content-hash keyed"| staticCache
  staticRules --> analyst
  analyst -->|"optional explicit action"| workbench
  workbench -.->|"hash-only .request marker per<br/>selected analyzer, same spool<br/>pattern every native route uses"| analyst
```

Captured samples are content, never configuration. Cowrie stores uploaded and
downloaded files, Dionaea stores malware captures, and the dashboard turns
recognized inline scripts into inert SHA-256-named artifacts. The dashboard's
own periodic disk scan walks all configured stores, accepts only hash-shaped
regular filenames, and indexes identical hashes into one inventory document
per hash in Elasticsearch (`dashboard-payload-inventory-v1`) while retaining
every source label — every dashboard instance's own scan feeds the same
index, so mount-path differences between instances don't affect what any
instance serves. `/payloads` itself reads only from that index, never
directly from the disk scan (#483) — Elasticsearch unreachable means the page
reports unavailable, not a stale or partial local view.

`payload-dedupe` hashes payloads and replaces duplicate files on the same
filesystem with hard links. It preserves all existing paths and does not merge
across devices. The YARA container has read-only payload mounts, no network,
and no execution path; it writes a bounded JSON result file that the dashboard
joins by hash. Static dashboard analysis adds file classification, platform and
execution-policy hints, strings/IOC observations, deterministic rules, and
YARA matches, cached in Elasticsearch (`dashboard-static-analysis-v1`) keyed
by content hash — content-addressed and immutable, so a cache hit never needs
invalidating, only a get-or-create write on first computation. These are
triage signals, not proof of behavior or attribution.

**The analyst's dispatch point is the payload workbench, not two standalone
"sandbox request"/"Ghidra request" buttons.** `/payload-workbench/{sha256}`
selects up to 5 analyzers per run from a fixed, server-computed registry of
7: deterministic local analysis, Ghidra, the Linux sandbox, the isolated
Windows sandbox, the WAN-permitted Windows/GHOSTS sandbox, Rev·Deck, and
CAPE — see [`docs/payload-analysis-workbench.md`](payload-analysis-workbench.md)
for the full registry table, orchestration sequence, and idempotency model.
Every analyzer still resolves to the same hash-only `.request` marker
handoff — no sample bytes, path, or command ever crosses — a Ghidra request
in particular runs unconditionally on anything with code in it, including
the PE DLLs and documents the sandbox routes correctly refuse to detonate.
The host-owned Ghidra worker drains its request spool, talks to a headless
Ghidra REST service and a local-only fuzzy-hashing/structural-parsing
sidecar (`analysis/ghidra/statictools/`), and optionally an on-host
language model for a first-pass triage opinion — never a hosted one, and
never given anything but what Ghidra already extracted. See
[`analysis/ghidra/README.md`](analysis/ghidra/README.md) for the full Ghidra
pipeline, and ["Sandbox submission, detonation, and result return"](#sandbox-submission-detonation-and-result-return)
below for the dynamic-detonation routes.

## Sandbox submission, detonation, and result return

```mermaid
sequenceDiagram
  autonumber
  actor Analyst
  participant Auth as Traefik + auth-backend
  participant Dashboard as hp-dashboard
  participant WebSpool as requests/pending
  participant Handoff as root web-request service
  participant Submit as honeypot-sandbox-submit
  participant Queue as root inbox queue
  participant Worker as root sandbox worker
  participant Libvirt as libvirt/KVM
  participant Guest as disposable Linux guest
  participant Export as bounded offline exporter
  participant Result as read-only export directory

  Analyst->>Auth: POST /sandbox/submit with captured hash
  Auth->>Dashboard: trusted user/role headers
  Dashboard->>Dashboard: require admin, same origin, valid hash, existing capture
  Dashboard->>WebSpool: create empty hash.request with O_EXCL
  Note over Dashboard,WebSpool: No sample bytes, path, command, XML, or VM controls cross this boundary

  WebSpool-->>Handoff: systemd path unit notices request
  Handoff->>Submit: pass validated hash only
  Submit->>Submit: resolve hash inside approved capture roots
  Submit->>Submit: recompute SHA-256 and deduplicate prior/queued work
  Submit->>Queue: root-owned sample copy + typed JSON job
  Handoff->>WebSpool: remove request or move it to rejected with error

  Queue-->>Worker: systemd path/explicit start drains queue
  Worker->>Queue: atomically move queued job to running
  Worker->>Libvirt: create fresh qcow2 overlay from read-only base
  Worker->>Libvirt: inject sample and fixed guest runner offline
  Worker->>Libvirt: attach isolated filtered network and start host PCAP
  Libvirt->>Guest: boot transient VM
  Guest->>Guest: classify, collect baseline, and extract static metadata
  Guest->>Guest: bounded execution under unprivileged user + strace
  Guest->>Guest: collect process, socket, file, DNS, PCAP, stdout/stderr evidence
  Guest-->>Libvirt: power off
  Worker->>Libvirt: force stop and undefine if needed, then delete overlay

  Worker->>Export: parse powered-off guest output
  Export->>Export: bound text/files and summarize syscalls, diffs, network, and ATT&CK evidence
  Export->>Result: sanitized JSON + diagnostics + bounded host/guest PCAP
  Worker->>Queue: mark completed or failed and update status.json
  Dashboard->>Result: read-only status and result files
  Analyst->>Dashboard: view report or admin-download PDF/PCAP/diagnostics
```

The submission endpoint accepts only `POST`, requires the configured admin
role, verifies a same-origin browser request, validates the hash, and confirms
that the captured payload exists. It creates an empty request file with
exclusive-create semantics, making double submission idempotent at the
dashboard boundary.

The host's root-owned handoff service accepts only filenames matching the hash
contract. `honeypot-sandbox-submit` searches fixed Cowrie, Dionaea, and inline
script roots, recomputes SHA-256, copies the selected sample into a root-only
staging area, and creates a typed queue record. Neither attacker input nor the
dashboard can supply an arbitrary host path, command line, libvirt definition,
or result location.

For each job, the worker creates a fresh qcow2 overlay backed by the prepared
Ubuntu base, injects a fixed runner and sample while the guest is offline, and
boots a transient VM on the `honeypot-sandbox` libvirt network. A strict
libvirt network filter is applied. The normal mode is isolated; the optional
controlled-egress mode uses the separately installed DNS and allowlist proxy
described in [`sandbox/README.md`](sandbox/README.md). Host `tcpdump`
captures traffic for the job without granting packet-capture privileges to
the guest.

Inside the guest, the runner records before/after processes, sockets, and
filesystem state; classifies the payload; extracts static metadata and PE
forensics where relevant; and runs supported Linux/script payloads for a
bounded time as an unprivileged user under `no-new-privs` and `strace`. The
configured Windows compatibility policy is either static-only or bounded Wine
execution inside this Linux guest. It is not the future native Windows 11
sandbox design.

After shutdown—or a forced deadline—the host destroys the transient domain and
overlay before exporting results. The offline exporter treats every guest file
as untrusted, applies size/line/count limits, summarizes host and guest PCAP,
DNS queries, network syscalls, process/socket/file differences, PE imports,
ATT&CK evidence, run status, timeout reason, and a heuristic risk score. It
publishes only bounded artifacts to the dashboard's read-only export mount.
Raw result trees, oversized captures, samples, libvirt, systemd, and the
worker's queue remain unavailable to the dashboard container.

## Analysis result interpretation

The stack deliberately keeps observation types separate:

- **Static evidence** says what bytes, structure, strings, imports, or YARA
  signatures are present. It does not prove execution.
- **Dynamic evidence** says what the bounded guest run observed: syscalls,
  created/changed files, process/socket differences, DNS, and packets.
- **Network IDS evidence** says what Suricata matched on public traffic.
- **Full-packet evidence** preserves the traffic Arkime can reconstruct.
- **Correlation evidence** links shared infrastructure, credentials, payload
  hashes, sessions, fingerprints, and timing without claiming actor identity.
- **Failure/timeout evidence** is not a clean verdict. `guest-no-result`,
  `host-timeout`, unsupported/static-only execution, and incomplete PCAP must
  remain visibly distinct from "no malicious behavior observed."

The dashboard-generated risk score and ATT&CK mappings are conservative triage
aids. They remain linked to their underlying evidence and must not trigger
automatic firewall changes, public reporting, or sample execution.
