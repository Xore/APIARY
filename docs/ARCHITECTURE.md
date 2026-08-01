# System architecture and data flow

[← back to README](../README.md)

This section describes the active implementation in the root and VPS Compose
files, plus two pieces that are real but live outside them: the Ghidra static
analysis pipeline (`analysis/ghidra/`, its own Compose file plus a host
systemd worker — genuinely deployed, see "Captured payload lifecycle and
static analysis" below) and the Linux KVM sandbox (root-owned host worker
described below). `sandbox/windows/` is still a plan, not yet deployed — see
that directory's own `IMPLEMENTATION_PLAN.md` and #47 for status; until its
golden image exists, Windows samples take the static-only/Wine-in-Linux-guest
path the sandbox section below describes, not a native Windows 11 guest.
TANNER containers are web-request emulators, not malware detonation sandboxes.

## Deployment and trust boundaries

```mermaid
flowchart LR
  attacker["Untrusted internet client"]

  subgraph vps["Public VPS"]
    direction TB
    suricata["Suricata<br/>IDS + EVE + rotating PCAP"]
    traefik["Traefik<br/>TLS routing"]
    auth["Xore/auth-backend<br/>forward-auth SSO"]
    httpBridges["socat HTTP bridges<br/>dashboard, Kibana, EveBox,<br/>Arkime, TANNER, web honeypots"]
    portbridge["portbridge<br/>raw TCP/UDP forwarding<br/>optional PROXY v1"]
    connlog[("portbridge connection log")]
  end

  wg["WireGuard tunnel"]

  subgraph home["Home server / Dockge"]
    direction TB
    sensors["Honeypot sensor containers"]
    analysis["Analysis containers<br/>Dashboard, Filebeat, Elasticsearch,<br/>Kibana, EveBox, Arkime, YARA"]
    hostSandbox["Root-owned sandbox services<br/>systemd + libvirt/KVM"]
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
  wg --> sensors
  wg --> analysis
  sensors -->|"logs and captured artifacts"| analysis
  analysis -.->|"hash-only request spool"| hostSandbox
  suricata -.->|"read-only SSHFS logs over WireGuard"| analysis
```

The VPS is the only internet-facing layer. Suricata sees traffic before it
enters WireGuard, so IDS records and PCAPs retain the original network view.
Traefik handles HTTPS routes and delegates authentication for investigation
UIs to the separately deployed `Xore/auth-backend`. Raw protocols pass through
`portbridge`; targets that understand HAProxy PROXY v1 receive the original
client address in-band, while the connection log lets the dashboard recover
source attribution for PROXY-unaware sensors.

Home container ports bind to `HP_BIND` (normally the home WireGuard address),
not to every host interface. The root Compose network `honeynet` is for
container-to-container communication. TANNER additionally uses
`tanner_local`, which contains its Redis, API, PHP emulator, and disposable
nested Docker daemon. That daemon is deliberately not the homeserver Docker
socket.

## Home container interaction map

```mermaid
flowchart TB
  subgraph honeypotInit["honeypot-init — separate Compose project (#111)"]
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

  subgraph sensorGroup["Sensors on honeynet (honeypot-stack)"]
    cowrie["Cowrie"]
    multipot["multipot"]
    http["HTTP + API honeypots"]
    dionaea["Dionaea"]
    conpot["Conpot personas"]
    dnp3["DNP3"]
    tftp["TFTP relay"]
  end

  subgraph tannerGroup["TANNER application-emulation boundary"]
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
  es[("Elasticsearch")]
  maintenance["log-maintenance<br/>bounded text-log rotation"]
  filebeat["Filebeat"]
  dashboard["Live dashboard"]
  kibana["Kibana"]
  evebox["EveBox"]
  pcapSync["PCAP sync"]
  arkCapture["Arkime capture"]
  arkViewer["Arkime viewer"]

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

  logs --> dashboard
  payloads --> dashboard
  dashboardState --> dashboard
  yaraResults --> dashboard
  dashboard --> es
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

`honeypot-init` is a **separate Dockge stack**, deployed independently of
`honeypot-stack` (see [`CGNAT-DEPLOYMENT.md`](CGNAT-DEPLOYMENT.md)) — it
exists because Compose's `depends_on: condition: service_completed_successfully`
cannot reach across a project boundary. Its one-shot jobs write a `<job>.done`
marker file to a shared `state/init-markers/` directory on success; every
dependent in `honeypot-stack` polls for that file at container entrypoint
(`until [ -f /markers/<job>.done ]; do sleep 3; done`) instead of using a
Compose-level dependency. `log-init` also prepares host log paths before
sensors start, and `log-maintenance` — itself one of the marker-waiting
services, not a bootstrap job — rotates only the human-readable logs that are
safe to copy-truncate; structured streams tailed by Filebeat are preserved.
`honeypot-kibana-setup` is the one job with no dependents anywhere: nothing
waits on its marker because nothing needs to.

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
  live["Dashboard parser<br/>bounded file tails"]
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
| Dashboard live parser | recent sensor/EVE/portbridge file tails | normalized in-memory snapshot, alerts, campaigns, exports | immediate operations and cross-sensor pivots |
| Filebeat | durable JSON filestreams | versioned Elasticsearch indices/data streams | complete historical indexing with restart-safe offsets |
| Elasticsearch setup | templates and pipelines | flattened heterogeneous sensor fields, GeoIP, ILM, dead-letter fallback | mapping safety and retention |
| Kibana | Elasticsearch | saved searches, visualizations, archive investigations | long-range analysis |
| Suricata | public-interface packets | signatures, protocol events, flows, rotating PCAP | IDS and network evidence |
| EveBox | the `suricata-v2-*` indices | alert-focused UI over Elasticsearch | fast Suricata triage |
| Arkime | closed PCAP files | indexed sessions plus retained packet files | full-packet search and payload inspection |
| Dashboard correlation | normalized events and portbridge metadata | attacker profiles, sessions, clusters, campaigns, ATT&CK context | evidence-led behavioral investigation |

`pcap-sync` exists because remote SSHFS writes do not produce usable local
inotify events: it skips the newest file because Suricata may still be writing
it, then copies closed files locally so Arkime receives the `IN_CLOSE_WRITE`
event it expects.

EveBox needs no such sidecar. It queries the `suricata-v2-*` indices Filebeat
already writes, so it holds no copy of the event data and nothing to outgrow.

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
  inventory["Dashboard payload inventory<br/>hash merge + source labels"]
  staticRules["Built-in static classification<br/>MIME, type, platform, strings,<br/>entropy and deterministic rules"]
  analyst["Authenticated analyst"]
  sandboxRequest["Admin-only sandbox request"]
  ghidraRequest["Admin-only Ghidra request"]
  ghidraWorker["Host-owned worker<br/>(analysis/ghidra/worker/ghidra-worker.py)"]
  ghidraResult[("{sha256}_ghidra.json")]

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

  cowrieStore --> inventory
  dionaeaStore --> inventory
  scriptStore --> inventory
  yaraOut --> inventory
  inventory --> staticRules
  staticRules --> analyst
  analyst -->|"optional explicit action"| sandboxRequest
  analyst -->|"optional explicit action"| ghidraRequest
  ghidraRequest -.->|"hash-only .request marker,<br/>same spool pattern as the sandbox"| ghidraWorker
  ghidraWorker --> ghidraResult
  ghidraResult --> analyst
```

Captured samples are content, never configuration. Cowrie stores uploaded and
downloaded files, Dionaea stores malware captures, and the dashboard turns
recognized inline scripts into inert SHA-256-named artifacts. The dashboard
walks all configured stores, accepts only hash-shaped regular filenames, and
merges identical hashes into one inventory row while retaining every source
label.

`payload-dedupe` hashes payloads and replaces duplicate files on the same
filesystem with hard links. It preserves all existing paths and does not merge
across devices. The YARA container has read-only payload mounts, no network,
and no execution path; it writes a bounded JSON result file that the dashboard
joins by hash. Static dashboard analysis adds file classification, platform and
execution-policy hints, strings/IOC observations, deterministic rules, and
YARA matches. These are triage signals, not proof of behavior or attribution.

A Ghidra request is the same idempotent hash-only handoff as a sandbox
request — no sample bytes, path, or command crosses the dashboard/host
boundary — but it runs unconditionally on anything with code in it, including
the PE DLLs and documents the sandbox correctly refuses to detonate. The
host-owned worker drains the request spool, talks to a headless Ghidra REST
service and a local-only fuzzy-hashing/structural-parsing sidecar
(`analysis/ghidra/statictools/`), and optionally an on-host language model for
a first-pass triage opinion — never a hosted one, and never given anything but
what Ghidra already extracted. See [`../analysis/ghidra/README.md`](../analysis/ghidra/README.md)
for the full pipeline.

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
described in [`../sandbox/README.md`](../sandbox/README.md). Host `tcpdump`
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
