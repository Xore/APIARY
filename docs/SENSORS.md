# Sensors

[← back to README](../README.md)

| Sensor | Ports | Exposed via | Notes |
|---|---|---|---|
| **cowrie** | SSH 22, Telnet 23 | raw tunnel | seeded NexusAI Ubuntu GPU node ([cowrie/README-fs.md](../cowrie/README-fs.md)) |
| **multipot** | SMTP 25, Postgres 5432, VNC 5900, Redis 6379, ES 9200, Docker 2375, POP3 110, IMAP 143, SOCKS5 1080, HL7/MLLP 2575, ADB 5555 | raw tunnel | light Go multi-protocol sensor — dashboard reads its events from Elasticsearch, not its log file (#403) |
| **dionaea** | FTP 21, TFTP 69/udp, MSRPC 135, SMB 445, MSSQL 1433, PPTP 1723, MQTT 1883, UPnP 1900/udp, MySQL 3306, SIP 5060 tcp/udp, printer 9100, Memcached 11211, Mongo 27017 | raw tunnel | broad legacy/IoT attack surface + **malware capture** |
| **conpot** | S7 102, Modbus 502, SNMP 161/udp, BACnet 47808/udp, IPMI 623/udp, ENIP 44818 | raw tunnel | **ICS/SCADA** (Siemens S7-200) |
| **conpot-s7-1200** | S7 1102, Modbus 1502 | raw tunnel | S7-1215C water-treatment persona |
| **conpot-s7-1500** | S7 2102, Modbus 2502 | raw tunnel | S7-1516 chemical-process persona |
| **conpot-iec104** | IEC-104 2404 | raw tunnel | S7-300 substation / IEC-60870-5-104 |
| **conpot-guardian** | Guardian AST 10001 | raw tunnel | fuel and tank-monitor attack surface |
| **conpot-kamstrup** | Kamstrup 1025, 50100 | raw tunnel | smart-meter data and management protocols |
| **dnp3** | DNP3 20000 | raw tunnel | ElbeGrid substation RTU -- decodes the link-layer function code plus, when the frame carries a transport+application-layer segment, the application-layer function code too (READ/WRITE/SELECT/OPERATE/DIRECT_OPERATE/etc., #610); the full frame is always captured as `frame_hex` regardless |
| **dicompot** | DICOM 11112 | raw tunnel + PROXY | vendored `nsmfoo/dicompot` medical-imaging decoy (C-ECHO/C-FIND/C-MOVE/C-GET/C-STORE) — ES-only from day one (#238, #413) |
| **dns-honeypot** | DNS 53/udp | raw tunnel | from-scratch UDP reflection bait, response capped in code to at most 1.5x request size — never contacts a real resolver, so it cannot be abused as a DDoS amplification vector — ES-only from day one (#238, #415) |
| **citrix-honeypot** | raw 4443 (→ container 443) | raw tunnel + PROXY | Citrix ADC/NetScaler Gateway decoy (CVE-2019-19781 path traversal), Go port of `t3chn0m4g3/CitrixHoneypot`, own self-signed TLS — ES-only from day one (#238, #414) |
| **cisco-asa-honeypot** | WebVPN 8443, IKE 500/udp | raw tunnel + PROXY (8443) | Cisco ASA WebVPN + IKE decoy (CVE-2018-0101), Go port of `t3chn0m4g3/ciscoasa_honeypot` — the IKE side replies once per source with a real Diffie-Hellman/nonce exchange then goes silent, matching upstream's actual (not fully protocol-correct) behavior exactly — ES-only from day one (#238, #414) |
| **rdp-honeypot** | RDP 3389 | raw tunnel + PROXY | RDP decoy, Go port of `CommunityHoneyNetwork/rdphoney` — reads the initial X.224 Connection Request, captures the `mstshash=` cookie username if present and the client's requested security protocols (plain RDP / TLS / CredSSP / RDSTLS / CredSSP-EarlyUserAuth) from the trailing `RDP_NEG_REQ` structure — ES-only from day one (#238, #412) |
| **http-honeypot** | `decoy.<domain>` (+ catch-all, + raw :8081) | Traefik | fake nginx / login pages — unrecognized scan/rce-probe paths get a HellPot-style Markov-garbage tarpit instead of a fast reply by default (`HTTP_TARPIT=0` to disable, #246) |
| **api-honeypot** | raw 8888 | raw tunnel + PROXY | cloud metadata, Kubernetes, registry, DevOps and LLM API probes — same binary as http-honeypot, same tarpit behavior |
| **snare + tanner** | `www-portal.<domain>` | Traefik | fictional Meridian portal → payload analysis |
| **endlessh** | SSH 2222 (own port, not cowrie's) | raw tunnel + PROXY (once wired) | SSH pre-auth tarpit, Go port of `skeeto/endlessh`'s core trick — sends random non-"SSH-" banner lines forever, real handshake never begins. Own port deliberately, not cowrie's: diverting an attacker here instead of cowrie's real fake-shell capture would trade depth for a cheap time-waste (#246) |
| **beelzebub** | SSH 2200 (2nd, LLM-capable listener, static-only here), LDAP 389, MCP 8000, HTTP 8880 | raw tunnel | vendored `beelzebub-labs/beelzebub` deception runtime (#1418) -- LDAP/MCP fill real protocol gaps, SSH is a second differently-fingerprinted listener alongside Cowrie, HTTP is a WordPress decoy; no Ollama wiring (would cross the `honeypot-llm` network's sensors-never-reach-the-model boundary, see docker-compose.beelzebub.yml) and no Traefik hostname (beelzebub can't parse PROXY protocol or read X-Forwarded-For, so a hostname-fronted copy would have an unattributable source IP) -- ES-only from day one |
| **hellpot** | HTTP 8080 | raw tunnel | vendored `yunginnanet/HellPot` bot tarpit (#1419) -- streams endless Markov-chain garbage to any request, punishing scanners/scrapers rather than just logging them; no Traefik hostname (upstream's own X-Real-IP trust is unconditional and client-spoofable -- confirmed live -- so `hellpot/router_patch.py` removes it and this stack resolves the real IP via `ip-enrichment-worker`'s via_port join instead, same as beelzebub) -- ES-only from day one |
| **suricata** | (sniffs all traffic, runs on the **VPS**) | — | IDS over every honeypot packet → eve.json → ELK, pcap → Arkime |

multipot cedes FTP/MySQL/MSSQL/Mongo to Dionaea automatically
(`MULTIPOT_DISABLE`), so ports never clash.

Dionaea enables `log_json`, `log_incident`, and `store` at startup. Connection
summaries go to `logs/dionaea/dionaea.json`, complete incident records go to
`logs/dionaea/dionaea_incident.json`, and captured payloads are stored by hash
in the persistent `dionaea-lib` volume for the dashboard's `/payloads` page.
Cowrie's hash-addressed upload/download directory is persisted under
`logs/cowrie/downloads`, so script payloads (shell, PowerShell, VBS, Python,
JavaScript, PHP, Perl, and arbitrary binaries) survive container recreation.
Inline script commands are additionally retained as inert SHA-256 artifacts in
the dashboard state volume. The dashboard `/payloads` page inventories all
three stores recursively, identifies each contributing source, and offers
per-source filters while deduplicating identical hash-addressed artifacts.
Captured content is never executed.
The `payload-dedupe` service scans these stores hourly and atomically replaces
same-filesystem duplicates with hard links. Existing event/download URLs remain
valid while duplicate disk blocks are reclaimed; its last-run report is stored
at `state/dedupe/payload-dedupe.json`.
Its diagnostic logger is limited to `info,warning,error` so debug chatter cannot
consume the data disk. The `log-maintenance` sidecar copy-truncates and gzips
human-readable Dionaea, Conpot, and Cowrie logs at 256 MiB (four archives).
Structured JSON event streams are deliberately never rotated by that sidecar,
which preserves Filebeat offsets and dashboard ingestion.
Because RFC 1350 TFTP switches to a dynamic transfer-ID port, the internal
`tftp-relay` keeps public UDP 69 stable while forwarding that exchange to
Dionaea inside `honeynet`; it is infrastructure and is not shown as a sensor.

Filebeat writes sensor events to versioned `honeypot-v2-*` data streams. The
`elasticsearch-setup` one-shot maps each original `honeypot` object as
`flattened`, so heterogeneous Dionaea/Conpot/Cowrie fields cannot reject one
another due to type conflicts. Non-indexable events also fall back to
`dead-letter-honeypot` instead of being silently discarded.
GeoIP enrichment is best-effort: empty or malformed addresses are skipped, but
the original event is always retained.
ILM keeps raw Suricata indices for 7 days, honeypot data streams for 30 days,
and dead-letter records for 60 days so high-volume scans cannot fill the disk.

## Runtime resource budgets

Every service has a CPU, memory, and Docker `json-file` log budget. The
limits are intentionally generous relative to the host (16 logical CPUs and
91 GiB RAM): Elasticsearch gets 8 GiB with a 4 GiB heap; Arkime capture 6 GiB;
Kibana, Filebeat, and the TANNER analyzer receive 2 GiB; EveBox, Dionaea, Arkime
viewer, and the live dashboard receive 1 GiB (the dashboard also has one CPU). The
remaining lightweight sensors receive 128-512 MiB. Docker console logs rotate
at 25 MiB with three files, independently from sensor event files under
`./logs`.

## HTTPS investigation UIs (each its own subdomain, all Keycloak-gated)

| Dashboard | Subdomain | Container |
|---|---|---|
| Live sensor view (ours) | `honeypot.<domain>` | `dashboard` :8090 |
| Kibana (ELK + Suricata) | `kibana.<domain>` | `kibana` :5601 |
| TANNER web-attack analysis | `tanner.<domain>` | `tanner_web` :8091 |
| EveBox (Suricata events) | `evebox.<domain>` | `evebox` :5636 |
| Arkime (packet sessions) | `arkime.<domain>` | `arkime-viewer` :8005 |
| Rev·Deck (Ghidra AI chat) | `rev.<domain>` | `revdeck` :5000 (separate `analysis/ghidra/` stack, `revdeck` profile — see [analysis/ghidra/revdeck/README.md](analysis/ghidra/revdeck/README.md)) |

Each is bridged to the VPS by its own `socat-hp-*` service (one socat per
service, the reliable/consistent way) and routed by
[Traefik](../vps/traefik/) through a per-service `oauth2-proxy` gateway
(ForwardAuth middleware), all backed by the same Keycloak realm running at
home (`honeypot-keycloak`, `docker-compose.keycloak.yml`). There is no
separate "auth portal" stack or container to deploy anymore — that was the
retired `Xore/auth-backend` runtime (hard cutover, see
[KEYCLOAK-CUTOVER.md](KEYCLOAK-CUTOVER.md)); `Xore/auth-backend` now only
supplies the Keycloak login/account/email theme
(`Xore/auth-backend`'s `themes/apiary`), not a running service. To stand
this up: deploy the Keycloak stack (`docker-compose.keycloak.yml`, Dockge-managed,
see [KEYCLOAK-OPERATIONS.md](KEYCLOAK-OPERATIONS.md)), configure each
investigation UI's `oauth2-proxy` client in `vps/docker-compose.yml`, then
point proxied Cloudflare records at the VPS for each subdomain.

## SNARE + TANNER

SNARE serves the repository-owned fictional Meridian customer portal and feeds every request to
TANNER, which emulates the vulnerabilities attackers probe for (SQLi, LFI/RFI,
XSS, command execution, PHP code/object injection, XXE, CRLF and template
injection) and stores sessions in Redis. TANNER's emulation containers are
isolated from the homeserver Docker socket and are not a malware detonation
environment. Suspicious payload detonation belongs in the separate KVM/libvirt
sandbox described in [`sandbox/README.md`](sandbox/README.md). Containers: `tanner_redis`,
`tanner_phpox`, `tanner_api`, `tanner` (analyzer, `:8090`), `tanner_web`
(dashboard, `:8091`), `snare_clone` (one-shot deterministic persona installer),
`snare` (`:8080`). The page source lives under [snare/persona](../snare/persona)
and is transformed into SNARE's content-addressed store during the image build;
no third-party site is cloned. All `mushorg/*` images are third-party
— verify tags/args upstream (needs a live build/pull).

## Suricata — analysing all the traffic

`suricata` runs **on the VPS** (host networking, sniffing the public interface
`SURICATA_IFACE`, default `ens6`) so it sees real attacker source IPs before the
tunnel. It writes to `/opt/stacks/apiary/logs/suricata/` on the VPS:

- `eve.json` (alerts, http, dns, tls, flow) — Filebeat on the home server ships
  it to the `suricata-*` Elasticsearch index (stats events are dropped, see
  [analysis/filebeat.yml](../analysis/filebeat.yml)).
- `pcap/log.pcap.<epoch>` — full packet capture, rotated at **4mb**
  (Suricata's hard minimum; smaller values crash pcap-log) with
  `max-files: 12500` ≈ 50 GB retention. Consumed by Arkime, see below.

**BPF filter (important):** the af-packet section of
[`vps/suricata/suricata.yaml`](../vps/suricata/suricata.yaml) sets
`bpf-filter: "not udp port 51820"` to exclude the WireGuard tunnel. Without it
Suricata captures its own log-shipping traffic (sshfs reads of pcap/eve.json
ride the tunnel on the same interface) — a feedback loop that inflates
pcap-log to 100 MB every few seconds. A positional BPF arg on the suricata
command line is silently ignored; it must live in the yaml.

The home server mounts the VPS log dir read-only via sshfs/fstab. Use
`setup-home-network.sh` to select the required uplink and
`setup-suricata-logs-home.sh` to install WireGuard-aware mount ordering and
retries. Rule updates: `suricata-update` runs as a one-shot container before
each suricata start.

## Arkime — full packet capture search

Arkime capture **cannot watch the sshfs mount directly**: its `--monitor` uses
kernel inotify, and inotify never fires for writes done on another machine.
The `pcap-sync` sidecar bridges that: every 30 s it copies **closed** pcap
files (skipping the newest, still being written by Suricata) from the sshfs
mount to the local `logs/arkime-raw/`, where inotify works and
`arkime-capture -R file:///opt/arkime/raw --monitor --skip` imports each file
seconds after it lands. It deliberately uses plain `cp` to the final name —
Arkime reacts to `IN_CLOSE_WRITE` only, so a rename would be invisible.

End-to-end latency is one Suricata rotation (~1–5 min depending on traffic)
plus a few seconds. A pcap file only becomes visible to Arkime once Suricata
*closes* it — there is no time-based rotation in Suricata 7, so quiet periods
mean longer latency. Local copies are pruned after 50 days (~50 GB, matching
the VPS ring); the viewer serves packet payloads from these files.

Web UI: `http://<HP_BIND>:19080` (`arkime.<domain>` via Traefik).

> **Source IPs & the tunnel.** socat/portbridge terminate the attacker's TCP
> connection on the VPS and re-dial over WireGuard, so without help the sensors
> would see the **VPS WireGuard IP** (`10.8.0.1`) as the source. This stack
> recovers the real attacker IP three ways:
>
> - **PROXY protocol.** portbridge rules tagged `:pp` prepend a HAProxy PROXY v1
>   header carrying the real client address. **multipot** and the
>   **http/api-honeypots** (`PROXY_PROTOCOL=1`), **dnp3** (`PROXY_PROTOCOL=1`),
>   **dicompot** (`PROXY_PROTOCOL=1`), **citrix-honeypot**,
>   **cisco-asa-honeypot**'s WebVPN side and **rdp-honeypot** (`PROXY_PROTOCOL=1`) and **all conpot sensors** (`CONPOT_PROXY_PROTOCOL=1`, gevent shim baked in
>   by `conpot/proxy_patch.py`) parse it, so those events log the true IP and
>   port. The http listener sniffs the header, so Traefik-routed requests (no
>   header) keep working too.
> - **X-Forwarded-For.** Traefik-routed **HTTP** requests arrive from the tunnel
>   peer with Traefik's XFF; the http-honeypot trusts XFF only from that peer.
> - **portbridge connection log.** For sensors that can't parse PROXY
>   (**cowrie** — Twisted's `haproxy:` endpoint parses but does not apply the
>   address — and **dionaea**), and for **every UDP port**, where PROXY protocol
>   has no meaning at all, portbridge's `CONN_LOG` records the real IP per
>   connection along with the upstream source port it will arrive on; ship that
>   dir to the home stack (same mount pattern as Suricata, but **without
>   `x-systemd.automount`** — autofs triggers return EPERM to container
>   processes) and the dashboard joins it by source port. The join reaches back
>   one log rotation; connections older than that are reported as
>   **Unattributed** on `/source-health` rather than blamed on the tunnel peer.
>
> Suricata already sees real IPs (it sniffs the public interface on the VPS).
> Net result: the live dashboard can pivot on a single attacker IP across every
> sensor. Running the whole stack **on the VPS** (`HP_BIND=0.0.0.0`, skip the
> tunnel) remains an option if you'd rather avoid PROXY protocol entirely.
