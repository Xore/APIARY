# IP Blocklist Reporting Plan

Automatically report attacker IPs observed by the honeypot stack to public threat-intel blocklists via their APIs.

---

## Goals

- Report every IP that touches a honeypot sensor to one or more blocklist feeds
- Deduplicate: never report the same IP twice within a cooldown window
- Respect rate limits of each upstream API
- Run as a lightweight sidecar container (`reporter`) already wired into the existing `docker-compose.yml` event bus
- No manual intervention after initial key setup in `.env`

---

## Target Blocklist APIs

| Service | API | Free tier | Best for |
|---|---|---|---|
| **AbuseIPDB** | `POST /api/v2/reports` | 1 000 reports/day | General abuse, SSH, HTTP scans |
| **Blocklist.de** | `POST https://api.blocklist.de/api` | Unlimited | Traditional fail2ban-style reporting |
| **GreyNoise RIOT** | Read-only free tier | — | Cross-check before reporting (avoid FP) |

Primary target: **AbuseIPDB** — widely used, has a public confidence score, and feeds back into many firewall blocklists automatically.

---

## Architecture

```
Cowrie / Dionaea / Conpot / HTTP-honeypot / DNP3
        │  (JSON events → shared Docker volume / Redis pub-sub)
        ▼
  ┌─────────────┐
  │  reporter   │  new Docker Compose service
  │  (Python)   │
  └──────┬──────┘
         │  POST /api/v2/reports
         ▼
     AbuseIPDB
         │  (optional)
         ▼
    Blocklist.de
```

The `reporter` container:
- Watches the same log/event volume already mounted by the `analysis` and `ml-worker` containers
- Maintains a local SQLite DB (`/data/reported.db`) to deduplicate IPs per service per 24 h
- Exposes a `/metrics` endpoint (Prometheus) so Grafana can graph reports-per-hour

---

## Log Sources per Sensor

| Sensor | Log path (inside container) | Event format |
|---|---|---|
| cowrie | `/cowrie/var/log/cowrie/cowrie.json` | JSON lines |
| dionaea | `/opt/dionaea/var/log/dionaea/` | JSON / SQLite |
| conpot | `/var/log/conpot/` | JSON lines |
| http-honeypot | stdout JSON | JSON lines |
| dnp3-honeypot | stdout JSON | JSON lines |
| snare/tanner | tanner REST API | JSON |

All sensors already write structured JSON. The reporter will tail these files (or consume Redis events if the stack is extended to pub-sub).

---

## AbuseIPDB Report Categories

Map honeypot events to [AbuseIPDB category codes](https://www.abuseipdb.com/categories):

| Honeypot event | Category codes |
|---|---|
| SSH brute-force (cowrie) | `18` (Brute-Force), `22` (SSH) |
| Telnet login attempt (cowrie) | `18`, `23` (IoT Targeted) |
| HTTP scan / exploit attempt | `21` (Web App Attack) |
| Port scan (multipot/conpot) | `14` (Port Scan) |
| Malware download (dionaea) | `20` (Malware) |
| ICS/SCADA probe (conpot/dnp3) | `14`, `15` (Hacking) |
| DNS abuse | `11` (DNS Compromise) |

---

## Implementation Plan

### Phase 1 — Reporter Container (week 1)

1. Create `reporter/` directory with:
   - `reporter.py` — main event loop
   - `Dockerfile` — slim Python 3.12 image
   - `requirements.txt` — `requests`, `watchdog`, `prometheus-client`
2. Logic:
   ```python
   # Pseudocode
   for event in tail_logs(SENSOR_PATHS):
       ip = event["src_ip"]
       if not recently_reported(ip, service="abuseipdb", window_hours=24):
           categories = map_to_categories(event["type"])
           abuseipdb_report(ip, categories, comment=build_comment(event))
           mark_reported(ip, "abuseipdb")
   ```
3. SQLite schema:
   ```sql
   CREATE TABLE reports (
     ip TEXT NOT NULL,
     service TEXT NOT NULL,
     reported_at INTEGER NOT NULL,  -- Unix timestamp
     event_type TEXT,
     PRIMARY KEY (ip, service, reported_at / 86400)  -- 1 report per IP per day
   );
   ```

### Phase 2 — Blocklist.de Integration (week 2)

- Add secondary reporter for Blocklist.de using the same dedup logic
- Blocklist.de uses a simple HTTP POST with `server`, `ip`, `logs` fields
- Useful for SSH/FTP/SIP — feeds European ISP blocklists

### Phase 3 — Pre-report Validation (week 3)

Before reporting, cross-check against:
- **GreyNoise RIOT** (`GET /v3/riot/{ip}`) — skip known benign scanners (Shodan, Censys, security researchers)
- Local whitelist file `reporter/whitelist.txt` — your own IPs, Tor exits you want to skip
- RFC 1918 / loopback / link-local guard (never report private IPs)

### Phase 4 — Observability (week 4)

- Prometheus metrics from `reporter`:
  - `honeypot_reports_total{service, category}` counter
  - `honeypot_report_errors_total{service, error}` counter
  - `honeypot_dedup_skips_total` counter
- Add Grafana panel to existing dashboard: "Reports sent this week" bar chart
- Alert webhook (existing `HONEYPOT_ALERT_WEBHOOK_URL`) if AbuseIPDB rate limit is approaching

---

## Docker Compose Addition

Add to `docker-compose.yml`:

```yaml
  reporter:
    build: ./reporter
    restart: unless-stopped
    environment:
      ABUSEIPDB_API_KEY: ${ABUSEIPDB_API_KEY}
      BLOCKLIST_DE_EMAIL: ${BLOCKLIST_DE_EMAIL}
      BLOCKLIST_DE_PASSWORD: ${BLOCKLIST_DE_PASSWORD}
      GREYNOISE_API_KEY: ${GREYNOISE_API_KEY:-}   # optional
      REPORTER_COOLDOWN_HOURS: ${REPORTER_COOLDOWN_HOURS:-24}
      REPORTER_WHITELIST: /config/whitelist.txt
    volumes:
      - cowrie_logs:/logs/cowrie:ro
      - dionaea_logs:/logs/dionaea:ro
      - conpot_logs:/logs/conpot:ro
      - reporter_data:/data
      - ./reporter/whitelist.txt:/config/whitelist.txt:ro
    ports:
      - "127.0.0.1:9101:9101"   # Prometheus metrics
    networks:
      - honeypot_internal
```

Add to `.env.example`:

```dotenv
# IP Blocklist Reporting
ABUSEIPDB_API_KEY=
BLOCKLIST_DE_EMAIL=
BLOCKLIST_DE_PASSWORD=
GREYNOISE_API_KEY=
REPORTER_COOLDOWN_HOURS=24
```

---

## Rate Limits & Throttling

| Service | Limit | Mitigation |
|---|---|---|
| AbuseIPDB free | 1 000 reports/day | Dedup per 24 h; batch high-volume periods |
| AbuseIPDB paid | 10 000/day | Upgrade if volume exceeds free tier |
| Blocklist.de | No hard limit; fair use | 1 report per IP per 24 h |
| GreyNoise free | 1 000 lookups/day | Cache RIOT lookups for 6 h in SQLite |

The reporter will track a daily counter and pause with exponential back-off on `429` responses.

---

## False Positive Mitigation

- **GreyNoise RIOT check**: if `riot=true` → skip (known benign scanner)
- **Minimum event threshold**: only report after ≥ 3 events from same IP within 10 min (configurable)
- **Whitelist**: `reporter/whitelist.txt` — CIDR and single IP entries, one per line
- **ASN filter**: optionally skip reports for IPs belonging to major cloud providers unless event severity is high

---

## Files To Create

```
reporter/
├── Dockerfile
├── requirements.txt
├── reporter.py          # main loop
├── sources.py           # per-sensor log parsers
├── apis.py              # AbuseIPDB + Blocklist.de clients
├── dedup.py             # SQLite-backed deduplication
├── whitelist.txt        # safe IPs/CIDRs to never report
└── metrics.py           # Prometheus exporter
docs/
└── ip-reporting-plan.md # this file
```

---

## Open Questions

- [ ] Should `reporter` consume raw log files (simple, no infra change) or a Redis pub-sub channel (lower latency, requires adding Redis to compose)? → Start with file tailing; migrate to Redis when ml-worker pubsub is implemented.
- [ ] Report Suricata IDS alerts (from Arkime capture) in addition to honeypot hits? → Yes, add in Phase 2.
- [ ] Auto-ban at firewall level (nftables/ipset) in addition to reporting? → Separate issue; keep reporter stateless and reporting-only.
