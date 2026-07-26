# Custom Suricata rules & tuning for the honeypot

This folder is mounted into the `suricata-update` container (as `/custom`) and
its `threshold.config` into `suricata` (as `/etc/suricata/threshold.config`).
`suricata-update` merges everything under `rules/` into the live ruleset and
applies `disable.conf`; the running Suricata reads the merged
`/var/lib/suricata/rules/suricata.rules` plus the global thresholds.

```
suricata/
├── rules/
│   ├── honeypot-ics.rules    # S7comm, Modbus and DNP3 ICS attack detection
│   ├── honeypot-web.rules    # web brute-force / default-cred / web-attack
│   └── honeypot-scan.rules   # per-service interaction + port-sweep telemetry
├── disable.conf              # noisy upstream SIDs/groups to silence
├── threshold.config          # global suppress / rate_filter / threshold
└── README.md
```

## What the rules detect

**ICS/SCADA (`honeypot-ics.rules`, SID 92010000–92039999).** Conpot answers
S7comm (102/1102/2102), Modbus (502/1502/2502), IEC-104 (2404),
Guardian AST (10001), Kamstrup (1025/50100), EtherNet/IP (44818),
BACnet (47808/udp), IPMI (623/udp), and DNP3 (20000/tcp). Because a honeypot has *no legitimate PLC clients*, every ICS
packet here is hostile — so unlike a production IDS we alert on all of it, but
split by function code so the alert names the technique:

- **S7comm** — Setup Communication, Read/Write Var, PLC **STOP**/**START**,
  program **download** (logic push) and **upload** (logic exfil), PLC password,
  set-clock, list-blocks, CPU/SZL fingerprint, **memory-erase** and **I/O
  force** programmer commands. Byte offsets (S7 header at 7, function at 17/19,
  userdata subfunction at 22) are adapted from Fischer's BSI thesis on S7comm
  attack detection.
- **Modbus** — read vs. **write** function codes (write = process manipulation),
  diagnostics (fc08 restart/listen-only), device-ID recon (fc17/fc43), plus
  write-rate flood detection.
- **DNP3** — read, write, select/operate/direct-operate, cold/warm restart, and
  application start/stop with ATT&CK for ICS tactic and technique metadata.

**Web (`honeypot-web.rules`, SID 92040000–92049999).** Fires on Suricata's HTTP
app-layer parser (any cleartext port): HTTP Basic **default creds**
(`admin:admin` etc., the base64 trick from the OT-SOC article), login/Basic
**brute force** (rate-tracked), SQLi / LFI-RFI / command-injection / Shellshock
payloads, scanner user-agents, webshell paths, and a TLS-side "no SNI" probe.

**Scan (`honeypot-scan.rules`, SID 92050000–92059999).** One clean
per-service, per-source **interaction** alert (SSH, Telnet, FTP, SMB, MSSQL,
MySQL, Redis, Docker API, …) plus Redis/Docker RCE-chain patterns and a
horizontal port-sweep detector.

## The HOME_NET gotcha (important)

Suricata runs on the **VPS public NIC**, so it sees the **real attacker IP**
before the WireGuard tunnel — unlike the home sensors, which only see the
tunnel IP. But Suricata's stock `HOME_NET` is RFC1918-only
(`192.168/16,10/8,172.16/12`), which **excludes the VPS public IP**. With that
default, nearly every inbound rule (`$EXTERNAL_NET any -> $HOME_NET …`, which is
most of ET Open *and* these honeypot rules — they match on `$HOME_NET`) never
matches. So `HOME_NET` **must** be set to the VPS public IP.

Do **not** set `HOME_NET=any`: `suricata.yaml` derives `EXTERNAL_NET` as
`!$HOME_NET`, and `!any` is a NIL address range that fails rule parsing at
startup. Set the real IP in `../.env`:

```
SURICATA_HOME_NET=203.0.113.10/32          # your VPS public IP (add ,10.8.0.0/24 for WG)
SURICATA_EXTERNAL_NET=!$SURICATA_HOME_NET
```

`/root/vps/docker-compose.yml` injects these with `--set vars.address-groups.*` at
runtime, overriding the safe `192.168.0.0/16` fallback baked into
`suricata.yaml`.

## Full-config, pcap & host-mode

`suricata.yaml` in this folder **replaces** the image's baked-in config (loaded
via `-c`). Notable settings:

- `host-mode: router` — inspects inbound *and* outbound packets on the single
  public NIC (sniffer-only would miss honeypot egress).
- `pcap-log` — full packet capture to `logs/suricata/pcap/`. **Create the dir
  first** or Suricata falls back to the log root:
  `mkdir -p /opt/stacks/honeypot-stack/logs/suricata/pcap`
- `eve-log` with `community-id`, payloads, HTTP bodies, and ICS app-layer
  events (modbus/enip/dnp3 parsers enabled) for EveBox/filebeat.
- The `threshold.config` here is wired via `threshold-file:`.

## Adding / editing rules

- Keep custom SIDs in **92000000+** (outside ET's 2xxxxxx).
- Put process-impacting ops (writes, STOP, erase, force, download) at
  `classtype:attempted-admin`; recon/reads at `attempted-recon`.
- After editing, re-run the update + restart on the VPS:

  ```bash
  cd /root/vps
  docker compose run --rm suricata-update   # re-merges rules/ + disable.conf
  docker compose restart suricata
  # or hot-reload without dropping the capture:
  docker compose kill -s USR2 suricata
  ```

## Validate before deploying

```bash
cd /root/vps
# syntax/load test against the merged ruleset, no packets captured:
docker compose run --rm --entrypoint suricata suricata -T \
  -S /var/lib/suricata/rules/suricata.rules -l /tmp

# test a single custom file in isolation:
docker run --rm -v "$PWD/rules:/r:ro" jasonish/suricata:latest \
  suricata -T -S /r/honeypot-ics.rules -l /tmp
```

## Viewing alerts

Alerts land in `eve.json` (mounted to the home server over WireGuard) and show
up in **EveBox** (`hp.<domain>` → `/evebox`) and **Kibana** (`suricata-*`
index). Filter on `alert.signature:HONEYPOT-*` to see only these custom rules,
or `alert.metadata.protocol:s7comm` for the ICS subset.

## Sources

- Fischer, *Framework zur Erkennung von Angriffen auf SPS am Beispiel des
  S7comm-Protokolls* (BSI / bachelor thesis) — S7comm function-code signatures.
- *Setup and Tune an OT SOC, Part 2* (biero-llagas, Medium) — default-cred and
  brute-force web rules, threshold tuning.
- [satta/awesome-suricata](https://github.com/satta/awesome-suricata) — sources
  (ptresearch/attackdetection), tuning (`suricata-update`, thresholds), EveBox.
