# Automating Network Traffic Analysis in the KVM Environment

> **Environment:** KVM host (bare-metal, not a nested hypervisor). All commands
> target `libvirt` / `virsh` running directly on the host. Containers run via
> `docker compose` as defined in the root `docker-compose.yml`.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [libvirt Network Design](#2-libvirt-network-design)
3. [Capture Layer — tcpdump / tshark on the Host](#3-capture-layer--tcpdump--tshark-on-the-host)
4. [Automated Capture via libvirt Hooks](#4-automated-capture-via-libvirt-hooks)
5. [Suricata — Real-Time IDS on the Mirror Bridge](#5-suricata--real-time-ids-on-the-mirror-bridge)
6. [Zeek — Protocol-Level Metadata Extraction](#6-zeek--protocol-level-metadata-extraction)
7. [Arkime — Full PCAP Indexing & Search](#7-arkime--full-pcap-indexing--search)
8. [INetSim — Simulated Internet for C2 Analysis](#8-inetsim--simulated-internet-for-c2-analysis)
9. [End-to-End Automated Pipeline](#9-end-to-end-automated-pipeline)
10. [Evidence Collection & Export](#10-evidence-collection--export)
11. [Dashboard Integration](#11-dashboard-integration)
12. [Retention & Rotation Policy](#12-retention--rotation-policy)
13. [Hardening the Capture Path](#13-hardening-the-capture-path)
14. [Pitfalls & Known Issues](#14-pitfalls--known-issues)

---

## 1. Architecture Overview

The honeypot-stack runs honeypot containers (Cowrie, Dionaea, Conpot, etc.) on
the **KVM host** network. Malware analysis VMs (Windows / Linux) run as **KVM
guests** on an isolated virtual network. Traffic analysis happens at the host
kernel level — no agent inside the guest is required.

```
┌─────────────────────────────────────────────────────────────────┐
│  KVM HOST (bare-metal)                                          │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Docker Bridge (honeypot containers)                     │  │
│  │  Cowrie · Dionaea · Conpot · HTTP-honeypot · Snare/Tanner│  │
│  │                          │                               │  │
│  │                    [virbr-honey]  ← host NIC / internet  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Isolated Malware Network (virbr-mal)                    │  │
│  │                                                          │  │
│  │  analysis-vm-1 (Win10)  ──┐                              │  │
│  │  analysis-vm-2 (Ubuntu) ──┤── virbr-mal ─── INetSim     │  │
│  │  analysis-vm-N ...      ──┘       │                      │  │
│  │                                   │                      │  │
│  │              tcpdump / Suricata / Zeek ← capture here    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Analysis Stack (Docker)                                 │  │
│  │  Arkime (PCAP index) · Elasticsearch · Kibana · Grafana  │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**Key design principles:**
- Traffic is captured **on the host bridge** (`virbr-mal`), not inside guests.
  No agents, no drivers, no trust in the infected VM.
- Malware VMs have **no real internet access** — INetSim provides fake
  responses to satisfy C2 beaconing without leaking traffic.
- All PCAPs and Zeek/Suricata logs are written to a **dedicated capture
  volume** on a separate mount point, isolated from the OS disk.
- The pipeline is fully automated: a libvirt hook starts/stops capture
  whenever a malware VM is started or destroyed.

---

## 2. libvirt Network Design

Two libvirt networks are required.

### 2.1 Isolated Malware Network (`virbr-mal`)

This network has **no `<forward>` element** — it is completely isolated.
INetSim runs on the host at `10.66.0.1` to handle all outbound C2 connections.

```xml
<!-- /etc/libvirt/qemu/networks/malware-isolated.xml -->
<network>
  <name>malware-isolated</name>
  <bridge name="virbr-mal" stp="on" delay="0"/>
  <!-- No <forward> = no NAT, no routing to real internet -->
  <ip address="10.66.0.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.66.0.10" end="10.66.0.99"/>
    </dhcp>
  </ip>
</network>
```

```bash
virsh net-define   /etc/libvirt/qemu/networks/malware-isolated.xml
virsh net-autostart malware-isolated
virsh net-start     malware-isolated

# Verify
virsh net-info malware-isolated
ip link show virbr-mal
```

### 2.2 Honeypot Exposure Network (`virbr-honey`)

Optional second network used when a honeypot container and a malware VM need
to communicate (e.g. Cowrie downloads an ELF into the analysis VM).

```xml
<!-- /etc/libvirt/qemu/networks/honeypot.xml -->
<network>
  <name>honeypot</name>
  <bridge name="virbr-honey" stp="on" delay="0"/>
  <forward mode="nat">          <!-- Cowrie needs real internet for luring -->
    <nat>
      <port start="1024" end="65535"/>
    </nat>
  </forward>
  <ip address="10.67.0.1" netmask="255.255.255.0">
    <dhcp>
      <range start="10.67.0.10" end="10.67.0.50"/>
    </dhcp>
  </ip>
</network>
```

> ⚠️ **Never attach a malware analysis VM to `virbr-honey`.**
> Only honeypot containers (Cowrie, Dionaea) attach here.

### 2.3 Assign the Malware VM to the Isolated Network

In the guest domain XML (`virsh edit <vm-name>`):

```xml
<interface type='network'>
  <mac address='52:54:00:XX:XX:XX'/>
  <source network='malware-isolated'/>
  <model type='virtio'/>
</interface>
```

Or when defining via `virt-install`:

```bash
virt-install ... --network network=malware-isolated,model=virtio
```

---

## 3. Capture Layer — tcpdump / tshark on the Host

All malware VM traffic passes through `virbr-mal` on the host. Capture here
requires no trust in the guest.

### 3.1 Manual Capture (Ad-hoc)

```bash
# Capture all traffic on the isolated bridge
tcpdump -i virbr-mal -n -s 0 \
  -w /mnt/capture/manual-$(date +%Y%m%d-%H%M%S).pcap &

# Capture only a specific VM's traffic by MAC
VM_MAC="52:54:00:ab:cd:ef"
tcpdump -i virbr-mal -n -s 0 \
  "ether host $VM_MAC" \
  -w /mnt/capture/vm-$VM_MAC-$(date +%s).pcap &

# Capture with ring buffer (1 GB per file, max 10 files)
tcpdump -i virbr-mal -n -s 0 \
  -C 1000 -W 10 \
  -w /mnt/capture/ring.pcap
```

### 3.2 tshark — Protocol-Aware Capture

```bash
# Decode DNS + HTTP in real time while writing PCAP
tshark -i virbr-mal \
  -w /mnt/capture/session-$(date +%s).pcap \
  -T fields \
  -e frame.time -e ip.src -e ip.dst \
  -e dns.qry.name -e http.host -e http.request.uri \
  -E separator=,

# Extract IOCs from an existing PCAP without running a VM
tshark -r /mnt/capture/session.pcap \
  -Y 'dns.qry.name or http.host or tls.handshake.extensions_server_name' \
  -T fields -e dns.qry.name -e http.host \
  -e tls.handshake.extensions_server_name \
  | sort -u > /mnt/capture/iocs-domains.txt
```

### 3.3 PCAP Storage Layout

```
/mnt/capture/
  raw/          # Full PCAPs from tcpdump (ring buffer)
  sessions/     # Per-VM-session PCAPs (named by VM + sample hash)
  zeek/         # Zeek log output
  suricata/     # Suricata alerts (eve.json)
  arkime/       # Arkime indexes (managed by Arkime)
  exports/      # Extracted files, IOC CSVs
```

```bash
# Create and mount a dedicated capture volume
mkdir -p /mnt/capture/{raw,sessions,zeek,suricata,arkime,exports}
# If using a separate disk:
mkfs.ext4 /dev/sdX
mount /dev/sdX /mnt/capture
echo '/dev/sdX /mnt/capture ext4 defaults,noatime 0 2' >> /etc/fstab
```

---

## 4. Automated Capture via libvirt Hooks

libvirt fires shell hooks at guest lifecycle events. Use them to
**automatically start tcpdump when a malware VM boots and stop it when
the VM is destroyed** — no manual intervention needed.

### 4.1 Hook Directory Structure

```
/etc/libvirt/hooks/
  qemu              ← main dispatcher (executable)
  qemu.d/
    capture-start   ← started on VM start
    capture-stop    ← started on VM stop/destroy
```

### 4.2 Main Hook Dispatcher

```bash
#!/bin/bash
# /etc/libvirt/hooks/qemu
# Dispatches to per-event scripts.
# Args: $1=domain-name $2=operation $3=sub-operation $4=extra

GUEST="$1"
OP="$2"
SUBOP="$3"
HOOK_DIR="/etc/libvirt/hooks/qemu.d"

# Only handle analysis VMs (name must start with "analysis-")
[[ "$GUEST" != analysis-* ]] && exit 0

case "$OP" in
  start)
    if [[ "$SUBOP" == "begin" ]]; then
      exec "$HOOK_DIR/capture-start" "$GUEST" "$OP" "$SUBOP"
    fi
    ;;
  stopped|destroy)
    exec "$HOOK_DIR/capture-stop" "$GUEST" "$OP" "$SUBOP"
    ;;
esac

exit 0
```

```bash
chmod +x /etc/libvirt/hooks/qemu
mkdir -p /etc/libvirt/hooks/qemu.d
```

### 4.3 Capture-Start Hook

```bash
#!/bin/bash
# /etc/libvirt/hooks/qemu.d/capture-start
set -euo pipefail

GUEST="$1"
CAPTURE_DIR="/mnt/capture/sessions"
IFACE="virbr-mal"
PID_FILE="/run/capture-${GUEST}.pid"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PCAP="${CAPTURE_DIR}/${GUEST}-${TIMESTAMP}.pcap"

mkdir -p "$CAPTURE_DIR"

# Get MAC address of this specific VM's vNIC on virbr-mal
# so we only capture that VM's traffic (not all VMs on the bridge)
VM_MAC=$(virsh domiflist "$GUEST" 2>/dev/null \
  | awk '/malware-isolated/{print $5}' | head -1)

if [[ -n "$VM_MAC" ]]; then
  FILTER="ether host $VM_MAC"
else
  FILTER=""
  logger -t capture-hook "WARNING: no MAC found for $GUEST, capturing all bridge traffic"
fi

# Start tcpdump in background, write PID for later cleanup
tcpdump -i "$IFACE" -n -s 0 $FILTER \
  -w "$PCAP" \
  >> /var/log/capture-hook.log 2>&1 &

echo $! > "$PID_FILE"
echo "$PCAP" > "/run/capture-${GUEST}.pcap"

logger -t capture-hook "Started capture for $GUEST → $PCAP (PID $!)"

# Also start Zeek on this session
/etc/libvirt/hooks/qemu.d/zeek-start "$GUEST" "$PCAP" &

exit 0
```

```bash
chmod +x /etc/libvirt/hooks/qemu.d/capture-start
```

### 4.4 Capture-Stop Hook

```bash
#!/bin/bash
# /etc/libvirt/hooks/qemu.d/capture-stop
set -euo pipefail

GUEST="$1"
PID_FILE="/run/capture-${GUEST}.pid"
PCAP_FILE="/run/capture-${GUEST}.pcap"

if [[ -f "$PID_FILE" ]]; then
  PID=$(cat "$PID_FILE")
  kill -TERM "$PID" 2>/dev/null || true
  # Wait for tcpdump to flush and close the PCAP
  sleep 2
  kill -9 "$PID" 2>/dev/null || true
  rm -f "$PID_FILE"
  logger -t capture-hook "Stopped capture for $GUEST (PID $PID)"
fi

# Trigger post-processing pipeline
if [[ -f "$PCAP_FILE" ]]; then
  PCAP=$(cat "$PCAP_FILE")
  rm -f "$PCAP_FILE"
  /etc/libvirt/hooks/qemu.d/post-process "$GUEST" "$PCAP" &
  logger -t capture-hook "Triggered post-processing for $GUEST → $PCAP"
fi

exit 0
```

```bash
chmod +x /etc/libvirt/hooks/qemu.d/capture-stop
```

---

## 5. Suricata — Real-Time IDS on the Mirror Bridge

Suricata runs on the **host** listening on `virbr-mal`. It detects known
malware C2 patterns, exploit kits, and lateral movement in real time.

### 5.1 Install

```bash
add-apt-repository ppa:oisf/suricata-stable
apt update && apt install suricata suricata-update

# Update rules (ET Open — free)
suricata-update
suricata-update update-sources
suricata-update enable-source et/open
suricata-update
```

### 5.2 Configure for Bridge Capture

Edit `/etc/suricata/suricata.yaml`:

```yaml
# Bind to the isolated malware bridge
af-packet:
  - interface: virbr-mal
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

# Output directory
default-log-dir: /mnt/capture/suricata/

# Enable EVE JSON output (feeds Elasticsearch / Kibana)
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            tagged-packets: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
        - flow
        - netflow
```

### 5.3 Run as a systemd Service

```bash
systemctl enable --now suricata

# Verify it is listening on virbr-mal
ss -nlup | grep suricata

# Tail alerts
tail -f /mnt/capture/suricata/eve.json | jq 'select(.event_type=="alert")'
```

### 5.4 Alert Severity Filter

To only alert on high-severity events during automated runs:

```bash
jq 'select(.event_type=="alert" and .alert.severity <= 2)' \
  /mnt/capture/suricata/eve.json
```

---

## 6. Zeek — Protocol-Level Metadata Extraction

Zeek processes each per-VM PCAP **after** the session ends, producing
structured logs: `conn.log`, `dns.log`, `http.log`, `ssl.log`,
`files.log`, `weird.log`.

### 6.1 Install

```bash
apt install zeek
echo 'export PATH="/opt/zeek/bin:$PATH"' >> /etc/environment
source /etc/environment
```

### 6.2 Zeek Start Hook

```bash
#!/bin/bash
# /etc/libvirt/hooks/qemu.d/zeek-start
# Called from capture-start with: $1=GUEST $2=PCAP_PATH
GUEST="$1"
PCAP="$2"   # Path to PCAP being written (live)
OUT_DIR="/mnt/capture/zeek/${GUEST}-$(date +%s)"

mkdir -p "$OUT_DIR"

# Live Zeek reading on the bridge interface for real-time logs
# (processed PCAP analysis in post-process is more reliable)
logger -t zeek-hook "Zeek live mode registered for $GUEST → $OUT_DIR"
echo "$OUT_DIR" > "/run/zeek-outdir-${GUEST}"
```

### 6.3 Post-Process Hook — Zeek Offline Analysis

```bash
#!/bin/bash
# /etc/libvirt/hooks/qemu.d/post-process
# Args: $1=GUEST $2=PCAP_PATH
set -euo pipefail

GUEST="$1"
PCAP="$2"
ZEEK_DIR="/mnt/capture/zeek/${GUEST}-$(basename ${PCAP%.pcap})"
EXPORT_DIR="/mnt/capture/exports/${GUEST}"

mkdir -p "$ZEEK_DIR" "$EXPORT_DIR"

# 1. Run Zeek offline on the captured PCAP
zeek -C -r "$PCAP" \
  LogAscii::output_dir="$ZEEK_DIR" \
  /opt/zeek/share/zeek/policy/tuning/logs-to-files.zeek \
  /opt/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek

logger -t post-process "Zeek complete for $GUEST: $ZEEK_DIR"

# 2. Extract IOCs from Zeek logs
python3 /opt/honeypot-stack/scripts/extract-iocs.py \
  --zeek-dir "$ZEEK_DIR" \
  --output   "$EXPORT_DIR/iocs.json"

# 3. Feed PCAP into Arkime
/opt/arkime/bin/capture \
  --config /opt/arkime/etc/config.ini \
  -r "$PCAP" \
  --tag "guest:${GUEST}"

# 4. (Optional) Feed EVE alerts into Elasticsearch
curl -s -X POST http://localhost:9200/suricata-alerts/_doc \
  -H 'Content-Type: application/json' \
  -d @<(cat /mnt/capture/suricata/eve.json | grep '"alert"' | tail -100)

logger -t post-process "Pipeline complete for $GUEST"
```

```bash
chmod +x /etc/libvirt/hooks/qemu.d/post-process
chmod +x /etc/libvirt/hooks/qemu.d/zeek-start
```

---

## 7. Arkime — Full PCAP Indexing & Search

Arkime (formerly Moloch) provides web-based PCAP search, session reconstruction,
and file extraction across all captured sessions.

### 7.1 Configuration (`arkime/config.ini`)

This stack already contains an `arkime/` directory. Key settings:

```ini
[default]
pcapDir=/mnt/capture/arkime
elasticsearch=http://elasticsearch:9200
interface=virbr-mal
bpf=
pcapWriteSize=2560000

# Tag sessions by which VM they came from
extraTag=honeypot-stack

# Only store, never forward
offlineFilenameRegex=^.+\.pcap$
```

### 7.2 Live Capture vs Offline Import

For automated analysis VMs, **offline import** is more reliable — Arkime
processes the complete PCAP after the session ends:

```bash
# Import a specific session PCAP
/opt/arkime/bin/capture \
  --config /opt/arkime/etc/config.ini \
  -r /mnt/capture/sessions/analysis-abc123-20260726.pcap \
  --tag sample:abc123

# Bulk import all PCAPs in a folder
/opt/arkime/bin/capture \
  --config /opt/arkime/etc/config.ini \
  --recursive \
  -r /mnt/capture/sessions/
```

### 7.3 Useful Arkime Queries

In the Arkime web UI (`http://localhost:8005`):

| Goal | Query |
|------|-------|
| All DNS queries | `protocols==dns` |
| HTTP to unknown IPs | `protocols==http && ip.dst != 10.66.0.1` |
| TLS with self-signed cert | `tls.notafter exists && tls.notbefore exists` |
| Large outbound transfers | `packets > 500 && node == analysis*` |
| C2 beacon pattern (regular intervals) | `packets > 10 && protocols==tcp` |
| IRC (common botnet C2) | `port.dst == 6667 || port.dst == 6697` |

---

## 8. INetSim — Simulated Internet for C2 Analysis

Malware almost always attempts to reach a C2 server or download stage-2
payloads. INetSim intercepts every outbound connection and returns fake
but valid-looking responses — keeping malware running longer for observation.

### 8.1 Install

```bash
apt install inetsim
```

### 8.2 Configure (`/etc/inetsim/inetsim.conf`)

```ini
# Bind to the isolated bridge IP so only VMs on virbr-mal reach it
service_bind_address  10.66.0.1
dns_bind_address      10.66.0.1
dns_default_ip        10.66.0.1   # All DNS queries resolve to INetSim itself

# Realistic fake responses
http_version          1.1
smtp_banner           mail.example.com
ftp_banner            FTP ready

# Services to simulate
start_service dns
start_service http
start_service https
start_service ftp
start_service smtp
start_service pop3
start_service irc
start_service ntp
```

### 8.3 Run INetSim

```bash
systemctl enable --now inetsim

# Confirm it is listening on the bridge
ss -tlnup | grep 10.66.0.1

# Monitor fake connections in real time
tail -f /var/log/inetsim/service.log
```

### 8.4 iptables Rules — Force All VM Traffic to INetSim

Even if malware hardcodes an IP, redirect all outbound connections to
INetSim:

```bash
# Redirect all TCP from VM subnet to INetSim HTTP
iptables -t nat -A PREROUTING -i virbr-mal \
  -p tcp --dport 80 -j DNAT --to-destination 10.66.0.1:80
iptables -t nat -A PREROUTING -i virbr-mal \
  -p tcp --dport 443 -j DNAT --to-destination 10.66.0.1:443

# Redirect DNS
iptables -t nat -A PREROUTING -i virbr-mal \
  -p udp --dport 53 -j DNAT --to-destination 10.66.0.1:53

# Block anything that is NOT addressed to INetSim
# (belt-and-suspenders — the missing <forward> already prevents routing)
iptables -A FORWARD -i virbr-mal ! -d 10.66.0.0/24 -j DROP

# Save rules
netfilter-persistent save
```

---

## 9. End-to-End Automated Pipeline

This pipeline runs automatically whenever a malware sample is submitted to
the analysis VM.

```
Step 1  Cowrie / Dionaea captures sample
        └─ drops file to /opt/honeypot-stack/samples/

Step 2  GitHub Action (Xore/Honeypot) triggers
        └─ VirusTotal / MalwareBazaar / HybridAnalysis / MetaDefender scan
        └─ results committed to reports/scanner/

Step 3  Local pipeline (sandbox/run-analysis.sh) triggers on new file
        └─ Spawns fresh KVM overlay VM (see kvm-snapshot-vs-golden-image.md)
        └─ libvirt hook: capture-start → tcpdump begins on virbr-mal
        └─ Copies sample into VM via virtio-serial
        └─ Executes sample inside VM
        └─ Timer: 5 minutes TTL

Step 4  VM destroyed
        └─ libvirt hook: capture-stop → tcpdump flushed
        └─ hook: post-process fires
            ├─ Zeek offline analysis → /mnt/capture/zeek/
            ├─ extract-iocs.py → iocs.json
            ├─ Arkime offline import → indexed + searchable
            └─ Suricata EVE alerts → Elasticsearch

Step 5  Dashboard auto-updates
        └─ Kibana: Suricata alerts, Zeek conn/dns/http logs
        └─ Arkime: PCAP search by sample hash / domain / IP
        └─ Grafana: volume trends, detection rates
```

### 9.1 `sandbox/run-analysis.sh`

```bash
#!/bin/bash
# sandbox/run-analysis.sh
# Usage: run-analysis.sh <path-to-sample>
set -euo pipefail

SAMPLE_PATH="$(realpath $1)"
SAMPLE_HASH=$(sha256sum "$SAMPLE_PATH" | awk '{print $1}')
SAMPLE_NAME=$(basename "$SAMPLE_PATH")
GOLDEN="/var/lib/libvirt/golden/golden-win10.qcow2"
OVERLAY="/var/lib/libvirt/overlays/analysis-${SAMPLE_HASH:0:12}.qcow2"
VM_NAME="analysis-${SAMPLE_HASH:0:12}"
TTL=300   # 5 minutes

log() { logger -t run-analysis "$*"; echo "[$(date +%H:%M:%S)] $*"; }

log "Starting analysis: $SAMPLE_NAME ($SAMPLE_HASH)"

# 1. Create overlay VM
qemu-img create -f qcow2 -b "$GOLDEN" -F qcow2 "$OVERLAY"
virt-clone \
  --original golden-win10 \
  --name    "$VM_NAME" \
  --file    "$OVERLAY" \
  --preserve-data
virsh start "$VM_NAME"
log "VM $VM_NAME started"

# Wait for guest agent to be ready
sleep 30

# 2. Copy sample into VM via QEMU guest agent
virsh qemu-agent-command "$VM_NAME" \
  '{"execute":"guest-file-open","arguments":{"path":"C:\\analysis\\sample.exe","mode":"wb"}}' \
  > /tmp/fh.json
FH=$(jq .return /tmp/fh.json)
base64 "$SAMPLE_PATH" | while IFS= read -r chunk; do
  virsh qemu-agent-command "$VM_NAME" \
    "{\"execute\":\"guest-file-write\",\"arguments\":{\"handle\":$FH,\"buf-b64\":\"$chunk\"}}"
done
virsh qemu-agent-command "$VM_NAME" \
  "{\"execute\":\"guest-file-close\",\"arguments\":{\"handle\":$FH}}"

# 3. Execute sample
virsh qemu-agent-command "$VM_NAME" \
  '{"execute":"guest-exec","arguments":{"path":"C:\\analysis\\sample.exe","capture-output":true}}'

log "Sample executing, waiting ${TTL}s..."

# 4. Wait for TTL, then destroy
sleep "$TTL"

log "TTL expired, destroying $VM_NAME"
virsh destroy  "$VM_NAME" 2>/dev/null || true
virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null || true
rm -f "$OVERLAY"

log "Analysis complete for $SAMPLE_HASH"
```

```bash
chmod +x sandbox/run-analysis.sh
```

---

## 10. Evidence Collection & Export

### 10.1 IOC Extractor (`scripts/extract-iocs.py`)

```python
#!/usr/bin/env python3
"""
extract-iocs.py — Parse Zeek logs and emit a structured IOC JSON.
"""
import argparse
import json
import re
from pathlib import Path

IPv4_RE = re.compile(r'\b(?!10\.|127\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)'
                     r'(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_RE = re.compile(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


def parse_zeek_log(path: Path) -> list:
    rows = []
    fields = []
    for line in path.read_text(errors='replace').splitlines():
        if line.startswith('#fields'):
            fields = line.split('\t')[1:]
        elif not line.startswith('#') and fields:
            values = line.split('\t')
            rows.append(dict(zip(fields, values)))
    return rows


def extract(zeek_dir: Path) -> dict:
    iocs = {'ips': set(), 'domains': set(), 'urls': set(), 'files': []}

    conn = zeek_dir / 'conn.log'
    if conn.exists():
        for row in parse_zeek_log(conn):
            ip = row.get('id.resp_h', '')
            if IPv4_RE.match(ip):
                iocs['ips'].add(ip)

    dns = zeek_dir / 'dns.log'
    if dns.exists():
        for row in parse_zeek_log(dns):
            q = row.get('query', '')
            if DOMAIN_RE.match(q) and q not in ('', '-'):
                iocs['domains'].add(q)

    http = zeek_dir / 'http.log'
    if http.exists():
        for row in parse_zeek_log(http):
            host = row.get('host', '')
            uri  = row.get('uri', '')
            if host:
                iocs['urls'].add(f'http://{host}{uri}')

    files_log = zeek_dir / 'files.log'
    if files_log.exists():
        for row in parse_zeek_log(files_log):
            md5 = row.get('md5', '-')
            sha1 = row.get('sha1', '-')
            mime = row.get('mime_type', '')
            if md5 != '-':
                iocs['files'].append({'md5': md5, 'sha1': sha1, 'mime': mime})

    return {
        'ips':     sorted(iocs['ips']),
        'domains': sorted(iocs['domains']),
        'urls':    sorted(iocs['urls']),
        'files':   iocs['files'],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--zeek-dir', required=True)
    parser.add_argument('--output',   required=True)
    args = parser.parse_args()

    result = extract(Path(args.zeek_dir))
    Path(args.output).write_text(json.dumps(result, indent=2))
    print(f'Extracted {len(result["ips"])} IPs, '
          f'{len(result["domains"])} domains, '
          f'{len(result["urls"])} URLs, '
          f'{len(result["files"])} files')
```

### 10.2 Export to MISP-Compatible CSV

```bash
#!/bin/bash
# scripts/iocs-to-csv.sh — aggregate all session IOC JSONs into one CSV
OUT="/mnt/capture/exports/all-iocs-$(date +%Y%m%d).csv"
echo "type,value,session" > "$OUT"
find /mnt/capture/exports -name 'iocs.json' | while read -r f; do
  SESSION=$(basename "$(dirname "$f")")
  jq -r --arg s "$SESSION" '
    (.ips[]    | ["ip",        ., $s]),
    (.domains[] | ["domain",   ., $s]),
    (.urls[]    | ["url",      ., $s])
    | @csv' "$f"
done >> "$OUT"
echo "Exported IOCs to $OUT"
```

---

## 11. Dashboard Integration

All components in the stack output to Elasticsearch. The existing `dashboard/`
directory contains Kibana dashboards. Add these index patterns and visualisations.

### 11.1 Filebeat — Ship Zeek & Suricata Logs to Elasticsearch

```yaml
# /etc/filebeat/filebeat.yml (on the KVM host)
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /mnt/capture/suricata/eve.json
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      source: suricata

  - type: log
    enabled: true
    paths:
      - /mnt/capture/zeek/*/conn.log
      - /mnt/capture/zeek/*/dns.log
      - /mnt/capture/zeek/*/http.log
      - /mnt/capture/zeek/*/ssl.log
    fields:
      source: zeek

output.elasticsearch:
  hosts: ["http://localhost:9200"]
  index: "honeypot-network-%{+yyyy.MM.dd}"
```

```bash
systemctl enable --now filebeat
```

### 11.2 Key Kibana Visualisations

| Panel | Index | Query |
|-------|-------|-------|
| Top C2 IPs | suricata | `event_type:alert AND alert.category:"A Network Trojan was detected"` |
| DNS exfil candidates | zeek | `source:zeek AND fields.source:zeek AND dns.query.length > 40` |
| HTTP user-agents | zeek | `source:zeek` → terms agg on `http.useragent` |
| Bytes per session | suricata | `event_type:flow` → sum `flow.bytes_toclient` |
| Protocol breakdown | zeek | terms agg on `proto` |
| Hourly alert rate | suricata | `event_type:alert` → date histogram |

---

## 12. Retention & Rotation Policy

```bash
#!/bin/bash
# scripts/rotate-captures.sh — run via cron daily

CAPTURE_DIR="/mnt/capture"
MAX_AGE_DAYS_PCAP=14      # Keep raw PCAPs 14 days
MAX_AGE_DAYS_LOGS=30      # Keep Zeek/Suricata logs 30 days
MAX_AGE_DAYS_EXPORTS=90   # Keep IOC exports 90 days
MIN_FREE_GB=20

# Age-based pruning
find "$CAPTURE_DIR/sessions"  -name '*.pcap' -mtime +$MAX_AGE_DAYS_PCAP  -delete
find "$CAPTURE_DIR/raw"       -name '*.pcap' -mtime +$MAX_AGE_DAYS_PCAP  -delete
find "$CAPTURE_DIR/zeek"      -type f        -mtime +$MAX_AGE_DAYS_LOGS  -delete
find "$CAPTURE_DIR/suricata"  -type f        -mtime +$MAX_AGE_DAYS_LOGS  -delete
find "$CAPTURE_DIR/exports"   -type f        -mtime +$MAX_AGE_DAYS_EXPORTS -delete

# Emergency pruning if disk is nearly full
FREE_GB=$(df -BG "$CAPTURE_DIR" | awk 'NR==2{gsub("G","",$4); print $4}')
if (( FREE_GB < MIN_FREE_GB )); then
  logger -t rotate-captures "WARNING: only ${FREE_GB}GB free, emergency pruning"
  find "$CAPTURE_DIR/sessions" -name '*.pcap' -mtime +3 \
    | sort -t- -k3 | head -50 | xargs rm -f
fi

logger -t rotate-captures "Rotation complete. Free: ${FREE_GB}GB"
```

```bash
chmod +x scripts/rotate-captures.sh
# Add to crontab:
echo '0 3 * * * root /opt/honeypot-stack/scripts/rotate-captures.sh' \
  > /etc/cron.d/honeypot-rotate
```

---

## 13. Hardening the Capture Path

```bash
# 1. tcpdump should run as a dedicated non-root user
groupadd pcap
useradd -r -g pcap -s /usr/sbin/nologin pcap
setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump
chown pcap:pcap /mnt/capture/sessions

# 2. Suricata — run as suricata user (default after apt install)
chown -R suricata:suricata /mnt/capture/suricata

# 3. Protect capture mount from guest escape
# virbr-mal has no route to /mnt/capture — they are on different namespaces.
# Additional: mount capture volume noexec so extracted malware cannot run
mount -o remount,noexec /mnt/capture

# 4. Arkime API — bind to localhost only
# In config.ini: interface=127.0.0.1:8005 for the web UI
# Use SSH tunnel or nginx reverse proxy with auth for external access

# 5. Rotate INetSim logs so they don't fill /var
cat >> /etc/logrotate.d/inetsim << 'EOF'
/var/log/inetsim/*.log {
  daily
  rotate 7
  compress
  missingok
  notifempty
  postrotate
    systemctl reload inetsim || true
  endscript
}
EOF
```

---

## 14. Pitfalls & Known Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| libvirt hook not firing | Hook file not executable or wrong path | `chmod +x /etc/libvirt/hooks/qemu`; restart `libvirtd` |
| tcpdump captures 0 bytes | VM not yet on bridge when hook fires | Add `sleep 2` before `tcpdump` in capture-start |
| Zeek `conn.log` empty | PCAP write not flushed before post-process | `kill -TERM` + `sleep 2` before reading PCAP in capture-stop |
| INetSim not receiving traffic | Missing iptables DNAT rules or wrong bind IP | Verify `ss -tlnup \| grep 10.66.0.1`; check iptables-save |
| Arkime fails to import PCAP | Elasticsearch not running | `docker compose up -d elasticsearch` first |
| PCAP disk fills up overnight | High-volume botnet scanning | Tune `tcpdump -C` ring buffer size; run rotate-captures.sh hourly |
| Malware detects virtual network | VirtIO NIC identified | Change VM NIC model to `e1000` in domain XML |
| Zeek misses TLS JA3 fingerprints | Old Zeek version | Upgrade to Zeek ≥ 5.0; enable `policy/protocols/ssl/ja3.zeek` |
| VM traffic appears on wrong interface | Multiple bridges | Verify `virsh domiflist <vm>` shows `malware-isolated` |

---

## References

- [libvirt Hooks Documentation](https://libvirt.org/hooks.html)
- [Suricata Configuration Reference](https://suricata.readthedocs.io/en/latest/configuration/suricata-yaml.html)
- [Zeek Documentation](https://docs.zeek.org/en/master/)
- [Arkime (Moloch) Documentation](https://arkime.com/documentation)
- [INetSim Manual](https://www.inetsim.org/documentation.html)
- [QEMU Guest Agent Protocol](https://qemu-project.gitlab.io/qemu/interop/qemu-ga-ref.html)
- [FakeNet-NG (alternative to INetSim)](https://github.com/mandiant/flare-fakenet-ng)
- [Cuckoo Sandbox Network Analysis](https://cuckoo.readthedocs.io/en/latest/usage/packages/)
- See also: [`docs/kvm-snapshot-vs-golden-image.md`](kvm-snapshot-vs-golden-image.md)
