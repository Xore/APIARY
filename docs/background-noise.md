# Generating Realistic Background Noise in Honeypot Networks

> **Status (2026-07-31): research. Nothing here is implemented, and none of
> the addresses below exist.** This is kept as a technique reference — the
> fingerprints in §1 and §9 are the durable part, and they are what any future
> attempt has to answer. Tracked as
> [#71](https://github.com/Xore/honeypot-stack/issues/71), which is not
> scheduled: the observer this design is written against has to be identified
> before any of it is worth building.
>
> Read §2 as an illustrative topology, not as this stack's. The commands below
> are unmodified from the original research and refer to `virbr0` /
> `10.0.1.0/24`, which are the document's own example network.

> **Goal:** Make honeypot VMs and containers look indistinguishable from a live production network by injecting realistic ambient traffic — without contaminating your captured attacker data.

---

## Table of Contents

1. [Why Background Noise Matters](#1-why-background-noise-matters)
2. [Architecture Overview (KVM Context)](#2-architecture-overview-kvm-context)
3. [Layer 1 — INetSim: Service Simulation](#3-layer-1--inetsim-service-simulation)
4. [Layer 2 — tcpreplay: PCAP Replay on the Bridge](#4-layer-2--tcpreplay-pcap-replay-on-the-bridge)
5. [Layer 3 — Scapy: Scripted Ambient Packets](#5-layer-3--scapy-scripted-ambient-packets)
6. [Layer 4 — Periodic Cron Jobs for Protocol Noise](#6-layer-4--periodic-cron-jobs-for-protocol-noise)
7. [KVM-Specific: Injecting Traffic via virbr / macvtap](#7-kvm-specific-injecting-traffic-via-virbr--macvtap)
8. [Isolating Noise from Attacker Captures](#8-isolating-noise-from-attacker-captures)
9. [Detection Evasion Checklist](#9-detection-evasion-checklist)
10. [Tool Reference](#10-tool-reference)

---

## 1. Why Background Noise Matters

An attacker who can observe network traffic will immediately recognise a dead-silent honeypot — no NTP syncs, no ARP broadcasts, no DNS lookups, no background TCP connections. Research shows that honeypots lacking realistic ambient traffic are trivially detectable as decoys even by passive observation alone.

Key signals an empty honeypot leaks:

- **No outbound DNS** — real hosts resolve hostnames constantly.
- **No NTP traffic** — all production hosts sync their clock every 64–1024 seconds.
- **Flat ARP table** — a live subnet has continuous ARP who-has/is-at chatter.
- **No HTTP/S background fetches** — browsers, package managers, update daemons all poll.
- **Zero ICMP** — production networks have continuous ping, traceroute, path-MTU probes.
- **Perfect TCP inter-arrival times** — synthetic traffic generators produce unnaturally uniform spacing.

The goal is to eliminate all of these tells.

---

## 2. Architecture Overview (KVM Context)

```
 KVM Host (bare metal)
 ┌──────────────────────────────────────────────────────────┐
 │ ┌─────────────┐ ┌──────────────────────────────────┐ │
 │ │ virbr0 │◄──────────────►│ Honeypot Docker Network │ │
 │ │ 10.0.1.1/24 │ │ (cowrie, dionaea, conpot, etc.) │ │
 │ └──────┬──────┘ └──────────────────────────────────┘ │
 │ │ │
 │ ▼ │
 │ ┌──────────────────────┐ │
 │ │ noise-injector │ │
 │ │ (this guide) │ │
 │ │ - INetSim container │ │
 │ │ - tcpreplay daemon │ │
 │ │ - Scapy noise.py │ │
 │ │ - cron jobs │ │
 │ └──────────────────────┘ │
 └──────────────────────────────────────────────────────────┘
```

The **noise-injector** runs on the KVM host itself (or a dedicated sidecar container bridged to `virbr0`) and emits packets directly onto the same L2 segment as the honeypot containers. Attacker traffic arriving from outside passes through the same bridge and is captured by Arkime/Zeek without modification.

> **This is where the research and this stack part company.** The exposed
> honeypots are containers on the `honeynet` Docker network, on a VPS, reached
> from the internet through `portbridge` — there is no shared L2 segment with a
> host-side injector on it, and no attacker holding a capture of one. The place
> in this stack that *does* match the picture above is a sandbox guest on
> `virbr-sandbox`, which sees exactly one neighbour (INetSim) and no ambient
> traffic at all. Note also that `honeypot-sandbox-strict` blocks source-MAC
> spoofing by design, so the §5 injector cannot run on a sandbox guest's own
> segment as written. See [#71](https://github.com/Xore/honeypot-stack/issues/71).

---

## 3. Layer 1 — INetSim: Service Simulation

[INetSim](https://www.inetsim.org/) simulates DNS, HTTP/S, SMTP, POP3, FTP, IRC, NTP, TFTP, Syslog, and "small servers" (Echo, Daytime, Chargen, Discard). It answers any query with plausible fake responses, making the honeypot network look like it has a full internet gateway.

### 3.1 Install

```bash
# On Debian/Ubuntu KVM host
apt-get install inetsim
```

Or use the official Docker image bridged to `virbr0`:

```yaml
# docker-compose.yml addition
  inetsim:
    image: remnux/inetsim
    network_mode: "host"          # so it binds on virbr0 IP
    cap_add: [NET_ADMIN, NET_RAW]
    volumes:
      - ./noise/inetsim.conf:/etc/inetsim/inetsim.conf:ro
    restart: unless-stopped
```

### 3.2 Minimal `inetsim.conf`

```ini
# /etc/inetsim/inetsim.conf
start_service dns
start_service http
start_service https
start_service smtp
start_service pop3
start_service ftp
start_service ntp
start_service irc
start_service tftp

dns_default_ip         10.0.1.1
dns_default_hostname   gateway.local

http_fakemode          yes
https_fakemode         yes

service_bind_address   10.0.1.1
max_childs             50
```

### 3.3 Point honeypots at INetSim

In your `.env` or container DNS config, set the resolver to the INetSim IP:

```bash
DNS_SERVER=10.0.1.1
# Or add to /etc/resolv.conf inside each container:
echo "nameserver 10.0.1.1" >> /etc/resolv.conf
```

Now every DNS lookup from any honeypot container resolves through INetSim, generating realistic DNS traffic visible to Arkime.

---

## 4. Layer 2 — tcpreplay: PCAP Replay on the Bridge

tcpreplay replays real-world PCAP captures onto `virbr0`, injecting authentic packet timing, TTL values, window sizes, and protocol behaviour that are statistically indistinguishable from real traffic.

### 4.1 Install

```bash
apt-get install tcpreplay tcprewrite
```

### 4.2 Obtain background PCAPs

Good public sources of clean background traffic:

- [MAWI Working Group](http://mawi.wide.ad.jp/mawi/) — daily backbone captures
- [CAIDA Passive Monitor](https://www.caida.org/catalog/datasets/passive_dataset/) — requires registration
- [NETRESEC](https://www.netresec.com/?page=PcapFiles) — curated packet captures
- Record 15 minutes of your own production network with `tcpdump -i eth0 -w prod.pcap`

### 4.3 Rewrite IPs to match your honeypot subnet

The captured PCAP will have foreign IPs. Rewrite them to your `10.0.1.0/24` range:

```bash
tcprewrite \
  --infile=mawi-sample.pcap \
  --outfile=noise.pcap \
  --srcipmap=0.0.0.0/0:10.0.1.0/24 \
  --dstipmap=0.0.0.0/0:10.0.1.0/24 \
  --enet-smac=02:00:00:aa:bb:01 \
  --enet-dmac=02:00:00:aa:bb:02 \
  --fixcsum
```

### 4.4 Replay in a loop with realistic rate

```bash
# Replay at 0.1x original speed, loop indefinitely, onto the KVM bridge
tcpreplay \
  --intf1=virbr0 \
  --multiplier=0.1 \
  --loop=0 \
  --quiet \
  noise.pcap &
```

Use `--multiplier=0.05` to `0.2` — too fast creates unrealistic bursts; too slow leaves gaps.

### 4.5 Run as a systemd service

```ini
# /etc/systemd/system/honeypot-noise.service
[Unit]
Description=Honeypot background noise (tcpreplay)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/tcpreplay --intf1=virbr0 --multiplier=0.1 --loop=0 --quiet /opt/noise/noise.pcap
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now honeypot-noise
```

---

## 5. Layer 3 — Scapy: Scripted Ambient Packets

Scapy lets you craft protocol-accurate packets tuned specifically to your honeypot personas. This fills gaps tcpreplay cannot cover (e.g. host-specific ARP, ICMP echo from a known IP).

### 5.1 Install

```bash
pip install scapy
```

### 5.2 `noise/noise_generator.py`

```python
#!/usr/bin/env python3
"""
noise_generator.py — continuous ambient packet injector for honeypot bridge.
Runs on the KVM host; sends on the virbr0 interface.
"""
import random
import time
import threading
from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, DNS, DNSQR,
    ARP, NTP, Raw, sendp, conf
)

IFACE      = "virbr0"
HOSTS      = [
    # (ip, mac)  — should match your honeypot container assignments
    ("10.0.1.10", "02:00:00:aa:00:10"),  # cowrie (SSH)
    ("10.0.1.11", "02:00:00:aa:00:11"),  # dionaea (SMB/FTP)
    ("10.0.1.12", "02:00:00:aa:00:12"),  # conpot (ICS)
    ("10.0.1.13", "02:00:00:aa:00:13"),  # http-honeypot
]
GATEWAY_IP  = "10.0.1.1"
GATEWAY_MAC = "02:00:00:aa:00:01"
DNS_DOMAINS = [
    "time.windows.com", "pool.ntp.org", "windowsupdate.microsoft.com",
    "ocsp.digicert.com", "clients1.google.com", "detectportal.firefox.com",
    "teredo.ipv6.microsoft.com", "ctldl.windowsupdate.com",
]
HTTP_HOSTS  = ["windowsupdate.microsoft.com", "ocsp.digicert.com",
               "clients1.google.com", "detectportal.firefox.com"]


def random_host():
    return random.choice(HOSTS)


def send_arp_broadcast():
    """Periodic ARP who-has from each host — keeps ARP tables warm."""
    while True:
        ip, mac = random_host()
        target_ip = random.choice([h[0] for h in HOSTS if h[0] != ip])
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
              ARP(op=1, hwsrc=mac, psrc=ip, pdst=target_ip)
        sendp(pkt, iface=IFACE, verbose=False)
        time.sleep(random.uniform(8, 30))


def send_ntp():
    """NTP client poll every 64-128s (RFC 5905 default range)."""
    while True:
        ip, mac = random_host()
        pkt = Ether(src=mac, dst=GATEWAY_MAC) / \
              IP(src=ip, dst=GATEWAY_IP) / \
              UDP(sport=random.randint(49152, 65535), dport=123) / \
              NTP()
        sendp(pkt, iface=IFACE, verbose=False)
        time.sleep(random.uniform(64, 128))


def send_dns():
    """Randomised DNS A-record queries (Windows/Linux update and telemetry domains)."""
    while True:
        ip, mac = random_host()
        domain = random.choice(DNS_DOMAINS)
        pkt = Ether(src=mac, dst=GATEWAY_MAC) / \
              IP(src=ip, dst=GATEWAY_IP) / \
              UDP(sport=random.randint(49152, 65535), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=domain))
        sendp(pkt, iface=IFACE, verbose=False)
        time.sleep(random.uniform(15, 90))


def send_icmp():
    """ICMP echo-request (ping) between hosts — path-MTU probing pattern."""
    while True:
        src_ip, src_mac = random_host()
        dst_ip, _       = random.choice([h for h in HOSTS if h[0] != src_ip])
        pkt = Ether(src=src_mac, dst=GATEWAY_MAC) / \
              IP(src=src_ip, dst=dst_ip, ttl=random.choice([64, 128])) / \
              ICMP() / Raw(b"\x00" * random.randint(32, 56))
        sendp(pkt, iface=IFACE, verbose=False)
        time.sleep(random.uniform(20, 120))


def send_http_head():
    """
    Lightweight HTTP HEAD request over a raw TCP connection.
    Simulates background update/telemetry checkins.
    """
    while True:
        ip, mac = random_host()
        host    = random.choice(HTTP_HOSTS)
        sport   = random.randint(49152, 65535)
        seq     = random.randint(1000000, 9000000)
        # SYN
        syn = Ether(src=mac, dst=GATEWAY_MAC) / \
              IP(src=ip, dst=GATEWAY_IP) / \
              TCP(sport=sport, dport=80, flags="S", seq=seq)
        sendp(syn, iface=IFACE, verbose=False)
        time.sleep(random.uniform(0.05, 0.2))
        # HTTP GET (INetSim will respond)
        payload = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        data = Ether(src=mac, dst=GATEWAY_MAC) / \
               IP(src=ip, dst=GATEWAY_IP) / \
               TCP(sport=sport, dport=80, flags="PA", seq=seq+1) / \
               Raw(payload.encode())
        sendp(data, iface=IFACE, verbose=False)
        time.sleep(random.uniform(120, 600))


if __name__ == "__main__":
    conf.iface = IFACE
    threads = [
        threading.Thread(target=send_arp_broadcast, daemon=True),
        threading.Thread(target=send_ntp,           daemon=True),
        threading.Thread(target=send_dns,           daemon=True),
        threading.Thread(target=send_icmp,          daemon=True),
        threading.Thread(target=send_http_head,     daemon=True),
    ]
    for t in threads:
        t.start()
    # Block forever
    for t in threads:
        t.join()
```

### 5.3 Run as systemd service

```ini
# /etc/systemd/system/honeypot-scapy-noise.service
[Unit]
Description=Honeypot Scapy ambient noise injector
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/noise/noise_generator.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now honeypot-scapy-noise
```

---

## 6. Layer 4 — Periodic Cron Jobs for Protocol Noise

These lightweight cron entries simulate specific host behaviours that Scapy and tcpreplay don't easily cover — outbound connections, certificate fetching, OCSP stapling.

```crontab
# /etc/cron.d/honeypot-noise
# Run from KVM host, targeting INetSim on 10.0.1.1

# DNS — every 5 minutes, query update domains
*/5 * * * *  root  dig @10.0.1.1 windowsupdate.microsoft.com A +short >/dev/null 2>&1
*/7 * * * *  root  dig @10.0.1.1 pool.ntp.org A +short >/dev/null 2>&1
*/11 * * * * root  dig @10.0.1.1 ocsp.digicert.com A +short >/dev/null 2>&1

# HTTP — simulate background update checks (INetSim responds with fake 200)
*/15 * * * * root  curl -s -o /dev/null -m 5 http://10.0.1.1/ -H "Host: detectportal.firefox.com" 2>&1
*/30 * * * * root  curl -s -o /dev/null -m 5 http://10.0.1.1/update -H "Host: windowsupdate.microsoft.com" 2>&1

# ICMP — host liveness pings between personas
*/3 * * * *  root  ping -c 1 -q 10.0.1.10 >/dev/null 2>&1
*/4 * * * *  root  ping -c 1 -q 10.0.1.11 >/dev/null 2>&1
*/6 * * * *  root  ping -c 2 -q 10.0.1.12 >/dev/null 2>&1

# NTP — force sync to INetSim NTP server
@hourly      root  ntpdate -u 10.0.1.1 >/dev/null 2>&1
```

---

## 7. KVM-Specific: Injecting Traffic via virbr / macvtap

### 7.1 Confirm bridge name

```bash
virsh net-list --all
# NAME      STATE    AUTOSTART   PERSISTENT
# default   active   yes         yes

virsh net-info default | grep Bridge
# Bridge:         virbr0
```

### 7.2 Allow raw packet injection on the bridge

By default, `ebtables` on KVM may filter crafted source MACs. Allow your noise MAC range:

```bash
# Allow spoofed MACs in the 02:00:00:aa:00:xx range used by Scapy injector
ebtables -I FORWARD -i virbr0 -s 02:00:00:aa:00:00/ff:ff:ff:ff:ff:00 -j ACCEPT
ebtables -I INPUT  -i virbr0 -s 02:00:00:aa:00:00/ff:ff:ff:ff:ff:00 -j ACCEPT

# Persist (Debian/Ubuntu)
apt-get install ebtables
iptables-save > /etc/iptables/rules.v4
ebtables-save > /etc/ebtables/rules
```

### 7.3 macvtap alternative (VM-level injection)

If you prefer injecting traffic at the QEMU/KVM VM level rather than the host bridge:

```xml
<!-- Add to VM XML via virsh edit <vm> -->
<interface type='direct'>
  <source dev='virbr0' mode='bridge'/>
  <model type='virtio'/>
  <alias name='noise-tap'/>
</interface>
```

Then run tcpreplay or Scapy inside a dedicated noise VM attached to the same bridge segment.

### 7.4 Verify traffic reaches honeypot bridge

```bash
# On KVM host — confirm packets appear on virbr0
tcpdump -i virbr0 -c 50 'arp or icmp or udp port 53 or udp port 123' \
  --immediate-mode -l 2>/dev/null
```

You should see a mix of ARP, DNS UDP, NTP UDP, and ICMP within 30 seconds.

---

## 8. Isolating Noise from Attacker Captures

Background noise **must not** pollute your attacker intelligence. Achieve separation at two levels:

> This is the constraint that decides whether the whole idea is affordable. A
> noise source that inflates event counts, the attack graph, or the top-talkers
> list is worse than a silent honeypot, and every consumer needs the exclusion —
> Suricata, Arkime, Zeek, and the dashboard's own counting. The precedent
> already exists: the VPS sensor keeps the WireGuard tunnel out of its capture
> with `bpf-filter: "not udp port 51820"` in `suricata.yaml`.

### 8.1 BPF filter in Arkime / Zeek

Mark all noise source MACs and exclude them from sessions:

```yaml
# arkime config.ini
bpf = not (ether src 02:00:00:aa:00:01 or ether src 02:00:00:aa:00:02)
```

```bash
# Zeek sensor — suppress noise in local.zeek
redef Site::local_nets += { 10.0.1.0/24 };
# Tag and suppress self-generated traffic
@load frameworks/packet-filter
redef PacketFilter::default_capture_filter = "not ether src 02:00:00:aa:00:00/ff:ff:ff:ff:ff:00";
```

### 8.2 iptables MARK for separate pcap ring buffer

```bash
# Tag noise traffic
iptables -t mangle -A PREROUTING -m mac --mac-source 02:00:00:aa:00:00/ff:ff:ff:ff:ff:00 \
  -j MARK --set-mark 0x10

# Capture tagged packets to a separate ring buffer (noise-only)
tcpdump -i virbr0 -w /pcap/noise/noise-%Y%m%d.pcap \
  'ether src 02:00:00:aa:00:00/ff:ff:ff:ff:ff:00'

# Capture attacker traffic (excluding noise MACs)
tcpdump -i virbr0 -w /pcap/attacker/capture-%Y%m%d.pcap \
  'not ether src 02:00:00:aa:00:00/ff:ff:ff:ff:ff:00'
```

---

## 9. Detection Evasion Checklist

An attacker attempting to fingerprint your honeypot will check for these artefacts. Verify each before going live:

| Signal | How to verify | Fix |
|---|---|---|
| Silent ARP table | `arping -I virbr0 10.0.1.10` — expect ARP reply | Enable Scapy ARP thread |
| No NTP UDP 123 | `tcpdump -i virbr0 udp port 123` for 3 min | Enable cron NTP + Scapy NTP |
| Flat DNS (no outbound queries) | `tcpdump -i virbr0 udp port 53` | Enable cron DNS + Scapy DNS |
| Perfect inter-arrival times | Check pcap in Wireshark — intervals must be irregular | Use `--multiplier=0.1` with tcpreplay + Scapy random sleeps |
| Identical packet payloads on loop | Replay same PCAP forever → byte-identical payloads | Rotate PCAPs weekly; use different MAWI captures |
| TTL fingerprint mismatch | OS TTL 64 (Linux) vs 128 (Windows) — must match persona | Set TTL in Scapy per host: `IP(ttl=128)` for Windows personas |
| TCP window size anomaly | Wireshark → Statistics → TCP Stream Graphs | Set correct window per persona in Scapy (`TCP(window=65535)`) |
| No NBNS / LLMNR | Windows hosts broadcast NBNS every ~60s | Add NBNS UDP 137 emitter in Scapy |
| No SSDP (UPnP) | Smart devices emit SSDP to `239.255.255.250:1900` | Add `sendp(UDP SSDP multicast)` for IoT personas |

---

## 10. Tool Reference

| Tool | Purpose | Install |
|---|---|---|
| [INetSim](https://www.inetsim.org/) | Simulates DNS, HTTP, SMTP, NTP, FTP, IRC response services | `apt-get install inetsim` |
| [tcpreplay](https://tcpreplay.appneta.com/) | Replays real PCAP captures onto bridge at controlled rate | `apt-get install tcpreplay` |
| [tcprewrite](https://tcpreplay.appneta.com/wiki/tcprewrite.html) | Rewrites PCAP IPs/MACs to match honeypot subnet | bundled with tcpreplay |
| [Scapy](https://scapy.net/) | Craft and send arbitrary protocol-accurate packets | `pip install scapy` |
| [MAWI captures](http://mawi.wide.ad.jp/mawi/) | Real backbone PCAP files for tcpreplay background | free download |
| [Wireshark](https://www.wireshark.org/) | Verify noise traffic authenticity and timing | `apt-get install wireshark` |
| ebtables | Permit spoofed MACs on KVM Linux bridge | `apt-get install ebtables` |

---

*Last updated: 2026-07-26 — KVM host deployment, Docker honeypot stack.*
