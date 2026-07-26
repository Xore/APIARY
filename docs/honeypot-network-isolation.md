# Best Practices for Isolating the Honeypot Host Network Traffic

> **Environment:** KVM host (bare-metal, not a nested hypervisor). All commands
> target `libvirt` / `virsh` and the host kernel network stack directly.
> Docker containers run via `docker compose` as defined in the root
> `docker-compose.yml`.

---

## Table of Contents

1. [Threat Model](#1-threat-model)
2. [Network Zone Design](#2-network-zone-design)
3. [libvirt Network Configurations](#3-libvirt-network-configurations)
4. [Anti-Spoofing with libvirt nwfilter](#4-anti-spoofing-with-libvirt-nwfilter)
5. [Host Firewall — iptables / nftables](#5-host-firewall--iptables--nftables)
6. [Bridge-Level Filtering with ebtables](#6-bridge-level-filtering-with-ebtables)
7. [Preventing Host Reachability from Guests](#7-preventing-host-reachability-from-guests)
8. [Out-of-Band Management Interface](#8-out-of-band-management-interface)
9. [Docker Container Network Isolation](#9-docker-container-network-isolation)
10. [Monitoring & Anomaly Detection](#10-monitoring--anomaly-detection)
11. [Periodic Audit Checklist](#11-periodic-audit-checklist)
12. [Pitfalls & Known Issues](#12-pitfalls--known-issues)

---

## 1. Threat Model

Understanding what you are protecting against drives every decision in this
guide. The honeypot host faces **three distinct adversary positions**:

| Threat | Source | Risk |
|--------|--------|------|
| **Internet attacker** | Public IP exposure | Honeypot compromised, used as pivot |
| **Guest escape** | Malware running inside a KVM guest | Host kernel reached via QEMU CVE or misconfiguration |
| **Container breakout** | Malicious payload in Cowrie/Dionaea | Docker container reaches host or other containers |

**Design principle:** Every zone is hostile until explicitly whitelisted.
The honeypot containers are intentionally exposed — but exposure must be
**narrowly scoped** so a compromise never propagates to:

- The KVM host OS itself
- The management/admin network
- Other containers or VMs in the stack
- Upstream networks (your ISP, your organisation)

---

## 2. Network Zone Design

Four zones are sufficient for the full honeypot-stack:

```
┌─────────────────────────────────────────────────────────────────┐
│  INTERNET (untrusted)                                           │
│  └─ Inbound: attacker-initiated connections to honeypots       │
│  └─ Outbound: honeypots NEVER initiate real internet traffic    │
└─────────────────────────────────────────────────────────────────┘
           │ (only ports in EXPOSE list reach Zone A)
┌─────────────────────────────────────────────────────────────────┐
│  ZONE A — Honeypot DMZ (docker bridge: honey-dmz)             │
│  Cowrie · Dionaea · Conpot · HTTP-honeypot · Snare/Tanner    │
│  └─ Accept: inbound from internet on declared ports            │
│  └─ Allow: push logs to Zone C (Elasticsearch / Filebeat)     │
│  └─ BLOCK: access to host, Zone B, Zone D                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  ZONE B — Malware Analysis (libvirt: virbr-mal, isolated)     │
│  KVM guests: analysis-win10, analysis-ubuntu, ...             │
│  └─ Accept: inbound from host only (sample delivery)          │
│  └─ Allow: outbound to INetSim on host (10.66.0.1) only       │
│  └─ BLOCK: all real internet, Zone A, Zone C, Zone D          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  ZONE C — Analysis Stack (docker bridge: analysis-net)        │
│  Arkime · Elasticsearch · Kibana · Grafana · Filebeat         │
│  └─ Accept: log ingestion from Zone A (one-way push only)     │
│  └─ Allow: web UI access from Zone D (admin) only             │
│  └─ BLOCK: all internet, Zone B                               │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  ZONE D — Management (separate physical NIC or VLAN)          │
│  SSH admin access · Kibana/Grafana browser · git push          │
│  └─ Isolated from all other zones at the NIC/VLAN level       │
│  └─ Protected by allowlist: only your admin IP/CIDR           │
└─────────────────────────────────────────────────────────────────┘
```

**IP Addressing Summary**

| Zone | Interface | Subnet | Routed? |
|------|-----------|--------|---------|
| A — Honeypot DMZ | `honey-dmz` (Docker) | `172.20.0.0/24` | NAT in only |
| B — Malware analysis | `virbr-mal` (libvirt) | `10.66.0.0/24` | No routing |
| C — Analysis stack | `analysis-net` (Docker) | `172.21.0.0/24` | Internal only |
| D — Management | `eth1` (physical/VLAN) | `192.168.100.0/24` | Admin only |

---

## 3. libvirt Network Configurations

### 3.1 Isolated Malware Bridge (Zone B)

No `<forward>` element — completely air-gapped from the host routing table.

```xml
<!-- /etc/libvirt/qemu/networks/malware-isolated.xml -->
<network>
  <name>malware-isolated</name>
  <bridge name="virbr-mal" stp="on" delay="0"/>
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

# Confirm: no route to internet exists on this bridge
ip route show table all | grep virbr-mal
# Expected output: only 10.66.0.0/24 local route, nothing else
```

### 3.2 Honeypot Exposure Bridge (Zone A)

NAT-forwarded for inbound attacker traffic. Outbound from containers to
the real internet is **explicitly blocked** by iptables rules in §5.

```xml
<!-- /etc/libvirt/qemu/networks/honeypot.xml -->
<network>
  <name>honeypot</name>
  <bridge name="virbr-honey" stp="on" delay="0"/>
  <forward mode="nat">
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

### 3.3 Verify libvirt Firewall Backend

Since libvirt ≥ 10.x, the default firewall backend may switch from iptables
to nftables depending on distribution. Docker also manages iptables rules.
Mixing backends causes silent rule conflicts. [web:268]

```bash
# Check the current backend
grep -i firewall_backend /etc/libvirt/network.conf 2>/dev/null || echo 'default'

# If Docker is in the stack, force libvirt to use iptables to avoid conflicts
cat >> /etc/libvirt/network.conf << 'EOF'
firewall_backend = "iptables"
EOF
systemctl restart virtnetworkd || systemctl restart libvirtd
```

> ⚠️ **Why this matters for this stack:** Docker manages its own iptables
> FORWARD chain. If libvirt uses nftables and Docker uses iptables, packets
> from a compromised Cowrie container could slip through libvirt rules that
> Docker never sees, or vice versa. Aligning both to iptables removes this
> ambiguity. [web:268]

---

## 4. Anti-Spoofing with libvirt nwfilter

libvirt's `nwfilter` applies iptables/ebtables rules per-NIC at the hypervisor
level — inside the guest kernel cannot override them. [web:258]

### 4.1 Apply the Built-in Clean-Traffic Filter

```bash
# This single filter blocks MAC spoofing, IP spoofing, and ARP spoofing
# from any guest NIC it is attached to.
virsh nwfilter-list | grep clean-traffic
# Should show: clean-traffic
```

Attach it in the guest domain XML:

```xml
<!-- Inside <devices> in the guest domain XML -->
<interface type='network'>
  <mac address='52:54:00:ab:cd:ef'/>
  <source network='malware-isolated'/>
  <model type='virtio'/>
  <filterref filter='clean-traffic'>
    <parameter name='IP' value='10.66.0.XX'/>   <!-- guest DHCP lease -->
  </filterref>
</interface>
```

```bash
# Verify the filter is enforced after VM start
virsh nwfilter-binding-list
ebtables -L | grep 10.66.0
```

### 4.2 Custom nwfilter — Deny All Except INetSim

For malware VMs, add a stricter custom filter that only permits traffic
to the INetSim host IP and blocks everything else at the NIC level:

```xml
<!-- /etc/libvirt/qemu/nwfilters/malware-vm-strict.xml -->
<filter name='malware-vm-strict' chain='root'>
  <rule action='accept' direction='out' priority='100'>
    <ip dstipaddr='10.66.0.1' dstipmask='255.255.255.255'/>
  </rule>
  <rule action='accept' direction='in' priority='100'>
    <ip srcipaddr='10.66.0.1' srcipmask='255.255.255.255'/>
  </rule>
  <!-- DHCP is handled by libvirt NAT, allow it -->
  <rule action='accept' direction='out' priority='200'>
    <udp dstportstart='67' dstportend='68'/>
  </rule>
  <!-- Drop everything else -->
  <rule action='drop' direction='inout' priority='1000'>
    <all/>
  </rule>
</filter>
```

```bash
virsh nwfilter-define /etc/libvirt/qemu/nwfilters/malware-vm-strict.xml
# Then reference it in the domain XML instead of 'clean-traffic':
# <filterref filter='malware-vm-strict'>
#   <parameter name='IP' value='10.66.0.XX'/>
# </filterref>
```

---

## 5. Host Firewall — iptables / nftables

### 5.1 Zone A — Honeypot DMZ Rules

Honeypots must accept inbound attacker traffic on specific ports but must
**never initiate real outbound connections**. Attackers can download further
toolkits using captured credentials — allowing egress would make your host
a relay for further attacks.

```bash
#!/bin/bash
# scripts/firewall-honeypot-dmz.sh
# Apply Zone A rules. Run once at boot (or via systemd unit).
set -euo pipefail

HONEY_BR="virbr-honey"
HONEY_NET="10.67.0.0/24"
PUBLIC_IF="eth0"    # Your internet-facing NIC

# --- Inbound: allow attacker traffic to honeypot ports only ---
DECLARED_PORTS="22,23,80,443,2222,8080,8888,102,502,1883,5000"
iptables -A FORWARD -i "$PUBLIC_IF" -o "$HONEY_BR" \
  -p tcp -m multiport --dports $DECLARED_PORTS \
  -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

iptables -A FORWARD -i "$HONEY_BR" -o "$PUBLIC_IF" \
  -m conntrack --ctstate ESTABLISHED -j ACCEPT

# --- Outbound: BLOCK all honeypot-initiated internet traffic ---
# Honeypots should never initiate connections to real IPs.
# Allow only established/related responses.
iptables -I FORWARD -i "$HONEY_BR" -o "$PUBLIC_IF" \
  -m conntrack --ctstate NEW -j DROP

# --- Block honeypot zone from reaching host or other zones ---
iptables -A FORWARD -s "$HONEY_NET" -d 192.168.100.0/24 -j DROP   # Zone D
iptables -A FORWARD -s "$HONEY_NET" -d 172.21.0.0/24   -j DROP   # Zone C
iptables -A FORWARD -s "$HONEY_NET" -d 10.66.0.0/24    -j DROP   # Zone B

# Block honeypot from reaching the host itself
iptables -A INPUT -i "$HONEY_BR" -s "$HONEY_NET" \
  ! -d 10.67.0.1 -j DROP

echo "Zone A rules applied."
```

### 5.2 Zone B — Malware Analysis Rules

```bash
#!/bin/bash
# scripts/firewall-malware-analysis.sh
set -euo pipefail

MAL_BR="virbr-mal"
MAL_NET="10.66.0.0/24"
INETSIM_IP="10.66.0.1"

# Allow malware VM → INetSim only
iptables -A FORWARD -i "$MAL_BR" -d "$INETSIM_IP" -j ACCEPT
iptables -A FORWARD -i "$MAL_BR" ! -d "$INETSIM_IP" -j DROP

# Allow INetSim replies back to VMs
iptables -A FORWARD -o "$MAL_BR" -s "$INETSIM_IP" -j ACCEPT

# Hard block: malware bridge CANNOT reach the real internet
iptables -A FORWARD -i "$MAL_BR" -o eth0 -j DROP

# Block malware bridge from reaching host management
iptables -A INPUT -i "$MAL_BR" -s "$MAL_NET" ! -d "$INETSIM_IP" -j DROP

# Redirect all outbound TCP/UDP from VMs to INetSim (belt-and-suspenders)
iptables -t nat -A PREROUTING -i "$MAL_BR" -p tcp ! -d "$INETSIM_IP" \
  -j DNAT --to-destination "$INETSIM_IP"
iptables -t nat -A PREROUTING -i "$MAL_BR" -p udp --dport 53 ! -d "$INETSIM_IP" \
  -j DNAT --to-destination "$INETSIM_IP"

echo "Zone B rules applied."
```

### 5.3 Zone C — Analysis Stack Rules

```bash
#!/bin/bash
# scripts/firewall-analysis-stack.sh
set -euo pipefail

ANAL_BR="br-analysis-net"   # Docker bridge name (check: docker network inspect analysis-net)
ADMIN_NET="192.168.100.0/24"

# Allow log ingestion from Zone A (one-directional push)
iptables -A FORWARD -i virbr-honey -o "$ANAL_BR" \
  -p tcp --dport 9200 -j ACCEPT   # Elasticsearch
iptables -A FORWARD -i virbr-honey -o "$ANAL_BR" \
  -p tcp --dport 5044 -j ACCEPT   # Filebeat/Logstash

# Allow admin access to dashboards from Zone D only
iptables -A INPUT -i eth1 -s "$ADMIN_NET" \
  -p tcp -m multiport --dports 5601,3000,8005 -j ACCEPT  # Kibana, Grafana, Arkime

# Block all other inbound to analysis stack
iptables -A INPUT -i eth0 -p tcp \
  -m multiport --dports 5601,3000,8005,9200 -j DROP

echo "Zone C rules applied."
```

### 5.4 Persist Rules Across Reboots

```bash
apt install iptables-persistent netfilter-persistent

# After all rules are applied:
netfilter-persistent save

# Create a systemd unit to re-apply custom scripts after docker+libvirt start
cat > /etc/systemd/system/honeypot-firewall.service << 'EOF'
[Unit]
Description=Honeypot Zone Firewall Rules
After=network-online.target docker.service libvirtd.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/honeypot-stack/scripts/firewall-honeypot-dmz.sh
ExecStart=/opt/honeypot-stack/scripts/firewall-malware-analysis.sh
ExecStart=/opt/honeypot-stack/scripts/firewall-analysis-stack.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now honeypot-firewall.service
```

---

## 6. Bridge-Level Filtering with ebtables

iptables operates at Layer 3 (IP). ebtables filters at Layer 2 (Ethernet frames
on the bridge). This catches attacks that bypass IP filtering, such as ARP
poisoning and MAC flooding. [web:258]

```bash
# Prevent ARP spoofing on the malware bridge
# Only allow the correct IP↔MAC bindings (fill in real DHCP leases)
ebtables -A FORWARD --in-interface virbr-mal \
  -p ARP --arp-opcode Reply \
  --arp-ip-src  ! 10.66.0.0/24 -j DROP

# Block VMs from sending broadcast storms
ebtables -A FORWARD --in-interface virbr-mal \
  --pkttype broadcast \
  -m limit --limit 10/second -j ACCEPT
ebtables -A FORWARD --in-interface virbr-mal \
  --pkttype broadcast -j DROP

# Prevent VLAN hopping via 802.1Q tags from guests
ebtables -A INPUT --in-interface virbr-mal \
  -p 802_1Q -j DROP

# Persist
ebtables-save > /etc/ebtables/rules.v4
```

Note: libvirt's `nwfilter` covers ARP spoofing automatically when
`clean-traffic` is applied (see §4.1). Use ebtables as a second layer or
when not using nwfilter.

---

## 7. Preventing Host Reachability from Guests

A compromised guest must not reach the KVM host's management services
(sshd, libvirtd API socket, Docker socket). This is the most critical
boundary in the entire setup.

### 7.1 Block Guest Access to Host Services

```bash
# The bridge gateway IP (e.g. 10.66.0.1) is the host. Guests can reach it
# for DHCP/INetSim. Block everything else the host listens on.
HOST_SERVICES="22,2375,2376,9090,8080"

iptables -A INPUT -i virbr-mal -p tcp \
  -m multiport --dports $HOST_SERVICES -j DROP

iptables -A INPUT -i virbr-honey -p tcp \
  -m multiport --dports $HOST_SERVICES -j DROP

# Also block ICMP from guests to host (prevents host enumeration)
iptables -A INPUT -i virbr-mal   -p icmp -j DROP
iptables -A INPUT -i virbr-honey -p icmp -j DROP
```

### 7.2 Disable Unnecessary Services on the Host

```bash
# Audit what is listening
ss -tlnup

# Disable services that should not exist on a dedicated honeypot host
systemctl disable --now avahi-daemon cups bluetooth ModemManager

# Bind sshd to management NIC only (never to honeypot NIC)
sed -i 's/^#ListenAddress.*/ListenAddress 192.168.100.X/' /etc/ssh/sshd_config
systemctl restart sshd

# Confirm sshd is no longer listening on public or VM interfaces
ss -tlnp | grep sshd
# Should show only 192.168.100.X:22
```

### 7.3 Restrict the libvirt API Socket

The libvirt UNIX socket (`/var/run/libvirt/libvirt-sock`) allows full VM
control. Ensure it is only accessible to the `libvirt` group, not world-readable.

```bash
ls -la /var/run/libvirt/libvirt-sock
# Expected: srwxrwx--- root libvirt

# If wrong permissions:
chmod 0770 /var/run/libvirt/libvirt-sock
chgrp libvirt /var/run/libvirt/libvirt-sock

# Never expose the TCP libvirt socket (disabled by default):
grep 'listen_tcp' /etc/libvirt/libvirtd.conf
# Should be: listen_tcp = 0
```

### 7.4 Secure the Docker Socket

```bash
# Docker socket = root equivalent. Never mount it in honeypot containers.
# Verify none of the stack containers expose it:
grep -r '/var/run/docker.sock' /opt/honeypot-stack/
# Must return: no results from honeypot-facing containers

# If a management container needs it (e.g. Portainer), keep it on Zone C only.
```

### 7.5 AppArmor / SELinux for QEMU Processes

```bash
# Ubuntu ships with AppArmor profiles for libvirt
aa-status | grep -i libvirt

# Ensure profiles are enforcing
aa-enforce /etc/apparmor.d/usr.sbin.libvirtd
aa-enforce /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper
aa-enforce /etc/apparmor.d/libvirt/TEMPLATE.qemu

# Check for AppArmor denials in real time
journalctl -f | grep 'apparmor="DENIED"'
```

---

## 8. Out-of-Band Management Interface

The honeypot host must be administered over a **separate NIC or VLAN** that
is not reachable from the internet or any VM zone. This ensures that even if
the honeypot NIC is compromised, SSH access and libvirt control are unaffected.

### 8.1 Two-NIC Setup (Recommended)

```
eth0  → Public internet (honeypot traffic only)
eth1  → Management VLAN (SSH, Kibana, git push)
```

```bash
# Assign static IP to management NIC
cat > /etc/netplan/02-mgmt.yaml << 'EOF'
network:
  version: 2
  ethernets:
    eth1:
      dhcp4: false
      addresses: [192.168.100.10/24]
      routes:
        - to: 192.168.100.0/24
          via: 192.168.100.1
          metric: 100
      nameservers:
        addresses: [192.168.100.1]
EOF
netplan apply
```

### 8.2 Block Management Port on Public NIC

```bash
# SSH must never be reachable from eth0
iptables -A INPUT -i eth0 -p tcp --dport 22 -j DROP
iptables -A INPUT -i eth0 -p tcp --dport 22 -j LOG \
  --log-prefix "SSH-SCAN-BLOCKED: " --log-level 4
```

### 8.3 Rate-Limit SSH on Management NIC

```bash
iptables -A INPUT -i eth1 -p tcp --dport 22 \
  -m conntrack --ctstate NEW \
  -m recent --set --name MGMT_SSH
iptables -A INPUT -i eth1 -p tcp --dport 22 \
  -m conntrack --ctstate NEW \
  -m recent --update --seconds 60 --hitcount 5 \
  --name MGMT_SSH -j DROP
iptables -A INPUT -i eth1 -s 192.168.100.0/24 \
  -p tcp --dport 22 -j ACCEPT
```

---

## 9. Docker Container Network Isolation

Docker's default bridge (`docker0`) connects all containers unless you
explicitly use named networks. The honeypot-stack `docker-compose.yml`
must place each service tier on the correct named network.

### 9.1 Named Networks in `docker-compose.yml`

```yaml
networks:
  # Zone A: honeypot DMZ — exposed to internet via host port bindings
  honey-dmz:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
    driver_opts:
      com.docker.network.bridge.name: honey-dmz

  # Zone C: analysis stack — internal only, never exposed
  analysis-net:
    driver: bridge
    internal: true          # <— key: Docker blocks all external routing
    ipam:
      config:
        - subnet: 172.21.0.0/24
    driver_opts:
      com.docker.network.bridge.name: br-analysis-net
```

Assign each service to its zone:

```yaml
services:
  cowrie:
    networks: [honey-dmz]
    # NOT analysis-net — Cowrie must not reach Elasticsearch directly

  filebeat:  # Bridge between zones A and C (log shipper only)
    networks: [honey-dmz, analysis-net]

  elasticsearch:
    networks: [analysis-net]
    # internal: true means no outbound internet from Elasticsearch

  kibana:
    networks: [analysis-net]
    ports:
      - "127.0.0.1:5601:5601"   # Bind to localhost only; expose via nginx+auth
```

### 9.2 Disable ICC (Inter-Container Communication) on DMZ Bridge

By default Docker allows all containers on the same bridge to talk to each
other. Disable this on the honeypot DMZ so a compromised Cowrie container
cannot reach Dionaea or Conpot directly:

```bash
# Set icc=false on the honey-dmz bridge
# In Docker daemon config:
cat > /etc/docker/daemon.json << 'EOF'
{
  "icc": false,
  "iptables": true,
  "ip-forward": true,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
systemctl restart docker
```

> Note: `icc=false` applies globally. If containers must communicate
> (e.g. Filebeat → Elasticsearch), they must be on the same Docker
> **named network** (`analysis-net`), which Docker handles with explicit
> link rules regardless of the `icc` setting.

### 9.3 Drop Privileged Containers and Cap Restrictions

All honeypot containers must run without `--privileged`. Add security
defaults to the compose file:

```yaml
# Add to every honeypot service (Cowrie, Dionaea, Conpot, etc.)
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
cap_add:
  - NET_BIND_SERVICE   # Only if the container binds ports < 1024
read_only: true
tmpfs:
  - /tmp
  - /run
```

---

## 10. Monitoring & Anomaly Detection

Isolation controls are only effective if violations are **detected and alerted
on**. The following rules catch common isolation failures.

### 10.1 iptables Logging Rules

```bash
# Log any packet dropped from Zone B that was NOT destined for INetSim
iptables -A FORWARD -i virbr-mal ! -d 10.66.0.1 \
  -j LOG --log-prefix "ZONE-B-ESCAPE: " --log-level 4

# Log any honeypot container attempting outbound NEW connections
iptables -A FORWARD -i honey-dmz -o eth0 \
  -m conntrack --ctstate NEW \
  -j LOG --log-prefix "HONEY-EGRESS-BLOCKED: " --log-level 4

# Log SSH attempts on public NIC
iptables -A INPUT -i eth0 -p tcp --dport 22 \
  -j LOG --log-prefix "SSH-ON-PUBLIC: " --log-level 4
```

### 10.2 Fail2ban for Host SSH

```bash
apt install fail2ban

cat > /etc/fail2ban/jail.d/honeypot-host.conf << 'EOF'
[sshd]
enabled  = true
port     = 22
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 3600
findtime = 300
EOF

systemctl enable --now fail2ban
```

### 10.3 Alert on Zone Crossing (Shell Script + cron)

```bash
#!/bin/bash
# scripts/zone-crossing-alert.sh
# Check iptables log for isolation violations and alert.
LOG_FILE="/var/log/kern.log"
ALERT_EMAIL="your@email.com"
LAST_CHECK_FILE="/run/zone-crossing-last-check"

SINCE=$(cat "$LAST_CHECK_FILE" 2>/dev/null || echo "1 hour ago")
date > "$LAST_CHECK_FILE"

MATCHES=$(grep -E 'ZONE-B-ESCAPE|HONEY-EGRESS-BLOCKED|SSH-ON-PUBLIC' \
  "$LOG_FILE" 2>/dev/null | wc -l)

if (( MATCHES > 0 )); then
  BODY=$(grep -E 'ZONE-B-ESCAPE|HONEY-EGRESS-BLOCKED|SSH-ON-PUBLIC' \
    "$LOG_FILE" | tail -20)
  echo -e "Subject: [HONEYPOT] Zone isolation violation detected\n\n$BODY" \
    | sendmail "$ALERT_EMAIL"
  logger -t zone-crossing "ALERT: $MATCHES isolation violations found"
fi
```

```bash
chmod +x /opt/honeypot-stack/scripts/zone-crossing-alert.sh
echo '*/5 * * * * root /opt/honeypot-stack/scripts/zone-crossing-alert.sh' \
  > /etc/cron.d/zone-crossing-alert
```

### 10.4 Netstat / ss Audit

```bash
#!/bin/bash
# scripts/listening-audit.sh
# Print all services listening on non-loopback interfaces.
# Run manually or schedule weekly to detect unexpected exposure.
echo "=== Listening services (non-loopback) ==="
ss -tlnup | grep -v '127.0.0.1\|\[::1\]'

echo "=== Docker published ports ==="
docker ps --format 'table {{.Names}}\t{{.Ports}}' | grep '0.0.0.0\|:::'

echo "=== libvirt network list ==="
virsh net-list --all
```

---

## 11. Periodic Audit Checklist

Run this checklist monthly or after any configuration change.

```bash
#!/bin/bash
# scripts/isolation-audit.sh — print PASS/FAIL for each check
PASS="\e[32m[PASS]\e[0m"
FAIL="\e[31m[FAIL]\e[0m"

check() {
  local desc="$1"; shift
  if eval "$@" &>/dev/null; then
    echo -e "$PASS $desc"
  else
    echo -e "$FAIL $desc"
  fi
}

echo "=== Network Isolation Audit: $(date) ==="

# 1. SSH not listening on public NIC
check "SSH not on eth0" \
  "! ss -tlnp | grep ':22' | grep -v '192.168.100'"

# 2. Malware bridge has no default route
check "virbr-mal has no default route" \
  "! ip route show table all | grep 'default.*virbr-mal'"

# 3. Zone B DNAT redirect active
check "Zone B DNAT to INetSim active" \
  "iptables -t nat -L PREROUTING -n | grep '10.66.0.1'"

# 4. Docker analysis-net is internal
check "analysis-net is internal Docker network" \
  "docker network inspect analysis-net | grep -q '\"Internal\": true'"

# 5. No honeypot container is privileged
check "No honeypot container is privileged" \
  "! docker inspect \$(docker ps -q) | grep -q '\"Privileged\": true'"

# 6. libvirt AppArmor profiles enforcing
check "libvirtd AppArmor profile enforcing" \
  "aa-status | grep -q 'libvirtd.*enforce'"

# 7. Zone A egress block active
check "Zone A outbound NEW connections blocked" \
  "iptables -L FORWARD -n | grep -q 'DROP.*honey-dmz'"

# 8. libvirt TCP socket disabled
check "libvirt TCP socket disabled" \
  "grep -q 'listen_tcp = 0' /etc/libvirt/libvirtd.conf"

# 9. Docker socket not mounted in any running container
check "Docker socket not mounted in containers" \
  "! docker inspect \$(docker ps -q) 2>/dev/null | grep -q 'docker.sock'"

# 10. INetSim running on management NIC
check "INetSim listening on 10.66.0.1" \
  "ss -tlnup | grep -q '10.66.0.1'"

echo "=== Audit complete ==="
```

```bash
chmod +x /opt/honeypot-stack/scripts/isolation-audit.sh
```

---

## 12. Pitfalls & Known Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| iptables rules lost after reboot | Not persisted | `netfilter-persistent save`; add `honeypot-firewall.service` |
| Docker rewrites iptables on restart | Docker always re-inserts DOCKER chains | Run `honeypot-firewall.service` **after** Docker starts (`After=docker.service`) |
| libvirt nwfilter not applied to VM | Filter not in domain XML | Add `<filterref>` to every interface; `virsh nwfilter-binding-list` to verify |
| Honeypot container reaches internet | icc=false not set, or network missing `internal:true` | Check `docker network inspect` for `Internal: true` on analysis-net |
| Guest escapes to host via bridge IP | INPUT rules missing for bridge interfaces | Add `iptables -A INPUT -i virbr-mal ...` rules explicitly |
| libvirt/Docker backend conflict | libvirt uses nftables, Docker uses iptables | Set `firewall_backend = "iptables"` in `/etc/libvirt/network.conf` [web:268] |
| AppArmor not enforcing after update | Profile not reloaded post kernel upgrade | `apparmor_parser -r /etc/apparmor.d/usr.sbin.libvirtd` |
| Admin dashboard exposed on eth0 | Kibana/Grafana bind to `0.0.0.0` | Always use `127.0.0.1:PORT` in compose ports; expose via nginx on eth1 only |
| Zone crossing not logged | LOG rule after DROP rule (never reached) | Insert LOG rules **before** DROP rules with lower rule number |
| ebtables rules don't survive reboot | `ebtables-persistent` not installed | `apt install ebtables netfilter-persistent`; run `netfilter-persistent save` |

---

## References

- [libvirt Firewall and Network Filtering](https://libvirt.org/firewall.html)
- [libvirt Virtual Networking](https://wiki.libvirt.org/VirtualNetworking.html)
- [libvirt nwfilter Documentation](https://libvirt.org/formatnwfilter.html)
- [libvirt nftables Backend (Fedora)](https://fedoraproject.org/wiki/Changes/LibvirtVirtualNetworkNFTables)
- [Docker Network Security](https://docs.docker.com/engine/network/)
- [KVM Network Isolation Q&A](https://stackoverflow.com/questions/43929557/what-is-the-best-way-to-isolate-the-networks-and-customers-kvm-qemu-libvirt)
- [Honeypot Escape Prevention (Tencent Cloud)](https://www.tencentcloud.com/techpedia/118448)
- See also: [`docs/kvm-network-traffic-analysis.md`](kvm-network-traffic-analysis.md)
- See also: [`docs/kvm-snapshot-vs-golden-image.md`](kvm-snapshot-vs-golden-image.md)
