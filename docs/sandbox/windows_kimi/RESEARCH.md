# Deep Research: From Static Golden Image to Living Analysis Workstation

Research summary and design rationale for the detnode upgrades
(60-living-persona.ps1, 70-traffic-noise.ps1, tools/filter-pcap.sh).

---

## 1. What modern malware actually checks

Sources: Red Report 2026 (Picus), VMRay evasion series, Unit42, MITRE
T1497/T1497.002/T1497.003, Apriorit sandbox-evasion survey.

### 1.1 User-activity checks (T1497.002) — back in the Top 10 in 2026

| Check | Real-world example | Defeat |
|---|---|---|
| Mouse moved at all (GetCursorPos loop, Sleep(300)) | LummaC2 v4.0 (Nov 2025) | Any continuous movement |
| **Movement quality**: 5 consecutive distinct positions, Euclidean distance + segment-angle smoothness vs hardcoded threshold | LummaC2 trigonometry check | Curved Bezier paths, ease-in-out velocity, micro-jitter — straight lines and constant speed fail |
| Clicks / double-clicks / scrolling inside a document before macros fire | macro families, Excel cell-click checks | Periodic clicks + wheel scroll events |
| GetLastInputInfo vs GetTickCount (idle time) | many stealers | Constant low-grade input |
| Dialog boxes / fake EULAs that must be clicked | various | Clicker with periodic center-screen clicks (partial) |
| Browser history, cache, cookies, bookmarks | widespread | Seeded history (50-chrome-history.ps1) + living browsing |
| Files on Desktop/Documents, RecentFiles count | Office-macro families | Persona docs (20-persona.ps1) + rotating recent files |
| Process count / process-name diversity | Blitz (2024) | Keep Chrome, Office apps, notepad open |

**Key insight from Red Report 2026:** angle-smoothness analysis means naive
"jiggler" scripts (teleport cursor, straight lines, fixed cadence) are now
*detected as synthetic*. The daemon in 60-living-persona.ps1 uses quadratic
Bezier curves with Gaussian-perpendicular control-point offsets and
ease-in-out velocity so consecutive segment angles change smoothly.

### 1.2 Environment checks (T1497.001)

Already handled in this repo: SMBIOS Dell identity, `-cpu host` with
Hyper-V enlightenments, 4 cores / 8GB / 80GB disk, corporate OEM registry.
Remaining tells to verify with **pafish** and **al-khaser** inside the guest:

- rdtsc-forced VM-exit timing (hardest; no reliable KVM fix — CAPE counters
  it dynamically via debugger `fake-rdtsc` instead)
- virtio driver names (Get-PnpEntity shows them; consider renaming via
  registry or switching to e1000e for the NIC)
- MAC OUI if using default QEMU OUI 52:54:00 — set a Dell/Intel OUI
- Screen resolution: run the desktop at 1920x1080, not 800x600
- System uptime < X minutes: keep the persona warm for hours pre-detonation

### 1.3 Time-based checks (T1497.003)

Long sleeps, timestamp-before/after-sleep comparison, date-gated logic
bombs. A pure persona can't fix these — this is where **CAPEv2's debugger**
(YARA-programmable breakpoints, `fake-rdtsc`, action=skip) is the right
tool. If you outgrow FakeNet-only analysis, bolt CAPE onto the same golden
image: it supports Win11 23H2 guests, per-analysis routing (drop/inetsim/
internet/VPN), Sysmon + EVTX collection, screenshots, and memory dumps.

---

## 2. The living persona architecture

### 2.1 Layers

```
Layer 0  Static artifacts     (20-persona, 50-chrome-history) — built into image
Layer 1  Presence daemon      (60-living-persona) — mouse/keyboard/scroll, always on
Layer 2  Traffic generator    (70-traffic-noise) — tagged background HTTP/DNS
Layer 3  (optional) GHOSTS    — CMU SEI NPC framework for multi-app behavior
```

### 2.2 Why a custom daemon instead of (only) GHOSTS

GHOSTS (cmu-sei/GHOSTS) is the gold standard: timeline-driven NPCs that
browse real sites, create Office documents with generated content, send
email, run shell commands — specifically built so that "defenders struggle
to filter NPC traffic" (SEI). It consists of a Windows client + an API
server (Docker Compose: API, Postgres, Grafana, n8n).

Recommendation:

- **Single detonation VM** → the custom daemon is enough: zero server
  dependency, compiles at provision time, hidden scheduled task, and it is
  *designed around the anti-evasion heuristics* (smoothness) rather than
  around range realism.
- **Multi-VM range / long-lived honeypot network** → deploy GHOSTS. Put the
  API stack on the Ubuntu host (`docker compose up -d` from
  src/Ghosts.Api), install the GHOSTS client on the golden image, and write
  a finance timeline: Outlook mail sync every ~9 min, SharePoint/ERP
  browsing bursts, Word doc editing 2-3x/day, Bloomberg/WSJ reading. The
  client is a single MSI/exe + JSON configs (timeline.json, email-content.csv).
- GHOSTS caveat (from upstream discussion #664, 2026): "scenario events"
  in the new UI are metadata-only and not executed by clients yet — use
  classic timeline.json handler configs, which work.

### 2.3 Continuous artifact accrual

A static image's artifacts decay in credibility (all history is from "before
the build date"). The living persona fixes that: the noise generator creates
fresh DNS cache entries and HTTP traffic, the daemon creates fresh notepad
sessions and input-event timestamps (GetLastInputInfo stays low), and —
importantly — Chrome history *grows* if you let the persona browse through
FakeNet with a visible (non-headless) Chrome instance.

Optional upgrade: extend noise-gen.ps1 to drive Chrome with
`--remote-debugging-port` + Selenium instead of Invoke-WebRequest so history,
cookies, and cache accrue naturally. Trade-off: heavier, flakier.

---

## 3. Tagged noise + deterministic filtering

The requirement "traffic that can be filtered out later" drives the design:

### 3.1 Triple tagging (all independent, all grep-able)

1. **Domain suffix** `*.mcg-persona.net` — filterable in pcaps
   (`dns.qry.name matches "\.mcg-persona\.net$"`), TLS SNI, FakeNet logs,
   proxy logs, Zeek/Suricata outputs.
2. **HTTP header** `X-Persona-Noise: 1` — survives hostname changes, visible
   in FakeNet's dumped HTTP requests.
3. **User-Agent marker** `MCGPersona/1.0` appended to a real Chrome UA —
   visible in HTTP logs; malware that copies "the browser UA" won't match
   unless it copies the whole string.

### 3.2 Filter implementation (tools/filter-pcap.sh)

Builds one tshark display filter from the markers and splits the capture
into `clean.pcap` / `noise.pcap`. Keep the noise pcap: it doubles as a
**baseline** — diff payload-run noise stats vs. no-payload baseline to catch
the noise generator itself being abused (e.g., malware piggybacking on the
persona's DNS channel would show up as query-volume anomalies).

### 3.3 What the filter cannot do (be honest with yourself)

- Noise and payload traffic share the guest IP; filtering is by *content
  markers*, not by flow. If you need strict flow separation, give the noise
  generator its own source IP (second NIC or a secondary address on the
  guest) and filter by `ip.addr == x.x.x.x`.
- ECH/hidden-SNI TLS degrades marker #1 at the handshake layer; DNS-layer
  filtering still works as long as the noise generator resolves first.
- Malware that imitates the noise generator exactly (suffix + header) would
  be filtered out — acceptable risk, since the suffix is a per-deployment
  secret you should change.

**Action item:** change `mcg-persona.net` to your own random suffix in
70-traffic-noise.ps1 *and* tools/filter-pcap.sh before first use.

---

## 4. Analysis usability upgrades (payload side)

The persona makes malware *run*; these make it *observable*:

1. **Sysmon + SwiftOnSecurity config** — install in the golden image
   (`sysmon64.exe -i sysmonconfig.xml -accepteula`). Process-create,
   network-connect, DNS-query, image-load, registry events go to
   `Microsoft-Windows-Sysmon/Operational`. This is the single highest-value
   visibility upgrade and is what CAPE ingests too.
2. **FakeNet listeners → structured logs** — FakeNet already dumps HTTP
   POSTs and packets; point its log dir at `C:\Detonation\fakenet-logs\`
   so each run's output is easy to grab via the overlay workflow.
3. **Capture at the host bridge, not in the guest** — detonate.sh with an
   isolated libvirt bridge (`detnet0`) + `tcpdump -i detnet0 -w run1.pcap`
   on the host. Guest-based capture (Wireshark) is tamper-able by the
   payload; host-side isn't.
4. **Zeek or Suricata on the host bridge** — Suricata with ET Open rules
   gives you IDS alerts per run for free; Zeek gives conn/dns/http logs
   that the noise filter also works on (same markers).
5. **Pre/post detonation diff script** — snapshot file lists, registry
   (reg export), autoruns (`autorunsc.exe -a * -c -accepteula`), and
   service lists before and after; diff to find persistence.
6. **Memory capture** — on the host: `virsh dump detnode-run1
   /tmp/run1.mem --memory-only` mid-run, analyze with Volatility 3
   (windows.pslist, malfind, netscan).
7. **Time budget** — with sleeps/logic bombs, run detonations for
   15-60 min, not 2-5 min. The persona's continuous activity keeps
   GetLastInputInfo low the entire time.

---

## 5. Suggested runbook

```
1. Boot overlay (detonate.sh run1)  → persona + noise + FakeNet auto-start
2. Warm-up 30-60 min (uptime, artifacts, noise baseline)
3. Start host-side capture: tcpdump -i <bridge> -w run1.pcap
4. Drop payload via \\vmshare or WinRM; execute as mwilson would
5. Observe 15-60 min; optional mid-run virsh memory dump
6. Kill VM; filter-pcap.sh run1.pcap run1_clean.pcap run1_noise.pcap
7. Diff autoruns/files/registry; carve FakeNet logs; analyze memory
8. Delete overlay
```

---

## Sources

- CAPEv2 repo & docs (Win11 23H2 support, debugger, routing): github.com/kevoreilly/CAPEv2, capev2.readthedocs.io
- CAPE guest hardening walkthrough (Defender/SmartScreen/Internet Options/Sysmon): endsec.au blog, 2024
- Red Report 2026 user-activity checks, LummaC2 mouse trigonometry: picussecurity.com T1497.002 explainer (2026-04)
- Sandbox evasion taxonomy + AI-based environment scoring: apriorit.com dev blog (2026-04)
- Human-interaction evasions & mitigations: Unit42 "Navigating the Vast Ocean of Sandbox Evasions"
- Context-aware triggers (time bombs, event gates): vmray.com evasion series (2025-05)
- GHOSTS NPC framework (timelines, NPCs, API/Grafana): cmu-sei.github.io/GHOSTS, github.com/cmu-sei/GHOSTS; SEI history page (2026-03); cylab.be GHOSTS v8.0 writeup (2025-03)
- GHOSTS scenario-events gap: GitHub discussion #664 (2026-07)
- UBER: user-behavior emulators defeating usage-artifact analysis: sunlab-gmu.github.io research slides
- MITRE ATT&CK T1497.003 procedure examples: attack.mitre.org
