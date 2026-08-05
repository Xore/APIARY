# GHOSTS Sandbox — Implementation Plan

> **Status**: Implemented and live-verified end to end. Host stack (#324),
> network policy (#325), client provisioning (#326), Workbench/dashboard
> integration (#327), and spool/worker integration (#328) are all shipped.
> Persona timeline content (#329) is in progress. See "What's verified"
> below for exactly what was tested, live, and how — not just what was
> configured.
> **Last updated**: 2026-08-03
> **Host platform**: KVM + QEMU + libvirt + docker-compose, same as
> `sandbox/windows` — no VMware, no Hyper-V, no CI-triggered detonation.
> **Tracking**: [#331](https://github.com/Xore/honeypot-stack/issues/331)
> (this chain), decided in
> [#300](https://github.com/Xore/honeypot-stack/issues/300).

---

## Why this exists, and why it is different from `sandbox/windows`

[#300](https://github.com/Xore/honeypot-stack/issues/300)'s research found
that GHOSTS' actual value — real external-site browsing, real document
downloads, real second-stage payload fetches — conflicts fundamentally with
`win11-sandbox`'s permanent no-WAN isolation. A sample detonated there can
never reach real C2 infrastructure by design; that is the entire point of
that pipeline. GHOSTS' realism requires the opposite: a guest that *can*
reach the real internet.

Rather than retrofitting WAN access onto the existing isolated network
(which would have weakened every other detonation route's guarantee), this
chain gives GHOSTS its own network segment, its own golden image, and its
own detonation route — **additive, not a replacement**. `win11-sandbox`
remains exactly as air-gapped as it always was.

**State this plainly, every time this document is read**: this is the one
detonation host in this repo with real WAN access, and that is deliberate,
not an oversight. Every other route (`sandbox/windows`, the Linux runner,
CAPE when it lands) is built around "the guest never has a real route to
the internet, so C2 checkins and second-stage downloads go to
FakeNet/INetSim, never anywhere real." A sample run through **this** host
can reach its actual C2 infrastructure, receive live second-stage payloads,
and exfiltrate real data if this sandbox's own artifacts contain anything
sensitive. What contains that blast radius is not "no route out" (this
host's whole reason for existing is that it *does* have one) — it is the
LAN-blocking network policy in `network-filter.sh`, verified live, not
just configured. Read "What's verified" below before treating this host as
safe to run anything through.

---

## Host Constraints

Same as `docs/sandbox/windows/IMPLEMENTATION_PLAN.md`:
- KVM/QEMU/libvirt + docker-compose only — no VMware, no Hyper-V
- No CI-triggered detonation — the dashboard's Workbench is the only
  trigger (`workbench_orchestrator.go` → spool file → host-side systemd
  worker)
- VM lifecycle via `virsh`/`qemu-img` only
- Results written to a spool directory the dashboard reads — no outbound
  network access from the orchestrator itself, no git push

Two constraints specific to this chain:
- **`win11-analysis.qcow2` and `win11-ghosts.qcow2` are never mixed.**
  `win11-ghosts.qcow2` is a full, independent `qemu-img convert` copy — no
  backing-file relationship, no shared writes, ever, after the copy is
  made. `sandbox/ghosts/provision-golden-image.sh` refuses to run against
  any path containing `analysis`; `orchestrate/run_sample.py` refuses to
  revert against one too.
- **Windows Defender stays enabled on `win11-ghosts.qcow2`.** Unlike
  `win11-analysis.qcow2` (disabled offline, #91), this guest keeps
  Defender on — explicit operator direction, not an oversight to fix
  later.

---

## Architecture Overview

```
Home server (KVM/libvirt host)
│
├── libvirt network: ghosts (virbr-ghosts, 10.20.30.0/24)         [#325]
│   <forward mode='nat' dev='ens9f0'> — REAL WAN egress, the one guest
│   network in this repo with this element present on purpose.
│   network-filter.sh: RFC1918 + 198.18.0.0/24 (IANA benchmarking space,
│   the Linux sandbox's forensic-egress net) DROPped on FORWARD; a
│   GHOSTS-IN chain on INPUT closing off every other host-owned address
│   (a multi-homed host otherwise answers for its own addresses
│   regardless of ingress interface — verified live, see below); one
│   narrow exception for the GHOSTS API's *post-DNAT backend* address
│   (Docker's port-publish DNAT rewrites the destination before FORWARD
│   runs) plus a DOCKER-USER rule for the return leg.
│
├── win11-ghosts guest (10.20.30.x, floating — no DHCP pin deployed yet,
│   see "Known gaps" below)                                   [#326/#327]
│   ├── Ghosts.Client.Universal (C:\ghosts\), not autostarted — the
│   │   detonation worker starts it per run
│   ├── #290's living-persona daemon (PersonaDaemon.exe, scheduled task
│   │   disguised as "Windows Shell Experience Helper") — disabled at
│   │   detonation time by the worker, not removed from the image
│   ├── Windows Defender: enabled (explicit operator direction)
│   ├── Same hardware/anti-detection profile as win11-kvm.xml (SMBIOS,
│   │   hidden KVM CPUID leaf, real disk serial) — none of that is
│   │   specific to the network-isolation model
│   └── WinRM (5985) + SMB (Samples/Logs, analyst-only #91) — host-
│       initiated only; verified live that this doesn't reopen the
│       guest's own outbound restrictions (#325's policy only restricts
│       guest-*originated* traffic)
│
├── Docker: ghosts-api + ghosts-postgres (ghosts_net, 10.90.0.0/24)  [#324]
│   Frontend/Grafana/n8n deliberately not deployed. ghosts-api published
│   on 10.20.30.1:5000 — virbr-ghosts's own gateway address, not a
│   docker-internal one (verified live in #325 that Docker's own `raw`
│   table blocks direct routing to a container backend IP from any
│   interface but its own bridge, regardless of FORWARD/DOCKER-USER
│   rules — the published-port path is what actually works)
│
└── Host-side GHOSTS sandbox worker (systemd path unit)              [#328]
    ├── Watches GHOSTS_SANDBOX_REQUEST_DIR for {hash}.request files
    │   written by dashboard/workbench_orchestrator.go's "windows-ghosts"
    │   analyzer — a deliberately opt-in-only Workbench selection, never
    │   auto-routed to by payload classification
    ├── process-ghosts-web-requests.sh resolves the hash against the same
    │   shared sample inbox sandbox/windows's own resolution step uses
    ├── orchestrate/run_sample.py: revert win11-ghosts.qcow2 → WinRM/SMB
    │   deliver sample → disable persona daemon → launch GHOSTS client →
    │   execute sample → Sysmon EVTX snapshot → pull GHOSTS' own activity
    │   log from Ghosts.Api's database → revert again, unconditionally
    └── Writes windows-ghosts-<job>.json → GHOSTS_SANDBOX_RESULTS_DIR,
        dashboard/sandbox.go's sandboxResult shape, "route": "windows-ghosts"
        so the result page's isolation description (#327) renders
        correctly instead of the default (wrong, for this route) claim of
        "no forwarding, strict libvirt NIC filter"
```

---

## Wiring pattern — mirrors the Windows sandbox's own Ghidra comparison

| Concern | GHOSTS sandbox (this plan) | Windows sandbox (reference) |
|---|---|---|
| Trigger | Workbench "windows-ghosts" analyzer → `{hash}.request` → `GHOSTS_SANDBOX_REQUEST_DIR` | Workbench "windows-sandbox" analyzer → `{hash}.request` → `WINDOWS_SANDBOX_REQUEST_DIR` |
| Sample resolution | `process-ghosts-web-requests.sh`, same shared sample inbox | `process-windows-web-requests.sh` (#47) |
| Worker | `honeypot-ghosts-sandbox-worker.path` → `.service`, never run by the dashboard | `honeypot-windows-sandbox-worker.path` → `.service` |
| Results | `windows-ghosts-<job>.json` → `GHOSTS_SANDBOX_RESULTS_DIR`; dashboard only reads | `windows-<job>.json` → `WINDOWS_SANDBOX_RESULTS_DIR` |
| Trust boundary | Dashboard never touches libvirt, Docker, or WinRM directly | Same |
| Detail page | `GET /sandbox/{job}` (shared route, `Route` field distinguishes) | `GET /sandbox/{job}` |

No new trust boundary. The dashboard container stays unprivileged and never
calls `virsh`, `docker`, or WinRM directly — same guarantee `sandbox/windows`
already holds itself to.

---

## Fixed addresses (the "one documented address" pattern)

Matches RevDeck's own `REVDECK_API_BASE=http://10.8.0.2:19500` convention —
pick a fixed address once, up front, specifically so later pieces can
reference a single line instead of a floating one.

| What | Address | Set by |
|---|---|---|
| `virbr-ghosts` bridge / GHOSTS API published port | `10.20.30.1:5000` | `network.xml` (#325), `compose.yml` (#324) |
| `ghosts-api` docker-internal backend (FORWARD-chain exception target only, never addressed directly) | `10.90.0.2:5000` | `compose.yml` (#324) |
| `win11-ghosts` guest | floating (`virsh net-dhcp-leases ghosts`) — **no pin deployed yet, see below** | — |

---

## What's verified (not just configured)

### Network policy (#325) — `verify-network-isolation.sh`, three consecutive clean runs

Boots a throwaway clone of the Linux sandbox's own golden Ubuntu image on
`virbr-ghosts` and checks, from inside the guest:

```
PASS: WAN ICMP reaches 1.1.1.1
PASS: WAN DNS resolves example.com
PASS: WAN HTTPS reaches example.com
PASS: GHOSTS API exception (10.20.30.1:5000) is reachable
PASS: host LAN gateway (192.168.42.254) is unreachable
PASS: host's own LAN address (192.168.42.249) is unreachable
PASS: another libvirt guest network (10.10.10.254, sandbox bridge) is unreachable
PASS: a docker bridge gateway (172.18.0.1) is unreachable
PASS: the Linux sandbox's forensic-egress net (198.18.0.1) is unreachable
PASS: ghosts-api's docker-internal address (10.90.0.2:5000, not the published one) is unreachable
PASS: ghosts-postgres (10.90.0.3:5432) is unreachable
```

Three real bugs were found only by testing from inside a guest, not by
reading the rules — see `network-filter.sh`'s own header comment for the
full account: (1) a multi-homed host answers for its own addresses
regardless of ingress interface, missed by FORWARD-only rules; (2) Docker's
`raw` table blocks direct container-backend routing outright, no
FORWARD/DOCKER-USER rule can override it; (3) Docker's port-publish DNAT
still needs a FORWARD exception matching the *post-DNAT* address, not the
published one.

### Client enrollment (#326) — `verify-client-enrollment.sh`

A real `Ghosts.Client.Universal.exe` crash was found and fixed
(`-p:PublishSingleFile=true` left `Assembly.Location` empty, crashing
`ApplicationDetails.VersionFile` before the client logged a single line).
Confirmed enrollment via a fresh `lastReportedUtc` check-in timestamp — not
machine count, which only rises once per fixed persona hostname
(`MatchMachinesBy: "name"`). Confirmed clean with the persona daemon
explicitly disabled first.

### Full detonation round trip (#328) — twice

1. Direct orchestrator invocation, 20s observation window: complete
   revert → boot → deliver → GHOSTS client launch → execute → collect →
   revert cycle, `run_status: "completed"`, real `ghosts_activity` payload
   with a `lastReportedUtc` from during the run.
2. The actual dashboard-facing path: a real `{sha256}.request` file
   dropped into the spool, systemd path unit fired, resolution service
   handed off, worker service began detonating automatically — confirmed
   via the live process tree.

---

## Known gaps (tracked, not silently dropped)

- **No DHCP pin deployed for `win11-ghosts`'s MAC.** `network.xml`'s
  header notes the pin is prepared for once #327's domain MAC is chosen,
  but the *deployed* network on the host is still running the plain-range
  version — the guest gets a floating lease (`.72` at last check), not a
  pinned address. Flagged on PR #425; reconcile before that PR merges.
- **Sysmon EVTX collection silently no-ops** in both live #328 test runs
  (`orchestrate/run_sample.py`'s `collect_artifacts` best-effort `get`
  calls). The GHOSTS-activity artifact — the priority one — worked both
  times; Sysmon collection wasn't investigated further given time.
- **Persona timeline content (#329/#463)**: expanded from a single
  `BrowserChrome` handler to `BrowserChrome` + `Clicks` (idle mouse
  jitter) + `Command` + `Notepad` (weighted create/modify/delete/view
  file churn) + `LightWord`/`LightExcel` (real .docx/.xlsx files via
  OpenXML, no COM automation). Staggered `UtcTimeOn`/`UtcTimeOff`
  windows per handler (browsing widest at 12:00-23:00 UTC, document
  work narrowest at 14:00-21:00) give the day a shape instead of one
  flat activity window, without needing any custom scheduling logic —
  all native GHOSTS features (time windows, `execution-probability`,
  `delay-jitter`).
  - **`Command` was broken, not just sparse** — #463 traced the root
    cause: `TimelineManager/Orchestrator.cs`'s `RunHandler` resolves a
    handler by reflection against the literal string of its
    `HandlerType` enum value (`Type.GetType("Ghosts.Client.Universal.
    Handlers." + type)`), and `HandlerType.Command` has no matching
    class — the class implementing it is named `Cmd`. Every
    `"HandlerType": "Command"` timeline entry threw
    `NotSupportedException` at dispatch, which is why #329 dropped it
    from the committed timeline rather than ship something that always
    fails. Fixed in `Dockerfile.client-win` (renames the class via the
    same build-time sed-patch mechanism #462 uses for `BrowserChrome.cs`)
    rather than in `timeline.json` — the JSON side was already correct.
  - **Still no `Word`/`Excel`/`PowerPoint`/`Outlook` handlers** (the
    real-COM-automation ones, distinct from `LightWord`/`LightExcel`
    above) — confirmed live that Office is not installed on this golden
    image (`HKLM:\SOFTWARE\Classes\{Word,Excel,PowerPoint}.Application`
    all absent), and those handlers have no fallback; using them would
    crash, not degrade. `Outlook` also excluded per #300's
    Redemption-licensing finding, unrelated to the Office-install gap.
  - **`BrowserChrome` now uses a persistent profile path**
    (`--user-data-dir=%USERPROFILE%\ChromeProfile` via
    `command-line-args`) instead of Chrome's own throwaway
    `C:\WINDOWS\SystemTemp\scoped_dir...` profile (cross-referenced
    from #462: a temp `scoped_dir` path is itself a tell). This is a
    structural fix only — the profile still starts empty on every fresh
    golden-image clone, since each detonation is a disposable CoW
    overlay. Actually pre-seeding History/cookies the way
    `06-chrome-history.ps1` does for win11-analysis would need an
    equivalent GHOSTS-side provisioner step; not built here, left as
    explicitly deferred future work rather than attempted partially.
