# CAPE Sandbox — Implementation Plan

> **Status**: #314, #315, #316, #317, #318, #320 done and verified live;
> #319 landed (registry entry and the result-detail page; what stays
> open is in Known Gaps). The golden image (#315) builds via PXE against
> the evaluation ISO already on the homeserver (no licensed ISO needed —
> see that section below for why this plan's earlier assumption was
> wrong). The host stack (#314) runs all four systemd services
> (`cape`/`cape-web`/`cape-processor`/`cape-rooter`) against a custom
> `capekvm` machinery module (see below for why the stock `kvm.py` module
> doesn't work against this guest's CPU config) and has completed a real,
> `reported`-status end-to-end analysis of a known-benign sample through
> its own `utils/submit.py` — not just a startup self-test. See "What's
> verified" for the concrete evidence and every bug found getting there.
> **Last updated**: 2026-08-07
> **Host platform**: KVM + QEMU + libvirt + docker-compose, same as
> `sandbox/windows` and `sandbox/ghosts` — no VMware, no Hyper-V, no
> CI-triggered detonation.
> **Tracking**: [#322](https://github.com/Xore/APIARY/issues/322)
> (this chain), decided in
> [#299](https://github.com/Xore/APIARY/issues/299).

---

## Why this exists, and why it is different from `sandbox/windows`

[#299](https://github.com/Xore/APIARY/issues/299)'s research (following on
from `sandbox/windows_kimi/RESEARCH.md`'s own §1.3) found a class of
evasion no amount of persona/environment realism defeats: debugger-class
time evasion — long sleeps, timestamp-gated logic bombs, `rdtsc` timing
checks. `win11-sandbox`'s own Sysmon+EVTX collection (Phase 3.2) already
covers everything else CAPE would otherwise duplicate. What CAPE adds that
is genuinely new is its YARA-programmable debugger — breakpoints,
`fake-rdtsc`, `action=skip` — which patches the guest's own notion of time
rather than trying to out-realism a check that inspects the clock directly.
"Path 1" from #299 (full CAPE standalone, its own golden image) won on that
basis specifically, over reimplementing CAPE's guest-side debugger inside
`sandbox/windows`'s own orchestrator.

Rather than retrofitting a debugger onto the existing golden image and
network (which would have meant carrying CAPE's own guest-side agent and
`capemon` DLL inside an image built and hardened for a different pipeline),
this chain gives CAPE its own network segment, its own golden image, and
its own detonation route — **additive, not a replacement**. `win11-sandbox`
remains exactly as it always was; CAPE is a second, independent way to run
a sample past a check the first route cannot answer.

---

## Host Constraints

Same as `docs/sandbox/windows/IMPLEMENTATION_PLAN.md` and
`docs/sandbox/ghosts/IMPLEMENTATION_PLAN.md`:
- KVM/QEMU/libvirt + docker-compose only — no VMware, no Hyper-V
- No CI-triggered detonation — the dashboard's Workbench is the only
  trigger (`workbench_orchestrator.go` → spool file → host-side systemd
  worker)
- VM lifecycle is CAPE's own responsibility once configured (its
  `kvm`/`libvirt` machinery module talks to `virsh` directly) — this
  worker never calls `virsh` itself, matching every other pipeline's own
  "the orchestrator doesn't hold hypervisor credentials, the host-side
  worker does" boundary
- Results written to a spool directory the dashboard reads — no outbound
  network access from the dashboard container itself, no git push

**Real numbers this host was sized against** (measured live, 2026-08-07):
16 logical CPUs (8 cores × 2 threads), 92GiB RAM (23GiB free / 69GiB
available at the time of measurement), 8GiB swap already **4.7GiB in use
at idle** — worth flagging for whoever sizes CAPE's own guest RAM, since
that pressure exists before CAPE adds anything. `win11-sandbox` alone is
already configured for 8 vCPU / 16GiB RAM. `/var` (where golden images and
VM disks live) has 1.2T free of 1.8T. See #320's section below for what
this means for running CAPE and `win11-sandbox` at the same time.

**Real, load-bearing compatibility problem found installing this, not
theoretical**: this host runs a very recent Ubuntu release whose only
system Python is 3.14. CAPEv2's pinned dependency set — `orjson` (via
PyO3, which explicitly refuses anything newer than Python 3.13),
`gevent`/`greenlet` (C extensions built against CPython internals that
changed in 3.13+) — cannot build against it at all, not "builds with
warnings." Fixed by building Python 3.12.8 from source via `pyenv` under
the `xore` account (no matching apt or deadsnakes package exists for this
OS release either) and pointing CAPEv2's poetry environment at it
explicitly (`poetry env use <pyenv python>`). A second, narrower trap:
CAPE's own systemd services are meant to run as the dedicated `cape` system
user `installer/cape2.sh` creates, and poetry venvs are per-user — running
`poetry install` as `xore` does **not** make that environment visible to
`cape`; each user needs its own `poetry env use` against the same pyenv
Python (world-readable, `chmod o+rX`, for that to be possible at all)
followed by its own `poetry install`. Getting this wrong looks like
individual packages silently missing (`ModuleNotFoundError: pytz`, then
`sqlalchemy`, one at a time) rather than one clear "wrong Python" error,
because each user's poetry silently created and used its *own*,
differently-configured venv without saying so.

---

## Architecture Overview

**Home server (KVM/libvirt host)**

- **libvirt network: `cape`** (`virbr-cape`, `10.40.50.0/24`) — [#316]
  Live. `virsh net-list --all` confirms `cape` alongside `ghosts`,
  `honeypot-sandbox`, `sandbox`, all active/autostart/persistent. No
  `<forward>` element — same as `sandbox/windows`'s and the Linux runner's
  own networks, unlike `ghosts`'s deliberate exception. A genuinely
  distinct fourth bridge, not a reuse of `virbr-sandbox` — two independent
  Windows guests on one bridge would let a CAPE detonation observe
  `win11-sandbox`'s guest on the same L2 segment, and vice versa.

- **Routing-mode decision (#316)**: CAPE supports per-analysis
  `drop`/`inetsim`/`internet`/`vpn`. `internet`/`vpn` are ruled out
  immediately by this repo's blanket no-outbound-network posture (the same
  posture `win11-sandbox` and the Linux runner both hold to — `ghosts` is
  the one deliberate, loudly-flagged exception elsewhere in this repo, not
  a precedent for CAPE). Default is `drop` (`CAPE_ROUTE` env var,
  `cape-worker.py`), matching every other detonation route's default.
  `inetsim` is CAPE's own supported alternative but is **not** wired to
  the existing `docker-compose.sandbox.yml` INetSim instance the Linux and
  Windows runners already share — two independent guests hitting one
  INetSim process risks session/state cross-contamination between
  unrelated detonations. A CAPE-dedicated INetSim instance is left as
  follow-up work under #314's scope, not built here.

- **`win11-cape` guest** (`10.40.50.50`, live — [#315]) — runs CAPE's
  `capemon` DLL (pushed per-analysis, not baked into the golden image —
  see that guest's own provisioning script header for why) + `agent.py`,
  built via PXE boot against the evaluation ISO already on the
  homeserver (never CD-ROM-mounted, same convention `win11-sandbox`'s
  own build already holds to — no licensed ISO needed, correcting this
  plan's own earlier assumption). The golden-image-vs-snapshot question
  `sandbox/windows`'s own plan resolved once already turned out to need
  resolving a *second* time here, differently — see #314's own "What's
  verified" section for why the stock CAPE machinery module can't reuse
  that same answer unmodified.

- **CAPEv2 core** (`/opt/CAPEv2`, host-native, not Docker — [#314]) —
  Installed via upstream's own `installer/cape2.sh base` (customized:
  `NETWORK_IFACE=virbr-cape`, `IFACE_IP=10.40.50.1`, so its tcpdump-sniffing
  setup targets CAPE's own bridge rather than the default `virbr1`, which
  does not exist on this host). Runs on the host directly, not in a
  container, for the same reason `sandbox/windows`'s own orchestrator does:
  it needs to reach libvirt/KVM directly, not across a socket boundary.
  Python environment is CAPEv2's own poetry-managed venv against a
  pyenv-built Python 3.12.8 (see Host Constraints above) — **not** this
  host's system Python. Task database is CAPE's built-in SQLite default
  (`conf/cuckoo.conf [database] connection=` unset) — a deliberate
  simplification, not an oversight; see Known Gaps.

- **`cape-mongo`** (`sandbox/cape/compose.yml`, Docker, `10.91.0.0/24`,
  loopback-published) — [#314] Live and verified (see below). No apt
  package for MongoDB exists for this host's OS release at all (its own
  apt repo publishes no packages for this codename), so this is Docker
  where the equivalent Ghosts/GHOSTS piece (`sandbox/ghosts/compose.yml`)
  is apt-installed `postgresql` upstream, or a Docker Postgres of its own —
  same "a full platform gets its own isolated compose file" reasoning that
  doc's header gives, narrowed to just the one service CAPE's own apt path
  could not provide on this host.

- **Host-side CAPE sandbox worker** (`sandbox/cape/worker/`, systemd path
  unit) — [#318]
  - Watches `CAPE_REQUEST_DIR` for `{sha256}.request` files written by
    `dashboard/workbench_orchestrator.go`'s "cape" analyzer
  - `cape-worker.py`: submits the sample to CAPE's own `apiv2`
    (`/apiv2/tasks/create/file/`), polls `/apiv2/tasks/status/{id}/` until
    `reported`, fetches `/apiv2/tasks/report/{id}/json/`, writes
    `{sha256}_cape.json` into `CAPE_RESULTS_DIR`
  - **Not yet verified against a live submission through this specific
    path** — narrower than before, not still fully open: #314's own
    `utils/submit.py` + `/apiv2/tasks/status/` have now been exercised
    against a real, `reported` analysis (see #314's own section below),
    so the service side of this is confirmed live. `cape-worker.py`'s
    own client code, though, has never itself submitted anything — its
    endpoint contract is CAPEv2's documented `apiv2` shape, the same
    starting point `ghidra-worker.py`'s own header warns went stale once
    already ("the endpoints originally taken from the plan documents
    were wrong"). Its own `--selftest` only checks reachability for
    exactly this reason — extend it into a real round trip next, the
    same discipline `ghidra-worker.py --selftest`'s real analysis round
    trip already holds itself to; nothing external blocks this now.

---

## Wiring pattern — mirrors the Windows sandbox's own Ghidra comparison

| Concern | CAPE sandbox (this plan) | Windows sandbox (reference) |
|---|---|---|
| Trigger | Workbench "cape" analyzer → `{hash}.request` → `CAPE_REQUEST_DIR` | Workbench "windows-sandbox" analyzer → `{hash}.request` → `WINDOWS_SANDBOX_REQUEST_DIR` |
| Sample resolution | Same shared sample inbox (`CAPE_SAMPLES_DIR`, defaults to the same path every other worker reads) | `process-windows-web-requests.sh` (#47) |
| Worker | `honeypot-cape-worker.path` → `.service`, never run by the dashboard | `honeypot-windows-sandbox-worker.path` → `.service` |
| VM lifecycle | CAPE's own `kvm`/`libvirt` machinery module (not this worker) | `sandbox/windows/orchestrate/run_sample.py`, direct `virsh` |
| Results | `{sha256}_cape.json` → `CAPE_RESULTS_DIR`; dashboard only reads | `{sha256}_sandbox.json` → `WINDOWS_SANDBOX_RESULTS_DIR` |
| Trust boundary | Dashboard never touches libvirt, Docker, or CAPE's API credentials directly | Same |
| Detail page | `/cape/{sha}` detail page (`/api/v1/cape/{sha}`) — built (#319, landed) | `GET /sandbox/{job}` |

No new trust boundary. The dashboard container stays unprivileged and never
calls `virsh`, `docker`, or CAPE's own API directly — same guarantee every
other pipeline in this repo already holds itself to.

---

## #317 — when a sample gets routed to CAPE

**Decision**: opt-in only, exactly like every other Workbench analyzer
except `deterministic`. There is no automatic classification-based routing
to CAPE (or to `windows-sandbox`, or `windows-ghosts`) anywhere in this
codebase today — an operator selects analyzers explicitly in the Workbench
UI, and `workbenchRegistry`'s `Applicable`/`Available` fields only control
whether "cape" is offered as a *choice*, never whether it runs
automatically. This was already the right answer by construction once the
registry entry existed (`dashboard/workbench_domain.go`'s `cape` entry,
`AcceptedKinds: ["windows"]`, `Applicable: windowsApplicable`,
`Confirmation: "detonation"`) — no separate routing logic needed building,
and none should be: an operator choosing to spend an hours-long CAPE
analysis slot is exactly the kind of decision this repo's Workbench
pattern reserves for a human, the same reasoning `windows-ghosts`'s own
loud, opt-in-only framing already documents for its own WAN-permitted
route.

---

## #320 — resource coexistence with `win11-sandbox`

CAPE's guest and `win11-sandbox` both run as KVM/QEMU domains on this host.
16 logical CPUs total; `win11-sandbox` alone is already configured for 8
vCPU. Two full-sized concurrent detonations would fully claim the host's
CPU, and the host's swap is already under real pressure at idle (see Host
Constraints). **Decision: the simplest option** — one host-wide lock,
shared across both pipelines, so only one KVM-backed detonation runs at a
time, full stop. Not per-pipeline; per-host.

Implemented, not just decided: `CAPE_KVM_SHARED_LOCK`
(`/run/lock/honeypot-kvm-detonation.lock` by default) is acquired
(blocking, not skip-if-busy — a queued sample should wait its turn, not
bounce) by `sandbox/cape/worker/cape-worker.py`'s `analyse_one()` around
the actual submit-through-report span, and the identical lock file is now
also acquired by `sandbox/windows/run_pending.sh` around its own
`orchestrate/run_sample.py` call. Neither pipeline's own per-worker lock
(`WINDOWS_SANDBOX_LOCK`, `CAPE_LOCK`) changes — those still just collapse
overlapping path-unit triggers within one pipeline, same as before; this
is an *additional*, second lock layered on top, held only while a guest is
actually running, not for the whole drain loop.

---

## Fixed addresses (the "one documented address" pattern)

Matches RevDeck's own `REVDECK_API_BASE=http://10.8.0.2:19500` convention
and `sandbox/ghosts/compose.yml`'s own fixed-address table.

| What | Address | Set by |
|---|---|---|
| `virbr-cape` bridge gateway | `10.40.50.1` | `sandbox/cape/network.xml` (#316) |
| `cape-mongo`, docker-internal | `10.91.0.2` | `sandbox/cape/compose.yml` (#314) |
| `cape-mongo`, published (loopback only) | `127.0.0.1:27017` | `sandbox/cape/compose.yml` (#314) |
| CAPE's own apiv2/web UI | `127.0.0.1:8000`, loopback only | `cape-web.service` (#314), scoped from upstream's `0.0.0.0` default |
| `win11-cape` guest | `10.40.50.50`, pinned DHCP | `sandbox/cape/network.xml` (#316), MAC in `win11-cape-kvm.xml` (#315) |

---

## What's verified (not just configured)

### Network isolation (#316)

`virsh net-list --all` on the real host: `cape` present, `active`,
`autostart: yes`, alongside the three pre-existing networks. Not yet run
through a from-inside-a-guest isolation check the way
`sandbox/ghosts/verify-network-isolation.sh` exercises its own network —
a real guest now exists on this bridge (#315) to boot one from, but that
specific verification script hasn't been adapted and run yet. Real
guest-level traffic on this bridge *has* been observed indirectly, via
`win11-cape`'s own confirmed analysis run (see #314 below) — a PCAP was
captured, the guest reached `10.40.50.1` (the resultserver) and nothing
else — but that's incidental to a real analysis, not a purpose-built
isolation check the way `ghosts`'s own script is.

### Windows golden image (#315)

Built via `sandbox/cape/packer/win11-cape.pkr.hcl`, PXE boot only (never
CD-ROM-mounted — same convention `win11-analysis.pkr.hcl` already
holds to), against the evaluation ISO already present on the homeserver.
Real bugs found and fixed in the build scripts themselves, not just
worked around live:

- PXE-unplug via `device_del` (the mechanism `unplug-pxe-on-reset.sh`
  uses) fails outright on q35's `pcie.0` root bus — `"Bus 'pcie.0' does
  not support hotplugging"`, confirmed live. Switched to the existing
  delay-based `unplug-pxe-after-delay.sh` (`set_link` + `eject`, no
  hotplug involved), matching a direct instruction to just stop serving
  PXE after a fixed delay rather than watching for a specific QMP event.
- `02-cape-agent.ps1`'s Unicode box-drawing comment border got mangled
  in transit to the guest over the Packer PowerShell provisioner,
  causing a real parse error (`MissingEndCurlyBrace`) that silently
  killed that provisioner step — Packer did **not** propagate the
  failure as a build failure, so the build reported success with the
  step never having run. Fixed at the source (plain ASCII in the
  comment, matching the em-dash convention used safely elsewhere in
  this repo) so a real Packer rebuild doesn't hit it again.
- `win11-cape-kvm.xml`'s `<nvram>` element was missing
  `templateFormat='raw'`, which fails `virsh define`+`start` outright on
  this host's current libvirt version (`"conversion of the nvram
  template to another target format is not supported"`) — found live
  defining this domain for the first time. The identical, previously
  unnoticed bug existed in the already-shipped `win11-kvm.xml` and
  `win11-ghosts-kvm.xml` too (their live domains just predate this
  libvirt version, or an earlier one auto-added the attribute); fixed in
  all three.

Confirmed live, not just built: `virsh start win11-cape` against a fresh
overlay boots to a logged-in desktop (`unattend.xml` `AutoLogon`) and the
CAPE agent answers on `:8000` with no manual steps — including after
recreating the overlay completely from scratch, the same way `capekvm`
(#314, below) does before every real analysis.

### CAPEv2 host stack (#314)

- **Real, once-broken, now-fixed compatibility chain**: base install
  (`installer/cape2.sh base`) run against this host's actual OS twice —
  the first attempt correctly surfaced Python 3.14 incompatibility (PyO3
  refusing outright, C-extension builds failing against changed CPython
  internals) rather than silently limping along; see Host Constraints for
  the full account.
- **Confirmed by import, not by installer log alone**: `poetry run python3
  -c "import gevent, greenlet, cffi, lxml, django, orjson, yara"` succeeds
  under the pyenv-built Python 3.12.8, both as `xore` and (separately,
  after discovering the per-user-venv trap above) as the dedicated `cape`
  system user CAPEv2's own systemd services are meant to run as.
- **`cape-mongo` confirmed live**: `docker compose up -d` in
  `sandbox/cape/` brought up a `healthy` container; `nc -zv 127.0.0.1
  27017` succeeded from the host, and separately, CAPE's own startup
  logged `Successfully connected to MongoDB at 127.0.0.1:27017` twice
  (once per its two DB handles) — a real client connection, not just an
  open TCP port.
- **`cuckoo.py -t -d` (CAPE's own startup self-test) run for real**, as
  the `cape` system user, against this exact host. What it needed beyond
  `poetry install` that upstream's own dependency manifest did not capture
  for this environment, each found and fixed one at a time rather than
  papered over: `pytz`/`pyzipper` (both **are** pinned in `pyproject.toml`
  but were absent from the first `poetry install` for reasons not fully
  chased down — reinstalling with `poetry install` again, correctly, as
  each user, resolved it); `elasticsearch` (imported by
  `dev_utils/elasticsearchdb.py` but **not declared in `pyproject.toml` at
  all** — a real upstream gap in this pinned snapshot, not a local
  mistake); once installed, the *latest* `elasticsearch` package (8.19.3)
  turned out API-incompatible with this code's ES 7.x-style
  `Elasticsearch(hosts=..., port=..., http_auth=..., use_ssl=...)`
  constructor call (`dev_utils/elasticsearchdb.py`'s own header comment
  already flags this exact ToDo) — worked around by disabling
  `conf/reporting.conf`'s `[elasticsearchdb]` entirely (`enabled = no`)
  rather than fighting a client-version pin for a CAPE-internal ES
  integration this repo doesn't need (APIARY has its own, separate
  Elasticsearch pipeline; CAPE's is a distinct, optional feature); and
  `libvirt-python`, which failed during the original `installer/cape2.sh`
  run (missing `libvirt-dev` headers at that point in the install) and
  needed a manual `poetry run pip install libvirt-python` once the header
  package was installed.
  Final, real result at the time: startup got all the way through config,
  MongoDB, and a live libvirt connection, and failed with exactly
  `libvirt.libvirtError: Domain not found: no domain with matching name
  'cuckoo1'` — `conf/kvm.conf`'s default machine name, which didn't exist
  because #315's guest hadn't been built yet. That was the correct,
  expected stopping point at the time; everything below picks up from
  there once #315 landed.

- **The stock `kvm.py` machinery module cannot drive `win11-cape` at
  all**, discovered live rather than assumed: `LibVirtMachinery.start()`
  (which `kvm.py` inherits unmodified) always reverts to a libvirt
  *internal, running-state* snapshot before starting a task —
  `vm.revertToSnapshot()`, which needs a full memory+disk snapshot. That
  snapshot type is flatly unavailable on this guest's domain config:
  `win11-cape-kvm.xml` sets `<cpu mode='host-passthrough' migratable='off'/>`
  (full host CPU feature exposure, for the same anti-detection reasoning
  `win11-sandbox`'s own domain XML already documents), and QEMU/libvirt's
  snapshot save/restore reuses the same machinery live migration does —
  `migratable='off'` blocks it outright, confirmed with a real
  `virsh snapshot-create-as` attempt: `cannot migrate domain: State
  blocked by non-migratable CPU device (invtsc flag)`. This is the exact
  same golden-image-vs-snapshot tension `sandbox/windows`'s own plan
  already resolved for `win11-sandbox` (that domain has the identical
  `migratable='off'` and also can't snapshot) — resolved here the same
  way: a custom machinery module, `sandbox/cape/capev2-overrides/modules/
  machinery/capekvm.py` (`CapeKVM`), whose `start()` destroys the overlay
  disk and recreates a fresh thin qcow2 clone from the golden image
  before every single boot instead of ever touching a snapshot. This also
  means the golden image's own single-use `unattend.xml` `AutoLogon`
  fires correctly on *every* analysis, not just the first: each new
  overlay's first boot is that overlay's actual first boot, reading the
  same pristine, never-logged-in-from-its-own-perspective base state off
  the read-only golden image every time. Config lives alongside it in
  `conf/capekvm.conf` (own `golden_image`/`vm_disk` keys read directly by
  the module, not part of stock `kvm.py`'s machine schema). Considered
  and rejected: setting `migratable='on'` instead, which would let the
  stock module work unmodified — rejected because it costs real CPU
  feature exposure (e.g. `invtsc`) specifically on the CAPE guest, a
  regression from the same anti-detection posture `win11-sandbox` already
  holds, for a guest whose whole purpose is running samples that might
  check for exactly that. See that module's own header comment for the
  full account; `AskUserQuestion` was used to confirm this direction
  before writing the code, given the real, opposite-tradeoff alternative.

- **Four systemd services, scoped rather than copy-pasted from
  upstream's examples**: `sandbox/cape/capev2-overrides/systemd/{cape,
  cape-web,cape-processor,cape-rooter}.service`, installed to
  `/etc/systemd/system/`. Real findings while scoping each, not assumed:
  - `cape-web.service`: upstream's own example binds `0.0.0.0:8000`.
    Changed to `127.0.0.1:8000` — #314's own issue text requires no
    service reachable from outside loopback unless the analysis
    explicitly needs it, same posture as Ghidra REST on `127.0.0.1:9090`.
    Confirmed: `curl 127.0.0.1:8000/` → `200`, `curl <LAN-IP>:8000/` →
    connection refused.
  - `cape-rooter.service`: upstream runs it as full, unscoped `root`.
    Checked what `rooter.py` (iptables/ip/sysctl network administration)
    actually needs rather than assuming full root was required — it
    isn't, in principle (`CAP_NET_ADMIN`/`CAP_NET_RAW` alone would
    cover the underlying operations) — but `rooter.py` itself
    hard-checks `os.getuid() == 0` at startup and never drops privilege
    afterward, an upstream design choice patching vendored code to work
    around was judged not worth the maintenance cost of re-applying
    across every future CAPEv2 update. What's scoped instead, without
    touching CAPE's own source: `CapabilityBoundingSet` strips every
    root capability except `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_CHOWN`,
    `CAP_FOWNER` — the last two found live to be genuinely required
    (not decorative): `rooter.py`'s own `AF_UNIX SOCK_DGRAM` reply path
    (`server.sendto(response, addr)`, replying to `cape.service`'s own
    bound socket) needs `CAP_DAC_OVERRIDE`-gated permission to write to
    a path this process doesn't own — without it, *every* rooter call
    (even the harmless `inetsim_disable` cleanup call
    `machinery_manager.py` fires on startup for each configured machine)
    raised an uncaught `PermissionError` that crashed the whole rooter
    process, which in turn hung `cape.service`'s own startup
    indefinitely waiting on a reply a crashed process could never send —
    confirmed by reproducing the hang with the capability missing, then
    confirming it goes away with it present.
  - `PYTHONUNBUFFERED=1` added to all four: Python block-buffers stdout
    by default off a TTY, which meant `journalctl -u cape` could sit
    silent for minutes while `cuckoo.py` was actively logging —
    materially slowed down diagnosing the rooter hang above.

- **SQLite task DB: usable, but real, load-bearing operational
  caveat found live.** The default `journal_mode` (`delete`, i.e. a
  rollback journal, not WAL) serializes writers hard enough that
  `utils/submit.py` reliably hit `sqlite3.OperationalError: database is
  locked` while `cape.service`'s own scheduler was concurrently polling
  the same file — reproduced consistently, not a one-off flake. Switched
  `PRAGMA journal_mode=WAL` (a standard, safe fix for exactly this
  multi-process contention pattern), which materially helped but did not
  eliminate every collision under concurrent load — CAPE's own database
  layer explicitly documents advisory locking as "Postgres only —
  no-op on sqlite (single-writer)". SQLite remains a deliberate
  simplification for #314's actual ask (get the host stack running), not
  an oversight; see Known Gaps for the Postgres migration this points at
  for anything beyond light, non-concurrent use.

- **Two reporting modules disabled for false-negative status, not
  actual failures**: real analyses were completing successfully — full
  behavioral logs, screenshots, process dumps, zero errors — yet the
  task status still read `failed_reporting`. Traced to
  `RunReporting.process()` in `lib/cuckoo/core/plugins.py`: it increments
  the same `reporting_errors` counter for a module that genuinely crashed
  *and* for a `CuckooDependencyError` (an optional module skipping itself
  over a missing dependency, logged only as a `WARNING`) — the counter
  can't distinguish the two, and `error_count != 0` alone flips the
  task's final status. `[maec41]` (needs the `cybox` package, not
  installed — MAEC 4.1 output isn't consumed anywhere in this repo) and
  `[gcs]` (needs `google-cloud-storage`, same story) both set to
  `enabled = no` in `conf/reporting.conf`, matching the same
  disable-the-unconfigured-optional-integration pattern already used for
  `[elasticsearchdb]`. Confirmed by reprocessing the same already-run
  analysis (`utils/process.py 7 -r`) with both disabled: status flipped
  from `failed_reporting` to `reported` with no other change.

- **Confirmed end-to-end with a real submission**: a known-benign `.bat`
  script (writes a file, echoes to stdout, exits) submitted via
  `utils/submit.py --machine win11-cape --package batch`. Full pipeline
  observed working, not assumed from partial signals: `capekvm` found
  and started the machine, the golden image's `AtLogon`-triggered CAPE
  agent answered on `:8000`, the sample executed, `capemon`'s behavioral
  logs (`logs/*.bson`), 5 real screenshots (`shots/000{1-5}.jpg`),
  process dumps, and a PCAP were all captured, and the task reached
  `status: reported` — confirmed both via direct SQLite query and CAPE's
  own `/apiv2/tasks/status/<id>/` endpoint. `curl 127.0.0.1:8000/` (the
  web UI, not the guest agent) separately returned `200`.

- **One golden-image bug found and fixed at the source, not just
  patched around**: the very first live boot of `win11-cape` (through
  `capekvm`, which recreates the guest's disk from the golden image
  before every analysis) never got its CAPE agent running — the
  AtLogon-triggered scheduled task fired but failed with
  `0x80070002` (file not found). Root cause: an earlier manual WinRM-based
  fixup (documented under #315) had corrected this on a disposable
  overlay that got discarded, never on the golden image's own base
  layer, so every fresh overlay `capekvm` creates inherited the
  original, still-broken task registration (pointing at
  `Python311\pythonw.exe`; the real install path, discovered by
  `Test-Path`, is `Python311-32\pythonw.exe` — python.org's 32-bit
  Windows installer for 3.11 uses that `-32` suffix, not a bare
  `Python311` folder). Fixed by booting the golden image directly (not
  an overlay) one more time, re-registering the scheduled task with the
  correct path, and shutting down — verified by then recreating a
  completely fresh overlay from scratch and confirming the agent came up
  correctly with zero manual intervention, the same way `capekvm` does
  it for every real analysis.

### Dashboard wiring (#319, landed)

`go build ./...` and the full existing `dashboard` test suite
(`go test ./... -run Workbench`) both pass unchanged after adding the
`cape` registry entry — no regression to any existing analyzer's
behavior. The entry correctly reports `unconfigured` (no live spool
directories exist on this dashboard instance) rather than claiming
availability nothing backs, same discipline `ghidraConfigured`/
`revdeckConfigured` already hold themselves to.

---

## Known gaps (tracked, not silently dropped)

- **`/cape/{sha256}` result detail page — built; closed out by #319
  (PR #944).** The page this entry used to warn about now exists: the
  backend serves `/api/v1/cape/{sha}` from `cape_run` in
  `backend-service/src/detail.rs` (a `/raw` full-report passthrough
  beside it), and the frontend renders the run at
  `routes/cape.$sha.tsx`. The registry entry's
  `ResultLinkShape: "/cape/{sha256}"` is therefore a working link
  rather than a route *promise* — clicking through lands on the detail
  page instead of 404ing. What stays open on this chain is the
  worker-side gap below, not the page.
- **`cape-worker.py`'s CAPE API client is still unverified against a
  live service** — narrower than before, not removed: #314's own
  `utils/submit.py` CLI and the `/apiv2/tasks/status/<id>/` read
  endpoint are both now confirmed live against a real analysis (see
  above), which was the actual blocker (no service to test against).
  `cape-worker.py`'s own client code, endpoints matched against CAPEv2's
  documented `apiv2` blueprint but never yet exercised, is real
  remaining work — same category of risk that turned out wrong once
  already for `ghidra-worker.py`'s Ghidra REST client. Run
  `cape-worker.py --selftest` (extended into a real submission, the way
  `ghidra-worker.py --selftest` already does for its own service) as the
  next concrete step; nothing external blocks it now.
- **PostgreSQL not stood up.** CAPE's default SQLite task DB works for
  #314's actual ask (get the host stack running, confirmed with a real
  end-to-end analysis) and was made noticeably more concurrent-safe by
  switching to `PRAGMA journal_mode=WAL` (see "What's verified" for why
  that was necessary at all) — but upstream's own code still documents
  its advisory-locking layer as Postgres-only, and a `database is
  locked` collision between `utils/submit.py` and the live scheduler was
  reproduced directly, not assumed. Fine for the current low, sequential
  submission volume; migrating `conf/cuckoo.conf`'s `connection=` to a
  Postgres container (mirroring `ghosts-postgres` exactly, including its
  `ipv4_address:` pinning reasoning) is the real fix once anything
  submits concurrently rather than one task at a time.
- **No `--memory` dump / deeper analysis-depth tuning attempted.** The
  one verified submission used default options against a trivial `.bat`
  — enough to prove the pipeline end-to-end (machinery, agent, capemon
  logging, screenshots, reporting), not a statement about analysis
  depth/quality against a real, more evasive sample. Tuning
  `conf/processing.conf`/package-specific options is real follow-up
  work once actual samples are being routed here (#317), not built
  speculatively against a synthetic test file.

---

## File Structure

```
sandbox/cape/
  IMPLEMENTATION_PLAN.md   this file
  network.xml              isolated libvirt network (#316) — live
  compose.yml              cape-mongo (#314) — live
  win11-cape-kvm.xml       guest domain definition (#315) — live
  packer/                  golden image build (#315) — live
    win11-cape.pkr.hcl
    build-with-retry.sh
    agent/agent.py                   vendored CAPEv2 agent
    autounattend.xml
    scripts/01-hardening.ps1
    scripts/02-cape-agent.ps1
  capev2-overrides/        tracked source of truth for what gets
                            deployed INTO the out-of-tree /opt/CAPEv2
                            install (#314) — live
    modules/machinery/capekvm.py     custom machinery (see "What's
                                       verified" for why stock kvm.py
                                       can't drive this guest)
    conf/capekvm.conf                its machine config
    systemd/{cape,cape-web,cape-processor,cape-rooter}.service
  worker/
    cape-worker.py                    spool drain / CAPE apiv2 client (#318)
    honeypot-cape-worker.path         systemd path unit
    honeypot-cape-worker.service      systemd service unit
    honeypot-cape.default.example     /etc/default/honeypot-cape template

dashboard/
  cape.go                  capeRequestDir/capeResultsDir (#319, partial)
  workbench_domain.go       "cape" entry in workbenchRegistry (#319)

sandbox/windows/run_pending.sh   #320's shared cross-pipeline lock added
```

`sandbox/cape/capev2-overrides/` is a deploy-time source of truth, not
something CAPEv2 itself reads in place — `/opt/CAPEv2` is upstream's own
checkout (installed via `installer/cape2.sh base`, not this repo's own
code, see "Why this exists" above), so anything this repo needs to exist
*inside* that checkout has to be copied in after a fresh install:
`modules/machinery/capekvm.py` → `/opt/CAPEv2/modules/machinery/`,
`conf/capekvm.conf` → `/opt/CAPEv2/conf/`, the four `.service` files →
`/etc/systemd/system/`, plus the two `cuckoo.conf` edits (`machinery =
capekvm`, `resultserver.ip = 10.40.50.1`) and the `reporting.conf`/
`processing.conf` toggles noted under "What's verified" above. No
install script wraps this yet — the same follow-up
`sandbox/cape/install-analysis-host.sh` (mirroring
`analysis/ghidra/install-analysis-host.sh`) noted here before is still
worth adding, now with a concrete, tested list of steps to encode
instead of a guess.
