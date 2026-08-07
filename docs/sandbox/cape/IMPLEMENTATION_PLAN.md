# CAPE Sandbox — Implementation Plan

> **Status**: In progress. Network isolation (#316) is live. Host stack
> (#314) is up as far as it can go without a guest: CAPEv2's core process
> (`cuckoo.py -t`) starts clean — config loads, MongoDB connects, the
> libvirt/KVM machinery module connects to `libvirtd` and correctly
> reports it has no `cuckoo1` domain configured, which is exactly the
> boundary #315 (the golden image) sits on the other side of. CAPE's own
> web/API service has NOT yet been started (see "What's verified" below
> for exactly what was and wasn't). Spool/worker code (#318) and Workbench wiring
> (#319's registry entry) are written and, where testable without a live
> CAPE instance, verified — the dashboard builds and its existing test
> suite passes unchanged. Resource coexistence (#320) has a decision, coded
> and live in both this chain's worker and `sandbox/windows/run_pending.sh`.
> Routing (#317) has a decision (see below). The Windows golden image
> (#315) has **not been started** — it needs a licensed Windows ISO and an
> hours-long Packer build on shared host hardware, deliberately not begun
> without that decision made explicitly.
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

- **`win11-cape` guest** (`10.40.50.x`, not created yet — [#315]) — will
  run CAPE's `capemon` DLL + `agent.py`, the same golden-image-vs-snapshot
  question `sandbox/windows`'s own plan resolved once already, and needs a
  licensed Windows ISO this plan does not assume access to.

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
  - **Not yet verified against a live submission** — there is no
    configured CAPE machine (#315) to detonate anything in, so nothing has
    ever actually been submitted through this path. The endpoint contract
    is CAPEv2's documented `apiv2` shape, the same starting point
    `ghidra-worker.py`'s own header warns went stale once already ("the
    endpoints originally taken from the plan documents were wrong"). Its
    own `--selftest` only checks reachability for exactly this reason —
    extend it into a real round trip once #315 lands, the same discipline
    `ghidra-worker.py --selftest`'s real analysis round trip already holds
    itself to.

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
| Detail page | **Not built yet** (#319 remaining scope — see below) | `GET /sandbox/{job}` |

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
| CAPE's own apiv2 | `127.0.0.1:8000` (default; not yet started) | CAPEv2 upstream default |
| `win11-cape` guest | not assigned yet — #315 | — |

---

## What's verified (not just configured)

### Network isolation (#316)

`virsh net-list --all` on the real host: `cape` present, `active`,
`autostart: yes`, alongside the three pre-existing networks. Not yet run
through a from-inside-a-guest isolation check the way
`sandbox/ghosts/verify-network-isolation.sh` exercises its own network —
there is no guest on this bridge yet (#315) to boot one from. Do that once
`win11-cape` exists, the same way that script's own header describes doing
for `ghosts`.

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
  Final, real result: startup gets all the way through config, MongoDB,
  and a live libvirt connection, and fails with exactly
  `libvirt.libvirtError: Domain not found: no domain with matching name
  'cuckoo1'` — `conf/kvm.conf`'s default machine name, which does not
  exist because #315's guest has not been built. This is the correct,
  expected stopping point, not a bug to chase further from this side.
- **Not yet done**: starting CAPE's own web/`apiv2` process specifically
  (`cuckoo.py`'s startup path above is the analysis daemon, a separate
  entry point from the Django web app) and confirming
  `/apiv2/cuckoo/status/` answers. No reason this couldn't be done with
  zero configured machines; left for once #315 lands so the two are
  brought up together rather than the web service sitting idle in the
  meantime.

### Dashboard wiring (#319, registry entry only)

`go build ./...` and the full existing `dashboard` test suite
(`go test ./... -run Workbench`) both pass unchanged after adding the
`cape` registry entry — no regression to any existing analyzer's
behavior. The entry correctly reports `unconfigured` (no live spool
directories exist on this dashboard instance) rather than claiming
availability nothing backs, same discipline `ghidraConfigured`/
`revdeckConfigured` already hold themselves to.

---

## Known gaps (tracked, not silently dropped)

- **No `/cape/{sha256}` result detail page.** #319's own issue text is
  explicit that this depends on "a real result shape" from #318, and
  #318's worker has never submitted a real sample (no golden image to
  detonate in). The registry entry's `ResultLinkShape: "/cape/{sha256}"`
  is therefore a route *promise*, not yet a working link — clicking
  through 404s today. Build `dashboard/cape.go`'s `loadCapeResults()` /
  `capePageData` / ES-mirror pair (mirroring `revdeck.go`'s shape, which
  is closer to CAPE's single-result-per-submission model than
  `ghidra.go`'s larger one) once a live `{sha256}_cape.json` exists to
  design the page against, not before.
- **`cape-worker.py`'s CAPE API client is unverified against a live
  service.** Endpoints match CAPEv2's documented `apiv2` blueprint, the
  same starting point that turned out wrong once already for
  `ghidra-worker.py`'s Ghidra REST client. Re-run `--selftest` (extended
  into a real submission, the way `ghidra-worker.py --selftest` already
  does for its own service) once #315's guest exists.
- **PostgreSQL not stood up.** CAPE's default SQLite task DB is enough to
  get the host stack running — #314's actual ask — but upstream
  recommends Postgres for anything beyond light use. Migrating
  `conf/cuckoo.conf`'s `connection=` to a Postgres container (mirroring
  `ghosts-postgres` exactly, including its `ipv4_address:` pinning
  reasoning) is real follow-up work, not built speculatively before
  anything has run a real analysis under load.
- **CAPE's own web service has never been started.** See "What's
  verified" above — nothing blocks doing this except that there is
  currently no machine to configure it against, so it was left for once
  #315 lands rather than started and left idle.
- **`win11-cape` golden image (#315) not begun at all.** Needs a licensed
  Windows ISO (source not assumed by this plan) and an hours-long Packer
  build on shared host hardware — the largest remaining piece of this
  chain by a wide margin, and the one every other unchecked box above
  ultimately depends on to become end-to-end-verifiable rather than
  configured-but-untested.

---

## File Structure

```
sandbox/cape/
  IMPLEMENTATION_PLAN.md   this file
  network.xml              isolated libvirt network (#316) — live
  compose.yml              cape-mongo (#314) — live
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

Not yet present: `sandbox/cape/packer/` (golden image build, #315),
`sandbox/cape/win11-cape-kvm.xml` (guest domain definition, #315),
`sandbox/cape/install-analysis-host.sh` (an install-time wrapper the way
`analysis/ghidra/install-analysis-host.sh` is for its own chain — worth
adding once this chain's install steps stop changing).
