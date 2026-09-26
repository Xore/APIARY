# Deployment profiles

[← back to README](../../README.md)

Which of the split home stacks (#258) are active for a given deployment
shape. The authoritative roster is
`arcane/manifests/home-production.json` — since #1502 there is no per-stack
sync loop anywhere (`deploy.yml` deploys no home stack itself; see
[ARCANE-GIT-SYNC.md](../ARCANE-GIT-SYNC.md)). Declared here instead of by
hand-editing which stacks you happen to run, so an operator running a
narrower deployment (fewer sensors, no VPS) has a named, checkable choice
instead of an implicit one nobody wrote down.

Different axis from [#258](https://github.com/Xore/APIARY/issues/258)
itself, which is about *topology* (one compose file per stack vs a
monolith) -- this is about *persona declaration*: which honeypots/dashboards
run for a given deployment, independent of how the compose files are
physically organized.

## Format

Each `.txt` file here is a plain list of home stack names (the suffix after
`honeypot-`, matching the directories under `arcane/home/`) -- one per
line, `#` comments and blank lines ignored.

## Profiles

| Profile | Backbone | Sensors | Shape |
|---|---|---|---|
| [`full.txt`](../../deploy-profiles/full.txt) | init, elk, dashboard, utilities, payload-analysis | every deception sensor stack under `arcane/home/` | the standard deployment -- everything this repo ships |
| [`ics-focused.txt`](../../deploy-profiles/ics-focused.txt) | init, elk, dashboard, utilities | conpot, dnp3 | OT/ICS-only exposure -- skip the general-purpose/web/SSH/legacy-protocol sensors entirely |
| [`minimal-web.txt`](../../deploy-profiles/minimal-web.txt) | init, elk, dashboard, utilities | http, tanner | web-attack-focused -- HTTP/API honeypot + SNARE/TANNER, skip ICS/SSH/legacy-protocol sensors |

`init`, `elk`, and `dashboard` are structural dependencies for any profile
that includes at least one sensor -- `scripts/validate-deploy-profile.sh`
(below) enforces
this, it isn't just a convention to remember. `payload-analysis` and
`utilities` are strongly recommended (payload dedup/YARA scanning, log
rotation/disk monitoring/autoheal) but not structurally required, so the
validator only warns if either is missing from a non-empty profile.

Not covered here: the VPS side (`vps/`, always deployed the same way
regardless of home profile -- see `docs/CGNAT-DEPLOYMENT.md`), the
analysis-plane workers (`ip-enrichment-worker`,
`agent-intrusion-worker`, and friends), and the `dashboard`/
`elk`/`keycloak` backbone -- none of these are persona declarations; they
are either unconditional infrastructure or governed separately from
sensor choices. The VPS is not a *profile* because it deploys the same way
whatever you pick here, but it is still a *host* with its own floor --
see [Host sizing by role](#host-sizing-by-role).

## Host sizing by role

A profile says **which** stacks run. Until #3328 it never said what machine
that needs. Two roles exist and they are sized independently: the **VPS**
(public gateway, plain `docker compose`, never Arcane) and the **home
server** (Arcane-managed, behind CGNAT). A deployment needs one of each,
and a narrow profile shrinks only the home role -- the VPS is identical
under all three.

### Three kinds of number, not one

They are not interchangeable, so each is labelled:

- **Hard floor** -- pinned in the tree. The software degrades below it, so
  it is a genuine minimum regardless of traffic.
- **Declared ceiling** -- what a compose file's `deploy.resources.limits`
  permits. **A ceiling is not a reservation.** The home role's largest
  profile declares 120.50 vCPU of ceilings and the reference host has 16
  logical CPUs; the VPS declares 7.40 vCPU on a 2-core box. Those sums are
  what the containers are *allowed*, not what they *use*, and sizing a
  host by adding them up is wrong by a wide margin.
- **Reference host** -- the one machine per role this repository has
  actually run on.

**There is no per-role load test in this repository, and nothing below is
one.** The reference-host figures are the only measured data here, and
there is exactly one host per role. The floors are derived from pinned
configuration. If you deploy somewhere else, measure it --
[below](#measure-your-own-host).

### Role: VPS

The public gateway, deployed by `scripts/install-vps.sh` rather than by a
profile -- see `docs/CGNAT-DEPLOYMENT.md` for the deployment itself. What
follows is only what it costs in host resources.

| | |
|---|---|
| hard floor | **2 vCPU.** `zeek` and `suricata` each declare `cpus: "1.0"`, and `vps/docker-compose.yml`'s own zeek comment states the premise: "The VPS has 2 cores and Suricata already runs here." Below two cores those two limits cannot both be honoured |
| declared ceilings | 50 services, 49 always-on. The 20 that carry limits sum to **7.40 vCPU / 4.38 GiB**; the other 29 -- every `socat-*` bridge plus `portbridge` -- carry **no limit at all**, so even that sum is an undercount |
| disk | `pcap-log` in `vps/suricata/suricata.yaml` rotates at `limit: 4mb` with `max-files: 12500` -- the config's own comment calls that "~50GB retention". That is the bound the VPS disk has to absorb, and it is enforced by Suricata, not by a cleanup script (`vps/suricata-log-maintenance.sh` prunes `eve-*.json`, `fast.log` and `stats.log` only) |
| reference host | 2 cores, **116 GB** disk holding ~50 GB of pcap -- `vps/docker-compose.yml`'s traefik-log-rotate comment |
| memory floor | **none published, because none is pinned.** Nothing in the tree reserves VPS RAM. The 29 unlimited services are socat relays and one Go relay, so the qualitative shape is small -- but their real footprint is measured nowhere in this repository, and the 4.38 GiB ceiling sum above covers only the 20 services that declare one. Treat any VPS RAM figure as unverified and measure it with `docker stats` |

### Role: home server

| | |
|---|---|
| hard floor | **6 GiB of permanently resident, unswappable RAM for Elasticsearch alone.** `arcane/home/honeypot-elk/compose.yml` pins `ES_JAVA_OPTS=-Xms6g -Xmx6g` *and* `bootstrap.memory_lock=true` with `ulimits.memlock: -1`, so the heap is mlocked into physical RAM -- a host under memory pressure cannot reclaim it by swapping (#240) |
| ES ceiling | the same service is capped at `memory: 12G` -- exactly 2x the heap, the ratio Elasticsearch's own heap-sizing rule produces. A host that cannot satisfy 12 GiB for this one container cannot run the stack as configured |
| declared ceilings | see the per-profile table below |
| reference host | **91 GiB RAM / 16 logical CPUs** (`docs/SENSORS.md`, `docs/gpu-llm-analysis-worker.md`); `/var` is a 1.8T xfs that sat at 131G free on 2026-08-31 |
| disk floor | **100 GB free on `/var`**, enforced rather than advisory: `scripts/install-homeserver.sh` writes `defaultMinFreeSpace: 100GB` into the Docker daemon's buildkit GC config, and its comment is explicit that on this host the build cache starts being pruned within ~31 GB of that line. Layer the pcap staging store (`PCAP_MAX_GB`, default 200, in `arcane/home/honeypot-elk/.env.example`) on top -- it is capped, but the cap only trims; it does not make room |
| GPU | 20475 MiB VRAM (RTX 4000 Ada) for the analysis plane only, confirmed live in `docs/gpu-llm-analysis-worker.md`. The `full` profile's sensors do not need a GPU |

### What a profile actually changes

The floor does **not** move with the profile: all three include `elk`, so
the 6 GiB mlocked heap applies to every one. What changes is how much is
declared, and how much traffic lands in Elasticsearch.

| Profile | Stacks | Services | With limits | Declared ceiling (vCPU) | Declared ceiling (GiB) |
|---|---|---|---|---|---|
| [`full.txt`](../../deploy-profiles/full.txt) | 26 | 75 | 74 | 120.50 | 66.81 |
| [`ics-focused.txt`](../../deploy-profiles/ics-focused.txt) | 7 | 41 | 40 | 73.00 | 43.81 |
| [`minimal-web.txt`](../../deploy-profiles/minimal-web.txt) | 7 | 43 | 42 | 82.00 | 49.56 |

Read the last two columns as the "ceiling is not a reservation" case above,
not as a host size. The one service in the home role with no limit at all
is `honeypot-elk`'s `arkime-pcap-init`, a one-shot bootstrap job; the VPS
role's 29 unlimited services are all long-running.

Two things in that table are worth knowing before you pick:

- **The backbone dominates, not the sensors.** `elk` alone declares
  35.00 vCPU and 26.50 GiB of the `full` profile's total, and it is in
  every profile. Dropping 19 of `full`'s 26 stacks -- every general-purpose
  honeypot -- takes 47.50 vCPU off 120.50, and none of that comes from the
  backbone. A narrow profile is a smaller attack surface and less ingest,
  not a proportionally smaller host.
- **Narrower is not always lighter.** `minimal-web` and `ics-focused` both
  list 7 stacks, but `minimal-web` declares 82.00 vCPU against
  `ics-focused`'s 73.00: `tanner` alone is 7 services and 16.00 vCPU of
  ceilings, which outweighs `conpot` (6 services, 8.00) plus `dnp3` (1
  service, 1.00). SNARE and its Redis and analyzer are not a light
  substitute for two protocol sensors.

### Measure your own host

The floors above come from configuration, so they cannot tell you whether
*your* machine is comfortable. These are the same checks the repo's own
diagnostics and tuning docs use:

```bash
# both roles
nproc; free -h; df -h /var /

# home: confirm the heap really is locked, and see real per-container use
docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}'
curl -s 'localhost:9200/_nodes?filter_path=**.mlockall'

# VPS: Suricata's own view of capture loss, the thing 2 vCPU has to survive
docker logs --tail 50 hp-suricata 2>&1 | grep -iE 'capture|kernel|dropped'
```

`mlockall: true` is the one to actually check. A silently-failed lock
(ulimit still too low) does not stop the container from starting or
reporting healthy -- `arcane/home/honeypot-elk/compose.yml` says so
directly -- so a healthy-looking Elasticsearch on a host that is swapping
is a 6 GiB heap that the kernel can take away.

If a host you picked is below a floor, the fix is the profile, not the
limit: dropping sensors changes the ceiling sum, but nothing changes the
`elk` floor. File a gap against #3328 if these figures and a real
deployment ever disagree.

## Validating a profile

```bash
scripts/validate-deploy-profile.sh deploy-profiles/ics-focused.txt
```

Checks, against the *current* repository state (not a hardcoded snapshot):

1. **Structural dependencies** -- `init`/`elk` present if any sensor stack
   is listed; `elk` present if `dashboard` is listed (the dashboard reads
   several sensors' events from Elasticsearch, not their log files --
   see #403 for why that's a real dependency, not a nice-to-have).
2. **Real-stack existence** -- every listed name must correspond to an
   actual `arcane/home/honeypot-<name>/` directory, so a typo'd or retired
   stack name fails here instead of surfacing mid-deploy or as a silently
   absent Arcane project.

Add a new profile by adding a `.txt` file here in the same format; no code
change needed for the validator to pick it up.

> **History: the EXPECTED_SENSORS cross-check (#2359).** The validator used
> to also parse an `EXPECTED_SENSORS=` value out of
> `arcane/home/honeypot-dashboard/compose.yml` and verify the profile's
> sensor names against it. Commit 824aa33d (#1628) removed that variable
> when the dashboard cutover completed; nothing consumes it anywhere today,
> because the modern source-health view (`backend-service/src/health.rs`)
> derives sensor liveness from observed `event.sensor` values rather than a
> static expectation list. Both the check and its `--emit-expected-sensors`
> helper were deleted rather than restored to an ownerless contract -- and
> the deletion was done loudly (#2359): passing `--emit-expected-sensors`
> now prints why it is gone instead of failing wordlessly, which is more
> than the old check ever managed when the variable vanished under it.
