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
sensor choices.

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

## Sizing, per host role

A profile says *which* stacks run. It never said what has to fit. The two
roles are not interchangeable — the VPS is a small public edge, the homeserver
is the whole sensor fleet — and the answer for both was previously written
down nowhere (#3328; the certificate half of that issue landed in #3352, this
is the sizing half). The VPS is not a profile choice — see "Not covered here"
above — it is in this section only because it has a size.

Two different kinds of number appear below, and they are not
interchangeable:

- **Measured** — taken from a running host, with the command and the date,
  cited to the doc that recorded it. They are only as current as that record.
- **Declared** — the sum of the ceilings the compose files set
  (`deploy.resources.limits`), recomputed from the trees by
  `scripts/deploy-profile-sizing.py`. Reproducible, but a declaration is not
  an observation.

```bash
scripts/deploy-profile-sizing.py            # full summary, per profile and per stack
scripts/deploy-profile-sizing.py --format md  # exactly the table rows below
```

The memory column is the one that decides whether a host is big enough: a
container is OOM-killed the moment it reaches its `memory` limit, so **the sum
of a profile's memory limits is the smallest amount of RAM that profile can run
on without the host killing its own containers.** The CPU column is a sum of
ceilings and nothing more — no CPU is reserved by declaring a limit, so
`full.txt`'s 120.5 is not a claim that it needs 120.5 cores. And every total is
a **lower bound**: services with no declared limit count as zero, which the
"no limits" column reports rather than hiding.

### homeserver — `arcane/home/`

| | measured | recorded in |
|---|---|---|
| CPU | Xeon Gold 5220R, 24 cores / 48 threads, 2.20 GHz (verified 2026-09-05) | [benchmarks/plans/2026-09-05-1947-resume-plan.md](../benchmarks/plans/2026-09-05-1947-resume-plan.md) |
| RAM | 93 GB, 6 × 16 GiB, 2 DIMM slots still empty (verified 2026-09-05) | [same plan](../benchmarks/plans/2026-09-05-1947-resume-plan.md) |
| Swap | 8 GiB swapfile at `/swap.img` on the root filesystem | [HOMESERVER-DISK-LAYOUT.md](../HOMESERVER-DISK-LAYOUT.md) |
| Disks | 238.5G NVMe OS disk, `sda` 447.1G reserved bulk, `/var` on its own RAID LUN | [HOMESERVER-DISK-LAYOUT.md](../HOMESERVER-DISK-LAYOUT.md) |
| `/var` | 1.8 T (`/dev/sdd1`); hit **96 % full on 2026-08-31**, failing two Elasticsearch-backed CI legs until `docker builder prune -af` reclaimed 179 GB of buildkit cache and took it back to 89 %. The installer's own sizing comment records 93 % (131 G free) the same day | [disk-usage-watch.py](../../scripts/disk-usage-watch.py), [install-homeserver.sh](../../scripts/install-homeserver.sh) |
| Container writable layers | 245.8 GB, 245 GB of it in one CI eval container (`docker system df`, 2026-09-03) | [container-writable-layer-audit-2026-09-03.md](../container-writable-layer-audit-2026-09-03.md) |
| GPU | RTX 4000 Ada, 20475 MiB VRAM, driver 580.173.02 / CUDA 13.0 | [gpu-llm-analysis-worker.md](../gpu-llm-analysis-worker.md) |
| CPU contention | load average **15–27** with seven `honeypot-ci` runner instances live — enough to swing identical benchmark work by 62 % (78.2 vs 126.7 min/run). The runners were cut to two on 2026-09-05 | [benchmarks/plans/2026-09-05-1947-resume-plan.md](../benchmarks/plans/2026-09-05-1947-resume-plan.md) |

That is the only homeserver this repo has any measurement of, and it is the
one running `full.txt` — so the honest minimum for the full profile is "this
box, or bigger": 24c/48t and 93 GB of RAM with the whole fleet's declared
ceilings (66.8 GiB) underneath it, which leaves about 25 GiB for everything
that is not a profile stack — the OS, Arcane, Ollama, the CI runners, the
benchmark and training planes. The two narrower profiles are subsets of the
same host, so their *declared* floors drop (43.8 and 49.6 GiB) while the
*measured* box does not; there is no record of either running on anything
smaller, and the OOM history below is the reason not to assume.

`arkime-pcap-init` is the one service in `elk` with no declared limit, so the
`elk` stack's 26.5 GiB understates it by whatever that init job uses.

### VPS — `vps/`

| | measured | recorded in |
|---|---|---|
| CPU | 2 cores | [vps/docker-compose.yml](../../vps/docker-compose.yml) (`zeek`'s comment) |
| Disk | one 120G virtio disk (`vda`) per the disk-layout doc, quoted in the compose file as a "116 GB VPS" | [HOMESERVER-DISK-LAYOUT.md](../HOMESERVER-DISK-LAYOUT.md), [vps/docker-compose.yml](../../vps/docker-compose.yml) |
| RAM | **not measured anywhere in this repo** — see below | — |
| Disk use | Suricata `pcap-log` ring ~50 GB (bounded), `eve.json` **unbounded**, 4.4 GB and climbing at the last check | [vps/suricata/README.md](../vps/suricata/README.md) |

4.4 GiB of declared memory across 50 services is a floor, and a soft one: 30
of those services — every `socat-*` bridge, `portbridge` itself, and
`suricata-update` — declare no limit at all, so the number says nothing about
what they actually use. The CPU sum (7.4) is no more meaningful than the
homeserver's.

The VPS's RAM is the one figure in this section that nobody has ever
recorded. The Diagnostics VPS job reaches the host over SSH every run, so
`free -b` there would close the gap; until someone adds it, treat the declared
4.4 GiB as the floor and measure the real number before sizing a second edge
box. Suricata is the reason that matters: it OOM-kills against its 768M limit
under live rules reload (verified 2026-08-01), so the VPS's margin is already
known to be thin in at least one container.

### Declared ceilings, per profile

| profile | stacks | services | cpus | memory | no limits |
|---|---|---|---|---|---|
| `full.txt` | 26 | 75 | 120.5 | 66.8 GiB | 1 |
| `ics-focused.txt` | 7 | 41 | 73.0 | 43.8 GiB | 1 |
| `minimal-web.txt` | 7 | 43 | 82.0 | 49.6 GiB | 1 |
| `vps/` (whole role) | — | 50 | 7.4 | 4.4 GiB | 30 |

`scripts/deploy-profile-sizing.py --format md` prints these four rows, and
`tests/docs/test_3328_profile_sizing_matches_compose.py` fails if they stop
matching the compose files — the numbers cannot silently go stale the way a
hand-copied table would.

### These ceilings are load-bearing, not aspirational

Every one of them was raised because a container was OOM-killed in production
against the previous value, which is the strongest available argument for
sizing above the sum rather than at it:

- **Elasticsearch** ran at a 512m limit and was OOM-killed (exit 137) by
  geoip mmdb loads and reindex jobs. It is now `memory: 12G` with a 6g heap —
  the largest single line item in any profile.
- **The dashboard's `backend-worker`** went 256M → 512M → 768M → 1536M. At
  512M, live `docker stats` showed it pinned at 508/512 MB *and* at
  50.22 % CPU — its entire 0.5-core quota — at the same time, slow enough that
  `/healthz` missed its timeout while the container kept running; 768M was
  OOM-killed too (2026-08-22, anon-rss ~778-782 MB every restart).
- **`payload-dedupe`** ran at 128M and OOM-looped every ~28 s for days,
  never completing a pass over the `bistreams/` backlog. It is now 2048M.

(`arcane/home/honeypot-elk/compose.yml`, `arcane/home/honeypot-dashboard/compose.yml`,
`arcane/home/honeypot-payload-analysis/compose.yml` — each carries the full
account in the comment above its own limits.)

Note that [SENSORS.md](../SENSORS.md)'s runtime-budgets paragraph still
quotes Elasticsearch at "8 GiB with a 4 GiB heap" and the host at "16 logical
CPUs and 91 GiB RAM" — both predate the current compose values and the
2026-09-05 CPU/RAM change. The compose files are authoritative; this table is
generated from them.

> **Disk is the other half of sizing, and it is the half that fills first.**
> The homeserver's `/var` (1.8 T) reached 96 % full on 2026-08-31 and took two
> CI legs down with it; `docker system df` three days later put 245.8 GB of
> that in container writable layers rather than ELK indices. The VPS's
> `eve.json` is unbounded on a ~116 GB disk that also has to hold a ~50 GB pcap
> ring. Neither number comes from this section's table, and both are what
> `scripts/disk-usage-watch.py` and the Diagnostics disk checks exist to catch.

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
