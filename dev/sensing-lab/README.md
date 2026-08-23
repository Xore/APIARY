# sensing-lab — local development harness for the S5 sensing layer

A workstation-local harness for developing and testing the sensing-layer
rebuild (EPIC #1742, decision in #1727 §0) **without deploying anything and
without filling this machine's disk**.

It runs Zeek — with the JA4+, HASSH and ICSNPP packages — over a small,
explicitly-bounded sample of real captured traffic pulled from the VPS, so
every parser and fingerprint can be exercised against genuine attacker
traffic rather than synthetic fixtures.

> This is a development harness. Nothing here deploys, and nothing here runs
> on the VPS or the homeserver. #1742 stays blocked behind the Phase 1
> backlog; this is the local build-and-test half of that work.

## Storage discipline — read this first

The production pcap corpus is **44 GB across 11 086 files** and Zeek's full
log set on real perimeter traffic is large. Neither belongs on this
workstation. Every path here is bounded, and the bounds are enforced by the
scripts rather than left to discipline:

| What | Variable | Default | Enforced by |
|---|---|---|---|
| pcap sample pulled from the VPS | `SAMPLE_MAX_BYTES` | **200 MB** | `fetch-sample.sh` stops copying at the cap |
| Zeek logs produced locally | `LOGS_MAX_BYTES` | **500 MB** | `run-zeek.sh` refuses to start over budget, prunes after |
| Where both live | — | `var/` | git-ignored in full |

- `./clean.sh` removes everything under `var/` and reclaims all of it.
- `./usage.sh` prints current consumption against the caps.
- **Never** rsync the whole corpus. `fetch-sample.sh` copies whole files
  newest-first and stops at the cap; it never pulls the directory wholesale.

## Layout

```
dev/sensing-lab/
├── Containerfile      Zeek 8.0 + zkg packages (JA4+, HASSH, ICSNPP suite)
├── build.sh           build the image
├── fetch-sample.sh    pull a bounded pcap sample from the VPS
├── run-zeek.sh        run Zeek over the sample into var/logs
├── usage.sh           show disk consumption vs the caps
├── clean.sh           delete everything under var/
└── var/               git-ignored: pcap/ and logs/
```

## Usage

```sh
./build.sh                      # once, ~10 min (ICSNPP compiles C++ plugins)
./fetch-sample.sh               # ~200 MB of real VPS traffic
./run-zeek.sh                   # parse it; logs land in var/logs
./usage.sh                      # confirm we are inside budget
./clean.sh                      # reclaim everything
```

Override a cap when a specific test needs more, deliberately:

```sh
SAMPLE_MAX_BYTES=$((500 * 1024 * 1024)) ./fetch-sample.sh
```

## What to look for

The point of running this against real traffic is to answer the questions
#1727 left open with measurement instead of documentation:

- Which Zeek logs actually populate on our perimeter traffic, and how densely?
- How many connections get a JA4T / JA4SSH / HASSH / JA4H fingerprint,
  compared with what p0f and Suricata produce over the same window?
- Does ICSNPP produce real transaction detail on ports 102/502/2404/20000/
  44818/47808, where we currently record only Suricata alerts?
- Does Zeek's `conn.log` genuinely supersede Suricata's `flow`/`netflow`
  (the premise of #1741's 80.1 % reduction)?

`run-zeek.sh` prints a per-log record count at the end, which is the raw
material for that comparison.
