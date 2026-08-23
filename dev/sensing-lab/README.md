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
├── Containerfile         Zeek 8.0 + zkg packages (JA4+, HASSH, ICSNPP suite)
├── build.sh              build the image
├── fetch-sample.sh       pull a bounded, recency-ordered pcap sample
├── fetch-port-sample.sh  pull a sample filtered to specific ports
├── fetch-ics-sample.sh   the ICS port list, wrapping the above
├── pcap-port-filter.py   stdlib pcap port filter, runs on the capture host
├── run-zeek.sh           parse a sample; PCAP_DIR selects which
├── usage.sh              disk consumption vs the caps, per directory
├── clean.sh              delete everything under var/
└── var/                  git-ignored: pcap*/ and logs*/
```

## Usage

```sh
./build.sh                                  # once, ~10 min (ICSNPP compiles plugins)
./fetch-sample.sh                           # newest traffic, up to 200 MB
./run-zeek.sh                               # parse it; logs land in var/logs
./usage.sh                                  # confirm we are inside budget
./clean.sh                                  # reclaim everything
```

### Targeted samples

Recency-ordered sampling only surfaces whatever dominates the wire. On this
perimeter that is telnet, VNC and SIP scanning — measured, **ICS traffic is
about 1 % of the telnet volume**, so the first general sample contained none
at all. For anything that is not the loudest thing on the link, filter:

```sh
./fetch-ics-sample.sh                       # ICS ports → var/pcap-ics
PCAP_DIR=var/pcap-ics ./run-zeek.sh         #            → var/logs-ics

SAMPLE_NAME=web SAMPLE_PORTS=80,443 ./fetch-port-sample.sh
PCAP_DIR=var/pcap-web ./run-zeek.sh
```

Filtering runs on the capture host, so scanning gigabytes there costs
megabytes here. Every scan also runs a known-busy **control port** and prints
both counts — a zero result is only believable next to a non-zero control.
That distinction was not free: the first ICS scan reported "no traffic found"
when in fact AppArmor had denied every single read.

Override a cap when a specific test needs more, deliberately:

```sh
SAMPLE_MAX_BYTES=$((500 * 1024 * 1024)) ./fetch-sample.sh
MAX_OUT_BYTES=$((100 * 1024 * 1024)) SAMPLE_NAME=web SAMPLE_PORTS=443 ./fetch-port-sample.sh
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
