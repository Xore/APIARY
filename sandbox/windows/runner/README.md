# Detonation is not triggered by GitHub Actions

> **Status (2026-07-31):** this directory is a placeholder. It used to hold a
> setup guide for a self-hosted runner that would detonate samples from a CI
> workflow. That approach was replaced by the systemd spool worker described
> below, and the guide was removed rather than kept: it named a workflow
> (`Xore/Honeypot/.github/workflows/analyze.yml`) that does not exist in a
> repository that is not this one, and it disagreed with the shipped
> configuration on the domain name, the snapshot name, the guest credentials
> and the bridge.

## What actually triggers a detonation

The dashboard writes `{sha256}.request` into the request spool and never touches
a hypervisor itself. A root-owned path unit notices the file and drains the
queue:

| Piece | File |
|---|---|
| Path unit watching the spool | `sandbox/windows/honeypot-windows-sandbox-worker.path` |
| Oneshot service it starts | `sandbox/windows/honeypot-windows-sandbox-worker.service` |
| Queue drain, one sample at a time under `flock` | `sandbox/windows/run_pending.sh` |
| Per-sample orchestration | `sandbox/windows/orchestrate/run_sample.py` |
| Host-specific values (never in the repo) | `/etc/default/honeypot-windows-sandbox` |

This is the same trust boundary the Linux sandbox uses (`sandbox/worker.sh`),
and it is the boundary for the same reason: the dashboard container is
unprivileged, holds no credentials, and can do nothing more privileged than
create a file whose name is a hash it has already validated. See
[`../IMPLEMENTATION_PLAN.md`](../IMPLEMENTATION_PLAN.md) §7.1.

## Why not a CI runner

The self-hosted runner is not the problem — one already exists and is in use.
`deploy.yml` and `diagnostics.yml` both run on
`[self-hosted, linux, x64, honeypot-home]`, on the same host as libvirt. Adding
detonation to it would have needed no new infrastructure.

It is the wrong place for it anyway:

- **A workflow run is triggerable by anything that can push or open a PR.**
  Detonation must be gated on an authenticated dashboard action against a
  capture the stack already holds, resolved by SHA-256. A CI trigger widens
  that to whoever can cause a workflow to fire.
- **A runner job needs the guest credentials in its environment.** The old
  guide put `VM_PASS` in `/opt/actions-runner/.env`, readable by every job the
  runner executes. The spool worker reads them from a root-owned
  `EnvironmentFile` that no workflow and no container can see.
- **Detonation is queue work, not build work.** `run_pending.sh` holds a
  non-blocking lock so overlapping triggers collapse into one drain — a second
  concurrent detonation would revert the snapshot out from under the first.
  Two workflow runs have no such interlock.
- **The result has to come back read-only.** The worker writes
  `{sha256}_sandbox.json` where the dashboard mounts it read-only. A workflow
  would have to push artifacts somewhere the dashboard could read, which means
  either giving the dashboard network egress or giving CI write access to its
  data — both are the boundary this design exists to avoid.

Nothing here is scheduled work. If a CI-driven path is ever wanted (for
example, a nightly regression detonation of a known-benign fixture), it is a
new proposal and needs an issue, not a revival of this file.
