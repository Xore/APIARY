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
