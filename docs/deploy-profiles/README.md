# Deployment profiles

[← back to README](../../README.md)

Which of the split home stacks (#258 -- `.github/workflows/deploy.yml`
currently syncs 17 of them, the authoritative list, not any doc's snapshot
of it) are active for a given deployment shape. Declared here instead of by
hand-editing which stacks you happen to run, so an operator running a
narrower deployment (fewer sensors, no VPS) has a named, checkable choice
instead of an implicit one nobody wrote down.

Different axis from [#258](https://github.com/Xore/APIARY/issues/258)
itself, which is about *topology* (one compose file per stack vs a
monolith) -- this is about *persona declaration*: which honeypots/dashboards
run for a given deployment, independent of how the compose files are
physically organized.

## Format

Each `.txt` file here is a plain list of home Dockge stack names (the
suffix after `honeypot-`, matching `.github/workflows/deploy.yml`'s own
`destination=/opt/stacks/honeypot-<name>` convention) -- one per line, `#`
comments and blank lines ignored.

## Profiles

| Profile | Backbone | Sensors | Shape |
|---|---|---|---|
| [`full.txt`](../../deploy-profiles/full.txt) | init, elk, dashboard, utilities, payload-analysis | every sensor stack `deploy.yml` currently syncs | the standard deployment -- everything this repo ships |
| [`ics-focused.txt`](../../deploy-profiles/ics-focused.txt) | init, elk, dashboard, utilities | conpot, dnp3 | OT/ICS-only exposure -- skip the general-purpose/web/SSH/legacy-protocol sensors entirely |
| [`minimal-web.txt`](../../deploy-profiles/minimal-web.txt) | init, elk, dashboard, utilities | http, tanner | web-attack-focused -- HTTP/API honeypot + SNARE/TANNER, skip ICS/SSH/legacy-protocol sensors |

`init`, `elk`, and `dashboard` are structural dependencies for any profile
that includes at least one sensor -- `validate-profile.sh` (below) enforces
this, it isn't just a convention to remember. `payload-analysis` and
`utilities` are strongly recommended (payload dedup/YARA scanning, log
rotation/disk monitoring/autoheal) but not structurally required, so the
validator only warns if either is missing from a non-empty profile.

Not covered here: the VPS side (`vps/`, always deployed the same way
regardless of home profile -- see `docs/CGNAT-DEPLOYMENT.md`) and
`ip-enrichment-worker` (currently has no `deploy.yml` sync step at all --
see [#560](https://github.com/Xore/APIARY/issues/560), a separate,
already-broken gap this doc doesn't paper over).

## Validating a profile

```bash
scripts/validate-deploy-profile.sh deploy-profiles/ics-focused.txt
```

Checks, against the *current* repository state (not a hardcoded snapshot):

1. **Structural dependencies** -- `init`/`elk` present if any sensor stack
   is listed; `elk` present if `dashboard` is listed (the dashboard reads
   several sensors' events from Elasticsearch, not their log files --
   see #403 for why that's a real dependency, not a nice-to-have).
2. **Dashboard consistency** -- every sensor stack in the profile maps to
   at least one name in `docker-compose.dashboard.yml`'s `EXPECTED_SENSORS`
   (parsed live from that file, so this can't silently drift the way a
   hardcoded copy would), and every name in `EXPECTED_SENSORS` traces back
   to a stack the profile actually includes. A stack enabled with no
   matching expected name would show as an unexplained extra; a name
   expected with no enabled stack behind it would show as permanently
   "missing" on the dashboard's health view -- both are real
   misconfigurations this catches before deploy, not after.

Add a new profile by adding a `.txt` file here in the same format; no code
change needed for the validator to pick it up.

## A real finding from writing this

`docker-compose.dashboard.yml`'s `EXPECTED_SENSORS` is a single hardcoded
value listing every sensor -- confirmed by running the validator: `full.txt`
passes cleanly (its emitted set matches `EXPECTED_SENSORS` exactly), but
both `ics-focused.txt` and `minimal-web.txt` correctly **fail** the
cross-check, because `EXPECTED_SENSORS` is not profile-aware today. Running
either narrower profile as-is would leave the dashboard reporting every
sensor outside that profile as permanently missing/offline -- exactly the
kind of silent-at-runtime failure this issue asked to catch before deploy
instead of after.

Until `EXPECTED_SENSORS` itself becomes profile-driven, get the correct
value for a given profile and use it to override that line by hand (or in
a compose override file) before deploying anything narrower than `full`:

```bash
scripts/validate-deploy-profile.sh --emit-expected-sensors deploy-profiles/ics-focused.txt
# EXPECTED_SENSORS=suricata,conpot,conpot-s7-1200,conpot-s7-1500,conpot-iec104,conpot-guardian,conpot-kamstrup,dnp3
```
