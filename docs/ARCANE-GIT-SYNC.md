# Arcane Git sync

How the 37 home-hosted stacks (31 that migrated under `arcane/home/` plus 6
that were already self-contained and stayed at their existing path) get to
the live host, replacing the old model of copying or symlinking top-level
`docker-compose.*.yml` files into place. Everything here was confirmed live
against the pinned Arcane `v2.8.0` API during #1502's own migration, not
taken from Arcane's docs — see the risk that motivated that in "Version/API
compatibility" below. Census numbers and the live sync-store state were
re-verified 2026-08-27 against the pinned `v2.9.0` image and its own sqlite
store (#2549): 31 in-tree directories + 6 self-contained = 37, exactly the
manifest's entry count.

## The model

Each stack gets its own **directory-aware Git sync**: Arcane clones the
`apiary` repository, materializes the *entire directory* containing the
selected `compose.yml` (not just that one file) under
`/var/dockge/stacks/<syncName>/`, and deploys it. The manifest at
[`arcane/manifests/home-production.json`](../arcane/manifests/home-production.json)
is the single source of truth for which 37 stacks exist, what branch/path
each syncs from, and any per-stack sync limits — `scripts/install-homeserver.sh`,
CI, and this doc all read from it rather than maintaining separate lists.

- The 31 `honeypot-*` stacks live under `arcane/home/<name>/`: their build
  context and git-tracked config were moved there from repository root
  (see each compose file's own `#1502` comment for what moved and why).
- The 6 other stacks (`auth-events-worker`, `llm-worker`, `ml-worker`,
  `analysis/ghidra`, `sandbox/ghosts`, `pihole`) were already self-contained
  and stayed at their existing path — moving them would have broken real
  references from `scripts/install-homeserver.sh`, CI workflows, and
  `deploy.yml`'s own ghidra-worker resync step. See each one's own compose
  file header for the specifics.
- `honeypot-arcane` itself is **not** in the manifest and never will be —
  syncing the thing that has to already be running before any sync can
  happen is a bootstrap loop, not a simplification. It stays
  installer/`deploy.yml`-managed exactly as before.

## Repository authentication

`Xore/APIARY` is public, so the registered repository
(`POST /customize/git-repositories`) uses `authType: "none"` — plain HTTPS
clone, no deploy key or token. If this repository is ever made private,
switch to a read-only deploy key or narrowly scoped token and set
`sshHostKeyVerification` to strict (not `accept_new`) once the host key has
been provisioned once.

## Manifest import

`scripts/install-homeserver.sh`'s `step_arcane_import_stacks` reads the
manifest and creates one `POST /environments/0/gitops-syncs` per matching
entry (environment `0` is Arcane's single "Local Docker" environment on a
one-host deployment). Its selection filter matches every `honeypot-*`
entry — and, since #1505, three of the six non-`honeypot-*` stacks too:
`auth-events-worker`, `llm-worker` and `ml-worker` are imported by that
step as well (each confirmed to have no host-local state beyond `.env`).
The other three keep their dedicated installer steps for reasons specific
to each: `pihole`'s non-`.env` host state, `analysis/ghidra`'s conditional
GPU compose overlay, and `sandbox/ghosts`'s Arcane build-context
limitation (#1506) — see the script's own Phase 8 header comment for the
reasoning behind each.

To import (or re-import) by hand instead, `POST` the manifest's entries to
`/environments/0/gitops-syncs/import` — the bulk-import shape matches the
manifest's own field names exactly (`syncName`, `gitRepo`, `branch`,
`dockerComposePath`, `autoSync`, `syncDirectory`, `syncInterval`).

## A directory-sync create call deploys immediately

**Not obvious from the field names**: creating a sync (`autoSync: false` or
not) performs an initial materialize-and-deploy right away. `autoSync` only
governs whether *future* commits on the tracked branch trigger another sync
automatically — it does not make the first one a dry run. Plan a cutover
accordingly: creating the sync *is* the cutover for that stack.

## Directory-collision behavior is fail-closed

Confirmed by a live test during #1502's migration: pointing a sync at a
directory name that already exists under Arcane's `PROJECTS_DIRECTORY` gets
refused outright —

```text
cannot create project "<name>": a directory with that name already exists;
refusing to create a duplicate
```

Arcane does **not** overwrite or merge into an existing directory. This is
good for secret safety (a sync can never silently wipe a directory holding
real secrets), but it means cutting an already-deployed stack over requires
removing the stack's legacy directory first — after backing up anything not
tracked in Git that lives there. See "Cutover procedure" below; this is
exactly why `step_arcane_import_stacks` stages `.env` aside rather than
letting Arcane's own directory check block the whole import.

## Cutover procedure (per stack)

1. **Enumerate everything at the stack's current directory that Git does
   not track** — not just `.env` and `secrets/`. Confirmed live: `pihole`
   also keeps its DNSCrypt resolver config and its own Pi-hole database
   directly under its own top-level directory (`dnscrypt-proxy/`,
   `etc-pihole/`, `etc-dnsmasq.d/`), a shape none of the other 37 stacks
   have. Back up the *actual* bind-mount sources a stack's compose file
   declares, not an assumed `.env`/`secrets/` checklist — read the compose
   file if in doubt.
2. Back up everything found in step 1.
3. Remove the stack's current directory.
4. Create the Arcane sync (`syncDirectory: true`) — this deploys
   immediately, and will legitimately fail-closed if a required secret
   isn't present yet (expected, not a bug — see canarytokens/ghosts/
   keycloak/dashboard's own `:?required` variables).
5. Restore everything backed up in step 1, **preserving original ownership
   and permissions, not just content**. Confirmed live: restoring a secret
   file as `root:root` when the container expects the previous owning
   user/UID to read it reproduces the exact crash-loop #1143 already
   documented for Keycloak — Postgres's `SCRAM-based authentication, but no
   password was provided` when the container can't actually open the file.
   Check `stat -c "%U:%G %a"` on the original before removing anything, and
   match it exactly on restore.
6. If step 5 restored anything the initial deploy needed,
   `POST /environments/0/projects/{id}/up` to redeploy with it now present.
7. Verify health, and for anything with a network-facing port, verify
   actual reachability at the address real clients will use — not just that
   the container reports healthy. A container can be genuinely healthy and
   correctly resolving DNS internally while the host's own NAT path to its
   published port is still broken from a stale `docker-proxy`/iptables
   state after several rapid recreations; a full `docker compose down` +
   `up` (not just `docker restart`) was what actually cleared that,
   confirmed live during the `pihole` cutover.

## Retirement procedure (per stack)

Deleting a stack's `arcane/home/<name>/` directory from this repo only ever
removes the *source*. It does nothing to what is already deployed — Arcane
has no "this project's directory disappeared, tear it down" behavior, and a
homeserver whose last sync predates the deletion just keeps its
already-synced compose file and already-running containers on disk exactly
as they were. #2813/#2814 (wordpot's retirement in #2381) both surfaced
this the same way: the repo said the stack was gone, but a live container
was still up weeks later — on the VPS because `docker compose up -d`
without `--remove-orphans` never removes a service dropped from the compose
file (fixed for the VPS's own deploy path in #2813), and on the homeserver
because nothing ever told Arcane to tear the project down at all. Retiring
a stack means:

1. Remove the stack's `arcane/home/<name>/` directory (or its VPS
   equivalent block in `vps/docker-compose.yml`) from this repo, same as
   any other change.
2. On every host that had it deployed, actually stop and remove the live
   containers — `docker compose -f compose.yml down` in the stack's
   directory, not just deleting the repo source and waiting for the next
   sync. Another, still-tracked stack's `--remove-orphans` redeploy will
   not do this for you — that flag only cleans up orphans within its own
   compose file's project, not a sibling stack entirely.
3. For an Arcane-managed (homeserver) stack, also delete the corresponding
   `gitops-syncs` record (`DELETE /environments/0/gitops-syncs/{id}`) and
   remove the on-disk stack directory under `/var/dockge/stacks/<name>/` —
   an orphaned sync record with no matching repo directory is itself a
   confusing half-retired state.
4. Re-run the live verification a normal cutover would (`docker ps -a
   --filter name=<stack>` on every host it was ever deployed to), not just
   a repo grep — the repo can be fully clean while the live fleet still
   isn't.

## Known Arcane v2.8.0 limitations, confirmed live

These are platform behaviors, not something fixable from a compose file
alone. Re-verify against whatever Arcane version is pinned in
`docker-compose.arcane.yml` if it's ever upgraded.

- **A `:?required` compose variable used inside a port-binding host-IP
  position breaks Arcane's own compose validator.** The same `:?required`
  pattern works correctly inside an `environment:` block (Arcane surfaces
  the real "missing value" error there, confirmed against
  `honeypot-canarytokens`/`ghosts`). In a port-binding position, Arcane's
  pre-flight validation substitutes a placeholder for the unset variable
  and then fails Docker's own strict host-IP format check on that
  placeholder — the resulting error (`invalid IP address:
  /placeholder-undefined`) doesn't point at the real cause. Workaround:
  don't use `:?required` for a variable in that position; use `:-` with a
  safe, non-functional default instead (see `pihole/compose.yml`'s
  `LAN_IP` — defaults to `127.0.0.1`, deliberately not the real LAN
  address, since a real deployment-specific address in a public compose
  file would also trip `scripts/check-public-leaks.py`).
- **The build-context git-ref resolver only understands `refs/heads/`.** A
  remote build context pinned to a tag (`ghosts`'s
  `GHOSTS.git#v9.0.0:src`, before the fix below) fails with
  `couldn't find remote ref "refs/heads/v9.0.0"`, even though plain
  `docker build`/BuildKit resolves the same ref fine on its own. Pinning to
  the tag's commit SHA instead of the tag name does **not** fix it —
  Arcane prefixes `refs/heads/` onto *any* ref string given this way, tag
  or SHA. There is currently no compose-file-level workaround:
  **`ghosts-api` has to be built with plain `docker compose build`
  outside Arcane** after every sync (Arcane's own directory sync still
  correctly materializes the files, just not this one image build).
  ```bash
  cd /var/dockge/stacks/ghosts && docker compose up -d ghosts-api
  ```
- **The default sync file-count limit (500) is easy to exceed with a
  vendored dependency tree.** `honeypot-dashboard`'s manifest entry sets
  `maxSyncFiles: 2500` explicitly — headroom carried over from when its
  build context still included the Go dashboard's vendored tree
  (`dashboard/vendor/`, exactly 650 tracked files at the #1502 move,
  re-counted from git history), which exceeded the default back then. That
  tree is gone with the Go tier itself (#1659) and the synced directory is
  down to 268 tracked files (re-counted 2026-08-27,
  `git ls-files arcane/home/honeypot-dashboard`) — under the default
  again, so the bump is dormant headroom, kept because raising it is an
  Arcane-side change rather than a repo one. The failure mode itself
  remains: if a future stack's build context grows a large
  vendored/generated tree, expect the same `file count limit exceeded`
  failure and raise that stack's own `maxSyncFiles` rather than assuming
  the default is enough.
- **The directory-sync walk has no exclude/scope mechanism at all** —
  confirmed against the source (`pkg/gitutil/git.go`'s `WalkDirectory`):
  it walks everything under `filepath.Dir(composePath)` except `.git` and
  symlinks, with no glob, no `.gitopsignore`, no sub-path option. #2711:
  `ghosts`'s sync (`sandbox/ghosts/compose.yml`) always failed — either a
  ~40s-then-500 with no detail, or (once `maxSyncTotalSize` alone was
  raised) a fast `file count limit exceeded` — because
  `sandbox/ghosts/vendor/ghosts-src/` (963 tracked files, ~132 MB) sits in
  the same directory tree as the compose file, so the sync's whole-directory
  walk of `sandbox/ghosts/` (989 files, 135,789,139 bytes in total) blows
  past *both* defaults (`maxSyncFiles: 500`, `maxSyncTotalSize: 50MB`), not
  just the one either failure message names. Fixed the same way as the
  `honeypot-dashboard` case above — both limits raised on the sync record
  and mirrored into the manifest (`arcane/manifests/home-production.json`:
  `maxSyncFiles: 1500`, `maxSyncTotalSize: 209715200`, ~1.5x headroom over
  the measured size). Verified live 2026-08-31: `Directory walk complete
  syncId=... totalFiles=989 totalSize=135789139 skippedBinaries=0`, sync
  request returned `200` with `"Successfully synced directory with 989
  files to project ghosts"`, `ghosts-api` rebuilt and redeployed from the
  synced tree, confirmed serving real data afterward. Total request time
  was **227s** — comfortably under the #2705 ~5 minute internal deploy
  timeout today, but with much less margin than any other project in this
  manifest; if the vendored tree grows further (see #2256, which questions
  whether it belongs in the repo at all — deliberately not addressed
  here), this is the first sync that will hit that deadline again.
- **A destroyed project can leave a stale path/sync binding.** Deleting a
  *sync* does not always fully clear the *project* record Arcane created
  for it — a subsequent sync attempt at the same path can fail with
  `UNIQUE constraint failed: projects.path` or
  `project <id> is already managed by a different GitOps sync` even after
  the blocking sync was deleted. Archiving the stale project
  (`POST .../projects/{id}/archive`) does **not** free the path either;
  only destroying it does
  (`DELETE /environments/0/projects/{id}/destroy`). Confirmed live that
  `destroy` does *not* touch a named Docker volume the stack's containers
  were using — `ghosts-postgres-data` survived a `destroy` cleanly and the
  recreated Postgres container found its existing database intact. It can,
  however, remove the stack's *containers* even when they were healthy and
  serving traffic at the time — check `docker ps -a` immediately after any
  `destroy` call and be ready to bring the affected service back up by
  hand (plain `docker compose up -d`, same as the ghosts-api workaround
  above) rather than assuming the next sync attempt alone will do it.
- **Arcane has no Docker Compose `profiles:` support at all** — not a
  quirk, a confirmed missing feature
  ([getarcaneapp/arcane#1193](https://github.com/getarcaneapp/arcane/issues/1193),
  open/unimplemented as of v2.8.1, the latest release at time of writing;
  still open against the pinned `v2.9.0`, re-checked 2026-08-27).
  Confirmed independently against this deployment, re-derived 2026-08-27
  against the exact digest-pinned `v2.9.0` image this host runs (image
  digest verified against `docker-compose.arcane.yml`; response schemas
  exported from that container with `./arcane openapi`; the project
  record read from Arcane's own store — no API token was on hand for a
  fresh authenticated GET, so the schema and the stored record stand in
  for it): `GET /environments/0/gitops-syncs` and `GET
  /environments/0/projects/{id}` still expose no profile-activation state
  — the only `profiles`-shaped fields anywhere in either response's schema
  are the raw compose service-config passthroughs embedded in the project
  response's optional `services[]` / `runtimeServices[].serviceConfig`
  arrays, which merely echo what a compose file declared and are omitted
  from a plain project GET. `honeypot-dashboard`'s project record reports
  `serviceCount: 8` — exactly the eight services its
  `arcane/home/honeypot-dashboard/compose.yml` defines today
  (`oidc-sessions`, `backend-service-mounted`, `backend-worker`,
  `dashboard-next`, `backend-worker-importer`,
  `backend-worker-enrichment`, `backend-worker-payload-inventory`,
  `services-adapter`), none of them profile-gated: the file contains no
  `profiles:` key at all. (The request/response `backend-service` itself
  now lives one stack over, in `honeypot-dashboard-backend` — its own
  one-service project record, same zero-profile shape.) The four-service
  snapshot this section used to quote (`dashboard`, `oidc-sessions`,
  `es-results-importer`, `services-adapter` at `serviceCount: 4` /
  `runningCount: 4` when captured during #1502) is an era record now: the
  Go `dashboard` went away with its folder (#1659), the Python
  `es-results-importer` was ported to the Rust `backend-worker-importer`
  (#1610), and the #1610/#1612 worker migration added the rest.
  `runningCount` is not a fixed record field: v2.9.0 recomputes it from
  `docker compose ps` on every project GET, so it tracks actual container
  state at query time (7/8 on 2026-08-27, with `backend-worker-enrichment`
  exited at that moment), not profile gating. This settles
  #1628's own open question: a sync brings up only a stack's base
  (non-profiled) services; activating any `profiles:`-gated service group
  — same as `geoip-update`/`threat-intel`/`revdeck`/`mitm`/`test`/
  `blackhole` elsewhere in this repo — is always a manual `docker compose
  --profile X up -d` run against the synced directory on the host
  afterward. There is no Arcane-native mechanism (env override or
  otherwise) that activates a profile instead. (`next` itself never got
  that treatment: #1608's cutover deleted the profile outright rather
  than activating it.)

## Local environment overrides

Compose's own `.env`-in-project-directory interpolation already covers
every `${VAR}` reference in these 37 stacks — none of them use `env_file:`,
and none needed it added. Arcane's effective environment merge
(`project.env` + `.env.git` → `.env`) feeds that same mechanism
transparently, so a local override set through Arcane's own UI for a synced
project works exactly like editing `.env` by hand always did; no stack-file
changes were needed to support it.

Two things worth knowing when setting an override:

- A stack whose `.env.example` documents a variable as `# REQUIRED` will
  fail-closed at sync/deploy time if that variable is missing — this is by
  design (see "Environment and secret handling" in the parent issue), not
  something Arcane's own UI will warn about before you deploy.
- A Git sync **never** touches host-local files that aren't tracked in
  Git — `.env`, `secrets/`, and (for the handful of stacks that keep other
  runtime state directly in their own directory, see `pihole` above) those
  directories all survive a re-sync of the tracked files around them,
  *provided the directory itself isn't removed and recreated* the way a
  full cutover does. Routine re-syncs (pulling a normal commit on the
  tracked branch) do not remove the directory; only the explicit
  remove-then-resync cutover sequence above does.

## Manual sync, deploy, rollback, and failure triage

- **Trigger a sync manually**: `POST /environments/0/gitops-syncs/{syncId}/sync`.
- **Redeploy without re-syncing** (e.g. after restoring a secret):
  `POST /environments/0/projects/{projectId}/up`.
- **Check a sync's last result**:
  `GET /environments/0/gitops-syncs/{syncId}` — look at `lastSyncStatus`
  and `lastSyncError`. A `"failed"` status with a container exit-code error
  for a one-shot job (`restart: no`, e.g. `honeypot-init`'s
  `snare-clone`/`elasticsearch-setup`) can be a **false negative**: Arcane's
  health-check-aware deploy logic treats any container exit — including a
  legitimate `exit 0` from a one-shot job — as a deploy failure. Confirmed
  live: the job had actually completed successfully (exit code 0, its
  state markers written) despite the sync reporting `"failed"`. Verify the
  real container exit code (`docker inspect <container> --format
  '{{.State.ExitCode}}'`) before treating a one-shot-job stack's failed
  sync status as a real incident.
- **Rollback**: point the sync's `branch` back at the previously-known-good
  ref (or revert the offending commit on the tracked branch) and trigger a
  manual sync. There is no dedicated "rollback" API call — a directory sync
  is idempotent against whatever the tracked ref currently resolves to, so
  moving that ref backward and re-syncing is the rollback.
- **A stalled-looking sync/build is often not actually stuck.** Several
  stacks in this migration took multiple minutes to build (uncached Rust
  and PyTorch compiles in particular) with no visible progress in Arcane's
  own API response — the HTTP call to create/trigger a sync can return
  well before the underlying `docker build`/`compose up` finishes. Check
  for an active build process (`ps aux | grep -i buildkit` on the host) and
  `docker logs hp-arcane` for recent activity before assuming a stuck
  build needs intervention; Arcane has an internal ~5 minute deploy
  timeout, past which it gives up waiting even though the underlying
  `docker build` keeps running and usually finishes on its own — if it
  does, `POST .../projects/{id}/up` once the image exists
  (`docker images | grep <stack>`) completes the deploy cleanly.

## Promotion workflow and change control

Decided in #1507: **release/tag promotion**, with `autoSync` enabled for
exactly the three stacks where a sync is the whole deploy. As of
2026-08-27 that policy has **never been put into effect** — every sync
still tracks `main` and nothing auto-deploys (#2549 re-derived the live
state). What actually runs is the manual model below; #2577 holds the
one-time activation steps and the dangling-sync cleanup if that ever
changes.

### Two facts (still true today)

**A sync does not build, but it redeploys anyway when a file changed —
`redeploy_after_sync = 0` does not prevent that.** #2706 caught this
live: the log line is explicit, `Redeploying project due to content
change from Git sync`, and it fires regardless of the stored
`redeploy_after_sync` flag. 28 of 38 projects were redeployed this way
during what was intended to be a files-only sync pass on 2026-08-30. The
live store carries `auto_sync = 0`, `pull_image_after_sync = 0` and
`redeploy_after_sync = 0` on every sync (re-verified 2026-08-27 against
the pinned `v2.9.0` image's own sqlite store) — those are Arcane's
defaults, not manifest-set values: the manifest carries neither field,
and #2455's schema check confirmed the bulk-import request has no way to
set them (only the single create-sync request does) — but none of the
three flags gate the content-change redeploy path, so do not read
`redeploy_after_sync = 0` as "this sync only materializes files." Plan
every sync as a restart of that stack. Confirmed operationally: syncing
`honeypot-dashboard` redeploys the dashboard project from whatever image
is already present — since that project has no `build:` service itself,
`apiary-backend:latest` is left exactly as it was until a separate
`POST /projects/{id}/build` (a call that belongs to the sibling
`honeypot-dashboard-backend` project since #1622 — its `backend-service`
is the one service in the pair with a `build:`). Without that call the
content-change redeploy recreates the containers from the *previous*
image — green, healthy, running the old code.

**The content-change redeploy runs with `removeOrphans=true`.** A
compose file that drops a service will delete that service's container
as a side effect of an ordinary sync — nobody has to ask for it, and
there is no separate confirmation step. Removing a service from a
compose file and pushing that change is enough to delete its container
on the next sync.

**This is also what causes the #2705 5-minute sync deadline.** A
files-only sync would finish well inside Arcane's ~5 minute internal
deploy timeout (see "stalled-looking sync" below); it is the implicit
redeploy documented here that pushes a sync of many/large stacks past
it. There is currently no known flag that suppresses the content-change
redeploy — until one is found (or upstream confirms there isn't one),
treat every sync as a per-project restart and bound the blast radius
accordingly: scope each run to one stack at a time and verify the result — rather than firing
 a fleet-wide sync pass and racing the timeout. (A purpose-built
 single-project script is a natural follow-up; ship it separately so the
 doc's claim of 'every sync is a restart' is reviewable on its own.)**34 of the 37 stacks build an image.** Only `honeypot-elk`,
`honeypot-keycloak` and `pihole` pull — re-derived 2026-08-27 from the 37
manifest compose paths (34 carry `build:`; the same three pullers the
#1502-era text named, which said "35 of the 38" before #2381 retired
wordpot and f139fe24 retired the Go ip-enrichment-worker). For any
building stack, `autoSync: true` would mean every merge produces a
deployment that looks successful and changes nothing — worse than a
manual process, because it is unattended.

### What actually runs

- **Every sync tracks `branch: "main"`** — all 38 live `gitops_syncs`
  rows (the 37 manifest stacks plus #2577's dangling `honeypot-wordpot`
  orphan). The rows predate #1507's decision and nothing re-pointed
  them; no `production` pointer exists.
- **`autoSync` is 0 everywhere, including the three the manifest flags.**
  `honeypot-elk`, `honeypot-keycloak` and `pihole` carry `autoSync: true`
  in `arcane/manifests/home-production.json`, but the live store has
  `auto_sync = 0` on all 38 rows — the elk/keycloak/pihole auto-follow
  policy is silently inert: a promotion, or any push, will not deploy
  them.
- **Every deploy is manual**: sync → build → redeploy per stack. The
  order matters and is not arbitrary: `honeypot-dashboard` must sync
  before `honeypot-dashboard-backend` builds, because the Rust source
  lives in the dashboard project's directory.
- **Promotion is CI-only.** `scripts/promote-release.sh v0.1.0` exists
  and still refuses a ref that is not a tag, and a tag that is not an
  ancestor of `main` — so if a pointer ever exists, what reaches it has
  always been through CI. Today it moves nothing, because there is no
  pointer to move.

### The #1507 design, for the record

- **What deploys is a tagged commit.** Releases are tagged `v*` on `main`.
- **`production` is a pointer at the current release.** Promotion moves
  the pointer; rollback is the same command naming an earlier tag.
- **`autoSync: true` for the three pullers**, which would follow a
  promotion within `syncInterval` (300s). Making that a real deploy
  rather than a file copy requires `pullImageAfterSync` and
  `redeployAfterSync` set on the Arcane side — fields the manifest
  schema has no way to carry (see the fact above), so they would be
  single-sync PATCH work.

Activating any of that is live-store work, collected with the wordpot
cleanup in #2577.

### Arcane cannot track a tag

`branch` accepts a tag name — the API stores it without complaint — and then
every sync against it fails with a bare `500 Failed to perform GitOps sync`.
Verified live on 2026-08-25 against the `pihole` sync and reverted. This is
the same `refs/heads/` assumption documented above for the build-context
resolver: Arcane prefixes `refs/heads/` onto whatever ref it is given.

That is why the #1507 design is a tag *promoted onto a branch* rather than
a tag tracked directly. The deployed commit would still always be a tagged
one; the branch is only the pointer Arcane is able to follow.

## Security implications of Arcane's Docker-socket access

Arcane's own container bind-mounts `/var/run/docker.sock` — Arcane
compromise is host compromise, the same trust level Dockge held before it
(#1185's own migration rationale). Nothing about directory-aware Git sync
changes that boundary; it just changes *how* a project's files get onto the
host, not what Arcane itself is trusted with once running. The existing
mitigations remain: Arcane is only reachable over the WireGuard tunnel (no
public exposure), native OIDC/MFA gates its own login, and the registered
Git credential (currently none needed — public repo) should stay
least-privilege and read-only if the repository is ever made private.
