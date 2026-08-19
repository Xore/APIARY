# Arcane Git sync

How the 39 home-hosted stacks (33 that migrated under `arcane/home/` plus 6
that were already self-contained and stayed at their existing path) get to
the live host, replacing the old model of copying or symlinking top-level
`docker-compose.*.yml` files into place. Everything here was confirmed live
against the pinned Arcane `v2.8.0` API during #1502's own migration, not
taken from Arcane's docs — see the risk that motivated that in "Version/API
compatibility" below.

## The model

Each stack gets its own **directory-aware Git sync**: Arcane clones the
`apiary` repository, materializes the *entire directory* containing the
selected `compose.yml` (not just that one file) under
`/var/dockge/stacks/<syncName>/`, and deploys it. The manifest at
[`arcane/manifests/home-production.json`](../arcane/manifests/home-production.json)
is the single source of truth for which 39 stacks exist, what branch/path
each syncs from, and any per-stack sync limits — `scripts/install-homeserver.sh`,
CI, and this doc all read from it rather than maintaining separate lists.

- The 33 `honeypot-*` stacks live under `arcane/home/<name>/`: their build
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
manifest and creates one `POST /environments/0/gitops-syncs` per
`honeypot-*` entry (environment `0` is Arcane's single "Local Docker"
environment on a one-host deployment). The 6 non-`honeypot-*` stacks are
**not** imported by that step — they're still provisioned by their own
existing `scripts/install-homeserver.sh` steps on a from-scratch install
(retiring those in favor of Arcane management is a deliberate follow-up,
not done in #1502 — see that script's own comment on why).

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
  vendored dependency tree.** `honeypot-dashboard`'s vendored Go
  dependencies (`dashboard/vendor/`, ~650 tracked files) exceed it; the
  manifest entry sets `maxSyncFiles: 2500` explicitly. If a future stack's
  build context grows a large vendored/generated tree, expect the same
  `file count limit exceeded` failure and raise that stack's own
  `maxSyncFiles` rather than assuming the default is enough.
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

## Local environment overrides

Compose's own `.env`-in-project-directory interpolation already covers
every `${VAR}` reference in these 39 stacks — none of them use `env_file:`,
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

Every sync in the manifest currently uses `branch: "main"` with
`autoSync: false`. This is a deliberate first-pass choice, not a permanent
one — the parent issue's own "Suggested implementation order" leaves the
`main`-only-vs-protected-`production`-branch decision as a fast-follow once
this migration has run under `autoSync: false` for an observation period.
Until that decision is made:

- Every deploy to a home stack is a manual, operator-triggered sync — never
  automatic on merge to `main`.
- A commit that changes a home stack's compose file only takes effect on
  the live host once someone deliberately triggers that stack's sync (or
  re-runs `step_arcane_import_stacks`, which skips any stack whose
  directory already has a `compose.yml`, so it won't redeploy an
  already-imported stack on its own either).

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
