# Vendored GHOSTS source (#1506)

This directory is a trimmed copy of [`cmu-sei/GHOSTS`](https://github.com/cmu-sei/GHOSTS)'s
`src/` tree, pinned at commit `335d11e5b73c278626a0a63f5bfbdec60cda7d8e` (the
`v9.0.0` tag) — the same commit `sandbox/ghosts/compose.yml` was already
building from via a remote Git build context before this change.

## Why this exists

Arcane's own image-prep step resolves a Docker build context's remote Git
ref only under `refs/heads/`, unlike plain `docker build`/BuildKit (which
resolves a tag name or a commit SHA on its own with no ref-namespace
guessing needed). Confirmed live against the pinned Arcane `v2.8.0`, in
order: a tag name failed with `couldn't find remote ref "refs/heads/v9.0.0"`,
and re-pinning to the tag's commit SHA instead failed the exact same way —
Arcane prefixes `refs/heads/` onto *any* ref string passed this way, not
just tag names. See #1506 and `docs/ARCANE-GIT-SYNC.md`'s "Known Arcane
v2.8.0 limitations" section for the full write-up.

There is no compose-file-level fix for that — Arcane's directory sync
already correctly materializes local files (it just can't resolve *remote*
git refs the way `docker build` does), so trading "no local copy of
upstream source" for "actually buildable through Arcane like every other
stack" makes `ghosts-api`/`ghosts-client-test` build the same way through
Arcane as everything else in this repo, no manual post-sync `docker compose
build` step required.

## What's here vs. upstream

Only what `Dockerfile-api` and `Dockerfile-client-universal` actually `COPY`
into their build stages, trimmed the same way upstream's own
`src/.dockerignore` already trims the Docker build context (`bin/`, `obj/`,
`_db/`, `Ghosts.Api/wwwroot/lib/fontawesome/svgs/`,
`Ghosts.Api/wwwroot/flags/` are all excluded here too — the running
container never received those either way, so excluding them changes
nothing at runtime and just avoids vendoring ~14MB nothing uses):

- `Dockerfile-api`, `Dockerfile-client-universal`, `.dockerignore`
- `certs/` (client-universal's CA bundle)
- `Ghosts.Api/`, `Ghosts.Domain/`, `Ghosts.Animator/` (ghosts-api's build —
  `Ghosts.Api.csproj`'s own `ProjectReference`s)
- `Ghosts.Client.Universal/`, `Ghosts.Domain/` (ghosts-client-test's build —
  `Ghosts.Client.Universal.csproj`'s own `ProjectReference`)
- `LICENSE.md` (MIT-style, Carnegie Mellon University — required to
  accompany copies of the software)

Not vendored: everything else in upstream's `src/` (`Ghosts.Client.Lite`,
`Ghosts.Client.Windows`, `Ghosts.Frontend`, `Ghosts.Pandora`, test projects,
`apphost`, `tools`) — none of it is reachable from either Dockerfile this
repo actually builds, matching #324's own original scope decision to skip
GHOSTS' operator-facing tooling.

## Updating the pin

There's no script for this yet (a genuine gap, same as every other vendored
dependency in this repo) — bump it by hand:

1. Check out `cmu-sei/GHOSTS` at the new tag/commit.
2. Re-copy the same path list above from its `src/` into this directory,
   applying the same `.dockerignore`-matching exclusions.
3. Update the commit SHA in this file and in `sandbox/ghosts/compose.yml`'s
   own header comment.
4. Rebuild locally (`docker compose -f sandbox/ghosts/compose.yml build`)
   and re-run the enrollment smoke test
   (`docker compose --profile test run ghosts-client-test`) before trusting
   the bump.
