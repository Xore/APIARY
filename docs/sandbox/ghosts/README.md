# GHOSTS host stack (#324)

Part of the GHOSTS tracking issue [#331](https://github.com/Xore/honeypot-stack/issues/331)
(path decided on [#300](https://github.com/Xore/honeypot-stack/issues/300)).
This is step one of that chain: get `Ghosts.Api` and its database running,
isolated from everything else this repo deploys. It does not touch the
network-isolation, golden-image, VM domain, spool, or timeline work — those
are #325-#330.

## What's deployed, and what isn't

`ghosts-postgres` + `ghosts-api` only, built from CMU SEI's
[`cmu-sei/GHOSTS`](https://github.com/cmu-sei/GHOSTS) source pinned to the
`v9.0.0` tag (no published images exist upstream, so `compose.yml`'s
`build.context` points a git URL straight at `src/` — nothing to clone by
hand).

**Deliberately not deployed**: Frontend, Grafana, n8n. None of the three are
required for NPC-simulation (timeline-driven browsing/document/handler
activity) — they're operational tooling for GHOSTS' own primary use case
(live cyber-range exercise management). Add any of them later via a separate
compose overlay if a concrete need shows up; don't add them speculatively.
The Frontend in particular can likely stay skipped permanently if the
timeline is authored directly as a file and machine enrollment never needs
the web UI.

**Deliberately not folded into this repo's `docker-compose.yml`** — same
reasoning as CAPE's host-stack issue (#314): a full platform with its own
database and API blurs the trust boundary the rest of this stack keeps
narrow (dashboard container never touches Docker/libvirt/WinRM directly).

## Fixed address

`ghosts-api` publishes no host port. It gets a static address on the
dedicated `ghosts_net` bridge instead:

```
GHOSTS_API_ADDR=10.90.0.2:5000
```

Reachable from this host directly — Docker routes user-defined bridges
without any `-p` — and, once #325 exists, from the WAN-permitted GHOSTS
guest through exactly one narrow routing/firewall exception written against
this single address. Same pattern as RevDeck's
`REVDECK_API_BASE=http://10.8.0.2:19500`: pick the fixed address once, up
front, specifically so later issues can write a one-line exception instead
of a floating rule.

Don't change `10.90.0.2` without updating #325's LAN-blocking exception to
match, and without updating `/etc/default/honeypot-ghosts` on the host
(written by `install-host.sh`, read by whatever #325/#328 add later).

## Deploy

```bash
sandbox/ghosts/install-host.sh
```

On a Dockge host this deploys `compose.yml` to `/opt/stacks/ghosts` (a copy —
edit the file here and re-run, don't edit it there) so the stack shows up as
one Dockge can start/stop/tail. It generates `.env` (`POSTGRES_PASSWORD`)
there on first run and never overwrites an existing one.

The first run does a full `dotnet publish` from source and takes a while.
Subsequent runs are cheap (Docker layer cache).

After bringing the containers up, it builds the same pinned source tree's
`Ghosts.Client.Universal`, runs it once on `ghosts_net` (where the client's
own default config resolves the API via the `ghosts-api` service name, no
override needed), and polls `/api/machines/list` for that machine to appear
before tearing the test container down. That's the "confirmed with a test
machine enrollment" bar from #324 — a real client registering through the
real API against the real database, not just an HTTP 200 from a health
endpoint.

```bash
sandbox/ghosts/install-host.sh --skip-enroll-test   # containers only
```

## Notes for whoever picks up #325 (network isolation)

- `ghosts-api` currently only needs to be reachable from this host and from
  other containers on `ghosts_net` — nothing reaches it from outside yet.
  #325's job is adding the single guest → `10.90.0.2:5000` exception through
  the isolated bridge that issue creates for the GHOSTS guest, not opening
  this address any wider.
- The stack has no authentication in front of it (matches GHOSTS' own
  defaults — verify this hasn't changed before relying on it). That's fine
  while the only path to it is host-local/docker-internal; it stops being
  fine the moment #325 adds a route from a WAN-permitted guest, so revisit
  before that lands.
