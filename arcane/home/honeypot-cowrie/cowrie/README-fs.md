# Cowrie seeded filesystem

This directory builds a Cowrie image whose fake shell looks like a real,
in-use production GPU server (`gpu01`, a fictional "NexusAI Research GmbH"
Ubuntu 22.04 node running inference and model-training workloads) — not an
empty honeypot.

## How it works

Cowrie decides what `ls` shows from **fs.pickle**, and what `cat` returns from
the **honeyfs** directory. So two things are needed for a file to look real:

1. `honeyfs/<path>` — the actual file contents.
2. an entry in `fs.pickle` for `<path>`, with `A_REALFILE` pointing at (1).

[`bin/sync-fs.py`](bin/sync-fs.py) does (2) automatically: it walks the honeyfs
overlay and indexes every dir/file into fs.pickle (creating parents, fixing
sizes, setting realfile + plausible perms/owners). The [`Dockerfile`](Dockerfile)
overlays honeyfs + txtcmds onto the official Cowrie image and runs the sync at
build time. `docker compose build cowrie` bakes it all in.

> **A rebuild is not a delivery.** `bin/entrypoint.sh` seeds the bind-mounted
> honeyfs from the image's `honeyfs.dist` **only when that mount is empty**, so
> that the honeyfs-implant service (#1487) can plant a live artifact without
> being overwritten on the next boot. On a host where cowrie has already
> booted once, rebuilding the image changes `honeyfs.dist` and changes nothing
> an attacker sees. Tracked in #2913; until it is fixed, a honeyfs change
> reaches a running honeypot only via a one-time copy into the host's state
> mount or a mount that starts empty (a fresh install).

## What an attacker finds

| Path | Bait |
|---|---|
| `/etc/passwd`, `/etc/group`, `/etc/shadow` | realistic users (`deploy`, `mwagner`, `svc-backup`, `postgres`…), fake password hashes |
| `/etc/motd`, `/etc/issue.net`, `/etc/hosts` | company banner, internal hostnames (db-01, cache-01) |
| `/root/.bash_history`, `/home/deploy/.bash_history`, `/home/mwagner/.bash_history` | a believable ops story: git pulls, deploys, psql, redis-cli |
| `/opt/nexusai-inference/.env` | **credential bait** — registry, model-store, Redis, JWT and monitoring secrets (all fake) |
| `/opt/nexusai-inference/{docker-compose.yml,README.md}` | app layout + deploy notes |
| `/etc/nginx/sites-available/portal.conf` | reverse-proxy config |
| `/etc/crontab` | backup + certbot jobs |
| `/var/log/auth.log` | normal admin logins + a couple of failed brute-force lines |
| `df` / `free` / `lscpu` | canned output ([txtcmds/](txtcmds)) |

**Everything is fictional.** No real company, domains (`*.nexusai.local` /
`*.nexusai.example` / `*.nexusai.internal`), IPs (RFC 5737/1918), keys or
credentials. The fake secrets look real but authenticate to nothing — that's
the point: an attacker wastes time chasing them while you capture exactly what
they grep for and try.

> Corrected 2026-09-03 (#2884): this used to say `*.example.com` / `*.internal`,
> which described neither this persona's actual domains (`nexusai.local`
> dominates; `nexusai.example` and `nexusai.internal` cover a handful of
> external-facing/error-reporting hosts) nor real reserved fictional-domain
> space (`example.com` is itself a real registered domain reserved by IANA for
> documentation, distinct from the unregistrable `.example` TLD). Keep this
> paragraph in sync with the domains actually used under `honeyfs/` — grep for
> `nexusai\.(local|example|internal)` before editing either.

## Customising

- Edit files under `honeyfs/` and rebuild (`docker compose build cowrie`) — the
  sync re-indexes automatically.
- Change the company/hostname: edit `honeyfs/etc/*`, the `.env`, the histories,
  and `hostname` in [`../cowrie.cfg`](../cowrie/cowrie.cfg) so they agree.
- The stock Cowrie image still ships a default `/home/phil`; to strip leftover
  defaults entirely, regenerate `fs.pickle` from a real box with Cowrie's
  `bin/createfs` and drop it in `share/cowrie/fs.pickle`.

> After building, always test: `ssh -p 22 root@<host>` then `cat /opt/nexusai-inference/.env`,
> `cat /etc/passwd`, `history` — confirm the content shows and sizes match.
