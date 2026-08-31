# Essentials backup and restore

[← back to README](../README.md)

The backup that exists so the stack can be rebuilt. It captures what cannot be
recreated from this repository — secrets, keys, certificates, the Keycloak
identity database, operator-edited config — and deliberately nothing else.

For a *deliberate* reset of a working host see [`RECOVERY.md`](RECOVERY.md);
for restoring onto a replacement host see
[`analysis/RECOVERY.md`](analysis/RECOVERY.md).

## What is and isn't in it

**In**, roughly 23 MB uncompressed as of 2026-08-23:

| | |
|---|---|
| `homeserver/env/*.env` | all 41 Arcane/Dockge stack `.env` files |
| `homeserver/secrets/` | secret files kept beside a stack rather than in its `.env` |
| `homeserver/wireguard/` | `wg0.conf` including the private key |
| `homeserver/installer/` | `install-homeserver.conf` — the installer's answers file, which exists only on the root filesystem a reinstall wipes |
| `homeserver/pihole/` | hand-maintained Pi-hole config |
| `homeserver/keycloak/keycloak.sql.gz` | `pg_dump` of the identity DB — realm, clients, client secrets, users |
| `homeserver/volumes/` | `dashboard-state`, `arcane-data`, `evebox-config`, `canarytokens-redis-data`, `es-importer-state` |
| `vps/env/vps.env`, `vps/secrets/`, `vps/traefik/`, `vps/wireguard/` | the VPS's entire config surface, including the Traefik origin certificates |
| `*/manifest/` | host reference notes — disks, volumes, containers, WireGuard, nftables |
| `repo/docs/`, `repo/scripts/`, `repo/analysis/` | this repository's runbooks and operational scripts |

**Out**, on purpose. These are bulk capture data, and a rebuilt stack does not
need any of them to come back up (sizes measured live 2026-08-23):

| | | |
|---|---|---|
| `es-data` | 30 GB | Elasticsearch store — events, alerts |
| `state/elasticsearch-snapshots` | 14 GB | the ES snapshot repository |
| `dionaea-lib` | 90 GB | captured malware samples |
| `/var/dockge/sandbox` | 105 GB | Windows sandbox golden images and ISOs |
| `ghidra_ollama_models` | 18 GB | re-pullable model weights |
| `arcane-trivy-cache` | 5.6 GB | rebuildable scanner cache |
| `reporter-data` | 2.8 GB | generated reports |
| `ghidra_ghidra_projects` | 158 MB | analysis output derived from payloads |
| Pi-hole `gravity.db`, `pihole-FTL.db` | 689 MB | recompiled blocklists, DNS query log |
| sensor logs, PCAP, Filebeat registries | | |

The runbooks ride along on purpose. Without them a rebuild that starts from one
of these sticks has every secret in the fleet and no instructions — the restore
procedure, the stack start order, the disk layout and the Keycloak runbook
would all live only in git, on a host you are trying to reach from a machine
you have not rebuilt yet. It costs 3 MB.

Each destination also gets a plaintext `RESTORE-README.txt` beside the
archives. The runbooks are *inside* the archive, which is the wrong side of the
encryption if what you have forgotten is how to open it; that one file is
unencrypted, holds no secret, and carries the `gpg -d` command and the reading
order.

**A stack restored from this comes back with its own identity and
configuration intact and an empty event history.** That is the trade. If
captured data ever needs preserving, give it its own job with its own
retention — do not couple it to this one. Coupling is precisely what broke the
previous arrangement (see *History* below).

## Where it goes

Three locations, all written by the workstation, which is the backup host:

| # | Location | Filesystem | Notes |
|---|---|---|---|
| 1 | `/run/media/xore/<uuid>/apiary-backups` | ext4 (Crucial X8 USB) | udisks auto-mount — only present while plugged in |
| 2 | `~/apiary-backups` | XFS (internal) | always available |
| 3 | `homeserver:/mnt/usb-recovery/apiary-backups` | ext4 (Samsung T7, label `APIARY-BACKUP`) | mounted from fstab by UUID with `nofail` |

Location 3 was a Ventoy stick formatted exfat until 2026-08-23, mounted
read-only and absent from `/etc/fstab` — so every write to it failed and it
would not have survived a reboot. It is now a single ext4 partition with a
proper `nofail` fstab entry, which also means it preserves ownership and the
archive's `0600`; exfat could express neither.

A destination that is unavailable is a warning, not a failure — one missing
copy must not stop the other two. All three missing does fail the run.

Retention is 30 archives per destination, pruned oldest-first after each
successful write.

## Encryption

Every archive is GPG symmetric AES256. It contains WireGuard private keys, TLS
private keys, OIDC client secrets and the full Keycloak user database, and two
of the three copies live on removable drives — plaintext there would mean
anyone who walks off with a stick owns the fleet.

Symmetric with a passphrase, not a keypair, so that recovery depends on one
string a human can keep in a password manager and nothing else. No key file
that itself needs backing up, no keyring, no dependency on this repo:

```bash
gpg -d apiary-essentials-<stamp>.tar.gz.gpg | tar xz
```

`scripts/install-backup-essentials.sh` generates the passphrase on first run,
stores it at `/etc/apiary-backup.pass` (0600, owned by the run user) and prints
it once. **Save it somewhere other than the machine being backed up** — a
passphrase that only exists on the dead host is not a passphrase.

`BACKUP_ENCRYPT=0` writes plaintext archives. Only reasonable if all three
destinations are trusted, which today they are not.

## Running it

```bash
scripts/backup-essentials.sh              # collect and fan out
scripts/backup-essentials.sh --dry-run    # collect, print the tree and size, discard
scripts/backup-essentials.sh --list       # what each destination currently holds
```

Requirements on the workstation: SSH aliases `homeserver` and `vps` working
(see `~/.ssh/config`), passwordless `sudo` on the homeserver — the stack `.env`
files are root-owned and unreadable without it — and `gpg`.

The script only ever reads from the two servers.

### Automatic runs

```bash
sudo scripts/install-backup-essentials.sh
```

Installs `apiary-backup-essentials.timer` — daily, ±30 min jitter,
`Persistent=true` so a run missed while the workstation was powered off fires
at the next boot instead of being skipped.

The installer copies the script to `/usr/local/libexec/apiary-backup-essentials.sh`
and points the unit there, so **re-run the installer after a `git pull`** to
pick up a new version.

That is the opposite of `analysis/install-backup-timer.sh`, which deliberately
runs `backup-honeypot.sh` in place — but that script tars up the very checkout
it lives in, so a copied-out version would drift from what it backs up.
`backup-essentials.sh` has no such coupling; it only talks to remote hosts.

It is also forced here. The backup host runs Rocky with SELinux enforcing,
where a systemd unit cannot exec a file labelled `user_home_t`:

```
avc: denied { execute } ... scontext=system_u:system_r:init_t:s0
                            tcontext=unconfined_u:object_r:user_home_t:s0
```

Running in place from `~/Github/APIARY` fails with `203/EXEC`. Anything under
`/usr/local/libexec` gets `bin_t` and works.

It runs as the workstation user (`User=xore`), not root — the SSH identity, the
`~/.ssh/config` aliases and the udisks USB mount all belong to that user. A
system unit with `User=` does not need lingering enabled, which a `--user`
timer would (`Linger=no` on this box).

```bash
systemctl start apiary-backup-essentials.service     # run now
systemctl list-timers apiary-backup-essentials.timer # when next
journalctl -u apiary-backup-essentials.service       # what happened
```

## Restoring

The archive is a plain tar.gz behind a symmetric GPG envelope on purpose: the
restore path must not need this repository, this script, or any tool that is
not already on a rescue system.

```bash
gpg -d apiary-essentials-<stamp>.tar.gz.gpg | tar xz -C /tmp/restore
cat /tmp/restore/MANIFEST.txt
```

Then, onto a rebuilt host:

**Before any of the below**, put `homeserver/installer/*-install-homeserver.conf`
back at the path you intend to pass to `scripts/install-homeserver.sh --config`.
The installer will not run without it, and it is not reconstructible from the
repository — `install-homeserver.conf.example` carries only placeholders.

1. **Stack `.env` files.** Copy each `homeserver/env/<stack>.env` back to
   `/var/dockge/stacks/<stack>/.env`. Restore ownership and mode
   (`root:deploy-runner`, `0600` for most). Never overwrite a live `.env`
   wholesale without reading it first — the same rule that applies to any
   edit on these hosts.
2. **Secrets.** `homeserver/secrets/<stack>/secrets/*` back to the matching
   `/var/dockge/stacks/<stack>/secrets/`, `0600`.
3. **WireGuard.** `homeserver/wireguard/wg0.conf` to `/etc/wireguard/`, `0600`
   root. Reusing the original private key means the derived public key still
   matches the peer record on the far side, so **the VPS needs no WireGuard
   change at all** for the tunnel to come back.
4. **Keycloak.** Bring up `hp-keycloak-postgres` alone, then
   `gunzip -c keycloak/keycloak.sql.gz | docker exec -i hp-keycloak-postgres psql -U keycloak -d keycloak`.
   The dump is `--clean --if-exists`, so it drops and recreates. Start
   `hp-keycloak` only once the restore has finished. This is what saves the
   8-client OIDC secret resync that a fresh realm import otherwise forces —
   the clients come back with their original secrets, matching the ones in
   `vps/secrets/oidc/`.
5. **Volumes.** For each `homeserver/volumes/<name>.tar.gz`, with the stack
   stopped, create the volume and unpack into it through a networkless
   container:
   ```bash
   docker volume create <name>
   docker run --rm --network none -v <name>:/dst -v "$PWD/homeserver/volumes:/src:ro" \
     busybox:1.36 tar -C /dst -xzf /src/<name>.tar.gz
   ```
   Never unpack into a running container's volume.
6. **Pi-hole.** `homeserver/pihole/etc-pihole/*` back into the stack's
   `etc-pihole/`. `gravity.db` is not in the archive by design — run
   `pihole -g` once to recompile it from the restored `adlists.list`.
7. **VPS.** `vps/env/vps.env` to `/root/vps/.env`; `vps/secrets/` and
   `vps/traefik/` back to `/root/vps/`; `vps/wireguard/wg0.conf` to
   `/etc/wireguard/`. The Traefik origin certificates matter — they are valid
   until 2028 and cannot be regenerated from this repo, which is why
   `deploy.yml` refuses to overwrite `traefik/` on a normal deploy.

Then follow [`STACK-REBUILD.md`](STACK-REBUILD.md)'s start order —
`honeypot-elk` healthy before `honeypot-init`, everything else after.

Verify with `analysis/verify-stack.py` — `DASHBOARD_SERVICE_TOKEN` from the
stack's `.env`; it judges source-health through dashboard-next's `/bff`
passthrough and exits nonzero when anything is wrong.

## The on-host copy

`analysis/backup-honeypot.sh` captures the same material on the homeserver
itself, into `/opt/backups/honeypot/<stamp>/`, on the `backup-honeypot.timer`
schedule. Same scope, same exclusions. It is faster to reach and useless if the
box dies; the two are complements, not alternatives.

Validate one with `analysis/verify-backup.sh <directory>`.

## History

The Elasticsearch snapshot that `analysis/backup-honeypot.sh` used to take is
gone, for two reasons that happen to point the same way:

- It was the bulk ES data this backup is explicitly not meant to hold; the
  `honeypot-fs` repository it wrote into had reached 14 GB.
- **It had never once succeeded.** Every scheduled run since the timer was
  installed on 2026-08-16 failed with `curl: (22) ... error: 400` from the
  snapshot API. That call sat under `set -e`, so the run aborted right there —
  the volume archives never ran, retention never ran, and the service sat in
  `failed`. Seven consecutive days of "backups" held one config tarball, an
  empty `volumes/` directory and a zero-byte `elasticsearch-snapshot.json`.

Also found and worth knowing: `honeypot-keycloak/.env` carries a full set of
`RESTIC_*` variables pointing at `/mnt-2/apiary-keycloak`, but that repository
directory does not exist, its password file (`secrets/restic-password`) does
not exist, `restic` is not installed on the homeserver and no unit references
it. It is dead configuration — no Keycloak restic backup has ever run. The
`keycloak.sql.gz` dump in both scripts here covers that gap.

All of the above is tracked in
[#1694](https://github.com/Xore/APIARY/issues/1694).
