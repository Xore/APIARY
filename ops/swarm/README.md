# Swarm phase 1: host state, rollout and runbooks (#3589)

**Status (2026-10-10, applied and verified).** The three nodes form one swarm on the WireGuard hub addresses:

| Node | Swarm role, address | Availability | WireGuard | Firewall zone `apiary-swarm` |
|---|---|---|---|---|
| homeserver (`supermicro`) | manager (Leader), `10.8.0.2` | `Pause` (tasks schedule on precision, #3583) | `wg0` hub spoke (peer VPS), `wg-fibre` `10.8.1.1`, `wg-lan` `10.8.2.1` | `ens9f1`, `wg0`, `wg-fibre`, `wg-lan`; `DOCKER-USER` hub policy (`home-wg-forward`) |
| precision | manager (Reachable), `10.8.0.3` | `Active` | `wg0` hub spoke (peer VPS), `wg-fibre` `10.8.1.2`, `wg-lan` `10.8.2.2` | `enp4s0f1`, `wg0`, `wg-fibre`, `wg-lan` |
| VPS (hostname `localhost`) | worker, `10.8.0.1` | `Active` | `wg0` hub (peers homeserver, precision) | `wg0` |

Both managers are needed for quorum: if either fails, running tasks continue but scheduling and updates stop (accepted, #3587 decision 1). Never promote the VPS. Phase 1 creates no stack or service. Compose projects, sensor binds, Arcane, runners and the registry mirror are unchanged.

The decisions, flow matrix, MTU budget and failure modes are in [docs/SWARM-NETWORK.md](../../docs/SWARM-NETWORK.md).

## What lives where

Keys, preshared keys, join tokens, the VPS public endpoint and the homeserver LAN address never enter git. Templates carry `REPLACE_WITH_*` placeholders that are rendered **on the host**, with keys read from root-only files and not passed on a command line.

| Repo file | Host path | Hosts |
|---|---|---|
| `hosts/*-wg-fibre.conf.example`, `hosts/*-wg-lan.conf.example` | `/etc/wireguard/wg-fibre.conf`, `wg-lan.conf` (0600), `wg-quick@wg-fibre`/`@wg-lan` enabled | homeserver, precision |
| `hosts/precision-wg0.conf.example` | `/etc/wireguard/wg0.conf`, `wg-quick@wg0` enabled | precision |
| `vps-hub-peer.sh` | `/usr/local/libexec/apiary-vps-hub-peer`; adds the precision block to the VPS `wg0.conf` | VPS |
| `peer-route.sh`, `peer-route.service` | `/usr/local/libexec/apiary-swarm-peer-route`, `/etc/systemd/system/peer-route.service` (enabled) | homeserver, precision |
| `hosts/homeserver.env`, `hosts/precision.env` | `/etc/apiary/swarm-peer.env` | homeserver, precision |
| `../firewall/swarm-plane.sh`, `../firewall/hosts/*.env` | env rendered to `/etc/apiary/swarm-plane.env` (precision: `REPLACE_WITH_HOMESERVER_LAN_IP` filled in) | all three |
| `../firewall/home-wg-forward.{sh,service}`, `../firewall/hosts/homeserver-wg-ports.txt` | `/usr/local/libexec/apiary-home-wg-forward`, `/etc/systemd/system/home-wg-forward.service`, `/etc/apiary/homeserver-wg-ports.txt` | homeserver |
| `nm-profiles.sh`, `hosts/homeserver.nm`, `hosts/precision.nm` | NetworkManager profiles (LAN, fibre, MTU 9000, metrics, zones); placeholders from `/etc/apiary/host.env` | homeserver, precision |
| `hosts/precision-multihome.conf` | `/etc/sysctl.d/90-apiary-multihome.conf` | precision |
| `hosts/arcane-fibre-tunnel.service` | `~xore/.config/systemd/user/arcane-fibre-tunnel.service` (user unit, linger on) | precision |
| `hosts/homeserver-arcane-authorized_keys.fragment` | one line of `~xore/.ssh/authorized_keys` | homeserver |
| `hosts/precision-fstab.fragment` | `/etc/fstab` lines (XFS volume and three bind mounts) | precision |
| `hosts/precision-runners.txt` | runner units from `scripts/github-ci-runner/install-ci-runner.sh`, registry mirror from `install-registry-mirror.sh` | precision |
| `swarm-membership.sh` | runs on the admin workstation (SSH aliases `homeserver`, `precision`, `vps`) | swarm |
| `scripts/install-vps.sh` (`live-restore: false`) | `/etc/docker/daemon.json` | VPS |

homeserver's strict `rp_filter` on `ens9f0`/`eno1` comes from the distribution default (`/usr/lib/sysctl.d/50-redhat.conf`), not a site file. It is what drops spoofed fibre or hub sources arriving on the LAN. `wg-fibre`/`wg-lan` set loose mode in their `PostUp`, because the peer hub `/32` moves between them on failover and `AllowedIPs` already rejects spoofed sources.

Check for drift at any time: `nm-profiles.sh check hosts/HOST.nm`, `swarm-plane.sh status /etc/apiary/swarm-plane.env`, `swarm-membership.sh status`.

## How it was applied (and how to re-apply)

One host at a time. Before **every** network, firewall or swarm change, arm a dead-man and confirm its timer is active. Then change, prove from outside and inside, and only then disarm. Probes after each step: fresh `ssh HOST` from the workstation, `honeypot-v2*` count rising with recent public `source.ip`, Arcane environment `precision` `online`, runners online, `docker node ls` from a manager.

| Dead-man | Host | Restores |
|---|---|---|
| `network-rollback.sh backup` / `arm DIR 10min` → `swarm-net-rollback-3589` | homeserver, precision | `/etc/wireguard`, `wg-quick@*` and `peer-route` state, routes, the Arcane user unit, the `DOCKER-USER` hub policy |
| `swarm-plane.sh backup` / `ROLLBACK_UNIT=fw-rollback-3589 swarm-plane.sh arm DIR 10min` | all | `/etc/firewalld` and NM zone bindings |
| `vps-hub-peer.sh arm PUBKEY 10min` → `vps-hub-peer-rollback-3589` | VPS | removes that one hub peer and restores `wg0.conf`, **without** touching the homeserver peer (no `syncconf` or restart) |
| `swarm-membership.sh arm 10min` → user unit `swarm-membership-rollback-3589` | workstation | phase-0 membership: homeserver sole manager on `10.254.250.1` (`Pause`), precision worker |

Order used on 2026-10-10:
1. `wireguard-tools` on precision.
2. Keys generated on each host (`umask 077; wg genkey`); only public keys and the PSK are piped host to host. Templates are rendered in place.
3. precision, then homeserver: firewall (adds UDP 51821 from the fibre peer in `apiary-swarm` and UDP 51822 from the peer LAN address in `public`), `wg-fibre` and `wg-lan` up, interfaces bound to `apiary-swarm`. MTU proof with `ping -M do` (below).
4. VPS: `vps-hub-peer.sh arm`, then `add` the precision peer (`10.8.0.3/32`, PSK). precision: `wg0` up, `peer-route.service`. Prove that homeserver↔precision hub traffic does not touch the VPS: the VPS precision-peer counters stay flat while precision pings `10.8.0.2`.
5. `swarm-membership.sh managers` (homeserver re-initialised on `10.8.0.2` with the existing `10.200.0.0/16` /24 address pool, `Pause`, ingress MTU 1310; precision joins as manager on `10.8.0.3`).
6. homeserver `wg0` into `apiary-swarm` plus `home-wg-forward`. Then VPS `wg0` into `apiary-swarm` (`SWARM_SSH_PORT=2222`: VPS port 22 is the cowrie honeypot). `check-home-wg-ports.py LIVE_PORTS` must pass first. Watch the `APIARY-WG-IN` DROP counter: it must not grow with normal traffic.
7. VPS: `live-restore` off via `systemctl reload docker` (no container restart; swarm refuses live-restore), then `swarm-membership.sh join-vps` and `labels`.
8. `arcane-fibre-tunnel` switched to `xore@10.8.0.2`, after pinning `10.8.0.2` in its `known_hosts` only if its key equals the trusted `10.254.250.1` entry, and adding `10.8.0.3` to the `from=` of its `authorized_keys` line.

### Proofs to repeat after any change

- **MTU**, `ping -M do` (payload = MTU − 28): `wg-fibre` `-s 8892` passes, `-s 8893` → `Message too long`; `wg-lan` `-s 1472`/`1473`; hub `wg0` `-s 1392`/`1393`; raw fibre `-s 8972`.
- **Fibre failover:** on precision, drop all traffic on the fibre inside a dead-man:
  ```sh
  sudo systemd-run --on-active=3min --unit=fibre-cut-rollback-3589 /usr/sbin/nft delete table inet cut3589
  sudo nft -f - <<'EOF'
  table inet cut3589 {
    chain in  { type filter hook input  priority -300; iifname "enp4s0f1" drop; }
    chain out { type filter hook output priority -300; oifname "enp4s0f1" drop; }
  }
  EOF
  ```
  Expected: `ip route show exact 10.8.0.2/32` names `wg-lan` within about 3 s, both managers stay `Ready`/`Leader`/`Reachable`, Arcane `precision` stays `online`, and after `nft delete table inet cut3589` the route returns to `wg-fibre` without loss. Measured on 2026-10-10: a 2.7 s gap, and no Raft election.
- **Outside:** `nmap -Pn -sT -sU -p T:2377,7946,U:7946,4789` against the VPS public address and both LAN addresses: TCP `filtered`, UDP `open|filtered`, logged as `apiary-swarm-lan:`.

## Runbook: node maintenance (drain → work → active)

1. Record state: `docker node ls`, `docker node inspect NODE --format '{{.Spec.Availability}}'`, active CI jobs (`gh api repos/Xore-Inc/APIARY/actions/runners`), any running backfill, and the `honeypot-v2*` count.
2. Wait until no CI job or backfill would be cut off. For precision, also stop the runner units if the work restarts Docker.
3. `docker node update --availability drain NODE` (from a manager). Draining moves tasks; it does **not** remove a manager's Raft vote.
4. Do the work. **Powering off or rebooting a manager loses quorum**: running tasks continue, but nothing schedules until it is back. Keep the window short, and never take both managers down. Losing the VPS worker costs only its tasks.
5. Restore the recorded availability: precision and VPS `active`; homeserver `pause`, never `active` (#3583).
6. Verify: `docker node ls` from both managers (all `Ready`, one Leader), `wg show` handshakes on the node's tunnels, `ip route show exact 10.8.0.2/32` (or `10.8.0.3/32`) via `wg-fibre`, `peer-route.service` active, Arcane `precision` online, runners online, ingest rising with public `source.ip`.

## Runbook: restart after a precision storage migration or reboot

Lesson from #3584: Docker and the runners must never start on empty mountpoints.
1. **Before** starting Docker or runners: `findmnt /var/lib/precision-storage /var/lib/docker /var/lib/github-runners /var/lib/github-runner-data` shows the XFS volume and the three binds from `/var/lib/precision-storage/live/*`, matching `hosts/precision-fstab.fragment`. If one is missing, **stop**: starting on the root filesystem creates divergent state.
2. Network: `nm-profiles.sh check hosts/precision.nm`; `wg show` for `wg0`, `wg-fibre` and `wg-lan`; `systemctl is-active peer-route.service`; `ip route show exact 10.8.0.2/32` via `wg-fibre`; `firewall-cmd --get-active-zones` lists `enp4s0f1 wg0 wg-fibre wg-lan` in `apiary-swarm`.
3. Docker: `docker info` (swarm `active`, NodeAddr `10.8.0.3`, manager), and `docker node ls` from both managers.
4. Arcane: `systemctl --user is-active arcane-fibre-tunnel`, `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:13552/api/health` → 200, and environment `precision` `online` in the manager.
5. Runners: every unit in `hosts/precision-runners.txt` active and online in GitHub. `ci-registry-mirror.service` active, published on `172.16.0.1:5555` only.
6. Run a GitOps sync, and confirm homeserver ingest is still rising with public `source.ip`.

## Runbook: key rotation

Run on suspected compromise or yearly, one tunnel at a time, inside the dead-man of the host whose key changes (procedure and rationale: [docs/SWARM-NETWORK.md](../../docs/SWARM-NETWORK.md#key-handling-and-rotation)).
- **`wg-fibre` / `wg-lan`** (homeserver↔precision): rotate one side while the other tunnel carries the hub route. Example: rotating `wg-fibre`, first confirm the failover proof above works. Then generate the new key on the host, pipe the new public key into the peer's config, and `wg set` both ends; `peer-route` fails over and back on its own. Record the date on the issue.
- **Hub `wg0`, precision spoke:** generate a new precision `wg0.key` and a new PSK on the VPS (`wg genpsk`). On the VPS, `vps-hub-peer.sh arm OLD.pub`, then add the new peer with `vps-hub-peer.sh add` and remove the old one with `wg set wg0 peer OLD remove` (and its `wg0.conf` block). Re-render precision `wg0.conf`, then `systemctl restart wg-quick@wg0` on precision. Precision's hub path carries only VPS↔precision swarm traffic.
- **Hub `wg0`, homeserver spoke or VPS key:** this tunnel carries live sensor forwarding. Use `scripts/install-homeserver.sh`'s `step_wireguard_sync_vps_peer` path, inside a VPS dead-man, with ingest probes, at a quiet time. A VPS key change also needs re-rendering precision `wg0.conf`.
- **Arcane tunnel SSH key:** a new key pair in `/var/lib/github-runners/precision-services/arcane/ssh/` on precision, and a matching update of the restricted line from `hosts/homeserver-arcane-authorized_keys.fragment`.

## Known consequences

- The VPS dockerd now runs without `live-restore` (swarm requirement). A dockerd restart there restarts portbridge and the edge containers; restart policies bring them back.
- `scripts/install-vps.sh` rewrites `wg0.conf` with only the homeserver peer. After a VPS rebuild, re-add precision with `vps-hub-peer.sh add`.
- The Arcane manager stays a Compose project; phase 3 (#3590) moves stacks under Arcane GitOps.
