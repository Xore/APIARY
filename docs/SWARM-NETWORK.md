# Swarm network: phase 0 firewall and phase 1 tunnel design

The [#3588 live/repo port inventory](https://github.com/Xore/APIARY/issues/3588#issuecomment-6098046203) is the per-service, per-port matrix for every running Compose publication on all three hosts, including bind address, container port, protocol, consumer, `expose:` findings and drift. This document owns the network decisions and the firewall flows. The inventory is evidence from 2026-10-10; check live state again before changing a host.

## Decisions

1. The VPS is the WireGuard hub; homeserver and precision are spokes.
2. homeserver ↔ precision uses WireGuard over the raw 10 Gb fibre.
3. LAN and fibre underlay MTU is 9000. The Internet WireGuard path keeps its default MTU (about 1420). A mixed-path overlay must fit its smallest path; verify with `ping -M do`.
4. Hub addresses are `10.8.0.0/24`: VPS `.1`, homeserver `.2`, precision `.3`. Fibre WireGuard is `10.8.1.0/30`: homeserver `.1`, precision `.2`, over `10.254.250.0/30`.
5. All nodes re-join Swarm using their `10.8.0.x` address for both `--advertise-addr` and `--data-path-addr`. Route homeserver ↔ precision hub traffic over the fibre tunnel, never through the VPS.
6. On fibre failure, a second WireGuard path over the LAN (MTU 1500) takes over automatically. Test failover and recovery before relying on it.
7. Each host generates its own private key; private keys never enter git. Rotate manually on suspected compromise or yearly: generate replacement keys on hosts, update peer public keys one peer at a time with the other path available, verify handshakes and probes, then retire old keys.
8. The flow matrix below derives from the linked inventory. Apply it with a dead-man rollback and the probes below; no further design review gate.

WireGuard rebuild, route failover, MTU tuning and Swarm re-join are **#3589**. Phase 0 (#3588) changes only homeserver and precision's existing Swarm plane on the direct fibre. The VPS is not a Swarm member yet. No sensor, gateway, DNS, admin UI or CI publication changes in this phase. The LAN listener and portbridge drift decisions are [#3604](https://github.com/Xore/APIARY/issues/3604).

#3589 must replace the phase 0 per-host rules with interface-specific peer rules for the new WireGuard paths. Every new tunnel is default-deny in **both ingress and egress**; allowing the whole hub subnet on a pooled fibre/WireGuard zone would reintroduce the spoofed-source hole.

## Flow matrix

`F` is the direct fibre (`ens9f1` on homeserver, `enp4s0f1` on precision). `H` is the existing VPS ↔ homeserver `wg0`; `L` is the LAN/uplink. Phase 0 inbound Swarm rules are interface-bound in `apiary-swarm`, source-restricted to the single fibre peer, and default-deny with rate-limited logging. Its SSH rule preserves the existing Arcane fibre forward. `public` logs and drops the Swarm protocols on LAN/uplink. Ordinary egress and existing unrelated publications are unchanged.

| Source → destination | Interface; protocol/port | Purpose | Owner / phase |
|---|---|---|---|
| precision `10.254.250.2` → homeserver `10.254.250.1` | F; TCP 2377, TCP/UDP 7946, UDP 4789, ESP (IP protocol 50) | Manager control, gossip, VXLAN, encrypted overlay | #3588 / now |
| homeserver `10.254.250.1` → precision `10.254.250.2` | F; TCP/UDP 7946, UDP 4789, ESP | Gossip and overlay; precision has no TCP 2377 listener while a worker | #3588 / now |
| precision → homeserver | F; TCP 22, then loopback TCP 13552 → H TCP 3552 | `arcane-fibre-tunnel` SSH forward to Arcane manager; agent listens on loopback TCP 3553 | #3588 / existing |
| LAN admin → homeserver/precision | L; TCP 22 | Existing SSH access, kept in `public` | ops / existing |
| VPS portbridge → homeserver sensors | H; exact TCP/UDP mappings in [inventory](https://github.com/Xore/APIARY/issues/3588#issuecomment-6098046203), including translated ports | Internet honeypot traffic; preserve attacker `source.ip` | #3573 / existing |
| VPS Traefik/socat → homeserver gateways | H; exact dashboard, Arcane, Keycloak, Kibana and other published ports in inventory | OIDC-gated tools; no new host openings | #3579 / existing |
| CI runners → precision registry mirror | local Docker bridge; TCP 5555 → 5000 | Image pulls; not LAN-published | CI / existing |
| LAN clients → homeserver Technitium and Unsloth | L; TCP/UDP 53, TCP 5380/53443, TCP 8888/8899 | Existing LAN publications, access decision pending | #3604 |
| VPS ↔ homeserver/precision | H; WireGuard UDP 51820 underlay, then peer-scoped TCP 2377, TCP/UDP 7946, UDP 4789, ESP | Three-node Swarm and encrypted overlays | #3589 |
| homeserver ↔ precision | fibre WG `10.8.1.0/30`, LAN fallback; peer-scoped Swarm ports above; WG listener ports per #3589 config | Direct encrypted Swarm path and failover | #3589 |

The inventory also records pentagi TCP 28012–28013, public VPS web/game/SSH/WireGuard ports, all 80 homeserver Compose publications, precision's loopback Arcane agent and internal-only container ports. `expose:` creates no host publication. The repo's VPS portbridge has TCP 8543 while the live RULES omit it. Do not infer that a firewalld `INPUT` rule protects a Docker-published port: DNAT sends that traffic through `FORWARD`/`DOCKER-USER`. Those chains are currently empty of site policy. Phase 0 Swarm listeners and kernel VXLAN/ESP use `INPUT`, so this script changes no `DOCKER-USER` rule and cannot claim protection for the unrelated published ports. #3593 must add peer-scoped `DOCKER-USER` enforcement before host-mode sensor publication; #3604 owns existing exposed listeners. Preserve portbridge forwarding and source attribution in both follow-ups.

## Apply, probe and rollback

Apply **precision first, then homeserver**, from a checkout of this PR on each host. Run each host independently. Confirm current interface zones, Swarm node state, SSH path, sensor ingest and timer state before touching rules. Do not apply `hosts/vps.env` in phase 0. Never run concurrent firewalld changes during a rollback window.

```bash
sudo -n firewall-cmd --get-active-zones
sudo -n systemctl list-timers --all 'fw-rollback-3588*'
ssh homeserver 'sudo -n docker node ls'  # both nodes must be Ready
cd ops/firewall
backup=$(sudo -n ./swarm-plane.sh backup hosts/HOST.env)
sudo -n ./swarm-plane.sh arm "$backup" 20min
sudo -n ./swarm-plane.sh apply hosts/HOST.env
sudo -n ./swarm-plane.sh status hosts/HOST.env
```

Use `precision.env` or `homeserver.env` for `HOST.env`. Verify the timer is **active and scheduled** before `apply`. From a separate workstation session, reconnect with `ssh precision` or `ssh homeserver`, scan TCP 2377/7946 and UDP 7946/4789 on the LAN address (`nmap -Pn -sT -sU -p T:2377,7946,U:7946,4789`), and spoof the fibre peer source on the LAN uplink as in [#3588's probe](https://github.com/Xore/APIARY/issues/3588#issuecomment-6098151008). There must be no SYN-ACK. Confirm `apiary-swarm-lan:` drops for the ordinary LAN probe; homeserver's strict reverse-path filter can discard the spoof before firewalld logs it. From the actual fibre peer, confirm SSH and permitted Swarm ports and both nodes `Ready`. Test an encrypted overlay ping both ways with `--opt encrypted`, observe ESP packets on the fibre and nonempty `ip xfrm state`, then remove the test overlay and restore the manager's original availability. Confirm precision runners online, query live precision containers through the Arcane manager API, and complete a GitOps sync through the fibre-forwarded Arcane API with a successful `lastSyncStatus`; a local socket or unit being active alone is insufficient. Check fresh `honeypot-v2-*` ingest and a sample event's preserved attacker `source.ip` after each host change.

Only after **independent outside and inside proofs** pass, stop that host's timer with `sudo -n ./swarm-plane.sh disarm` and confirm `fw-rollback-3588.timer` is inactive. If any proof is missing, **leave the timer armed**; it will restore the saved `/etc/firewalld` and NetworkManager interface zone, then reload firewalld. Check the resulting zone, SSH, Swarm and sensor state. Manual rollback is `sudo -n "$backup/rollback.sh" "$backup"`. If SSH is lost, use the host console (homeserver IPMI or precision local console) to run the saved rollback script; stopping firewalld is an emergency access path. The saved nft ruleset is diagnostic evidence, not the restore source.
