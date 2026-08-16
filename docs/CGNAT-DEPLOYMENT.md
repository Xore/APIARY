# CGNAT deployment

The deployment is deliberately split between a public VPS and a home server
behind CGNAT.

```mermaid
flowchart TD
    Internet --> Traefik["VPS Traefik<br/>HTTPS"]
    Internet --> Portbridge["VPS portbridge<br/>TCP/UDP"]
    Traefik --> HTTPBridge["WireGuard HTTP bridge"]
    Portbridge --> Tunnel["WireGuard tunnel"]
    HTTPBridge --> Home["home server 10.8.0.2<br/>Arcane APIARY stack"]
    Tunnel --> Home
```

## Authoritative deployment paths

- Home server: **#258 split what used to be two stacks into one Arcane-managed
  project per compose file**, and **#1502 moved every one of those projects
  onto Arcane's own directory-aware Git sync** — `honeypot-init` (one-shot
  bootstrap: log paths, Elasticsearch templates, Arkime schema, persona
  validation), `honeypot-elk`, `honeypot-cowrie`, `honeypot-dionaea`,
  `honeypot-conpot`, `honeypot-dnp3`, `honeypot-http`, `honeypot-multipot`,
  `honeypot-payload-analysis`, `honeypot-tanner`, `honeypot-dashboard`,
  `honeypot-utilities`, the standalone honeypots (cisco-asa, citrix, rdp,
  dicompot, dns-honeypot, endlessh, beelzebub, hellpot, elasticpot, galah,
  sentrypeer, wordpot, mailoney, canarytokens), `honeypot-keycloak`, and the
  workers (ip-enrichment, agent-intrusion, attacker-identity, correlator,
  payload-inventory) — 32 stacks total, one Arcane-managed directory each
  under `arcane/home/<name>/`. `honeypot-init` still deploys first; every
  sensor stack waits on its completion markers at its own entrypoint rather
  than a Compose-level dependency, same reasoning as before, just across
  more projects now. See `docs/STACK-REBUILD.md` for the full current list
  and the ordering traps (Elasticsearch must be healthy before
  `honeypot-init` runs, not the other way around), and
  `docs/ARCANE-GIT-SYNC.md` for how a commit actually reaches the live
  host now.
- VPS: plain Docker Compose manages `/root/vps/docker-compose.yml`.
  Unchanged by #1502 — VPS deployment stays outside Arcane entirely, as
  that issue's own scope decision.
- Each of the 32 stacks' Compose source (build context, git-tracked config,
  `compose.yml` with an explicit top-level `name:` pinned to its live
  project name) lives self-contained under `arcane/home/<name>/` in this
  repository. Arcane clones the repo and materializes the *entire
  directory* containing the selected `compose.yml`, not just that one
  file — that's what makes a build context or sidecar config file
  resolvable without a shared checkout. Runtime data (`logs/`, `state/`,
  and similarly host-owned paths) deliberately stays outside that synced
  directory, at its existing absolute host path, unchanged.
  `scripts/install-homeserver.sh`'s `step_arcane_import_stacks` creates
  these syncs on a from-scratch install, driven by the single source of
  truth at `arcane/manifests/home-production.json`. Six more home-hosted
  stacks (`auth-events-worker`, `llm-worker`, `ml-worker`,
  `analysis/ghidra`, `sandbox/ghosts`, `pihole`) are Arcane-managed the
  same way but were already self-contained, so they kept their existing
  repository-root path instead of moving.
- The public gateway source is under `vps/`.

Arcane is used only on the home server. The VPS uses `docker compose` directly.
See `docs/ARCANE-GIT-SYNC.md` for the sync model, cutover procedure, and
confirmed Arcane v2.8.0 platform limitations (a required compose variable
in a port-binding position, remote build contexts pinned to a Git tag, the
sync file-count limit, and stale project records after a `destroy` call
all have confirmed workarounds documented there).

## WireGuard addressing

The examples reserve `10.8.0.1` for the VPS and `10.8.0.2` for the home server.
Change the subnet consistently if it conflicts with an existing network.
Sensors bind `HP_BIND=10.8.0.2`, never the home LAN address. The VPS gateway is
the only internet-facing component.

## Home deployment

> **Prefer the script.** [`scripts/install-homeserver.sh`](../scripts/install-homeserver.sh)
> automates Docker, GPU/NVIDIA, WireGuard, Arcane, the repo checkout,
> per-stack provisioning, secret restore, and starting every stack in the
> correct order (plus the GPU/LLM/ML worker chain and, optionally, the
> KVM/libvirt sandbox VMs) against a manually-installed base Ubuntu system
> — fill in
> [`scripts/install-homeserver.conf.example`](../scripts/install-homeserver.conf.example)
> first. Run multiple times end-to-end (including a from-genuinely-fresh
> install and a full idempotent re-run) under
> [#518](https://github.com/Xore/APIARY/issues/518), with real bugs
> found and fixed each pass — it's the current source of truth for the
> real deployment order, not the numbered steps below, which describe the
> pre-#258 two-stack model and haven't been re-verified against the current
> per-stack split. File a gap against #518 if the script and reality ever
> disagree. As of #1502, per-stack provisioning means importing an Arcane
> directory-aware Git sync per `arcane/manifests/home-production.json`
> entry, not copying/symlinking a compose file — see
> `docs/ARCANE-GIT-SYNC.md`. Note the gap that doc's own comments flag: a
> genuinely from-scratch run of this script can't reach that step yet,
> since `step_dockge_install` still installs Dockge rather than Arcane
> (tracked as an explicit follow-up, not fixed in #1502).

1. Establish WireGuard and verify that the VPS can reach `10.8.0.2`.
2. Copy this repository to `/opt/stacks/apiary/`.
3. Copy `.env.example` to `.env` in `/opt/stacks/apiary/` and generate
   every value marked `CHANGE_ME`.
4. Create `/opt/stacks/honeypot-init/`, copy `docker-compose.init.yml` from
   the repo into it as `compose.yml`, and copy the repo's
   `honeypot-init.env.example` to `.env` there (set
   `ARKIME_ADMIN_PASSWORD`/`ARKIME_PASSWORD_SECRET` — the latter must match
   the value in `APIARY`'s `.env` exactly).
5. Before first deploying `honeypot-init`:
   `install -d -m 777 /opt/stacks/apiary/state/init-markers` — its
   jobs run as several different container UIDs, and a root-owned 755
   directory 403's the non-root ones.
6. Ensure the repository `docker-compose.yml` is also present as
   `/opt/stacks/apiary/compose.yml`.
7. In Arcane, validate and deploy **`honeypot-init` first**, then
   `APIARY`. `APIARY`'s sensors wait on `honeypot-init`'s
   completion markers at their own entrypoint rather than a Compose-level
   dependency (they can't cross a Compose project boundary) — deploying
   `APIARY` first won't fail, but nothing finishes initialising
   (log paths, Elasticsearch templates, Arkime schema) until `honeypot-init`
   has run at least once. See the root `README.md`'s "Home container
   interaction map" for why these are two stacks.
8. Run `python3 analysis/verify-stack.py` and inspect `/source-health`.

Each stack is a folder under your Arcane stacks dir (default `/opt/stacks/`).
Upload the whole home folder via SFTP — compose **and** the build
sub-folders (`cowrie/`, `multipot/`, `http-honeypot/`, `dashboard/`, …) —
since Arcane's own editor only edits the compose file. After editing Go
source or honeyfs content, rebuild from the `APIARY` stack's Arcane
**terminal**: `docker compose -f compose.yml up -d --build`.

### Boot-safe home networking and VPS log mounts

The home stack reads Suricata and portbridge logs through read-only SSHFS
mounts over `wg0`. `_netdev` only orders an fstab mount after
`network-online.target`; it does not guarantee that the WireGuard interface is
ready. Likewise, SSHFS's `reconnect` option only reconnects a session that was
successfully established once.

On the reference homeserver, the 10 GbE interface `ens9f0` is the required
uplink. `eno1` and `eno2` are optional. Install the Netplan override first:

```bash
sudo ./setup-home-network.sh
sudo netplan try
```

The first command writes and validates
`/etc/netplan/90-honeypot-uplink.yaml`, but deliberately does not change the
live network. `netplan try` applies it with an automatic rollback unless it is
confirmed. Run this from the local console or through the required interface.
To use different interface names, set `REQUIRED_INTERFACE`,
`SECONDARY_INTERFACE`, and `UNUSED_INTERFACE` for the installer.

The override makes the required uplink use the preferred DHCP route metric,
marks the other interfaces optional, and pins
`systemd-networkd-wait-online` to the required routable interface. It does not
hard-code the DHCP address.

After confirming Netplan, install the mount ordering and recovery unit:

```bash
sudo ./setup-suricata-logs-home.sh
```

This installer requires the existing Suricata and portbridge entries in
`/etc/fstab`. It adds drop-ins that make both generated mount units require and
start after `wg-quick@wg0.service`. It also enables
`honeypot-log-mounts.service`, which retries failed mounts every 15 seconds and
restarts EveBox and Filebeat after recovery so they discover `eve.json`.

Verify the installed state:

```bash
systemctl status systemd-networkd-wait-online wg-quick@wg0 \
  honeypot-log-mounts.service
findmnt /opt/stacks/apiary/logs/suricata
findmnt /opt/stacks/apiary/logs/portbridge
docker logs --since 5m hp-evebox
```

The expected boot order is required uplink, WireGuard, SSHFS mounts, then
ingestion recovery. A temporarily unavailable VPS may delay ingestion, but the
retry service prevents the mounts from remaining failed until the next manual
intervention.

## VPS deployment

> **Prefer the script.** [`scripts/install-vps.sh`](../scripts/install-vps.sh)
> automates Docker, WireGuard, the firewall, the NIC offload fix, the `vps/`
> checkout, secret restore, and starting the stack against a
> manually-installed base Ubuntu system — fill in
> [`scripts/install-vps.conf.example`](../scripts/install-vps.conf.example)
> first. Filed as [#1059](https://github.com/Xore/APIARY/issues/1059) after
> confirming nothing in this repo could previously bring a genuinely
> wiped/reimaged VPS back up — it's the current source of truth for the real
> deployment order, not the numbered steps below, which predate it and
> haven't been kept in lockstep since. File a gap against #1059 if the
> script and reality ever disagree.
>
> For a genuinely fresh pair of hosts, run this script BEFORE
> `install-homeserver.sh` — see its own header comment for why (its
> WireGuard peer entry for home starts as a placeholder that
> `install-homeserver.sh`'s `step_wireguard_sync_vps_peer` fills in once the
> home side exists).

1. Move real admin SSH to `2222` first, so cowrie can own `22` — confirm
   `2222` works before continuing. There is no script for this step; do it
   by hand and keep the old session open until the new port answers.
2. `sudo ufw allow 2222/tcp comment 'REAL admin SSH'` and, for `443/tcp`,
   allow only Cloudflare's published ranges
   (<https://www.cloudflare.com/ips-v4/> — see
   `scripts/install-vps.sh`'s `step_firewall_base` for the exact list this
   repo currently pins), not `Anywhere`: every real hostname is proxied
   through Cloudflare, and a direct-origin connection bypassing it skips
   Cloudflare's own WAF/rate-limiting. There is no `80/tcp` rule — Traefik
   has no plain-HTTP listener here. Both of these are outside
   `honeypot-firewall.sh`'s scope (below), so do them by hand too if not
   using the script above.
3. Copy `vps/.env.example` to `/root/vps/.env`.
4. Replace all example domains, the Suricata `HOME_NET`, authentication
   credentials, cookie secrets, and TOTP values.
5. Copy `vps/` contents to `/root/vps/`.
6. Validate with `docker compose -f /root/vps/docker-compose.yml config`.
7. Start with `docker compose -f /root/vps/docker-compose.yml up -d --build`.
8. Apply `vps/honeypot-firewall.sh` only after reviewing the exposed ports —
   it opens every raw (non-Traefik) port `portbridge` forwards, including
   `21`/`22`/`23`/`25` (Dionaea FTP, cowrie SSH/Telnet, multipot SMTP).
   Portbridge's `22` is a separate host listener from real admin SSH — it
   only binds there because step 1 already moved admin SSH to `2222` — so
   opening it does not affect step 2's rule. Run
   `vps/check-firewall-portbridge-sync.sh` after editing either
   `honeypot-firewall.sh` or portbridge's `RULES` env var; it fails loudly if
   the two fall out of sync again (#152).
9. Run `sudo vps/disable-nic-hw-gro.sh --apply` (#342). Most VPS providers
   put the public interface on `virtio-net`, whose hardware-accelerated GRO
   (`rx-gro-hw`) is a separate feature from the standard
   `generic-receive-offload` toggle and coalesces multiple physical frames
   into one oversized packet — Suricata's AF_PACKET capture then logs the
   result as a "truncated packet" decoder-event alert (SID `2200003`/
   `2200122`), which can dominate alert volume. This installs a
   `systemd-networkd` `.link` file so the fix survives reboots.

`portbridge` binds every raw port on the public interface and forwards it
over WireGuard to `10.8.0.2`; the `socat-hp-*` services put the HTTP
honeypots on the `proxy` network for Traefik. The reusable Traefik router
template is in [`vps/traefik/dynamic.yml`](../vps/traefik/dynamic.yml):
`honeypot-http` (`decoy.<domain>`) + `honeypot-web` (catch-all) → fake nginx,
`honeypot-snare` (`www-portal.<domain>` and `snare.<domain>`) → SNARE, one
native-OIDC route for the dashboard (no gateway, since #1026), one native-OIDC
route for Arcane (no gateway, #1185), and six forward-auth-protected
investigation routes sitting behind their own Keycloak-backed `oauth2-proxy`
gateway: Kibana, TANNER, EveBox, Arkime, Rev·Deck, and the Traefik dashboard
itself. Each has a matching
`socat-hp-*` bridge in [`vps/docker-compose.yml`](../vps/docker-compose.yml).

Traefik is an HTTP(S) reverse proxy — it adds TLS, per-subdomain routing and
auth to the web honeypots and dashboards. The other protocols (SSH, SMB,
MySQL, Modbus, …) aren't HTTP, so Traefik can't route them; `portbridge`
forwards them raw. Both paths terminate on the VPS public IP.

### The forward-auth bridge, generically

Six investigation UIs (Kibana, TANNER, EveBox, Arkime, Rev·Deck,
the Traefik dashboard) reach home through the identical chain — one pattern,
six routers in `vps/traefik/dynamic.yml`, six `socat-hp-*` bridges, each
fronted by its own Keycloak-backed `oauth2-proxy` gateway container, not
six different mechanisms. The honeypot dashboard and Arcane are the two
exceptions — both speak native OIDC directly, no gateway — see the note below.

```mermaid
sequenceDiagram
  autonumber
  actor Op as operator's browser
  participant CF as Cloudflare<br/>(proxied DNS)
  participant TR as Traefik<br/>(TLS termination + routing)
  participant OA as oauth2-proxy<br/>(forward-auth, one per service)
  participant KC as Keycloak<br/>(honeypot-keycloak, at home)
  participant SOC as socat-hp-*<br/>(VPS container)
  participant WG as WireGuard tunnel
  participant APP as home app<br/>(HP_BIND:port)

  Op->>CF: HTTPS request, e.g. kibana.<domain>
  CF->>TR: proxied, real client IP in X-Forwarded-For
  TR->>OA: forward-auth check
  alt no valid session
    OA-->>Op: redirect to Keycloak login (auth.<domain>)
    Op->>KC: authenticate (password + mandatory TOTP)
    KC-->>OA: OIDC callback, session established
  end
  OA-->>TR: identity headers
  TR->>SOC: request, security-headers applied
  SOC->>WG: raw TCP, VPS listen port → 10.8.0.2:home-exposed-port
  WG->>APP: delivered to the app's own internal port
  APP-->>Op: response, relayed back through the same chain
```

The socat hop is a dumb TCP relay — all the routing/auth decisions happen in
Traefik and `oauth2-proxy` before it, which is why adding a new
gateway-fronted UI means one new router + one new `oauth2-proxy` container +
one new `socat-hp-*` container, never a change to this flow itself.
`vps/traefik/dynamic.yml`'s own comment table lists every current listen-port
→ home-port → app-internal-port mapping.

> **The honeypot dashboard doesn't use this chain.** Since #1026 it speaks
> OIDC to Keycloak natively (its own Go client, PKCE S256) instead of sitting
> behind an `oauth2-proxy` gateway. Traefik routes its traffic straight to
> `socat-hp-dashboard` with no forward-auth hop at all; the actual OIDC token
> exchange happens homeserver-local, directly between `honeypot-dashboard`
> and `honeypot-keycloak`, and never crosses the VPS. `Xore/auth-backend` is
> retired as a runtime service across every app now — it supplies only the
> read-only Keycloak login theme (`themes/apiary`).

> **Source IP:** the HTTP honeypots recover the real client IP from
> `X-Forwarded-For` (Traefik/Cloudflare). Some raw sensor logs initially
> contain the **VPS WireGuard IP**, but the dashboard correlates those
> connections with the portbridge connection log and attributes the real
> attacker — see "Source-IP preservation" below. The HTTPS catch-all only
> catches requests with a valid SNI/`Host`; raw-IP scanners are caught by the
> direct `:8081` tunnel instead.

## DNS

Create proxied DNS records for the HTTP services you enable, normally:

- `auth`
- `dashboard` or `honeypot`
- `decoy`
- `www-portal` or `snare`
- `kibana`
- `tanner`
- `evebox`
- `arkime`
- `rev` (optional — Rev·Deck; only if the `analysis/ghidra/` stack's
  `revdeck` profile is enabled; see `docs/analysis/ghidra/revdeck/README.md`)
- `traefik` (optional — Traefik's own dashboard/API, read-only, behind
  forward-auth same as everything else here)
- `arcane` (optional — **root-equivalent host control**: Arcane has
  `/var/run/docker.sock` mounted read-write. Unlike the routes above, it
  authenticates natively against Keycloak rather than through an
  `oauth2-proxy` gateway, but treat this subdomain as sensitive as SSH
  access to the homeserver itself)

All names point to the VPS. Raw TCP/UDP sensors need no DNS record.

## Source-IP preservation

The VPS port bridge records the public source and, where supported, adds the
HAProxy PROXY protocol header. The dashboard uses bridge correlation only to
recover the real attacker IP; `portbridge` is never shown as a sensor.

## Public-repository safety

Never commit `.env`, WireGuard private keys, real VPS addresses, captured
payloads, PCAPs, GeoIP license keys, authentication databases, or sandbox
images/results. CI runs the repository leak audit for every push and pull
request.
