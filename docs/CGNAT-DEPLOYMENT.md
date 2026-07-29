# CGNAT deployment

The deployment is deliberately split between a public VPS and a home server
behind CGNAT.

```text
Internet
  │
  ├─ HTTPS → VPS Traefik → WireGuard HTTP bridge ─┐
  └─ TCP/UDP → VPS portbridge → WireGuard tunnel ─┤
                                                  ▼
                                 home server 10.8.0.2
                                 Dockge honeypot stack
```

## Authoritative deployment paths

- Home server: Dockge manages `/opt/stacks/honeypot-stack/compose.yml`.
- VPS: plain Docker Compose manages `/root/vps/docker-compose.yml`.
- The repository home Compose source is `docker-compose.yml`; copy it to the
  Dockge path as `compose.yml`.
- The public gateway source is under `vps/`.

Dockge is used only on the home server. The VPS uses `docker compose` directly.

## WireGuard addressing

The examples reserve `10.8.0.1` for the VPS and `10.8.0.2` for the home server.
Change the subnet consistently if it conflicts with an existing network.
Sensors bind `HP_BIND=10.8.0.2`, never the home LAN address. The VPS gateway is
the only internet-facing component.

## Home deployment

1. Establish WireGuard and verify that the VPS can reach `10.8.0.2`.
2. Copy `.env.example` to `.env` and generate every value marked `CHANGE_ME`.
3. Copy this repository to `/opt/stacks/honeypot-stack/`.
4. Ensure the repository `docker-compose.yml` is also present as
   `/opt/stacks/honeypot-stack/compose.yml`.
5. In Dockge, validate and deploy the stack.
6. Run `python3 analysis/verify-stack.py` and inspect `/source-health`.

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
findmnt /opt/stacks/honeypot-stack/logs/suricata
findmnt /opt/stacks/honeypot-stack/logs/portbridge
docker logs --since 5m hp-evebox
```

The expected boot order is required uplink, WireGuard, SSHFS mounts, then
ingestion recovery. A temporarily unavailable VPS may delay ingestion, but the
retry service prevents the mounts from remaining failed until the next manual
intervention.

## VPS deployment

1. Copy `vps/.env.example` to `/root/vps/.env`.
2. Replace all example domains, the Suricata `HOME_NET`, authentication
   credentials, cookie secrets, and TOTP values.
3. Copy `vps/` contents to `/root/vps/`.
4. Validate with `docker compose -f /root/vps/docker-compose.yml config`.
5. Start with `docker compose -f /root/vps/docker-compose.yml up -d --build`.
6. Apply `vps/honeypot-firewall.sh` only after reviewing the exposed ports.

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
