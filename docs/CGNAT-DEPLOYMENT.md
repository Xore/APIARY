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
