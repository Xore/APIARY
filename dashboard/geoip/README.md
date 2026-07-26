# GeoIP and network intelligence

The live dashboard prefers native MaxMind GeoLite2 MMDB databases mounted from
`analysis/geoip/`:

- `GeoLite2-City.mmdb` — country, city, latitude/longitude and accuracy radius
- `GeoLite2-ASN.mmdb` — ASN and organization

Both IPv4 and IPv6 are supported. The dashboard also classifies providers
(scanner, cloud, hosting, or network) and can override that classification with
CIDRs from `threat-cidrs.csv` in this directory.

The deployed stack already works with manually supplied MMDB files. For official
automatic MaxMind updates, set `MAXMIND_ACCOUNT_ID` and
`MAXMIND_LICENSE_KEY` in Dockge's stack environment, then enable the optional
profile:

```bash
cd /opt/stacks/honeypot-stack
docker compose -f compose.yml --profile geoip-update up -d geoipupdate
```

As a compatibility fallback, `country.csv` may contain one IPv4 range per line:

```csv
start_ip,end_ip,country_code
1.0.0.0,1.0.0.255,AU
```

The fallback does not provide city, coordinates, ASN, organization, or IPv6.
`country.csv` and downloaded `.mmdb` files are intentionally ignored by Git;
credentials and licensed/generated databases must not be committed.

GeoIP files are loaded when `hp-dashboard` starts. Restart that container after
a manual database replacement. Geolocation is approximate and must not be
treated as proof of an attacker's physical location.
