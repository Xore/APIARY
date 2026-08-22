# GeoIP and network intelligence

City/ASN geolocation runs entirely inside Elasticsearch now: the
`geoip-honeypot` ingest pipeline (`arcane/home/honeypot-init/analysis/elasticsearch-setup.sh`)
enriches every document at write time from native MaxMind GeoLite2 MMDB
databases mounted from `analysis/geoip/`:

- `GeoLite2-City.mmdb` — country, city, latitude/longitude and accuracy radius
- `GeoLite2-ASN.mmdb` — ASN and organization

Both IPv4 and IPv6 are supported. The same pipeline also classifies providers
(scanner, cloud, hosting, or network) into `source.as.type` from the ASN
organization name.

### Threat-intel enrichment (`threat-cidrs.csv`, #244, #1659)

`analysis/threat-intel/threat-cidrs.csv` is `CIDR,label` pairs. Unlike the
MMDB lookups above, this isn't matched at ES ingest time — `backend-service`'s
`threat_intel.rs` worker loop (`WORKER_LOOPS=threat-intel`) polls it, matches
recently-seen source IPs against it, and writes a match onto the *same*
`source.as.type` field the ingest pipeline populates: intel always wins over
the plain provider class when both would apply, so every existing
`source.as.type` aggregation/filter/badge in the dashboard already shows intel
labels with no separate wiring.

When more than one entry matches the same address, the highest-severity label
wins regardless of file order (`threat_intel.rs`'s `category_rank`, ported
from the old Go dashboard's `intelCategoryRank`): `blocklist:*` (a
reputation-list hit) beats `tor-exit` (a real but not inherently malicious
signal) beats everything else, including the `cloud:aws`/`cloud:gcp` ground
truth and any custom label an operator adds. Ties (equal severity) go to the
more specific prefix.

Like `country.csv` and `.mmdb` files above, `threat-cidrs.csv` is generated
content and intentionally ignored by Git -- `threat-cidrs.csv.example` is the
tracked starter. Get real coverage one of two ways:

- Populate it by hand: `cp threat-cidrs.csv.example threat-cidrs.csv` and add
  your own entries.
- Run `./refresh-threat-cidrs.sh` (or enable the `threat-intel`
  Compose profile in `arcane/home/honeypot-init/compose.yml`, which runs it on a daily
  loop) to auto-populate it from Spamhaus DROP, the Tor bulk exit list, and
  AWS/GCP's published IP ranges -- all free, no signup required. It creates
  the file from `threat-cidrs.csv.example` on first run, and leaves any
  manually-added lines above its auto-fetched block untouched on every
  later run. AbuseIPDB (needs a registered API key) is intentionally not
  included; add it by hand if wanted.

A refresh reaches previously-tagged and newly-seen documents within the
worker's own reload/run interval (`threat_intel.rs`), no restart needed.

The deployed stack already works with manually supplied MMDB files. For official
automatic MaxMind updates, set `MAXMIND_ACCOUNT_ID` and
`MAXMIND_LICENSE_KEY` in Dockge's stack environment, then enable the optional
profile:

```bash
cd /opt/stacks/apiary
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

MMDB databases and a manually-edited `threat-cidrs.csv` are loaded when
`hp-dashboard` starts -- restart that container after replacing a database or
hand-editing the file directly. `threat-cidrs.csv` refreshed by
`refresh-threat-cidrs.sh` is the one exception: the running dashboard picks
that up on its own (see above), no restart needed. Geolocation is
approximate and must not be treated as proof of an attacker's physical
location.
