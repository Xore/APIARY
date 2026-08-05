#!/bin/sh
set -eu

stack_dir=${STACK_DIR:-/opt/stacks/honeypot-stack}
backup_root=${BACKUP_ROOT:-/opt/backups/honeypot}
stamp=$(date -u +%Y%m%dT%H%M%SZ)
destination="$backup_root/$stamp"
mkdir -p "$destination/volumes"
chmod 700 "$destination"

cd "$stack_dir"
docker compose -f compose.yml config -q

# Config/state archive excludes event logs, PCAP, Elasticsearch data, captured
# malware and generated databases. Those have dedicated retention/snapshot paths.
set -- ./compose.yml
for candidate in ./.env ./README.md ./analysis ./dashboard ./personas ./state; do
  [ ! -e "$candidate" ] || set -- "$@" "$candidate"
done
tar -czf "$destination/stack-config-state.tar.gz" \
  --exclude='./logs' --exclude='./analysis/geoip/*.mmdb' --exclude='./dashboard/geoip/*.csv' \
  "$@"

# Use Elasticsearch's supported snapshot API instead of copying a live data dir.
snapshot="honeypot-$stamp"
docker exec hp-elasticsearch curl -fsS -X PUT "http://localhost:9200/_snapshot/honeypot-fs/$snapshot?wait_for_completion=true" \
  -H 'Content-Type: application/json' --data-binary '{"indices":"honeypot-v2-*,suricata-*,dead-letter-honeypot*","include_global_state":false}' \
  >"$destination/elasticsearch-snapshot.json"

# Back up non-Elasticsearch named volumes. Archives are inert data; restoring is
# intentionally a separate, stopped-stack procedure documented in RECOVERY.md.
docker volume ls -q --filter label=com.docker.compose.project=APIARY | while IFS= read -r volume; do
  [ -n "$volume" ] || continue
  case "$volume" in *es-data*) continue ;; esac
  safe=$(printf '%s' "$volume" | tr -c 'A-Za-z0-9._-' '_')
  docker run --rm --network none -v "$volume:/source:ro" -v "$destination/volumes:/backup" busybox:1.36 \
    tar -C /source -czf "/backup/$safe.tar.gz" .
done

(cd "$destination" && sha256sum stack-config-state.tar.gz elasticsearch-snapshot.json volumes/*.tar.gz >SHA256SUMS 2>/dev/null || sha256sum stack-config-state.tar.gz elasticsearch-snapshot.json >SHA256SUMS)
chmod -R go-rwx "$destination"
echo "$destination"
