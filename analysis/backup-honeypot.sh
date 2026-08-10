#!/bin/sh
set -eu

stack_dir=${STACK_DIR:-/opt/stacks/apiary}
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
# Index patterns must track every template analysis/elasticsearch-setup.sh
# declares (es-data itself is covered by this snapshot too, so it does not
# also need a volume backup below).
snapshot="honeypot-$stamp"
docker exec hp-elasticsearch curl -fsS -X PUT "http://localhost:9200/_snapshot/honeypot-fs/$snapshot?wait_for_completion=true" \
  -H 'Content-Type: application/json' --data-binary '{"indices":"honeypot-v2-*,suricata-*,portbridge-v2-*,dionaea-incidents-v1-*,ghidra-analysis-v1,sandbox-analysis-v1,github-analysis-v1,workbench-runs-v1,ghidra-report-artifacts-v1,sandbox-export-artifacts-v1,dashboard-alert-state-v1,dashboard-static-analysis-v1,dashboard-payload-inventory-v1,dashboard-generated-reports-v1,cowrie-ttylog-v1,dashboard-workbench-runs-v1,dashboard-workbench-recipes-v1,dead-letter-honeypot*","include_global_state":false}' \
  >"$destination/elasticsearch-snapshot.json"

# Back up shared named volumes (explicit `name:` overrides in the compose
# files, not project-scoped auto-named ones) -- these are the ones another
# stack depends on reading/writing across stack boundaries, so they can't be
# recreated from a single stack's own state. es-data is excluded: it's
# covered by the Elasticsearch snapshot above, not a tar archive. Listed
# directly by name rather than filtered by compose-project label: since
# #258 split the stack, no single project label covers them any more (each
# is owned by whichever stack first declares it non-external, and several
# are `external: true` volumes created directly by
# scripts/install-homeserver.sh, which never get any compose-project label
# at all). Archives are inert data; restoring is intentionally a separate,
# stopped-stack procedure documented in RECOVERY.md.
for volume in dionaea-lib yara-results reporter-data dashboard-state snare-pages; do
  docker volume inspect "$volume" >/dev/null 2>&1 || continue
  safe=$(printf '%s' "$volume" | tr -c 'A-Za-z0-9._-' '_')
  docker run --rm --network none -v "$volume:/source:ro" -v "$destination/volumes:/backup" busybox:1.36 \
    tar -C /source -czf "/backup/$safe.tar.gz" .
done

(cd "$destination" && sha256sum stack-config-state.tar.gz elasticsearch-snapshot.json volumes/*.tar.gz >SHA256SUMS 2>/dev/null || sha256sum stack-config-state.tar.gz elasticsearch-snapshot.json >SHA256SUMS)
chmod -R go-rwx "$destination"
echo "$destination"
