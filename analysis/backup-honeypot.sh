#!/bin/sh
set -eu

stack_dir=${STACK_DIR:-/opt/stacks/apiary}
backup_root=${BACKUP_ROOT:-/opt/backups/honeypot}
retention_days=${RETENTION_DAYS:-14}
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
# --exclude='./state/elasticsearch-snapshots' (#1413): this is the `fs`
# repository's own live-managed blob storage, the exact data the ES
# snapshot API call below already properly backs up -- confirmed live this
# was never just redundant but actively unsafe: ES's own post-delete
# repository cleanup was concurrently mutating files under here while tar
# read it, aborting the whole run under `set -e` ("file removed before we
# read it" / "file changed as we read it"). Snapshotting through the API is
# already the point-in-time-correct backup; tar-ing the raw directory
# underneath it too was never needed.
tar -czf "$destination/stack-config-state.tar.gz" \
  --exclude='./logs' --exclude='./analysis/geoip/*.mmdb' \
  --exclude='./arcane/home/honeypot-dashboard/dashboard/geoip/*.csv' \
  --exclude='./state/elasticsearch-snapshots' \
  "$@"

# Use Elasticsearch's supported snapshot API instead of copying a live data dir.
# Index patterns must track every template analysis/elasticsearch-setup.sh
# declares (es-data itself is covered by this snapshot too, so it does not
# also need a volume backup below).
#
# ignore_unavailable:true (#1413): several of these indices are only ever
# created by a producer that's disabled by default (github-analysis-v1's
# publisher, e.g. -- see analysis/github/install-github-publisher.sh's own
# GITHUB_PUBLISH_ENABLED=0 default). Confirmed live: without this flag, the
# snapshot request 400s outright the moment ANY named index doesn't exist
# yet, which on a real cluster is the common case, not an edge case -- this
# is the second of two real reasons this script had never actually
# completed a run, on top of never being scheduled at all.
snapshot="honeypot-$stamp"
docker exec hp-elasticsearch curl -fsS -X PUT "http://localhost:9200/_snapshot/honeypot-fs/$snapshot?wait_for_completion=true" \
  -H 'Content-Type: application/json' --data-binary '{"indices":"honeypot-v2-*,suricata-*,portbridge-v2-*,dionaea-incidents-v1-*,ghidra-analysis-v1,sandbox-analysis-v1,github-analysis-v1,workbench-runs-v1,ghidra-report-artifacts-v1,sandbox-export-artifacts-v1,dashboard-alert-state-v1,dashboard-static-analysis-v1,dashboard-payload-inventory-v1,dashboard-generated-reports-v1,cowrie-ttylog-v1,dashboard-workbench-runs-v1,dashboard-workbench-recipes-v1,dead-letter-honeypot*","ignore_unavailable":true,"include_global_state":false}' \
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

# Retention: prune both the local archive directories and the ES snapshots
# older than $retention_days -- #1413 found the original script never
# pruned anything at all, so BACKUP_ROOT and the honeypot-fs repository
# would have grown without bound. Directory names are the UTC timestamp
# stamp itself, all the same fixed width (%Y%m%dT%H%M%SZ) -- stripped of
# its non-digit T/Z separators that's a plain 14-digit number, safe to
# compare with -lt. Deliberately not `[ "$a" \< "$b" ]`: this script is
# #!/bin/sh, and on this fleet that's dash (confirmed: `readlink -f
# /bin/sh` -> /usr/bin/dash), whose test/[ builtin has no </> string
# operators at all -- that's a bash-only extension and would have failed
# every single run.
cutoff=$(date -u -d "-${retention_days} days" +%Y%m%dT%H%M%SZ 2>/dev/null || date -u -v-"${retention_days}"d +%Y%m%dT%H%M%SZ)
cutoff_n=$(echo "$cutoff" | tr -d 'TZ')
for old in "$backup_root"/*/; do
  old_stamp=$(basename "$old")
  old_n=$(echo "$old_stamp" | tr -d 'TZ')
  case $old_n in ''|*[!0-9]*) continue ;; esac
  [ "$old_n" -lt "$cutoff_n" ] || continue
  rm -rf "$old"
done

docker exec hp-elasticsearch curl -fsS "http://localhost:9200/_snapshot/honeypot-fs/_all" \
  | grep -o '"honeypot-[0-9TZ]*"' | tr -d '"' | while read -r name; do
    snap_n=$(echo "${name#honeypot-}" | tr -d 'TZ')
    case $snap_n in ''|*[!0-9]*) continue ;; esac
    [ "$snap_n" -lt "$cutoff_n" ] || continue
    docker exec hp-elasticsearch curl -fsS -X DELETE "http://localhost:9200/_snapshot/honeypot-fs/$name" >/dev/null
  done
