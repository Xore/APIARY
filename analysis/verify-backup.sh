#!/bin/sh
set -eu
directory=${1:?usage: verify-backup.sh /opt/backups/honeypot/TIMESTAMP}
cd "$directory"
sha256sum -c SHA256SUMS
gzip -t stack-config-state.tar.gz
[ ! -f keycloak.sql.gz ] || gzip -t keycloak.sql.gz
for archive in volumes/*.tar.gz; do [ -e "$archive" ] || continue; gzip -t "$archive"; done
# The Elasticsearch snapshot assertion that used to live here is gone with the
# snapshot itself -- backup-honeypot.sh no longer captures ES data. See that
# script's header for why.
echo "backup verified: $directory"
