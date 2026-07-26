#!/bin/sh
set -eu
directory=${1:?usage: verify-backup.sh /opt/backups/honeypot/TIMESTAMP}
cd "$directory"
sha256sum -c SHA256SUMS
gzip -t stack-config-state.tar.gz
for archive in volumes/*.tar.gz; do [ -e "$archive" ] || continue; gzip -t "$archive"; done
python3 -c 'import json; d=json.load(open("elasticsearch-snapshot.json")); assert d.get("snapshot",{}).get("state") == "SUCCESS", d'
echo "backup verified: $directory"
