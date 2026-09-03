#!/usr/bin/env bash
# Audits the ghidra_ollama_models volume: classifies every stored blob as
# (a) referenced by a live-service manifest, (b) referenced only by a
# manifest for a model no longer in any known roster, or (c) referenced by
# nothing at all (orphaned from an interrupted pull). See
# analysis/ghidra/models/BLOB-RETENTION-POLICY.md for how to read the
# output and what to do with each class.
#
# Run from a host that can `docker exec` into the ghidra-ollama-1 container
# (the homeserver). Never touches files under /var/lib/docker/volumes
# directly -- classification only. Removal, if any class (b)/(c) blobs are
# found, goes through `ollama rm <tag>` by hand, never this script.
set -euo pipefail

CONTAINER="${OLLAMA_CONTAINER:-ghidra-ollama-1}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
APPROVED_MODELS="$REPO_ROOT/analysis/ghidra/models/approved-models.json"

# Extra roster files: one tag per line, '#' comments allowed. Pass paths as
# args, e.g. the paused #1947 benchmark's models_all.txt/models_extra_all.txt
# on the homeserver at /mnt-1/benchmarks/. Without any, only approved-models.json
# and the live compose LLM_MODEL/VAULT_EMBEDDING_MODEL references are honored.
ROSTER_FILES=("$@")

live_tags() {
	python3 - "$APPROVED_MODELS" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for slot in d.get("slots", {}).values():
    tag = slot.get("artifact", {}).get("tag")
    if tag:
        print(tag)
PY
	grep -h '^\s*LLM_MODEL=' "$REPO_ROOT/llm-worker/.env.example" 2>/dev/null | cut -d= -f2-
	# CAUTION: this reads the live tag out of compose by pattern, not by
	# parsing YAML. A quoting or line-wrapping change upstream makes the
	# sed produce nothing, which drops a live model out of the "known" set
	# and *over*-classifies it as prunable. That is harmless today because
	# this script only reports and has no removal mode. It must not gain
	# one without a test that fails when this extraction returns empty.
	grep -h 'LLM_MODEL=' "$REPO_ROOT/arcane/home/honeypot-galah/compose.yml" 2>/dev/null \
		| sed -n 's/.*LLM_MODEL=\([^"]*\)".*/\1/p; s/.*LLM_MODEL=\([^[:space:]"]*\)$/\1/p'
	grep -h '^\s*VAULT_EMBEDDING_MODEL=' "$REPO_ROOT/vault-worker/.env.example" 2>/dev/null | cut -d= -f2-
}

roster_tags() {
	for f in "${ROSTER_FILES[@]:-}"; do
		[ -f "$f" ] || continue
		grep -v '^\s*#' "$f" | grep -v '^\s*$'
	done
}

{ live_tags; roster_tags; } | LC_ALL=C sort -u > /tmp/audit-known-tags.$$
KNOWN_TAGS=/tmp/audit-known-tags.$$
trap 'rm -f "$KNOWN_TAGS"' EXIT

echo "== Known tags (live-service + roster files given) =="
cat "$KNOWN_TAGS"
echo

echo "== Currently pulled models =="
docker exec "$CONTAINER" ollama list | tail -n +2 | awk '{print $1}' | LC_ALL=C sort -u > /tmp/audit-pulled.$$
cat /tmp/audit-pulled.$$
echo

echo "== Classification: pulled but NOT in any known/live/roster list (candidates for (b)/(c)) =="
LC_ALL=C comm -23 /tmp/audit-pulled.$$ "$KNOWN_TAGS" || true
rm -f /tmp/audit-pulled.$$

echo
echo "== Blob-level cross-reference (orphaned / missing blobs) =="
echo "Reads the volume mountpoint directly, read-only (find/jq), on the host"
echo "running this script -- requires sudo. Never writes under this path."
VOLUME_DATA="$(docker volume inspect --format '{{.Mountpoint}}' "$(docker inspect "$CONTAINER" --format '{{ range .Mounts }}{{ if eq .Destination "/root/.ollama" }}{{ .Name }}{{ end }}{{ end }}')")/models"
sudo bash -c "
cd '$VOLUME_DATA'
find manifests -type f | while read -r f; do
  jq -r '.layers[].digest, (.config.digest // empty)' \"\$f\"
done | sed 's/sha256:/sha256-/' | sort -u > /tmp/referenced.audit.\$\$
find blobs -type f -printf '%f\n' | sort -u > /tmp/existing.audit.\$\$
echo 'orphaned (blob exists, no manifest references it):'
comm -13 /tmp/referenced.audit.\$\$ /tmp/existing.audit.\$\$
echo 'missing (manifest references it, blob absent -- broken pull):'
comm -23 /tmp/referenced.audit.\$\$ /tmp/existing.audit.\$\$
rm -f /tmp/referenced.audit.\$\$ /tmp/existing.audit.\$\$
"
