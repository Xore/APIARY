#!/bin/sh
# Resolve the versioned fictional page directory, then launch SNARE.
set -e
PAGES=/opt/snare/pages

pick_dir() {
  if [ -n "$PAGE_URL" ] && [ -d "$PAGES/$PAGE_URL" ]; then
    echo "$PAGE_URL"
    return
  fi
  # Compatibility fallback for an existing named volume during upgrades.
  for d in "$PAGES"/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    [ "$name" = "snare" ] && continue
    echo "$name"
    return
  done
}

DIR=$(pick_dir)
if [ -z "$DIR" ]; then
  echo "snare-entrypoint: FATAL - no persona page directory found under $PAGES" >&2
  ls -la "$PAGES" >&2 || true
  exit 1
fi

echo "snare-entrypoint: serving page-dir '$DIR'"
exec snare \
  --no-dorks true \
  --auto-update false \
  --host-ip 0.0.0.0 \
  --port "${PORT:-8080}" \
  --page-dir "$DIR" \
  --path /opt/ \
  --tanner "${TANNER:-tanner}"
