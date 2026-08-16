#!/usr/bin/env bash
# provision-arcane-oidc-secret.sh (#1504) -- a fresh --import-realm generates
# a new random client secret for the `arcane` OIDC client (same reasoning as
# provision-dashboard-oidc-secret.sh's own comment: the realm JSON has no
# concept for pinning a client secret, so it can't be baked into the export).
# install-homeserver.sh's step_arcane_install stands Arcane up with a
# throwaway placeholder ARCANE_OIDC_CLIENT_SECRET just to satisfy
# docker-compose.arcane.yml's `:?` guard; this script replaces it with the
# real value once Keycloak is up, so interactive OIDC login actually works.
#
# Unlike the dashboard (which reads OIDC_CLIENT_SECRET_FILE from a mounted
# secrets file this can just overwrite in place), Arcane has NO *_FILE
# variant for this secret -- it reads OIDC_CLIENT_SECRET straight from the
# stack's own .env (confirmed against Arcane's env-var reference, see
# docker-compose.arcane.yml). So this script rewrites the .env line and then
# re-ups the stack to pick it up, rather than just dropping a file a running
# container's restart loop would notice.
#
# Idempotent: safe to re-run after a realm re-import (the .env line is simply
# rewritten with the current value and the stack re-upped).
#
# Run on the homeserver (needs docker exec access to hp-keycloak and docker
# compose access to the honeypot-arcane stack).
set -euo pipefail

REALM="${KEYCLOAK_REALM:-apiary}"
KC_CONTAINER="${KC_CONTAINER:-hp-keycloak}"
KC_CONFIG="${KC_CONFIG:-/tmp/kcadm-provision-arcane-oidc-secret.config}"
ARCANE_DIR="${ARCANE_STACK_DIR:-/var/dockge/stacks/honeypot-arcane}"
ENV_FILE="$ARCANE_DIR/.env"
KC="/opt/keycloak/bin/kcadm.sh"

: "${KEYCLOAK_ADMIN_USERNAME:?set KEYCLOAK_ADMIN_USERNAME (master-realm admin -- the bootstrap account works fine right after a fresh --import-realm, before a named admin exists yet)}"
: "${KEYCLOAK_ADMIN_PASSWORD:?set KEYCLOAK_ADMIN_PASSWORD}"

[[ -f "$ENV_FILE" ]] || { echo "no $ENV_FILE -- was step_arcane_install run first?" >&2; exit 1; }

docker exec "$KC_CONTAINER" "$KC" config credentials \
  --config "$KC_CONFIG" --server http://127.0.0.1:8080 --realm master \
  --user "$KEYCLOAK_ADMIN_USERNAME" --password "$KEYCLOAK_ADMIN_PASSWORD"

client_uuid="$(docker exec "$KC_CONTAINER" "$KC" get clients -r "$REALM" \
  -q "clientId=arcane" --fields id --format csv --noquotes --config "$KC_CONFIG")"
[[ -n "$client_uuid" ]] || { echo "arcane client not found in realm $REALM -- import the realm first" >&2; exit 1; }

secret="$(docker exec "$KC_CONTAINER" "$KC" get \
  "clients/${client_uuid}/client-secret" -r "$REALM" --config "$KC_CONFIG" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"])')"
[[ -n "$secret" ]] || { echo "empty client secret returned for arcane client" >&2; exit 1; }

# Rewrite the single ARCANE_OIDC_CLIENT_SECRET line in place, preserving the
# rest of the .env (ENCRYPTION_KEY/JWT_SECRET must NOT change). Use a
# non-/ delimiter -- a base64/hex secret never contains '#'.
if grep -q '^ARCANE_OIDC_CLIENT_SECRET=' "$ENV_FILE"; then
  sed -i "s#^ARCANE_OIDC_CLIENT_SECRET=.*#ARCANE_OIDC_CLIENT_SECRET=${secret}#" "$ENV_FILE"
else
  printf 'ARCANE_OIDC_CLIENT_SECRET=%s\n' "$secret" >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"
echo "wrote real arcane OIDC client secret to $ENV_FILE"

# Re-up so Arcane's container picks up the new secret (env changes only take
# effect on recreate, not on a bare restart).
(cd "$ARCANE_DIR" && docker compose -f compose.yml up -d)

docker exec "$KC_CONTAINER" rm -f "$KC_CONFIG"
