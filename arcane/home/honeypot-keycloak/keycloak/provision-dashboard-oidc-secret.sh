#!/usr/bin/env bash
# provision-dashboard-oidc-secret.sh -- a fresh --import-realm generates a
# new random client secret for apiary-dashboard (same reasoning as
# provision-events-poller.sh's own comment: no realm-JSON concept for
# pinning a client secret). Nothing ever wrote that secret to where the
# dashboard binary itself expects it
# (arcane/home/honeypot-dashboard/compose.yml's OIDC_CLIENT_SECRET_FILE=
# /run/dashboard-secrets/oidc-client-secret) -- sync-client-secrets.sh
# covers the *gateway* sidecars' copies on the VPS, not this one. Found
# live during #787's homeserver reinstall (2026-08-09): both dashboard and
# dashboard-b crash-looped forever on "OIDC_CLIENT_SECRET(_FILE) must
# contain at least 32 characters" because secrets/ was simply empty.
#
# Idempotent: safe to re-run after a realm re-import (the secret file is
# simply overwritten with the current value). Both dashboard containers
# have restart: unless-stopped, so writing the file here is enough --
# no need to also restart them, their own crash-restart loop picks it up.
#
# Run on the homeserver (needs docker exec access to hp-keycloak).
set -euo pipefail

REALM="${KEYCLOAK_REALM:-apiary}"
KC_CONTAINER="${KC_CONTAINER:-hp-keycloak}"
KC_CONFIG="${KC_CONFIG:-/tmp/kcadm-provision-dashboard-oidc-secret.config}"
SECRETS_DIR="${DASHBOARD_SECRETS_DIR:-/var/dockge/stacks/honeypot-dashboard/secrets}"
KC="/opt/keycloak/bin/kcadm.sh"

: "${KEYCLOAK_ADMIN_USERNAME:?set KEYCLOAK_ADMIN_USERNAME (master-realm admin -- the bootstrap account works fine right after a fresh --import-realm, before a named admin exists yet)}"
: "${KEYCLOAK_ADMIN_PASSWORD:?set KEYCLOAK_ADMIN_PASSWORD}"

docker exec "$KC_CONTAINER" "$KC" config credentials \
  --config "$KC_CONFIG" --server http://127.0.0.1:8080 --realm master \
  --user "$KEYCLOAK_ADMIN_USERNAME" --password "$KEYCLOAK_ADMIN_PASSWORD"

# #2194: from this point the config file holds the live admin access token
# -- remove it on every exit path, not just success (a mid-run failure under
# set -euo pipefail used to leave it in hp-keycloak:/tmp until restart).
cleanup() { docker exec "$KC_CONTAINER" rm -f "$KC_CONFIG" >/dev/null 2>&1 || true; }
trap cleanup EXIT

client_uuid="$(docker exec "$KC_CONTAINER" "$KC" get clients -r "$REALM" \
  -q "clientId=apiary-dashboard" --fields id --format csv --noquotes --config "$KC_CONFIG")"
[[ -n "$client_uuid" ]] || { echo "apiary-dashboard client not found in realm $REALM -- import the realm first" >&2; exit 1; }

secret="$(docker exec "$KC_CONTAINER" "$KC" get \
  "clients/${client_uuid}/client-secret" -r "$REALM" --config "$KC_CONFIG" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"])')"

install -d -m 750 "$SECRETS_DIR"
umask 077
printf '%s' "$secret" > "$SECRETS_DIR/oidc-client-secret"
# dashboard/dashboard-b have no explicit `user:` in arcane/home/honeypot-dashboard/compose.yml
# and no USER in their Dockerfile, so they run as root:root -- matching
# ownership here, same as step_provision_keycloak_secrets' own
# postgres-password/bootstrap-admin-password convention.
chown root:root "$SECRETS_DIR/oidc-client-secret"
chmod 440 "$SECRETS_DIR/oidc-client-secret"
echo "wrote client secret to $SECRETS_DIR/oidc-client-secret"
