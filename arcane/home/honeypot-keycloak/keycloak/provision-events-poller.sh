#!/usr/bin/env bash
# provision-events-poller.sh (#1066) -- auth-events-poller is a
# service-account-only client (see apiary-realm.json's own comment on it);
# a fresh --import-realm creates the client but Keycloak has no realm-JSON
# concept for granting a client's service-account user another client's
# roles (same reasoning docs/KEYCLOAK-OPERATIONS.md already gives for why
# secrets/users are never baked into the export). This script does that
# one-time grant -- realm-management's view-events role, the minimum needed
# for GET /admin/realms/{realm}/events -- and writes the client secret to
# where auth-events-worker's compose stack expects it.
#
# Idempotent: safe to re-run after a realm re-import (grants a role a
# second time is a no-op in Keycloak, and the secret file is simply
# overwritten with the current value).
#
# Run on the homeserver (needs docker exec access to hp-keycloak).
set -euo pipefail

REALM="${KEYCLOAK_REALM:-apiary}"
KC_CONTAINER="${KC_CONTAINER:-hp-keycloak}"
KC_CONFIG="${KC_CONFIG:-/tmp/kcadm-provision-events-poller.config}"
SECRETS_DIR="${EVENTS_POLLER_SECRETS_DIR:-/var/dockge/stacks/auth-events-worker-secrets}"
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
  -q "clientId=auth-events-poller" --fields id --format csv --noquotes --config "$KC_CONFIG")"
[[ -n "$client_uuid" ]] || { echo "auth-events-poller client not found in realm $REALM -- import the realm first" >&2; exit 1; }

sa_user_id="$(docker exec "$KC_CONTAINER" "$KC" get "clients/${client_uuid}/service-account-user" \
  -r "$REALM" --fields id --format csv --noquotes --config "$KC_CONFIG")"
[[ -n "$sa_user_id" ]] || { echo "auth-events-poller has no service-account user -- is serviceAccountsEnabled true?" >&2; exit 1; }

docker exec "$KC_CONTAINER" "$KC" add-roles -r "$REALM" --config "$KC_CONFIG" \
  --uusername "service-account-auth-events-poller" --cclientid realm-management --rolename view-events
echo "granted realm-management:view-events to auth-events-poller's service account"

secret="$(docker exec "$KC_CONTAINER" "$KC" get \
  "clients/${client_uuid}/client-secret" -r "$REALM" --config "$KC_CONFIG" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"])')"

install -d -m 750 "$SECRETS_DIR"
umask 077
printf '%s' "$secret" > "$SECRETS_DIR/client-secret"
# GID 10101 matches auth-events-worker/Dockerfile's fixed, non-root
# `authevents` user -- same reasoning as vps/secrets/oidc/*'s
# "chown root:65532" convention (docs/KEYCLOAK-OPERATIONS.md). The
# directory itself needs the same group, not just the file -- traversal
# (the executable bit) is checked on the directory, and a file-only chown
# left group-root's directory unreadable by GID 10101 (caught live).
chown root:10101 "$SECRETS_DIR" "$SECRETS_DIR/client-secret"
chmod 440 "$SECRETS_DIR/client-secret"
echo "wrote client secret to $SECRETS_DIR/client-secret"
