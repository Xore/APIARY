#!/usr/bin/env bash
# sync-client-secrets.sh -- after a fresh `--import-realm` (apiary-realm.json
# pins no client "secret", so Keycloak generates a new random one for every
# confidential client on each import), fetches all 8 gateway clients' fresh
# secrets from Keycloak on the homeserver and writes them into the matching
# `vps/secrets/oidc/<client>/client-secret` file on the VPS, then restarts
# each gateway. Replaces the fully-manual per-client procedure in
# docs/KEYCLOAK-OPERATIONS.md -- run this instead of copy-pasting kcadm
# commands eight times by hand.
#
# Run from the homeserver (needs docker exec access to hp-keycloak) with SSH
# access to the VPS. Secret values are piped directly over SSH, never
# written to a local file or passed as a command-line argument.
set -euo pipefail

REALM="${KEYCLOAK_REALM:-apiary}"
VPS_HOST="${VPS_HOST:-vps}"
VPS_SECRETS_DIR="${VPS_SECRETS_DIR:-/root/vps/secrets/oidc}"
KC_CONTAINER="${KC_CONTAINER:-hp-keycloak}"
KC_CONFIG="${KC_CONFIG:-/tmp/kcadm-sync-client-secrets.config}"
KC="/opt/keycloak/bin/kcadm.sh"

# client id -> vps/docker-compose.yml service/container name (not always a
# plain "oidc-<client>" prefix -- apiary-dashboard's gateway is oidc-dashboard,
# traefik-dashboard's is oidc-traefik).
declare -A CLIENT_CONTAINERS=(
  [apiary-dashboard]=oidc-dashboard
  [kibana]=oidc-kibana
  [evebox]=oidc-evebox
  [arkime]=oidc-arkime
  [tanner]=oidc-tanner
  [revdeck]=oidc-revdeck
  [traefik-dashboard]=oidc-traefik
  [dockge]=oidc-dockge
)
CLIENTS=("${!CLIENT_CONTAINERS[@]}")

: "${KEYCLOAK_ADMIN_USERNAME:?set KEYCLOAK_ADMIN_USERNAME (master-realm admin -- the bootstrap account works fine right after a fresh --import-realm, before a named admin exists yet)}"
: "${KEYCLOAK_ADMIN_PASSWORD:?set KEYCLOAK_ADMIN_PASSWORD}"

docker exec "$KC_CONTAINER" "$KC" config credentials \
  --config "$KC_CONFIG" --server http://127.0.0.1:8080 --realm master \
  --user "$KEYCLOAK_ADMIN_USERNAME" --password "$KEYCLOAK_ADMIN_PASSWORD"

fail=0
for client in "${CLIENTS[@]}"; do
  uuid="$(docker exec "$KC_CONTAINER" "$KC" get clients -r "$REALM" \
    -q "clientId=${client}" --fields id --format csv --noquotes --config "$KC_CONFIG")"
  if [[ -z "$uuid" ]]; then
    echo "SKIP $client: no such client in realm $REALM" >&2
    fail=1
    continue
  fi
  secret="$(docker exec "$KC_CONTAINER" "$KC" get \
    "clients/${uuid}/client-secret" -r "$REALM" --config "$KC_CONFIG" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["value"])')"

  ssh "$VPS_HOST" "install -d -m 750 '${VPS_SECRETS_DIR}/${client}' && \
    umask 077 && cat > '${VPS_SECRETS_DIR}/${client}/client-secret' && \
    chown root:65532 '${VPS_SECRETS_DIR}/${client}/client-secret' && \
    chmod 440 '${VPS_SECRETS_DIR}/${client}/client-secret'" <<<"$secret"
  echo "synced $client"
done

docker exec "$KC_CONTAINER" rm -f "$KC_CONFIG"

containers=()
for client in "${CLIENTS[@]}"; do containers+=("${CLIENT_CONTAINERS[$client]}"); done
ssh "$VPS_HOST" "cd /root/vps && docker compose up -d --force-recreate ${containers[*]}"

exit "$fail"
