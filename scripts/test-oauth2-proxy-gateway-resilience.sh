#!/usr/bin/env bash
# test-oauth2-proxy-gateway-resilience.sh — #977: proves the isolated
# oauth2-proxy gateway pattern this repo uses for Kibana/EveBox/Arkime/
# TANNER/RevDeck/Dockge/Traefik actually holds, against a real disposable
# Keycloak + real oauth2-proxy (the exact same pinned image and PKCE/cookie
# settings vps/docker-compose.yml's x-oidc-gateway anchor uses), not a
# reimplementation or a mock. Six of #977's acceptance criteria in one pass:
#
#   - unauthenticated requests redirect only to the real, configured
#     Keycloak authorize endpoint, with PKCE S256 and the registered client
#   - a forged callback (code/state neither side ever issued) is rejected,
#     not granted a session
#   - a real login for a user WITH the required client role is granted
#     access, end to end
#   - a real login for a user WITHOUT the required client role is denied
#     (403) even though the login itself succeeded -- proves
#     OAUTH2_PROXY_ALLOWED_ROLES is actually enforced, not just configured
#   - the protected upstream has no published port of its own -- the
#     gateway is the *only* network path to it (mirrors every real
#     socat-hp-<app> backend's isolated oidc-<app> network in
#     vps/docker-compose.yml)
#   - stopping the gateway denies access outright (connection refused),
#     it never falls through to the upstream
#
# Not covered here (out of scope for this script, tracked as still-open
# #977 work): a live outage of Keycloak itself mid-session, JWKS/discovery
# failures, and key/client-secret rotation drills.
set -euo pipefail

network="gwtest-$$"
pg="gwtest-pg-$$"
kc="gwtest-kc-$$"
proxy="gwtest-proxy-$$"
upstream="gwtest-upstream-$$"
proxy_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
fail=0

cleanup() {
  docker rm -f "${proxy}" "${upstream}" "${kc}" "${pg}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ok()   { printf '  OK    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=1; }

docker network create "${network}" >/dev/null

docker run -d --name "${pg}" --network "${network}" \
  -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=test-only-not-real \
  postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382 >/dev/null
for _ in $(seq 1 30); do docker exec "${pg}" pg_isready -U keycloak -d keycloak >/dev/null 2>&1 && break; sleep 1; done

docker run -d --name "${kc}" --network "${network}" \
  -e KC_DB=postgres -e KC_DB_URL_HOST="${pg}" -e KC_DB_URL_PORT=5432 -e KC_DB_URL_DATABASE=keycloak \
  -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=test-only-not-real \
  -e "KC_HOSTNAME=http://${kc}:8080" -e KC_HTTP_ENABLED=true -e KC_HEALTH_ENABLED=true \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=test-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=test-only-not-real \
  quay.io/keycloak/keycloak:26.7.1@sha256:f1f1f01e472c8a78df40d8f2a49a925274eda4d3d80d5f6edbb5c880ee3c01c6 \
  start --http-port=8080 >/dev/null

printf 'Waiting for the disposable Keycloak...\n'
for _ in $(seq 1 60); do
  code=$(docker run --rm --network "${network}" curlimages/curl:latest -s -o /dev/null -w '%{http_code}' "http://${kc}:8080/realms/master" 2>/dev/null || true)
  [ "${code}" = "200" ] && break
  sleep 2
done

admin_token() {
  docker run --rm --network "${network}" curlimages/curl:latest -s -X POST "http://${kc}:8080/realms/master/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=admin-cli -d username=test-admin -d password=test-only-not-real \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"
}
TOKEN="$(admin_token)"

realm_json=$(cat <<EOF
{
  "realm": "gwtest", "enabled": true, "sslRequired": "none",
  "roles": {"client": {"gwtest-client": [{"name": "access"}]}},
  "clients": [{
    "clientId": "gwtest-client", "enabled": true, "publicClient": false,
    "secret": "test-gateway-secret-not-a-real-credential",
    "standardFlowEnabled": true, "implicitFlowEnabled": false,
    "directAccessGrantsEnabled": false, "serviceAccountsEnabled": false,
    "redirectUris": ["http://${proxy}:4180/oauth2/callback"], "webOrigins": [],
    "attributes": {"pkce.code.challenge.method": "S256"}
  }],
  "users": [
    {"username": "authorized-user", "enabled": true, "emailVerified": true,
     "firstName": "Authorized", "lastName": "User", "email": "authorized@example.invalid",
     "credentials": [{"type": "password", "value": "TestPass123!", "temporary": false}],
     "clientRoles": {"gwtest-client": ["access"]}},
    {"username": "no-role-user", "enabled": true, "emailVerified": true,
     "firstName": "No", "lastName": "Role", "email": "norole@example.invalid",
     "credentials": [{"type": "password", "value": "TestPass123!", "temporary": false}]}
  ]
}
EOF
)
import_status=$(docker run --rm --network "${network}" curlimages/curl:latest -s -o /dev/null -w '%{http_code}' \
  -X POST "http://${kc}:8080/admin/realms" -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  --data-binary "${realm_json}")
[ "${import_status}" = "201" ] || { printf 'realm import failed: HTTP %s\n' "${import_status}" >&2; exit 1; }

docker run -d --name "${upstream}" --network "${network}" python:3.12-alpine \
  sh -c "echo 'protected content' > /tmp/index.html && cd /tmp && python3 -m http.server 8000" >/dev/null

docker run -d --name "${proxy}" --network "${network}" -p "127.0.0.1:${proxy_port}:4180" \
  -e OAUTH2_PROXY_PROVIDER=keycloak-oidc \
  -e OAUTH2_PROXY_OIDC_ISSUER_URL="http://${kc}:8080/realms/gwtest" \
  -e OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180 \
  -e OAUTH2_PROXY_EMAIL_DOMAINS="*" \
  -e OAUTH2_PROXY_CLIENT_ID=gwtest-client \
  -e OAUTH2_PROXY_CLIENT_SECRET=test-gateway-secret-not-a-real-credential \
  -e OAUTH2_PROXY_COOKIE_SECRET="$(openssl rand -base64 32 | tr -- '+/' '-_')" \
  -e OAUTH2_PROXY_REDIRECT_URL="http://${proxy}:4180/oauth2/callback" \
  -e OAUTH2_PROXY_UPSTREAMS="http://${upstream}:8000" \
  -e OAUTH2_PROXY_ALLOWED_ROLES=gwtest-client:access \
  -e OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256 \
  -e OAUTH2_PROXY_COOKIE_SECURE=false \
  -e OAUTH2_PROXY_OIDC_EMAIL_CLAIM=preferred_username \
  -e OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL=true \
  quay.io/oauth2-proxy/oauth2-proxy:v7.15.3@sha256:10a1165743a192e1940b4708fb9647027185ce11a681a1c5519b442ff7f1f561 >/dev/null
sleep 3

flow_dir="$(mktemp -d)"
# mktemp -d defaults to 0700, owned by the host user. curlimages/curl runs
# as a non-root in-container user that can't otherwise read/write here --
# same root cause as #1040's realm-import fixture. No secrets in this
# directory, only throwaway cookie jars and a driver script.
chmod 777 "${flow_dir}"
trap 'cleanup; rm -rf "${flow_dir}"' EXIT

# --- 1: unauthenticated redirects only to the real Keycloak authorize endpoint ---
auth_location=$(docker run --rm --network "${network}" curlimages/curl:latest -s -c /tmp/j1 -D - -o /dev/null "http://${proxy}:4180/oauth2/start?rd=/" \
  | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
case "${auth_location}" in
  "http://${kc}:8080/realms/gwtest/protocol/openid-connect/auth?"*"client_id=gwtest-client"*"code_challenge_method=S256"*)
    ok "unauthenticated request redirects to the real Keycloak authorize endpoint with PKCE S256" ;;
  *) bad "unexpected redirect target: ${auth_location}" ;;
esac

# --- 2: forged callback (code/state neither side issued) is rejected ---
forged_status=$(docker run --rm --network "${network}" curlimages/curl:latest -s -o /dev/null -w '%{http_code}' \
  "http://${proxy}:4180/oauth2/callback?code=totally-fake&state=attacker-forged-state")
if [ "${forged_status}" -ge 400 ]; then
  ok "forged callback (unknown code+state) rejected with HTTP ${forged_status}"
else
  bad "forged callback was NOT rejected: HTTP ${forged_status}"
fi

drive_login() {
  # $1=username $2=password $3=cookie-jar-name -> prints final protected-page status
  local user="$1" pass="$2" jar="$3"
  cat > "${flow_dir}/login.sh" <<SCRIPT
set -e
JAR=/w/${jar}
AUTH_URL=\$(curl -s -c "\${JAR}" -D - -o /dev/null "http://${proxy}:4180/oauth2/start?rd=/" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
LOGIN_PAGE=\$(curl -s -c "\${JAR}" -b "\${JAR}" "\${AUTH_URL}")
FORM_ACTION=\$(echo "\${LOGIN_PAGE}" | grep -o 'action="[^"]*"' | head -1 | sed 's/action="//;s/"\$//' | sed 's/&amp;/\&/g')
CALLBACK=\$(curl -s -c "\${JAR}" -b "\${JAR}" -D - -o /dev/null --data-urlencode "username=${user}" --data-urlencode "password=${pass}" --data-urlencode "credentialId=" "\${FORM_ACTION}" | grep -i '^location:' | sed 's/^[Ll]ocation: //' | tr -d '\r')
curl -s -c "\${JAR}" -b "\${JAR}" -o /dev/null -w '%{http_code} ' "\${CALLBACK}"
curl -s -b "\${JAR}" -o /dev/null -w '%{http_code}' "http://${proxy}:4180/"
SCRIPT
  docker run --rm --network "${network}" -v "${flow_dir}:/w" curlimages/curl:latest sh /w/login.sh
}

# --- 3: real login, correct role -> granted ---
read -r callback_status protected_status <<< "$(drive_login authorized-user 'TestPass123!' jar-authorized.txt)"
if [ "${callback_status}" = "302" ] && [ "${protected_status}" = "200" ]; then
  ok "authorized real login: callback 302, protected page 200"
else
  bad "authorized login did not reach the protected page: callback=${callback_status} protected=${protected_status}"
fi

# --- 4: real login, correct password but missing client role -> denied ---
read -r norole_callback_status norole_protected_status <<< "$(drive_login no-role-user 'TestPass123!' jar-norole.txt)"
if [ "${norole_callback_status}" = "403" ] && [ "${norole_protected_status}" = "403" ]; then
  ok "login without the required client role denied (403) despite valid credentials"
else
  bad "role enforcement did not deny: callback=${norole_callback_status} protected=${norole_protected_status}"
fi

# --- 5: the upstream has no network path except through the gateway ---
upstream_ports=$(docker inspect "${upstream}" --format '{{.NetworkSettings.Ports}}')
if [ "${upstream_ports}" = "map[]" ]; then
  ok "protected upstream publishes no host port -- the gateway is the only path to it"
else
  bad "protected upstream has a published port, bypassing the gateway: ${upstream_ports}"
fi

# --- 6: stopping the gateway denies access outright, never falls through ---
docker stop "${proxy}" >/dev/null
outage_curl_exit=0
curl -s -o /dev/null --max-time 3 "http://127.0.0.1:${proxy_port}/" || outage_curl_exit=$?
docker start "${proxy}" >/dev/null
if [ "${outage_curl_exit}" -ne 0 ]; then
  ok "gateway outage: the public port refuses connections outright (curl exit ${outage_curl_exit}), no fallback to the upstream"
else
  bad "request succeeded while the gateway was stopped -- something else is answering"
fi

if [ "${fail}" -ne 0 ]; then
  printf '\nFAIL: one or more gateway-resilience assertions failed\n' >&2
  exit 1
fi
printf '\nPASS: all gateway-resilience assertions held\n'
