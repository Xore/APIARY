#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
realm_file="${script_dir}/apiary-realm.json"

command -v jq >/dev/null || { printf 'jq is required\n' >&2; exit 1; }

# verifyEmail: false and no VERIFY_EMAIL default action -- no SMTP is
# configured for this realm, and mandatory 2FA is TOTP/WebAuthn, not an
# emailed code or link. Caught live: a real admin-created account had no
# email set, then got one added later -- Keycloak's realm-level
# verifyEmail flag auto-queued VERIFY_EMAIL on the account regardless of
# the required-action's own defaultAction setting, and login broke
# outright trying (and failing) to send a verification email.
jq -e '
  .realm == "apiary" and
  .enabled == true and
  .registrationAllowed == false and
  .verifyEmail == false and
  .loginTheme == "apiary" and
  .rememberMe == false and
  .bruteForceProtected == true and
  .ssoSessionIdleTimeout == 3600 and
  .ssoSessionMaxLifespan == 43200 and
  ([.requiredActions[] | select(.alias == "CONFIGURE_TOTP" and .enabled and .defaultAction)] | length == 1) and
  ([.requiredActions[] | select(.alias == "VERIFY_EMAIL" and .defaultAction)] | length == 0) and
  ([.clients[].clientId] | sort == ["apiary-dashboard", "arkime", "dockge", "evebox", "kibana", "revdeck", "tanner", "traefik-dashboard"]) and
  (all(.clients[];
    .publicClient == false and
    .standardFlowEnabled == true and
    .implicitFlowEnabled == false and
    .directAccessGrantsEnabled == false and
    .serviceAccountsEnabled == false and
    .attributes["pkce.code.challenge.method"] == "S256" and
    (if .clientId == "apiary-dashboard" then (.redirectUris | length == 2) else (.redirectUris | length == 1) end) and
    (all(.redirectUris[]; startswith("https://") and (contains("*") | not))) and
    (.webOrigins | length == 1) and
    (all(.webOrigins[]; startswith("https://") and (contains("*") | not)))
  )) and
  (has("users") | not) and
  ([paths | .[-1] | tostring | ascii_downcase |
    select(. == "secret" or . == "credentials")] | length == 0)
' "${realm_file}" >/dev/null

if jq -e '.. | strings | select(test("localhost|127\\.0\\.0\\.1|http://"))' "${realm_file}" >/dev/null; then
  printf 'Realm contains a development or plaintext URL\n' >&2
  exit 1
fi

# Keycloak's KEYCLOAK_ROLE table stores name/description in
# character varying(255) columns. jq's own static checks above never
# caught this -- confirmed live against a real Postgres: a 263-char role
# description made the real `kc.sh start --import-realm` bootstrap path
# (the same one docker-compose.keycloak.yml uses on every fresh install)
# fail its batch update and crash-loop the container outright.
if jq -e '
  [(.roles.realm // [])[], (.roles.client // {} | to_entries[] | .value[])] |
  any(.name != null and (.name | length) > 255 or (.description != null and (.description | length) > 255))
' "${realm_file}" >/dev/null; then
  printf 'A realm or client role name/description exceeds Keycloak schema'"'"'s 255-character limit\n' >&2
  exit 1
fi

printf 'Realm static validation passed: %s\n' "${realm_file}"
