#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
realm_file="${script_dir}/apiary-realm.json"

command -v jq >/dev/null || { printf 'jq is required\n' >&2; exit 1; }

jq -e '
  .realm == "apiary" and
  .enabled == true and
  .registrationAllowed == false and
  .verifyEmail == true and
  .loginTheme == "apiary" and
  .rememberMe == false and
  .bruteForceProtected == true and
  .ssoSessionIdleTimeout == 3600 and
  .ssoSessionMaxLifespan == 43200 and
  ([.requiredActions[] | select(.alias == "CONFIGURE_TOTP" and .enabled and .defaultAction)] | length == 1) and
  ([.clients[].clientId] | sort == ["apiary-dashboard", "arkime", "dockge", "evebox", "kibana", "revdeck", "tanner", "traefik-dashboard"]) and
  (all(.clients[];
    .publicClient == false and
    .standardFlowEnabled == true and
    .implicitFlowEnabled == false and
    .directAccessGrantsEnabled == false and
    .serviceAccountsEnabled == false and
    .attributes["pkce.code.challenge.method"] == "S256" and
    (.redirectUris | length == 1) and
    (.redirectUris[0] | startswith("https://")) and
    (.redirectUris[0] | contains("*") | not) and
    (.webOrigins | length == 1) and
    (.webOrigins[0] | startswith("https://")) and
    (.webOrigins[0] | contains("*") | not)
  )) and
  (has("users") | not) and
  ([paths | .[-1] | tostring | ascii_downcase |
    select(. == "secret" or . == "credentials")] | length == 0)
' "${realm_file}" >/dev/null

if jq -e '.. | strings | select(test("localhost|127\\.0\\.0\\.1|http://"))' "${realm_file}" >/dev/null; then
  printf 'Realm contains a development or plaintext URL\n' >&2
  exit 1
fi

printf 'Realm static validation passed: %s\n' "${realm_file}"
