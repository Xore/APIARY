#!/usr/bin/env bash
# test-keycloak-realm-import.sh — boots an ephemeral, disposable
# Keycloak + PostgreSQL and imports keycloak/realm/apiary-realm.json through
# the exact bootstrap path docker-compose.keycloak.yml uses on every real
# fresh install (`kc.sh start --import-realm`), then asserts it actually
# succeeds.
#
# #982 phase 1 / #1040: keycloak/realm/validate.sh's jq checks are static --
# they check structure and policy, never what a real Keycloak+Postgres
# import does with the file. That gap let a 263-char role description (over
# Postgres's KEYCLOAK_ROLE.DESCRIPTION varchar(255) column) crash-loop the
# container on any genuinely fresh install, undetected until this script's
# manual precursor caught it live. This is the regression test for that
# class of bug -- it does not exercise login, roles, or client behavior
# (that's the rest of #982), only "does the realm this repo ships actually
# import into a real Keycloak."
#
# Uses no docker-compose.keycloak.yml secrets/volumes -- this is a
# throwaway topology (plain `docker run`, ephemeral network, ephemeral
# ports, ephemeral admin credentials), never real production Keycloak.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
realm_file="${repo_root}/keycloak/realm/apiary-realm.json"

command -v docker >/dev/null || { printf 'docker is required\n' >&2; exit 1; }

network="kctest-import-$$"
pg="kctest-import-pg-$$"
kc="kctest-import-kc-$$"
kc_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
rendered_realm="$(mktemp)"

cleanup() {
  docker rm -f "${kc}" "${pg}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
  rm -f "${rendered_realm}"
}
trap cleanup EXIT

# Test-only substitution, never applied to the checked-in file: the real
# realm's redirect URIs are all https://<subdomain>.example.invalid/... --
# this fixture has no TLS termination in front of it (unlike the real
# deployment, where VPS Traefik always terminates TLS before Keycloak ever
# sees a request), so every subdomain collapses onto one plain-http
# 127.0.0.1:<port> origin. Fine here: this script only proves the *import*
# succeeds, it never drives a login through these URLs.
sed -E "s|https://[a-zA-Z0-9.-]*\\.example\\.invalid|http://127.0.0.1:${kc_port}|g" \
  "${realm_file}" > "${rendered_realm}"

docker network create "${network}" >/dev/null

docker run -d --name "${pg}" --network "${network}" \
  -e POSTGRES_DB=keycloak -e POSTGRES_USER=keycloak -e POSTGRES_PASSWORD=test-only-not-real \
  postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382 >/dev/null

for _ in $(seq 1 30); do
  docker exec "${pg}" pg_isready -U keycloak -d keycloak >/dev/null 2>&1 && break
  sleep 1
done

docker run -d --name "${kc}" --network "${network}" -p "127.0.0.1:${kc_port}:8080" \
  -e KC_DB=postgres -e KC_DB_URL_HOST="${pg}" -e KC_DB_URL_PORT=5432 -e KC_DB_URL_DATABASE=keycloak \
  -e KC_DB_USERNAME=keycloak -e KC_DB_PASSWORD=test-only-not-real \
  -e "KC_HOSTNAME=http://127.0.0.1:${kc_port}" -e KC_HTTP_ENABLED=true -e KC_HEALTH_ENABLED=true \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=test-admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=test-only-not-real \
  -v "${rendered_realm}:/opt/keycloak/data/import/apiary-realm.json:ro" \
  quay.io/keycloak/keycloak:26.7.1@sha256:f1f1f01e472c8a78df40d8f2a49a925274eda4d3d80d5f6edbb5c880ee3c01c6 \
  start --http-port=8080 --import-realm >/dev/null

printf 'Waiting for realm import against a real Postgres (up to 90s)...\n'
for i in $(seq 1 90); do
  if docker logs "${kc}" 2>&1 | grep -q "KC-SERVICES0032: Import finished successfully"; then
    printf 'PASS: apiary-realm.json imported cleanly\n'
    exit 0
  fi
  if docker logs "${kc}" 2>&1 | grep -q "ERROR: Failed to start server"; then
    printf 'FAIL: realm import crashed the server -- log follows\n' >&2
    docker logs "${kc}" 2>&1 | tail -60 >&2
    exit 1
  fi
  sleep 1
  if [[ "$i" -eq 90 ]]; then
    printf 'FAIL: timed out waiting for import to finish -- log follows\n' >&2
    docker logs "${kc}" 2>&1 | tail -60 >&2
    exit 1
  fi
done
