#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
stack_dir="${KEYCLOAK_STACK_DIR:-$(cd -- "${script_dir}/.." && pwd)}"
env_file="${KEYCLOAK_ENV_FILE:-${stack_dir}/.env}"
compose_file="${KEYCLOAK_COMPOSE_FILE:-${stack_dir}/compose.yml}"
snapshot="${1:-latest}"

if [[ "${KEYCLOAK_RESTORE_CONFIRM:-}" != "restore-keycloak-database" ]]; then
  printf '%s\n' 'Refusing destructive restore.' >&2
  printf '%s\n' 'Set KEYCLOAK_RESTORE_CONFIRM=restore-keycloak-database and retry.' >&2
  exit 1
fi

[[ -f "${env_file}" ]] || { printf 'Missing environment file: %s\n' "${env_file}" >&2; exit 1; }
set -a
# shellcheck disable=SC1090
source "${env_file}"
set +a

: "${RESTIC_REPOSITORY:?set RESTIC_REPOSITORY in the Dockge environment file}"
: "${RESTIC_PASSWORD_FILE:?set RESTIC_PASSWORD_FILE in the Dockge environment file}"
command -v docker >/dev/null || { printf 'docker is required\n' >&2; exit 1; }
command -v restic >/dev/null || { printf 'restic is required\n' >&2; exit 1; }

export RESTIC_REPOSITORY RESTIC_PASSWORD_FILE
docker compose --env-file "${env_file}" -f "${compose_file}" stop keycloak
restic dump "${snapshot}" keycloak.dump \
  | docker compose --env-file "${env_file}" -f "${compose_file}" exec -T postgres \
      pg_restore --username=keycloak --dbname=keycloak --clean --if-exists \
        --no-owner --single-transaction
docker compose --env-file "${env_file}" -f "${compose_file}" start keycloak
