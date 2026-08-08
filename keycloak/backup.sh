#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
stack_dir="${KEYCLOAK_STACK_DIR:-$(cd -- "${script_dir}/.." && pwd)}"
env_file="${KEYCLOAK_ENV_FILE:-${stack_dir}/.env}"
compose_file="${KEYCLOAK_COMPOSE_FILE:-${stack_dir}/compose.yml}"

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
export RESTIC_HOST="${RESTIC_HOST:-apiary-homeserver}"

docker compose --env-file "${env_file}" -f "${compose_file}" exec -T postgres \
  pg_dump --username=keycloak --dbname=keycloak --format=custom --no-owner \
  | restic backup --stdin --stdin-filename keycloak.dump \
      --host "${RESTIC_HOST}" --tag keycloak-postgres

restic forget --tag keycloak-postgres \
  --keep-daily "${BACKUP_KEEP_DAILY:-7}" \
  --keep-weekly "${BACKUP_KEEP_WEEKLY:-4}" --prune
restic check --read-data-subset="${RESTIC_CHECK_SUBSET:-5%}"
