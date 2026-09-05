#!/usr/bin/env bash
# Single entry point for APIARY host provisioning -- #1609 Phase 5.
#
#   sudo ./scripts/install.sh --profile home [--config <file>] [installer flags...]
#   sudo ./scripts/install.sh --profile vps  [--config <file>] [installer flags...]
#
# There are exactly two profiles, and there will not be a third: "configurable"
# here means the two real hosts' defaults are explicit and consistent, not that
# this supports a hypothetical deployment shape (#1609's Non-goals).
#
# What it does: picks the right installer, and supplies the default answers
# file for that profile when --config is not given. Everything else is passed
# through untouched -- --force-rerun-from, --reset-markers, --install-self and
# --help all behave exactly as they do on the installer itself, because it is
# the installer that handles them.
#
# Why a dispatcher rather than one merged script: the two installers share
# their retry/step/logging framework (scripts/lib/install-common.sh) but not
# their step lists, which have almost nothing in common -- the homeserver runs
# GPU/libvirt/Arcane/38 stacks, the VPS runs a firewall, portbridge, Traefik
# and Suricata. Merging the bodies would produce one file that is two files
# with an `if` around each half.
#
# Default answers files: /etc/apiary/install-<profile>.conf, which is where an
# operator's filled-in copy belongs -- it holds real keys and hostnames and
# must stay out of the checkout. Copy scripts/install-<profile>.conf.example
# there and fill in every <PLACEHOLDER>.

set -uo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
DEFAULT_CONF_DIR="/etc/apiary"

usage() {
  cat <<EOF
Usage: sudo $0 --profile home|vps [--config <answers.conf>] [installer flags...]

Profiles:
  home   scripts/install-homeserver.sh   default config: $DEFAULT_CONF_DIR/install-home.conf
  vps    scripts/install-vps.sh          default config: $DEFAULT_CONF_DIR/install-vps.conf

Flags after the profile are passed through to the installer unchanged
(--force-rerun-from <step-id>, --reset-markers, --install-self, --help).

Bootstrap order for a genuinely fresh pair of hosts: run --profile vps first,
feed the WireGuard public key it prints into the home answers file's
VPS_WG_PUBLIC_KEY, then run --profile home.
EOF
}

PROFILE=""
CONFIG=""
PASSTHROUGH=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --config)  CONFIG="${2:-}"; shift 2 ;;
    -h|--help)
      # Only ours if no profile has been named yet; once one has, the
      # installer's own --help is the more useful answer.
      if [[ -z "$PROFILE" ]]; then usage; exit 0; fi
      PASSTHROUGH+=("$1"); shift ;;
    *) PASSTHROUGH+=("$1"); shift ;;
  esac
done

case "$PROFILE" in
  home) INSTALLER="$SCRIPT_DIR/install-homeserver.sh"; DEFAULT_CONF="$DEFAULT_CONF_DIR/install-home.conf" ;;
  vps)  INSTALLER="$SCRIPT_DIR/install-vps.sh";        DEFAULT_CONF="$DEFAULT_CONF_DIR/install-vps.conf" ;;
  "")   echo "--profile is required (home or vps)." >&2; usage >&2; exit 2 ;;
  *)    echo "Unknown profile: $PROFILE (expected home or vps)." >&2; exit 2 ;;
esac

if [[ ! -x "$INSTALLER" ]]; then
  echo "Installer not found or not executable: $INSTALLER" >&2
  exit 2
fi

# --install-self and --help never need an answers file; don't demand one.
NEEDS_CONFIG=1
# bash 4.4+ treats an empty array under `set -u` as empty, not unset; the
# `${a[@]:-}` workaround would pass a literal empty argument through and the
# installer would reject it as an unknown flag.
for arg in "${PASSTHROUGH[@]}"; do
  case "$arg" in
    --install-self|-h|--help) NEEDS_CONFIG=0 ;;
  esac
done

ARGS=()
if [[ $NEEDS_CONFIG -eq 1 ]]; then
  if [[ -z "$CONFIG" ]]; then
    CONFIG="$DEFAULT_CONF"
    if [[ ! -f "$CONFIG" ]]; then
      echo "No --config given and the default for profile '$PROFILE' does not exist:" >&2
      echo "  $CONFIG" >&2
      echo "Copy scripts/install-${PROFILE/home/homeserver}.conf.example there, fill in every" >&2
      echo "<PLACEHOLDER>, and keep it out of version control." >&2
      exit 1
    fi
    echo "Using default answers file for profile '$PROFILE': $CONFIG"
  fi
  ARGS+=(--config "$CONFIG")
fi

exec "$INSTALLER" "${ARGS[@]}" "${PASSTHROUGH[@]}"
