#!/usr/bin/env bash
# Install a GitHub Actions self-hosted runner on this host, dedicated to
# fast CI feedback on already-trusted code -- NOT the deployment runner
# (scripts referenced from docs/CI-CD.md's "Home deployment" section,
# labels self-hosted/linux/x64/honeypot-home, environment production-home).
# This is a second, separate runner registration with its own labels, own
# unprivileged system user, and no Docker-socket/production-directory
# access, because its trust boundary is different: it only ever runs
# workflows gated to push/workflow_dispatch (see docs/CI-CD.md's "GitHub CI
# runner" section for why pull_request must never be wired to it -- a
# public repo's fork PRs are attacker-controlled input, and self-hosted
# runner code execution is real code execution on this network, not a
# sandboxed ephemeral VM the way GitHub-hosted runners are).
#
# Usage:
#   sudo scripts/github-ci-runner/install-ci-runner.sh --repo Xore/APIARY [--token TOKEN]
#
# --token is a short-lived (1h) registration token. If omitted, this script
# tries to fetch one itself via `gh api` (needs `gh auth login` done for an
# account with admin on the repo) -- convenient for an operator re-running
# this after a token expires, but never required to be long-lived or
# stored anywhere.
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

RUNNER_VERSION=2.336.0
RUNNER_SHA256=04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d
RUNNER_USER=github-ci-runner
RUNNER_HOME=/opt/github-ci-runner
RUNNER_LABELS="self-hosted,linux,x64,honeypot-ci"

repo=""
token=""
name="${HOSTNAME:-homeserver}-ci"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --token) token="$2"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[[ -n "$repo" ]] || { echo "Usage: $0 --repo OWNER/NAME [--token TOKEN] [--name RUNNER_NAME]" >&2; exit 1; }

# Only actually needed to register/re-register -- an already-configured
# runner (found $RUNNER_HOME/.runner below) must not fail here just
# because root's own shell has no `gh auth login` of its own.
if [[ -z "$token" && ! -f "$RUNNER_HOME/.runner" ]]; then
  command -v gh >/dev/null 2>&1 || { echo "no --token given and gh is not installed to fetch one" >&2; exit 1; }
  echo "fetching a fresh registration token via gh api..."
  token=$(gh api -X POST "repos/$repo/actions/runners/registration-token" --jq .token)
fi

# Dedicated, unprivileged system user -- deliberately NOT in the docker
# group and with no access to /var/lib/honeypot-*, /opt/stacks, or any
# sensor state. A workflow running here needs a language toolchain
# (go/python3/node/shellcheck), never host-level access.
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$RUNNER_HOME" --shell /usr/sbin/nologin "$RUNNER_USER"
fi
install -d -m 0755 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_HOME"

if [[ ! -f "$RUNNER_HOME/run.sh" ]]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL -o "$tmp/runner.tar.gz" \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
  echo "${RUNNER_SHA256}  $tmp/runner.tar.gz" | sha256sum -c -
  tar -xzf "$tmp/runner.tar.gz" -C "$RUNNER_HOME"
  chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_HOME"
  echo "extracted actions-runner v${RUNNER_VERSION} to $RUNNER_HOME"
  # The runner's .NET job-worker process needs libicu/openssl versions the
  # base OS may not have -- confirmed live: without this, the extracted
  # runner starts and connects fine (the listener is Node-based) but the
  # actual job-execution worker is missing libcoreclr.so and friends.
  "$RUNNER_HOME/bin/installdependencies.sh"
else
  echo "runner already extracted at $RUNNER_HOME, skipping download"
fi

if [[ ! -f "$RUNNER_HOME/.runner" ]]; then
  sudo -u "$RUNNER_USER" "$RUNNER_HOME/config.sh" \
    --url "https://github.com/$repo" \
    --token "$token" \
    --name "$name" \
    --labels "$RUNNER_LABELS" \
    --work "_work" \
    --unattended \
    --replace
else
  echo "runner already configured (found $RUNNER_HOME/.runner) -- not re-registering"
  echo "to re-register (e.g. after moving hosts), remove $RUNNER_HOME/.runner first"
fi

# The runner's own svc.sh wraps systemd unit creation -- installing that
# way rather than hand-writing a unit keeps it in sync with whatever this
# specific runner version's own supported service shape is. Not idempotent
# on its own (errors if the unit file already exists), so only install
# once; restart rather than reinstall on a later re-run of this script.
cd "$RUNNER_HOME"
service_file="/etc/systemd/system/actions.runner.$(tr '/' '-' <<<"$repo").$name.service"
if [[ ! -f "$service_file" ]]; then
  ./svc.sh install "$RUNNER_USER"
  ./svc.sh start
else
  ./svc.sh stop || true
  ./svc.sh start
fi

echo "done. status:"
./svc.sh status
