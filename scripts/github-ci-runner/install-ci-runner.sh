#!/usr/bin/env bash
# Install a GitHub Actions self-hosted runner on this host, dedicated to
# fast CI feedback on already-trusted code -- NOT the deployment runner
# (scripts referenced from docs/CI-CD.md's "Home deployment" section,
# labels self-hosted/linux/x64/honeypot-home, environment production-home).
# This is a second, separate runner registration with its own labels, own
# sudo-less system user, docker-group access (#2565: containers, the
# frontend lockfile check and the Keycloak/OIDC suites route here), and no
# production-directory/sensor-state access. Its trust boundary is
# different from the deployment runner's: it only ever runs workflows
# gated by the ci-target router (push/workflow_dispatch, plus same-repo
# pull_request when repo variable CI_HOMESERVER_PRS=true -- see
# docs/CI-CD.md's "GitHub CI runner" section for why fork pull_request
# must never be wired to it -- a public repo's fork PRs are
# attacker-controlled input, and self-hosted runner code execution is
# real code execution on this network, not a sandboxed ephemeral VM the
# way GitHub-hosted runners are).
#
# Usage:
#   sudo scripts/github-ci-runner/install-ci-runner.sh --repo Xore/APIARY [--token TOKEN]
#
# --token is a short-lived (1h) registration token. If omitted, this script
# tries to fetch one itself via `gh api` (needs `gh auth login` done for an
# account with admin on the repo) -- convenient for an operator re-running
# this after a token expires, but never required to be long-lived or
# stored anywhere.
#
# --instance N (#2572): registers a SECOND, THIRD, ... independent instance
# on the same box instead of re-touching the primary one. Before this flag
# existed, RUNNER_HOME/RUNNER_USER were fixed constants no matter what
# --name got passed, so a second `--name second-ci` invocation collided
# with the already-registered $RUNNER_HOME/.runner and either no-opped
# (leaving only one instance actually running) or clobbered it -- there was
# no way to actually scale past one executor. Every instance still
# registers under the SAME RUNNER_LABELS (honeypot-ci): GitHub schedules a
# queued job onto whichever instance is idle, so quality.yml's matrix rows
# (each already independent per #2389/#2565) gain real parallelism instead
# of serializing behind one machine. Default instance "1" reuses the
# original /opt/github-ci-runner + github-ci-runner user + "$HOSTNAME-ci"
# name unchanged, so the already-registered instance needs no migration.
set -euo pipefail

RUNNER_VERSION=2.336.0
RUNNER_SHA256=04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d
RUNNER_LABELS="self-hosted,linux,x64,honeypot-ci"

# --- BEGIN instance derivation (config test: tests/test_install_ci_runner_instances.py) ---
# Instance "1" is the original, unsuffixed layout -- anything else gets its
# own home dir and system user so N instances can run side by side without
# fighting over the same _work directory, .runner registration file, or
# systemd unit's working user. Kept between these markers, and pure
# (no filesystem/network touches), so the test can extract and execute
# exactly this argument-parsing + derivation logic in isolation.
repo=""
token=""
name=""
instance="1"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --token) token="$2"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    --instance) instance="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[[ -n "$repo" ]] || { echo "Usage: $0 --repo OWNER/NAME [--token TOKEN] [--name RUNNER_NAME] [--instance N]" >&2; exit 1; }

if [[ -z "$name" ]]; then
  name="${HOSTNAME:-homeserver}-ci"
  [[ "$instance" == "1" ]] || name="${name}-${instance}"
fi
if [[ "$instance" == "1" ]]; then
  RUNNER_USER=github-ci-runner
  RUNNER_HOME=/opt/github-ci-runner
else
  RUNNER_USER="github-ci-runner-${instance}"
  RUNNER_HOME="/opt/github-ci-runner-${instance}"
fi
# --- END instance derivation ---

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

# Only actually needed to register/re-register -- an already-configured
# runner (found $RUNNER_HOME/.runner below) must not fail here just
# because root's own shell has no `gh auth login` of its own.
if [[ -z "$token" && ! -f "$RUNNER_HOME/.runner" ]]; then
  command -v gh >/dev/null 2>&1 || { echo "no --token given and gh is not installed to fetch one" >&2; exit 1; }
  echo "fetching a fresh registration token via gh api..."
  token=$(gh api -X POST "repos/$repo/actions/runners/registration-token" --jq .token)
fi

# Dedicated, unprivileged system user -- no sudo, and no access to
# /var/lib/honeypot-*, /opt/stacks, or any sensor state. Since #2565 it
# DOES carry a docker-group membership (the same grant
# github-deploy-runner always had) because the homeserver-first routing
# sends docker-bound checks here: containers.yml, the frontend lockfile
# check, the Keycloak/oauth2-proxy/OIDC suites, compose validation. The
# trust gate in quality.yml's ci-target router (and the shared
# ci-router.yml) is what makes that acceptable -- only push-to-main,
# workflow_dispatch, and CI_HOMESERVER_PRS'd same-repo pull requests ever
# execute here; fork PRs can never qualify.
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$RUNNER_HOME" --shell /usr/sbin/nologin "$RUNNER_USER"
fi
install -d -m 0755 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_HOME"

# Host provision for the routed checks, kept idempotent so re-running this
# script restores a drifted box. The runner user has no sudo BY DESIGN, so
# every sudo-apt path inside a workflow check would be a guaranteed
# relocation failure -- everything a check needs is preinstalled here
# instead, and checks that would install on a missing dep fail loudly.
#   redis-server: the frontend-next browser fixture spawns its own
#     (daemon disabled -- only the binary is wanted).
#   nodejs/npm: the dashboard OIDC suites run the BFF build against the
#     node 22 the suites pin.
#   the shellcheck binary: the shell-syntax scripts-and-compose row
#     prefers an existing binary and only apt-installs where it was
#     already required. (This comment block is inside that row's scan
#     set: a comment line leading with the word "shellcheck" is parsed
#     as a shellcheck directive, which is why none of these lines
#     starts with it.)
#   chromium libs: playwright's own ubuntu26.04-x64 chromium dependency
#     list, extracted from the playwright-core version pinned by
#     frontend-next/package-lock.json (1.62.1 at the time of writing) --
#     when that pin moves, re-extract the list from the new
#     playwright-core and update here.
apt-get update -qq
apt-get install -y -qq \
  redis-server nodejs npm shellcheck \
  libasound2t64 libatk-bridge2.0-0t64 libatk1.0-0t64 libatspi2.0-0t64 \
  libcairo2 libcups2t64 libdbus-1-3 libdrm2 libgbm1 libglib2.0-0t64 \
  libnspr4 libnss3 libpango-1.0-0 libx11-6 libxcb1 libxcomposite1 \
  libxdamage1 libxext6 libxfixes3 libxkbcommon0 libxrandr2
systemctl disable --now redis-server.service 2>/dev/null || true
if ! id -nG "$RUNNER_USER" | tr ' ' '\n' | grep -qx docker; then
  usermod -aG docker "$RUNNER_USER"
  echo "added $RUNNER_USER to the docker group -- the runner service will be restarted below to pick it up"
fi

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

# #2742: writing and starting a unit is necessary but not sufficient. The
# 2026-08-29 outage was two units -- byte-identical in shape to the ones
# that worked -- that were simply never `enable`d, so they silently vanished
# on the next reboot without a single command failing anywhere along the
# way. `svc.sh install` above already calls `systemctl enable` internally
# and fails loudly if that call itself fails, but nothing previously
# confirmed the enabled state actually stuck, and nothing confirmed
# GitHub's own view of this runner -- a unit can be enabled and running
# locally and still never show up `online` (wrong labels, a stale/duplicate
# registration, a network path that can't reach GitHub). Assert both below
# and fail loudly rather than leaving either silently unknown.
unit_name="$(basename "$service_file")"
if ! systemctl is-enabled --quiet "$unit_name"; then
  echo "FATAL: $unit_name is not enabled after provisioning -- it will not survive a reboot" >&2
  exit 1
fi
echo "confirmed enabled: $unit_name"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  echo "confirming \"$name\" shows online to GitHub (up to 60s)..."
  online=""
  status=""
  for _ in $(seq 1 12); do
    status=$(gh api "repos/$repo/actions/runners" --paginate \
      --jq ".runners[] | select(.name==\"$name\") | .status" 2>/dev/null | tail -1) || status=""
    if [[ "$status" == "online" ]]; then
      online="1"
      break
    fi
    sleep 5
  done
  if [[ -z "$online" ]]; then
    echo "FATAL: \"$name\" did not report status=online to the GitHub API within 60s (last seen: '${status:-none}'). The unit is enabled and running locally but GitHub does not consider this runner available -- check $RUNNER_HOME/_diag for the runner's own connection log." >&2
    exit 1
  fi
  echo "confirmed online: $name"
else
  echo "WARNING: gh is not authenticated -- could not verify \"$name\" shows online to the GitHub API. Verify manually:" >&2
  echo "  gh api repos/$repo/actions/runners --jq '.runners[] | select(.name==\"'\"$name\"'\")'" >&2
fi
