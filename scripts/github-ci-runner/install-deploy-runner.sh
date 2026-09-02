#!/usr/bin/env bash
# Install/repair the "honeypot-home" self-hosted GitHub Actions runner --
# docs/CI-CD.md's "Home deployment" section, labels
# self-hosted/linux/x64/honeypot-home, attached to the protected
# production-home environment. Distinct from install-ci-runner.sh in this
# same directory: this runner has real production write access
# (docker.sock, /opt/stacks, /var/dockge/stacks), that one deliberately has
# none.
#
# #1143: before this script existed, docs/CI-CD.md only described what the
# runner's service account needs in prose ("write access to
# /opt/stacks/apiary and permission to run Docker Compose") -- no script
# ever set that up precisely. Re-registering this runner after a Tier 3
# reinstall, an operator improvised `chown -R github-deploy-runner:
# deploy-runner` over every deploy.yml destination= directory, matching its
# own destination list -- but deploy.yml's own rsync into /opt/stacks/apiary
# already excludes state/, dashboard-state/, and logs/ (see the "Preserved
# path" table in docs/CI-CD.md) precisely because those subtrees are
# container-owned, not deploy-runner's. A recursive chown swept them anyway,
# and two real outages followed: Keycloak (state/keycloak/secrets/
# postgres-password needs to stay UID 1000, the container's own internal
# user) and Filebeat (state/filebeat's registry/lock files, similarly
# container-owned). Both fixed live at the time; this script exists so a
# future re-registration has a precise, safe command to run instead of
# reasoning through the exclusion list by hand again.
#
# Usage:
#   sudo scripts/github-ci-runner/install-deploy-runner.sh --repo Xore/APIARY [--token TOKEN]
#
# --token is a short-lived (1h) registration token, same convention as
# install-ci-runner.sh -- omit it to have this script fetch one itself via
# `gh api` (needs `gh auth login` for an account with admin on the repo).
#
# Safe to re-run: every step below is idempotent (skips what already
# exists/is already correct) and the ownership fix specifically is safe to
# run repeatedly or on a partially-provisioned host -- it only ever touches
# the exact directories deploy.yml itself writes into, never anything under
# a state/, dashboard-state/, or logs/ subtree anywhere in that list.
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

RUNNER_VERSION=2.336.0
RUNNER_SHA256=04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d
RUNNER_USER=github-deploy-runner
RUNNER_GROUP=deploy-runner
RUNNER_HOME=/opt/github-deploy-runner
RUNNER_LABELS="self-hosted,linux,x64,honeypot-home"

# The exact set of directories deploy.yml writes into (destination= across
# every job in .github/workflows/deploy.yml, cross-checked against that
# file directly, not re-derived from memory -- if this list ever drifts
# again, re-derive it the same way: grep destination= out of
# .github/workflows/deploy.yml). The honeypot-arcane destination= is
# deliberately NOT listed here, same as every other stack: that job only
# ever `cp`s one compose.yml into an already-`install -d`'d directory,
# never rsyncs a tree into it, so there is no equivalent ownership risk to
# fix there -- adding it would only widen this script's blast radius for
# no real gain. (#2602: this list used to carry six pre-#1502 paths that
# deploy.yml stopped writing to once the Arcane manifest took over; one of
# them, /var/dockge/stacks/honeypot-keycloak, still existed on disk and
# was getting a gratuitous recursive chown every rerun.)
DEPLOY_DIRS=(
  /opt/stacks/apiary
)

# Subtree names that are container-owned wherever they appear under any of
# DEPLOY_DIRS above -- exactly what deploy.yml's own --exclude list already
# protects during rsync (see docs/CI-CD.md's "Preserved path" table).
# find -prune stops descending the moment it matches one of these, so nested
# occurrences (e.g. a per-stack state/ several directories deep) are equally
# protected, not just top-level ones.
STATE_SUBTREE_NAMES=(state dashboard-state logs)

repo=""
token=""
name="${HOSTNAME:-homeserver}-home"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) repo="$2"; shift 2 ;;
    --token) token="$2"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[[ -n "$repo" ]] || { echo "Usage: $0 --repo OWNER/NAME [--token TOKEN] [--name RUNNER_NAME]" >&2; exit 1; }

if [[ -z "$token" && ! -f "$RUNNER_HOME/.runner" ]]; then
  command -v gh >/dev/null 2>&1 || { echo "no --token given and gh is not installed to fetch one" >&2; exit 1; }
  echo "fetching a fresh registration token via gh api..."
  token=$(gh api -X POST "repos/$repo/actions/runners/registration-token" --jq .token)
fi

# System user + its two groups: RUNNER_GROUP (secondary, deploy-runner) and
# RUNNER_USER-as-group (primary, github-deploy-runner). useradd -g below
# requires the primary group to exist (#2288: only RUNNER_GROUP was being
# groupadd'd, so a fresh host aborted at useradd(8) with
# "useradd: group 'github-deploy-runner' does not exist" and a tier-3
# disaster-rebuild hit it). Both groups are created here on a genuinely
# new host; previously-provisioned hosts get past the getent guards and
# proceed straight to useradd.
if ! getent group "$RUNNER_GROUP" >/dev/null; then
  groupadd --system "$RUNNER_GROUP"
fi
if ! getent group "$RUNNER_USER" >/dev/null; then
  groupadd --system "$RUNNER_USER"
fi
if ! id "$RUNNER_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$RUNNER_HOME" --shell /usr/sbin/nologin \
    -g "$RUNNER_USER" -G "docker,$RUNNER_GROUP" "$RUNNER_USER"
else
  usermod -aG "docker,$RUNNER_GROUP" "$RUNNER_USER"
fi

# #2778: scripts/isolation-audit.sh (deployed under /opt/stacks/apiary,
# run by Diagnostics' "Isolation invariants (#88)" step against this
# runner) needs read access to libvirt (virsh net-info/net-dumpxml,
# nwfilter-dumpxml) and NOPASSWD root for exactly the read-only host
# commands it cannot reach any other way (iptables -S FORWARD, ss -tlnp,
# aa-status). Plain `docker ps`/`docker inspect`/`docker network inspect`
# are already covered by docker-group membership above and the script no
# longer routes those through sudo. Nothing here is broader than the
# audit script's own use, and nothing here touches github-ci-runner --
# that pool's trust boundary is #2780's decision, not this one's.
if getent group libvirt >/dev/null; then
  usermod -aG libvirt "$RUNNER_USER"
else
  echo "warning: no 'libvirt' group on this host -- isolation-audit.sh's virsh checks will keep reporting permission errors for $RUNNER_USER" >&2
fi

sudoers_file=/etc/sudoers.d/isolation-audit-github-deploy-runner
sudoers_tmp=$(mktemp)
cat > "$sudoers_tmp" <<EOF
# Managed by scripts/github-ci-runner/install-deploy-runner.sh (#2778).
# Read-only commands scripts/isolation-audit.sh needs and cannot reach via
# docker-group membership or libvirt-group membership alone. Do not widen
# past exactly these three invocations.
$RUNNER_USER ALL=(root) NOPASSWD: /usr/sbin/iptables -S FORWARD
$RUNNER_USER ALL=(root) NOPASSWD: /usr/bin/ss -tlnp
$RUNNER_USER ALL=(root) NOPASSWD: /usr/sbin/aa-status
EOF
if visudo -cf "$sudoers_tmp" >/dev/null 2>&1; then
  install -m 0440 -o root -g root "$sudoers_tmp" "$sudoers_file"
  echo "installed $sudoers_file"
else
  echo "error: generated sudoers fragment failed visudo -cf, not installing $sudoers_file" >&2
  visudo -cf "$sudoers_tmp" >&2 || true
  rm -f "$sudoers_tmp"
  exit 1
fi
rm -f "$sudoers_tmp"

# --- #1143: precisely scoped ownership fix, the actual replacement for the
# broad manual chown that caused this issue. ---
for dir in "${DEPLOY_DIRS[@]}"; do
  [[ -d "$dir" ]] || { echo "skip (does not exist yet): $dir"; continue; }
  prune_args=()
  for name_pattern in "${STATE_SUBTREE_NAMES[@]}"; do
    prune_args+=(-o -name "$name_pattern" -prune)
  done
  # The first -false primes the -o chain so every real prune clause is
  # genuinely "-o"'d together rather than the first one silently acting as
  # the whole expression's start. -print0 only reaches paths that survived
  # every -prune above.
  find "$dir" \( -false "${prune_args[@]}" \) -o -print0 \
    | xargs -0 -r chown "$RUNNER_USER:$RUNNER_GROUP"
  echo "ownership fixed (state/dashboard-state/logs excluded): $dir"
done

# --- Runner binary + registration, same shape as install-ci-runner.sh ---
install -d -m 0755 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_HOME"

if [[ ! -f "$RUNNER_HOME/run.sh" ]]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL -o "$tmp/runner.tar.gz" \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
  echo "${RUNNER_SHA256}  $tmp/runner.tar.gz" | sha256sum -c -
  tar -xzf "$tmp/runner.tar.gz" -C "$RUNNER_HOME"
  chown "$RUNNER_USER:$RUNNER_USER" "$RUNNER_HOME"
  find "$RUNNER_HOME" -maxdepth 1 -mindepth 1 -exec chown -R "$RUNNER_USER:$RUNNER_USER" {} +
  echo "extracted actions-runner v${RUNNER_VERSION} to $RUNNER_HOME"
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

# #2749: same hardening #2742 added to install-ci-runner.sh, ported here --
# this runner has real production write access, so a silently-never-enabled
# unit (the 2026-08-29 outage shape: `svc.sh install` succeeds, nothing else
# ever confirms it stuck) is at least as bad here as on the CI fleet. Assert
# both the local systemd state and GitHub's own view of the runner, and fail
# loudly rather than leaving either silently unknown.
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
