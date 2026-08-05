#!/usr/bin/env bash
# Unattended homeserver provisioning for honeypot-stack — the Ubuntu-side
# equivalent of a Windows autounattend.xml. This is the single entry point
# described in issue #518; it covers everything smoke-test-verified so far
# (see docs/research/518-smoke-test-research.md) and is expected to grow.
#
# Scope: this script provisions a MANUALLY installed base Ubuntu Server
# system into a running honeypot-stack homeserver (Docker, NVIDIA/GPU
# stack, Dockge, WireGuard, the repo checkout, secret restore, and starting
# the Compose stacks in dependency order). It does NOT partition disks or
# install the OS itself — that's docs/autoinstall/homeserver-user-data.yaml,
# run once, separately, before this script ever sees the box.
#
# Design goals (per #518): a single entry point, live status as it runs,
# a clear non-fatal-by-default failure report at the end so a partial run
# can be diagnosed and re-run, resumability (already-completed steps are
# skipped on re-run via markers under $MARKER_DIR), and retries for
# network-flaky steps (apt, git, rsync, docker pull) rather than a hard
# failure on the first transient blip.
#
# Usage:
#   sudo ./scripts/install-homeserver.sh --config /path/to/answers.conf
#   sudo ./scripts/install-homeserver.sh --config answers.conf --force-rerun-from docker-install
#   sudo ./scripts/install-homeserver.sh --config answers.conf --reset-markers   # ignore all markers, redo everything
#
# The answers file follows scripts/install-homeserver.conf.example --
# copy it, fill in every <PLACEHOLDER>, keep the filled-in copy OUT of
# version control (it will contain real IPs, keys, and a real git remote).

set -uo pipefail

# ---------------------------------------------------------------------------
# Status tracking / resumability — every phase reports through run_step so
# one failure doesn't abort the whole run; everything attempted gets
# recorded and printed in a final summary. Steps that already succeeded on a
# prior run (a marker file exists under $MARKER_DIR) are skipped unless
# --reset-markers or --force-rerun-from <step-id> is passed.
# ---------------------------------------------------------------------------
declare -A STEP_STATUS
declare -a STEP_ORDER
LOG_DIR="/var/log/honeypot-install"
MARKER_DIR="/var/lib/honeypot-install/markers"
RUN_LOG=""
FORCE_FROM=""
RESET_MARKERS=0
FORCE_ACTIVE=0

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*"; }

# with_retry <max_attempts> <sleep_base_seconds> -- cmd args...
# Retries transient (network/pull) failures with linear backoff. Does NOT
# swallow the final failure -- after the last attempt, the real exit code
# propagates so run_step still records FAILED correctly.
with_retry() {
  local max="$1" base="$2"; shift 2
  local attempt=1 rc=0
  while (( attempt <= max )); do
    if "$@"; then
      return 0
    fi
    rc=$?
    if (( attempt == max )); then
      return "$rc"
    fi
    local wait=$(( base * attempt ))
    echo "attempt $attempt/$max failed (exit $rc), retrying in ${wait}s: $*" >&2
    sleep "$wait"
    attempt=$(( attempt + 1 ))
  done
  return "$rc"
}

run_step() {
  local id="$1" desc="$2"
  shift 2
  STEP_ORDER+=("$id")

  # --force-rerun-from <id> reruns that step and every step after it, even
  # if markers exist -- must activate BEFORE the marker skip-check below, or
  # the named step itself (and everything after it) still gets skipped on
  # its own marker. Confirmed live (#518 test run 2): passing
  # --force-rerun-from shared-resources still skipped shared-resources
  # itself plus every step after it, because FORCE_ACTIVE was being set
  # only *after* run_step had already returned early.
  if [[ -n "$FORCE_FROM" && "$id" == "$FORCE_FROM" ]]; then
    FORCE_ACTIVE=1
  fi

  local marker="$MARKER_DIR/$id.done"
  if [[ $RESET_MARKERS -eq 0 && -f "$marker" && "$FORCE_ACTIVE" -eq 0 ]]; then
    STEP_STATUS["$id"]="SKIPPED (already done — marker $marker)"
    log "==> [$id] $desc — SKIPPED (marker present)"
    return 0
  fi

  log "==> [$id] $desc"
  if "$@" >>"$RUN_LOG" 2>&1; then
    STEP_STATUS["$id"]="OK"
    log "    [$id] OK"
    mkdir -p "$MARKER_DIR"
    date -Iseconds > "$marker"
  else
    local rc=$?
    STEP_STATUS["$id"]="FAILED (exit $rc)"
    log "    [$id] FAILED (exit $rc) — see $RUN_LOG"
  fi
}

skip_step() {
  local id="$1" desc="$2" reason="$3"
  STEP_ORDER+=("$id")
  STEP_STATUS["$id"]="SKIPPED ($reason)"
  log "==> [$id] $desc — SKIPPED ($reason)"
}

print_summary() {
  echo
  echo "==================== install-homeserver.sh summary ===================="
  local failed=0
  for id in "${STEP_ORDER[@]}"; do
    local status="${STEP_STATUS[$id]}"
    printf '  %-36s %s\n' "$id" "$status"
    [[ "$status" == FAILED* ]] && failed=1
  done
  echo "=========================================================================="
  echo "Full log: $RUN_LOG"
  if [[ $failed -eq 1 ]]; then
    echo "One or more steps FAILED. Fix the underlying issue and re-run this"
    echo "script — completed steps are skipped via markers under $MARKER_DIR,"
    echo "so re-running only retries what actually failed. Use"
    echo "--force-rerun-from <step-id> to redo a step whose marker exists but"
    echo "whose result you don't trust."
    return 1
  fi
  echo "All steps completed."
  return 0
}

# ---------------------------------------------------------------------------
# Args / config
# ---------------------------------------------------------------------------
CONFIG_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG_FILE="$2"; shift 2 ;;
    --force-rerun-from) FORCE_FROM="$2"; shift 2 ;;
    --reset-markers) RESET_MARKERS=1; shift ;;
    -h|--help)
      echo "Usage: sudo $0 --config /path/to/answers.conf [--force-rerun-from <step-id>] [--reset-markers]"
      echo "See scripts/install-homeserver.conf.example for the template."
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0 --config <file>" >&2
  exit 1
fi

if [[ -z "$CONFIG_FILE" || ! -f "$CONFIG_FILE" ]]; then
  echo "Missing or unreadable --config file." >&2
  echo "Copy scripts/install-homeserver.conf.example, fill in every" >&2
  echo "<PLACEHOLDER>, and pass it with --config." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

for var in INSTALL_HOSTNAME GIT_REPO_URL REPO_DIR HOME_WG_ADDRESS \
           VPS_WG_ADDRESS VPS_WG_ENDPOINT VPS_WG_PUBLIC_KEY \
           VPS_SSH_HOST VPS_SSH_PORT VPS_SSH_USER VPS_SSH_KEY ENABLE_GPU_STACK \
           INSTALL_TIMEZONE BACKUP_HOST BACKUP_HOST_USER BACKUP_HOST_KEY BACKUP_HOST_PATH \
           PIHOLE_LAN_IP ENABLE_SANDBOX_RESTORE; do
  if [[ -z "${!var:-}" || "${!var}" == *'<'*'>'* ]]; then
    echo "Config value $var is unset or still a <PLACEHOLDER> in $CONFIG_FILE." >&2
    echo "Fill in every field before running unattended." >&2
    exit 1
  fi
done
# HOME_WG_PRIVATE_KEY is intentionally allowed to be empty/absent — if the
# original tunnel private key wasn't part of the backup (it wasn't captured
# by the .env-only backup pass, see #518 comment history), step_wireguard_config
# generates a fresh keypair and step_wireguard_sync_vps_peer pushes the new
# public key to the VPS side automatically.

# BACKUP_HOST_SANDBOX_PATH is only needed when ENABLE_SANDBOX_RESTORE=true --
# don't force every user to fill it in just to skip a 170G+ optional restore.
if [[ "$ENABLE_SANDBOX_RESTORE" == "true" ]]; then
  if [[ -z "${BACKUP_HOST_SANDBOX_PATH:-}" || "${BACKUP_HOST_SANDBOX_PATH}" == *'<'*'>'* ]]; then
    echo "ENABLE_SANDBOX_RESTORE=true but BACKUP_HOST_SANDBOX_PATH is unset or still a <PLACEHOLDER>." >&2
    exit 1
  fi
fi

mkdir -p "$LOG_DIR" "$MARKER_DIR"
RUN_LOG="$LOG_DIR/install-$(date +%Y%m%dT%H%M%SZ).log"
: >"$RUN_LOG"

# ---------------------------------------------------------------------------
# Phase 0 — preflight
# ---------------------------------------------------------------------------
step_preflight_os() {
  . /etc/os-release
  [[ "$ID" == "ubuntu" ]] || { echo "Not Ubuntu ($ID)" >&2; return 1; }
}

step_preflight_disks() {
  # Non-fatal check: warn (in the log) if the layout from
  # docs/HOMESERVER-DISK-LAYOUT.md isn't present, but don't block —
  # a second build server may legitimately use a different layout.
  for mnt in /var; do
    mountpoint -q "$mnt" || echo "WARNING: $mnt is not a separate mount — see docs/HOMESERVER-DISK-LAYOUT.md"
  done
  return 0
}

step_set_hostname() {
  hostnamectl set-hostname "$INSTALL_HOSTNAME"
  timedatectl set-timezone "$INSTALL_TIMEZONE"
}

# ---------------------------------------------------------------------------
# Phase 1 — base packages
# ---------------------------------------------------------------------------
step_apt_update() {
  with_retry 3 10 env DEBIAN_FRONTEND=noninteractive apt-get update -y
}

step_base_packages() {
  with_retry 3 10 env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg lsb-release git jq rsync ufw \
    xfsprogs nvme-cli openssh-client
}

# ---------------------------------------------------------------------------
# Phase 2 — Docker + Compose plugin
# ---------------------------------------------------------------------------
step_docker_repo() {
  install -m 0755 -d /etc/apt/keyrings
  with_retry 3 10 curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  with_retry 3 10 apt-get update -y
}

step_docker_install() {
  with_retry 3 15 env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

step_docker_daemon_config() {
  # Matches the live homeserver's /etc/docker/daemon.json: bounded log
  # rotation (containers run forever, unbounded logs will fill /var), wider
  # default-address-pools (STACK-REBUILD.md documents this box exhausting
  # Docker's default pools once ~15+ Compose projects are up — fix it before
  # that happens rather than after), and the nvidia runtime registered once
  # the container toolkit is installed (safe to declare even before the
  # toolkit exists — dockerd just won't use it until nvidia-container-runtime
  # is on $PATH).
  cat >/etc/docker/daemon.json <<'EOF'
{
    "log-driver": "local",
    "log-opts": {
        "max-file": "3",
        "max-size": "10m"
    },
    "default-address-pools": [
        { "base": "172.16.0.0/12", "size": 24 }
    ],
    "runtimes": {
        "nvidia": {
            "args": [],
            "path": "nvidia-container-runtime"
        }
    }
}
EOF
  systemctl restart docker
}

# ---------------------------------------------------------------------------
# Phase 3 — NVIDIA GPU stack (driver + container toolkit), skippable
# ---------------------------------------------------------------------------
step_gpu_driver() {
  with_retry 3 10 env DEBIAN_FRONTEND=noninteractive apt-get install -y ubuntu-drivers-common
  # `ubuntu-drivers autoinstall` was removed in this box's ubuntu-drivers-common
  # (1:0.10.9, Ubuntu 26.04) -- the CLI now uses `install` with no args to mean
  # "install the recommended driver for every detected device", confirmed via
  # `ubuntu-drivers -h` live on this box. Keep the old subcommand as a fallback
  # in case a different target runs an older ubuntu-drivers-common.
  ubuntu-drivers install || ubuntu-drivers autoinstall
}

step_gpu_container_toolkit() {
  curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
    | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
  curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
    | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
    > /etc/apt/sources.list.d/nvidia-container-toolkit.list
  with_retry 3 10 apt-get update -y
  with_retry 3 15 env DEBIAN_FRONTEND=noninteractive apt-get install -y nvidia-container-toolkit
  nvidia-ctk runtime configure --runtime=docker
  systemctl restart docker
}

step_gpu_verify() {
  nvidia-smi -L || return 1
  docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi -L
}

# GPU driver installs a new kernel module -- on a genuinely fresh box this
# usually needs a reboot before `nvidia-smi` sees the card. Detect that
# instead of treating it as a hard failure so the operator knows to reboot
# and re-run rather than debug a phantom GPU problem.
step_gpu_verify_or_note_reboot() {
  if step_gpu_verify; then
    return 0
  fi
  if ! lsmod | grep -q '^nvidia '; then
    echo "nvidia kernel module not loaded yet -- this is expected right after"
    echo "a fresh driver install and usually just needs a reboot. Reboot the"
    echo "box, then re-run: $0 --config $CONFIG_FILE --force-rerun-from gpu-verify"
    return 1
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Phase 4 — WireGuard tunnel to the VPS
# ---------------------------------------------------------------------------
step_wireguard_install() {
  with_retry 3 10 env DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard
}

step_wireguard_config() {
  install -d -m 0700 /etc/wireguard
  umask 077

  # The home side's WireGuard private key AND preshared key were never part
  # of the .env-only backup (system config, not a Dockge stack secret) --
  # see #518 comment history. If the config didn't supply a private key,
  # generate a fresh keypair (and always generate a fresh PSK alongside it,
  # since a stale/mismatched PSK is exactly as fatal to the handshake as a
  # stale pubkey -- see the incident below). step_wireguard_sync_vps_peer
  # pushes both to the VPS's peer config, rather than silently failing to
  # bring the tunnel up with keys the other end doesn't have.
  #
  # #518 incident: an earlier version of this script only generated/synced
  # the keypair, not a PSK. The VPS's peer config required one (predating
  # this script entirely). Every run silently produced a wg0.conf that
  # associated cleanly (`wg show` displayed the interface fine) but never
  # completed a handshake -- 0 bytes received, forever, no error anywhere.
  # `step_wireguard_verify` below only checked the interface existed, not
  # that a handshake had actually happened, so this went undetected for the
  # entire rest of that session: real attacker traffic never reached the
  # honeypot sensors the whole time, silently. Both gaps are fixed here.
  # step_wireguard_sync_vps_peer always re-derives the current pubkey/PSK
  # from the wg0.conf written below and pushes them unconditionally -- no
  # need to track "was this freshly generated" separately (that tracking
  # via .new marker files was itself the source of the SSH-argument bug
  # documented on that function).
  local priv="${HOME_WG_PRIVATE_KEY:-}"
  local psk="${HOME_WG_PRESHARED_KEY:-}"
  if [[ -z "$priv" ]]; then
    priv="$(wg genkey)"
    echo "Generated a fresh WireGuard private key (no HOME_WG_PRIVATE_KEY in config)."
    echo "New home public key: $(echo "$priv" | wg pubkey)"
  fi
  if [[ -z "$psk" ]]; then
    psk="$(wg genpsk)"
    echo "Generated a fresh WireGuard preshared key (no HOME_WG_PRESHARED_KEY in config)."
  fi

  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${HOME_WG_ADDRESS}
PrivateKey = ${priv}
ListenPort = 51820

[Peer]
PublicKey = ${VPS_WG_PUBLIC_KEY}
PresharedKey = ${psk}
Endpoint = ${VPS_WG_ENDPOINT}
AllowedIPs = ${VPS_WG_ADDRESS}/32
PersistentKeepalive = 25
EOF
  chmod 600 /etc/wireguard/wg0.conf
  systemctl enable wg-quick@wg0
  systemctl restart wg-quick@wg0
}

# Always push home's CURRENT effective pubkey+PSK (from the just-written
# local wg0.conf), not just "whatever was freshly generated this run" --
# confirmed live (#518), two separate bugs with the old "only sync if a
# .new marker file exists" approach:
#  1. A stale .new marker from an earlier run lingered forever (nothing
#     ever cleaned it up), so a run that used already-persisted config
#     values still thought a fresh key had been generated and tried to
#     resync unnecessarily.
#  2. Worse: SSH does not preserve individual argv separation to the
#     remote command the way a local exec does -- per ssh(1), the command
#     and its arguments are concatenated into a SINGLE space-joined string
#     before being sent, then re-split by the remote shell. An empty-string
#     argument (e.g. "no new PSK this run") contributes nothing but a
#     space, which collapses away in that re-split -- every argument after
#     it silently shifts down one position. `peer_ip="$3"` on the remote
#     end became unbound because $psk had been empty, not because
#     anything was wrong with $VPS_WG_ADDRESS itself. Always deriving and
#     sending real, non-empty values sidesteps the whole class of bug --
#     the remote side becomes an unconditional idempotent replace instead
#     of a conditional one.
step_wireguard_sync_vps_peer() {
  rm -f /etc/wireguard/wg0.pub.new /etc/wireguard/wg0.psk.new
  local pubkey psk
  pubkey="$(grep '^PrivateKey' /etc/wireguard/wg0.conf | awk '{print $3}' | wg pubkey)"
  psk="$(grep '^PresharedKey' /etc/wireguard/wg0.conf | awk '{print $3}')"
  [[ -n "$pubkey" && -n "$psk" ]] || { echo "could not read local wg0.conf pubkey/PSK"; return 1; }

  ssh -i "$VPS_SSH_KEY" -p "$VPS_SSH_PORT" -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=10 "${VPS_SSH_USER}@${VPS_SSH_HOST}" bash -s -- "$pubkey" "$psk" "$VPS_WG_ADDRESS" <<'REMOTE'
set -euo pipefail
new_pub="$1"
new_psk="$2"
peer_ip="$3"
conf="/etc/wireguard/wg0.conf"
[[ -f "$conf" ]] || { echo "no $conf on VPS" >&2; exit 1; }
cp -p "$conf" "$conf.bak.$(date +%s)"
# Replace the PublicKey/PresharedKey lines inside the [Peer] block matching
# this home peer's AllowedIPs, not any other peer that might exist.
python3 - "$conf" "$new_pub" "$new_psk" "$peer_ip" <<'PY'
import re, sys
conf, new_pub, new_psk, peer_ip = sys.argv[1:5]
text = open(conf).read()
blocks = re.split(r'(?=\[Peer\])', text)
out = []
for b in blocks:
    if b.startswith('[Peer]') and f"{peer_ip}/32" in b:
        b = re.sub(r'PublicKey\s*=\s*\S+', f'PublicKey = {new_pub}', b)
        if re.search(r'^PresharedKey\s*=', b, re.MULTILINE):
            b = re.sub(r'PresharedKey\s*=\s*\S+', f'PresharedKey = {new_psk}', b)
        else:
            b = re.sub(r'(PublicKey\s*=\s*\S+\n)', rf'\1PresharedKey = {new_psk}\n', b)
    out.append(b)
open(conf, 'w').write(''.join(out))
PY
systemctl restart wg-quick@wg0
REMOTE
}

step_wireguard_verify() {
  # Confirmed live (#518): `wg show wg0` succeeding only proves the
  # interface exists, not that a handshake ever completed -- a stale/missing
  # PSK produces exactly this false-positive (interface up, 0 bytes
  # received, forever). Actually check for a completed handshake, with a
  # short retry window since one can take a few seconds after a fresh
  # restart.
  wg show wg0 >/dev/null

  local waited=0
  while (( waited < 30 )); do
    local hs
    hs=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}')
    if [[ -n "$hs" && "$hs" != "0" ]]; then
      echo "WireGuard handshake confirmed ($(date -d "@$hs" -Iseconds 2>/dev/null || echo "$hs"))."
      return 0
    fi
    sleep 3
    waited=$(( waited + 3 ))
  done
  echo "No WireGuard handshake after ${waited}s -- tunnel interface is up but not" >&2
  echo "actually passing traffic. Check the peer's PublicKey/PresharedKey match on" >&2
  echo "both ends (this is exactly the #518 incident this check was added for)." >&2
  return 1
}

# ---------------------------------------------------------------------------
# Phase 5 — repo checkout (must land at REPO_DIR exactly — other stacks'
# `build:` directives reference this path as an absolute string, see
# docker-compose.yml's #258 header comment)
# ---------------------------------------------------------------------------
step_clone_repo() {
  mkdir -p /opt
  ln -sfn "$(dirname "$REPO_DIR")" /opt/stacks 2>/dev/null || true
  if [[ -d "$REPO_DIR/.git" ]]; then
    with_retry 3 10 git -C "$REPO_DIR" fetch origin
    git -C "$REPO_DIR" checkout "$GIT_REF"
    with_retry 3 10 git -C "$REPO_DIR" pull --ff-only origin "$GIT_REF"
  else
    mkdir -p "$(dirname "$REPO_DIR")"
    with_retry 3 10 git clone --branch "$GIT_REF" "$GIT_REPO_URL" "$REPO_DIR"
  fi
}

# ---------------------------------------------------------------------------
# Phase 6 — Dockge
# ---------------------------------------------------------------------------
step_dockge_install() {
  mkdir -p /var/dockge/data /var/dockge/stacks
  if docker ps -a --format '{{.Names}}' | grep -qx dockge; then
    return 0
  fi
  docker run -d --name dockge --restart unless-stopped \
    -p 5001:5001 \
    -e DOCKGE_STACKS_DIR=/var/dockge/stacks \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/dockge/data:/app/data \
    -v /var/dockge/stacks:/var/dockge/stacks \
    louislam/dockge:1
}

# ---------------------------------------------------------------------------
# Phase 7 — secret restore from the LAN backup host
# ---------------------------------------------------------------------------
# Maps Dockge stack name -> subdirectory name under BACKUP_HOST_PATH. 1:1 for
# everything except pihole, which the backup captured a bare .env for (no
# compose file was ever backed up for it -- see step_pihole_provision, which
# reconstructs a minimal one since it isn't part of this git repo).
ENV_RESTORE_STACKS=(
  honeypot-init honeypot-cowrie honeypot-dionaea honeypot-conpot honeypot-dnp3
  honeypot-http honeypot-multipot honeypot-dashboard honeypot-payload-analysis
  honeypot-tanner honeypot-elk honeypot-utilities honeypot-stack ghidra ghosts
  pihole
)

step_restore_env_files() {
  local failures=0
  for name in "${ENV_RESTORE_STACKS[@]}"; do
    local src="${BACKUP_HOST_PATH}/${name}/.env"
    local dest_dir="/var/dockge/stacks/${name}"
    mkdir -p "$dest_dir"
    if with_retry 3 5 scp -i "$BACKUP_HOST_KEY" -P 22 -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 "${BACKUP_HOST_USER}@${BACKUP_HOST}:${src}" "$dest_dir/.env" 2>/dev/null; then
      chmod 600 "$dest_dir/.env"
      echo "restored .env for $name"
    else
      echo "WARNING: no backed-up .env found for $name at $src (may not have existed pre-rebuild)"
    fi
  done
  return 0   # missing individual .envs is a warning, not a hard failure -- see summary
}

# ---------------------------------------------------------------------------
# Phase 8 — stack provisioning + startup, in dependency order
# ---------------------------------------------------------------------------
# Format: "dockge-stack-name|repo-relative-compose-file"
# Order matters for the first three entries only (see STACK-REBUILD.md):
# Elasticsearch (honeypot-elk) must be healthy BEFORE honeypot-init runs its
# elasticsearch-setup/arkime-init one-shot jobs, which is the OPPOSITE of
# what a naive alphabetical/README-table order would suggest and is the #1
# trap STACK-REBUILD.md documents from the first live reset (2026-08-02).
# Everything after honeypot-init has no real cross-stack ordering
# requirement (shared volumes are non-external and get created empty by
# whichever stack starts first).
STACK_DEFS=(
  "honeypot-elk|docker-compose.elk.yml"
  "honeypot-init|docker-compose.init.yml"
  "honeypot-tanner|docker-compose.tanner.yml"
  "honeypot-cowrie|docker-compose.cowrie.yml"
  "honeypot-dionaea|docker-compose.dionaea.yml"
  "honeypot-conpot|docker-compose.conpot.yml"
  "honeypot-dnp3|docker-compose.dnp3.yml"
  "honeypot-http|docker-compose.http.yml"
  "honeypot-multipot|docker-compose.multipot.yml"
  "honeypot-cisco-asa-honeypot|docker-compose.cisco-asa-honeypot.yml"
  "honeypot-citrix-honeypot|docker-compose.citrix-honeypot.yml"
  "honeypot-rdp-honeypot|docker-compose.rdp-honeypot.yml"
  "honeypot-dicompot|docker-compose.dicompot.yml"
  "honeypot-dns-honeypot|docker-compose.dns-honeypot.yml"
  "honeypot-ip-enrichment-worker|docker-compose.ip-enrichment-worker.yml"
  "honeypot-payload-analysis|docker-compose.payload-analysis.yml"
  "honeypot-dashboard|docker-compose.dashboard.yml"
  "honeypot-utilities|docker-compose.utilities.yml"
)
# NOTE: cisco-asa/citrix/rdp/dicompot/dns-honeypot/ip-enrichment-worker are
# NOT in STACK-REBUILD.md's documented 12-stack reset list even though they
# have their own container_name and top-level compose file in this repo --
# that doc appears to predate these being split into their own stacks. They
# have no env_file/${VAR} substitution in their compose files (confirmed by
# grep), so no .env restore is needed for them either. Flagged as a
# docs-vs-reality gap in the #518 issue rather than silently guessed away.

step_provision_stack_dirs() {
  local name compose_file
  for entry in "${STACK_DEFS[@]}"; do
    IFS='|' read -r name compose_file <<<"$entry"
    local dir="/var/dockge/stacks/$name"
    mkdir -p "$dir"
    if [[ ! -f "$REPO_DIR/$compose_file" ]]; then
      echo "MISSING compose source in repo: $compose_file (stack $name)"
      continue
    fi
    ln -sf "$REPO_DIR/$compose_file" "$dir/compose.yml"
  done
}

step_bootstrap_missing_envs() {
  # Belt-and-suspenders after step_restore_env_files: any stack that still
  # has no .env at all (backup genuinely never had one, e.g. a stack created
  # after the last backup pass) gets bootstrapped from its .env.example so
  # `docker compose up` doesn't fail outright on a missing required file --
  # it'll be full of CHANGE_ME placeholders and won't be fully functional,
  # but that's a visible, fixable gap instead of a silent compose failure.
  local n=0
  for entry in "${STACK_DEFS[@]}"; do
    local name; name="${entry%%|*}"
    local dir="/var/dockge/stacks/$name"
    [[ -f "$dir/.env" ]] && continue
    local example=""
    case "$name" in
      honeypot-init) example="$REPO_DIR/honeypot-init.env.example" ;;
      *) example="$REPO_DIR/.env.example" ;;
    esac
    if [[ -f "$example" ]]; then
      cp "$example" "$dir/.env"
      chmod 600 "$dir/.env"
      n=$((n + 1))
      echo "bootstrapped placeholder .env for $name from $(basename "$example")"
    fi
  done
  echo "Bootstrapped $n placeholder .env file(s) — review for CHANGE_ME values."
}

step_create_shared_resources() {
  # docker-compose.init.yml declares these as external:true. On a genuinely
  # fresh Docker install none of them exist yet, and honeypot-init's
  # containers will fail to even create rather than run and fail --
  # STACK-REBUILD.md documents this exact trap.
  docker network inspect honeynet >/dev/null 2>&1 || docker network create honeynet
  docker volume inspect dionaea-lib >/dev/null 2>&1 || docker volume create dionaea-lib
  docker volume inspect yara-results >/dev/null 2>&1 || docker volume create yara-results

  # docker-compose.init.yml's own header comment: "state/init-markers/ must
  # be mode 777 on the host before this stack's [containers run]" --
  # log-init/elasticsearch-setup/arkime-init/snare-clone each touch a
  # <job>.done marker there on success. Confirmed live (first #518 test run):
  # without this, every one-shot job's actual work succeeds but the final
  # `touch /markers/....done` fails with Permission denied, so the container
  # exits 1 and looks like a real failure even though nothing is actually
  # broken.
  install -d -m 777 "$REPO_DIR/state/init-markers"
}

step_start_elasticsearch_first() {
  (cd /var/dockge/stacks/honeypot-elk && with_retry 3 15 docker compose -f compose.yml up -d --wait)
}

step_start_init() {
  (cd /var/dockge/stacks/honeypot-init && with_retry 3 15 docker compose -f compose.yml up -d)
  # honeypot-init's jobs are one-shots; give them a bounded window to exit 0
  # rather than racing straight into the sensor stacks that assume its log
  # paths/ES templates/persona state already exist.
  local waited=0
  while (( waited < 120 )); do
    local running
    running=$(docker compose -f /var/dockge/stacks/honeypot-init/compose.yml ps --status running -q 2>/dev/null | wc -l)
    (( running == 0 )) && return 0
    sleep 5
    waited=$(( waited + 5 ))
  done
  echo "honeypot-init still has running containers after 120s — check for the"
  echo "Elasticsearch-not-ready trap described in docs/STACK-REBUILD.md."
  return 1
}

step_start_remaining_stacks() {
  local failures=0
  for entry in "${STACK_DEFS[@]}"; do
    local name="${entry%%|*}"
    [[ "$name" == "honeypot-elk" || "$name" == "honeypot-init" ]] && continue
    local dir="/var/dockge/stacks/$name"
    [[ -f "$dir/compose.yml" ]] || continue
    echo "-- $name: docker compose up -d --wait"
    if ! (cd "$dir" && with_retry 3 15 docker compose -f compose.yml up -d --wait); then
      echo "FAILED: $name"
      failures=$((failures + 1))
    fi
  done
  [[ $failures -eq 0 ]]
}

# ---------------------------------------------------------------------------
# Phase 8a2 — read-only sshfs mounts of the VPS's Suricata/portbridge logs
# (and, since #518, the pcap/ subdirectory Suricata's pcap-log writes into
# once its output-directory ownership is fixed VPS-side -- see the earlier
# #518 issue comment on that bug). Filebeat and pcap-sync/Arkime both depend
# on these; must run after start-remaining, since honeypot-init's log-init
# job is what creates the mount-point directories in the first place.
# ---------------------------------------------------------------------------
step_sshfs_install() {
  with_retry 3 10 env DEBIAN_FRONTEND=noninteractive apt-get install -y sshfs
  mkdir -p /root/.ssh
  install -m 600 "$VPS_SSH_KEY" /root/.ssh/strato_vps
}

step_sshfs_mounts() {
  local suricata_dir portbridge_dir
  suricata_dir=$(readlink -f "$REPO_DIR/logs/suricata")
  portbridge_dir=$(readlink -f "$REPO_DIR/logs/portbridge")
  [[ -d "$suricata_dir" && -d "$portbridge_dir" ]] || {
    echo "logs/suricata or logs/portbridge doesn't exist yet -- honeypot-init's log-init job should have created these."
    return 1
  }

  local opts="_netdev,ro,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,IdentityFile=/root/.ssh/strato_vps,port=2222,allow_other,default_permissions,StrictHostKeyChecking=accept-new"
  grep -q "$suricata_dir" /etc/fstab || cat >>/etc/fstab <<EOF

# #518: read-only VPS log mounts for Suricata (eve.json + pcap/) and
# portbridge, pulled over the WireGuard tunnel. See docs/SENSORS.md.
root@${VPS_WG_ADDRESS}:/opt/stacks/honeypot-stack/logs/suricata $suricata_dir fuse.sshfs $opts 0 0
root@${VPS_WG_ADDRESS}:/opt/stacks/honeypot-stack/logs/portbridge $portbridge_dir fuse.sshfs $opts 0 0
EOF

  mountpoint -q "$suricata_dir" || mount "$suricata_dir"
  mountpoint -q "$portbridge_dir" || mount "$portbridge_dir"
  mountpoint -q "$suricata_dir" && mountpoint -q "$portbridge_dir"
}

step_sshfs_boot_ordering() {
  # Installs WireGuard-aware systemd mount ordering/retry (the raw fstab
  # _netdev/reconnect options alone don't guarantee the WG interface is up
  # before the mount is attempted at boot) and restarts filebeat/evebox so
  # they pick up newly-available mounts rather than waiting for their own
  # retry logic.
  bash "$REPO_DIR/setup-suricata-logs-home.sh"
}

# ---------------------------------------------------------------------------
# Phase 8b — pihole (not part of this repo; reconstructed compose since the
# LAN backup only captured pihole/.env, no compose file, see #518)
# ---------------------------------------------------------------------------
step_pihole_provision() {
  local dir="/var/dockge/stacks/pihole"
  mkdir -p "$dir/etc-pihole" "$dir/etc-dnsmasq.d"

  # Binding 0.0.0.0:53 collides with hp-dns-honeypot, which already publishes
  # 53/udp on 10.8.0.2 (the WireGuard bind IP every honeypot sensor uses,
  # per HP_BIND / CGNAT-DEPLOYMENT.md's "never reachable from your home LAN"
  # design) -- 0.0.0.0 overlaps every interface including that one, so
  # Docker's port allocator refuses the bind. Confirmed live (#518 test run):
  # deterministic "address already in use" on every attempt, not a race.
  # Pihole is real home-LAN infra, not a honeypot component, so it belongs on
  # the actual LAN-facing IP instead. This box has two LAN interfaces
  # (eno2/192.168.42.249, ens9f0/192.168.42.250, see
  # docs/research/518-smoke-test-research.md's NIC inventory) -- which one
  # pihole should actually serve is an operator choice, not something to
  # auto-detect via the default route (that picked the wrong one of the two
  # on this box's first pass), hence PIHOLE_LAN_IP is an explicit config
  # value, not inferred.
  local lan_ip="$PIHOLE_LAN_IP"

  cat > "$dir/compose.yml" <<'EOF'
# Reconstructed for #518 -- pihole was never part of this git repo (it's
# home-network infra, not a honeypot component) and no compose file for it
# existed in the pre-rebuild backup, only its .env (PIHOLE_PASSWORD). This
# is deliberately minimal (official image, standard ports/volumes) rather
# than guessed-at custom configuration.
#
# Ports are bound to __LAN_IP__ specifically, not 0.0.0.0 -- see
# step_pihole_provision in scripts/install-homeserver.sh for why (conflicts
# with hp-dns-honeypot's 10.8.0.2:53/udp otherwise).
services:
  pihole:
    image: pihole/pihole:latest
    container_name: pihole
    restart: unless-stopped
    ports:
      - "__LAN_IP__:53:53/tcp"
      - "__LAN_IP__:53:53/udp"
      - "__LAN_IP__:80:80/tcp"
    environment:
      TZ: "${INSTALL_TIMEZONE:-Europe/Berlin}"
      WEBPASSWORD: "${PIHOLE_PASSWORD}"
    volumes:
      - ./etc-pihole:/etc/pihole
      - ./etc-dnsmasq.d:/etc/dnsmasq.d
    cap_add:
      - NET_ADMIN
EOF
  sed -i "s/__LAN_IP__/$lan_ip/g" "$dir/compose.yml"
}

step_pihole_start() {
  [[ -f /var/dockge/stacks/pihole/.env ]] || { echo "no pihole .env restored — skipping start"; return 1; }
  (cd /var/dockge/stacks/pihole && with_retry 3 15 docker compose -f compose.yml up -d --wait)
}

# ---------------------------------------------------------------------------
# Phase 9 — LLM/ML worker (GPU-dependent, gated behind ENABLE_GPU_STACK)
# ---------------------------------------------------------------------------
step_ghidra_stack_provision() {
  # docker-compose.ghidra.yml uses RELATIVE build contexts (`build: ./statictools`,
  # `context: ./revdeck/ai-reverse-engineering`). Symlinking only compose.yml
  # into a separate /var/dockge/stacks/ghidra directory breaks those --
  # confirmed live (first #518 test run): "unable to prepare context: path
  # .../ghidra/statictools not found", because Compose resolves relative
  # build paths against the compose FILE's own directory, which was the
  # symlink's location, not analysis/ghidra/ where statictools/ actually
  # lives. Symlink the whole directory instead so relative paths resolve
  # correctly, matching what a real Dockge "point at this folder" stack
  # would do.
  local src="$REPO_DIR/analysis/ghidra"
  [[ -d "$src" ]] || { echo "missing $src"; return 1; }
  # step_restore_env_files ran earlier and put ghidra's .env at
  # /var/dockge/stacks/ghidra/.env (a plain directory at that point) --
  # rescue it before replacing that path with a symlink, since Compose
  # will read .env from wherever we `cd` to run it (the real analysis/ghidra
  # directory once symlinked).
  if [[ -f /var/dockge/stacks/ghidra/.env && ! -L /var/dockge/stacks/ghidra ]]; then
    mv /var/dockge/stacks/ghidra/.env "$src/.env"
  fi
  rm -rf /var/dockge/stacks/ghidra
  ln -sfn "$src" /var/dockge/stacks/ghidra
  ln -sf "$src/docker-compose.ghidra.yml" "$src/compose.yml"
  [[ -f "$src/docker-compose.ghidra.gpu.yml" ]] && ln -sf "$src/docker-compose.ghidra.gpu.yml" "$src/compose.gpu.yml"
}

step_ghidra_stack_start() {
  local dir="/var/dockge/stacks/ghidra"
  local files=(-f compose.yml)
  [[ -f "$dir/compose.gpu.yml" ]] && files+=(-f compose.gpu.yml)
  (cd "$dir" && with_retry 3 15 docker compose "${files[@]}" up -d --wait)
}

step_ollama_model_pull() {
  # Pinned model per analysis/ghidra/models/approved-models.json -- resolved
  # at runtime rather than hardcoded so a model-pin bump doesn't require
  # editing this script too. The file is a manifest object keyed by
  # `slots.<slot>.artifact.tag`, not a plain array -- confirmed live
  # (first #518 test run); the ghidra slot's pinned tag is what
  # ghidra-ollama-1 actually needs loaded.
  local model
  model=$(jq -r '.slots.ghidra.artifact.tag // empty' "$REPO_DIR/analysis/ghidra/models/approved-models.json" 2>/dev/null)
  [[ -n "$model" ]] || { echo "could not resolve pinned model from approved-models.json"; return 1; }
  docker exec ghidra-ollama-1 ollama pull "$model"
}

step_ml_worker_start() {
  # Same relative-build-context issue as ghidra (docker-compose.yml here has
  # `build: context: .`) -- symlink the whole directory, not just the
  # compose file, confirmed live (first #518 test run: "failed to read
  # dockerfile: open Dockerfile: no such file or directory").
  local src="$REPO_DIR/ml-worker"
  [[ -d "$src" ]] || { echo "no ml-worker/ directory in repo"; return 1; }
  [[ -f "$src/docker-compose.yml" ]] || { echo "no docker-compose.yml under ml-worker/"; return 1; }
  if [[ -f /var/dockge/stacks/ml-worker/.env && ! -L /var/dockge/stacks/ml-worker ]]; then
    mv /var/dockge/stacks/ml-worker/.env "$src/.env"
  fi
  rm -rf /var/dockge/stacks/ml-worker
  ln -sfn "$src" /var/dockge/stacks/ml-worker
  ln -sf "$src/docker-compose.yml" "$src/compose.yml"
  (cd "$src" && with_retry 3 15 docker compose -f compose.yml up -d --wait)
}

step_llm_worker_selftest() {
  # llm-worker's compose file (restart: unless-stopped, container_name
  # hp-llm-worker) keeps a persistent but harmless container running by
  # default -- LLM_ENABLED defaults to false and the base compose joins
  # only an internal synthetic-only network (per #66/#83), so "persistent"
  # here means "safely idle", not "actively processing". The worker itself
  # is CPU-only by design (Ollama holds the GPU reservation, see
  # docs/gpu-llm-analysis-worker.md's Architecture Overview) -- no --gpus
  # needed. The actual selftest invocation is documented in
  # llm-worker/README.md's Quick Start: bring the container up, then exec
  # into it. My first attempt here (docker run <image> --selftest as a
  # one-shot) was wrong on both counts -- confirmed live (#518 test run):
  # it failed with "exec: --selftest: executable file not found in $PATH"
  # because the image has no ENTRYPOINT, so args replace CMD rather than
  # appending to it.
  [[ -d "$REPO_DIR/llm-worker" ]] || { echo "no llm-worker/ directory in repo"; return 1; }
  ( cd "$REPO_DIR/llm-worker" && \
    with_retry 3 15 docker compose -f docker-compose.yml up -d --build --wait && \
    docker exec hp-llm-worker python worker.py --selftest )
}

# ---------------------------------------------------------------------------
# Phase 10 — verification
# ---------------------------------------------------------------------------
step_verify_containers_healthy() {
  local unhealthy
  unhealthy=$(docker ps --filter "health=unhealthy" --format '{{.Names}}')
  if [[ -n "$unhealthy" ]]; then
    echo "Unhealthy containers: $unhealthy"
    return 1
  fi
}

step_verify_exited() {
  local exited
  exited=$(docker ps -a --filter "status=exited" --format '{{.Names}}\t{{.Status}}' | grep -v 'Exited (0)' || true)
  if [[ -n "$exited" ]]; then
    echo "Containers exited non-zero:"
    echo "$exited"
    return 1
  fi
}

step_verify_elasticsearch_events() {
  docker run --rm --network honeynet curlimages/curl:latest -sf \
    http://elasticsearch:9200/honeypot-v2-*/_count >/dev/null
}

# ---------------------------------------------------------------------------
# Phase 11 — sandbox VM restore (GHOSTS + Windows detonation), gated behind
# ENABLE_SANDBOX_RESTORE since it's a 170G+ transfer and a genuinely separate
# subsystem (KVM/libvirt, not Docker) from everything above.
# ---------------------------------------------------------------------------
step_libvirt_install() {
  with_retry 3 15 env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    qemu-system-x86 libvirt-daemon-system libvirt-clients bridge-utils \
    virtinst libguestfs-tools ovmf
  systemctl enable --now libvirtd
}

step_sandbox_backup_restore() {
  # /var/dockge/sandbox is a hardcoded absolute path baked into multiple
  # files (win11-ghosts-kvm.xml's <source file=.../>, kvm_manage.sh's
  # SANDBOX_ROOT default, provision-golden-image.sh's default arg) -- it
  # must land exactly there, not somewhere symlinked or renamed.
  mkdir -p /var/dockge/sandbox
  with_retry 2 30 rsync -a -e "ssh -i $BACKUP_HOST_KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10" \
    "${BACKUP_HOST_USER}@${BACKUP_HOST}:${BACKUP_HOST_SANDBOX_PATH}/" /var/dockge/sandbox/
}

step_sandbox_checksum_verify() {
  # Golden images are the root of trust for every detonation guest cloned
  # from them (see kvm_manage.sh's own comment on this) -- verify every
  # .sha256 the backup carried rather than trusting the transfer blindly.
  local sums failures=0
  while IFS= read -r -d '' sums; do
    ( cd "$(dirname "$sums")" && sha256sum -c "$(basename "$sums")" ) || failures=$((failures + 1))
  done < <(find /var/dockge/sandbox -name "*.sha256" -print0)
  [[ $failures -eq 0 ]]
}

# Both win11-ghosts and win11-sandbox declare <nvram template='.../OVMF_VARS_4M.ms.fd'
# format='qcow2'> -- the template itself is raw, and this box's libvirt
# (12.0.0) refuses to do the raw->qcow2 conversion on first boot: "Operation
# not supported: conversion of the nvram template to another target format
# is not supported". Confirmed live (#518). Pre-creating the target file
# with the right format makes libvirt find it already there and skip the
# conversion path entirely, rather than working around it after the fact
# every time.
ensure_nvram_vars() {
  local target="$1"
  [[ -f "$target" ]] && return 0
  qemu-img convert -f raw -O qcow2 /usr/share/OVMF/OVMF_VARS_4M.ms.fd "$target"
  chown libvirt-qemu:kvm "$target"
}

step_ghosts_network_setup() {
  bash "$REPO_DIR/sandbox/ghosts/install-network.sh" net-setup
}

step_ghosts_host_install() {
  # --skip-enroll-test: the full test (build Ghosts.Client.Universal from
  # source, run it once, poll the API for enrollment) is the real
  # confirmation bar per sandbox/ghosts/README.md, but it's slow and this
  # step already follows a `dotnet publish`-from-source container build --
  # run the enrollment test manually after a restore, not on every
  # unattended run.
  bash "$REPO_DIR/sandbox/ghosts/install-host.sh" --skip-enroll-test
}

step_ghosts_vm_start() {
  ensure_nvram_vars /var/lib/libvirt/qemu/nvram/win11-ghosts_VARS.qcow2
  virsh list --all --name | grep -qx win11-ghosts \
    || virsh define "$REPO_DIR/sandbox/ghosts/win11-ghosts-kvm.xml"
  virsh domstate win11-ghosts | grep -q running || virsh start win11-ghosts
}

step_windows_sandbox_network_setup() {
  bash "$REPO_DIR/sandbox/windows/setup/kvm_manage.sh" net-setup
}

step_windows_sandbox_vm_create() {
  ensure_nvram_vars /var/lib/libvirt/qemu/nvram/win11-sandbox_VARS.qcow2
  if virsh list --all --name | grep -qx win11-sandbox; then
    echo "win11-sandbox already defined -- skipping create (use kvm_manage.sh revert to reset to golden)"
    return 0
  fi
  # kvm_manage.sh create refuses to run if $VM_DISK already exists (it may
  # hold a detonated guest, see its own comment) -- a restore can leave a
  # pre-existing thin-clone from before the backup that isn't a live
  # detonation. Confirmed live (#518): safe to clear before a first-time
  # restore create, since the domain isn't defined yet at that point.
  rm -f /var/dockge/sandbox/vms/win11-sandbox.qcow2
  bash "$REPO_DIR/sandbox/windows/setup/kvm_manage.sh" create
}

step_windows_sandbox_vm_start() {
  virsh domstate win11-sandbox | grep -q running || virsh start win11-sandbox
}

step_sandbox_verify_running() {
  local dom rc=0
  for dom in win11-ghosts win11-sandbox; do
    local state; state=$(virsh domstate "$dom" 2>&1)
    echo "$dom: $state"
    [[ "$state" == "running" ]] || rc=1
  done
  return $rc
}

step_sandbox_host_foundation() {
  # sandbox/install-host.sh: the honeypot-sandbox libvirt network + nftables
  # filter + /var/lib/honeypot-sandbox dir tree, shared foundation for the
  # Linux KVM sample-analysis path (separate from the GHOSTS/Windows
  # networks set up above). Also disables/destroys libvirt's default NAT
  # network as unnecessary and dangerous for malware VMs -- confirmed safe
  # to run after win11-ghosts/win11-sandbox already exist, since it only
  # touches the `default` and `honeypot-sandbox` networks, not theirs.
  bash "$REPO_DIR/sandbox/install-host.sh"
}

step_linux_sandbox_base() {
  # Downloads and GPG-verifies a fresh Ubuntu cloud image rather than
  # restoring one -- unlike the Windows golden images (custom Packer builds,
  # days of hardening work, must be preserved), the Linux base is
  # reproducible on demand and was never part of the sandbox backup.
  [[ -f /var/lib/honeypot-sandbox/base/ubuntu-noble.qcow2 ]] && { echo "base image already present"; return 0; }
  bash "$REPO_DIR/sandbox/prepare-linux-base.sh"
}

step_linux_sandbox_verify() {
  bash "$REPO_DIR/sandbox/verify-linux-sandbox.sh"
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
log "install-homeserver.sh starting — log: $RUN_LOG"

run_step preflight-os          "Confirm Ubuntu"                    step_preflight_os
run_step preflight-disks       "Check disk layout against docs"    step_preflight_disks
run_step hostname-timezone     "Set hostname/timezone"              step_set_hostname

run_step apt-update            "apt-get update"                     step_apt_update
run_step base-packages         "Install base packages"              step_base_packages

run_step docker-repo           "Add Docker apt repo"                step_docker_repo
run_step docker-install        "Install Docker Engine + Compose"    step_docker_install
run_step docker-daemon-config  "Write /etc/docker/daemon.json"      step_docker_daemon_config

if [[ "$ENABLE_GPU_STACK" == "true" ]]; then
  run_step gpu-driver             "Install NVIDIA driver"                step_gpu_driver
  run_step gpu-container-toolkit  "Install nvidia-container-toolkit"     step_gpu_container_toolkit
  run_step gpu-verify              "Verify GPU visible to Docker"         step_gpu_verify_or_note_reboot
else
  skip_step gpu-driver "Install NVIDIA driver" "ENABLE_GPU_STACK=false"
  skip_step gpu-container-toolkit "Install nvidia-container-toolkit" "ENABLE_GPU_STACK=false"
  skip_step gpu-verify "Verify GPU visible to Docker" "ENABLE_GPU_STACK=false"
fi

run_step wireguard-install     "Install WireGuard"                  step_wireguard_install
run_step wireguard-config      "Write wg0.conf and enable tunnel"   step_wireguard_config
run_step wireguard-sync-vps    "Sync home pubkey+PSK to VPS peer config" step_wireguard_sync_vps_peer
run_step wireguard-verify      "Verify tunnel is up"                step_wireguard_verify

run_step clone-repo            "Clone/update honeypot-stack to $REPO_DIR" step_clone_repo
run_step dockge-install        "Install Dockge"                     step_dockge_install

run_step restore-env-files     "Restore .env files from LAN backup" step_restore_env_files
run_step provision-stack-dirs  "Link compose.yml into each stack dir" step_provision_stack_dirs
run_step bootstrap-missing-envs "Bootstrap any still-missing .env from .example" step_bootstrap_missing_envs

run_step shared-resources      "Create honeynet + placeholder volumes" step_create_shared_resources
run_step start-elasticsearch   "Start honeypot-elk, wait healthy"   step_start_elasticsearch_first
run_step start-init            "Start honeypot-init, wait for one-shots" step_start_init
run_step start-remaining       "Start remaining sensor/dashboard stacks" step_start_remaining_stacks

run_step sshfs-install         "Install sshfs, place VPS key"        step_sshfs_install
run_step sshfs-mounts          "Mount VPS Suricata/portbridge logs"  step_sshfs_mounts
run_step sshfs-boot-ordering   "Install WireGuard-aware mount ordering" step_sshfs_boot_ordering

run_step pihole-provision      "Reconstruct pihole compose.yml"     step_pihole_provision
run_step pihole-start          "Start pihole"                       step_pihole_start

if [[ "$ENABLE_GPU_STACK" == "true" ]]; then
  run_step ghidra-provision      "Link ghidra compose.yml"            step_ghidra_stack_provision
  run_step ghidra-start          "Start ghidra/ollama stack"          step_ghidra_stack_start
  run_step ollama-model-pull     "Pull pinned Ollama model"           step_ollama_model_pull
  run_step ml-worker-start       "Start ml-worker"                    step_ml_worker_start
  run_step llm-worker-selftest   "Run llm-worker --selftest"          step_llm_worker_selftest
else
  skip_step ghidra-provision "Link ghidra compose.yml" "ENABLE_GPU_STACK=false"
  skip_step ghidra-start "Start ghidra/ollama stack" "ENABLE_GPU_STACK=false"
  skip_step ollama-model-pull "Pull pinned Ollama model" "ENABLE_GPU_STACK=false"
  skip_step ml-worker-start "Start ml-worker" "ENABLE_GPU_STACK=false"
  skip_step llm-worker-selftest "Run llm-worker --selftest" "ENABLE_GPU_STACK=false"
fi

run_step verify-containers     "Check for unhealthy containers"     step_verify_containers_healthy
run_step verify-exited         "Check for non-zero-exit containers" step_verify_exited
run_step verify-es-events      "Check Elasticsearch is reachable"   step_verify_elasticsearch_events

if [[ "$ENABLE_SANDBOX_RESTORE" == "true" ]]; then
  run_step libvirt-install        "Install libvirt/KVM/QEMU"              step_libvirt_install
  run_step sandbox-restore        "Pull sandbox backup from LAN host"     step_sandbox_backup_restore
  run_step sandbox-checksum       "Verify golden-image checksums"         step_sandbox_checksum_verify
  run_step ghosts-network         "Set up GHOSTS isolated libvirt network" step_ghosts_network_setup
  run_step ghosts-host            "Deploy ghosts-api/ghosts-postgres"      step_ghosts_host_install
  run_step ghosts-vm              "Define + start win11-ghosts VM"         step_ghosts_vm_start
  run_step windows-sandbox-network "Set up Windows sandbox libvirt network" step_windows_sandbox_network_setup
  run_step windows-sandbox-create "Create win11-sandbox thin-clone VM"     step_windows_sandbox_vm_create
  run_step windows-sandbox-start  "Start win11-sandbox VM"                 step_windows_sandbox_vm_start
  run_step sandbox-verify         "Verify both sandbox VMs running"        step_sandbox_verify_running
  run_step sandbox-host-foundation "Set up Linux sandbox network + dirs"   step_sandbox_host_foundation
  run_step linux-sandbox-base     "Download + verify Linux base image"    step_linux_sandbox_base
  run_step linux-sandbox-verify   "Run Linux sandbox smoke test"          step_linux_sandbox_verify
else
  skip_step libvirt-install "Install libvirt/KVM/QEMU" "ENABLE_SANDBOX_RESTORE=false"
  skip_step sandbox-restore "Pull sandbox backup from LAN host" "ENABLE_SANDBOX_RESTORE=false"
  skip_step sandbox-checksum "Verify golden-image checksums" "ENABLE_SANDBOX_RESTORE=false"
  skip_step ghosts-network "Set up GHOSTS isolated libvirt network" "ENABLE_SANDBOX_RESTORE=false"
  skip_step ghosts-host "Deploy ghosts-api/ghosts-postgres" "ENABLE_SANDBOX_RESTORE=false"
  skip_step ghosts-vm "Define + start win11-ghosts VM" "ENABLE_SANDBOX_RESTORE=false"
  skip_step windows-sandbox-network "Set up Windows sandbox libvirt network" "ENABLE_SANDBOX_RESTORE=false"
  skip_step windows-sandbox-create "Create win11-sandbox thin-clone VM" "ENABLE_SANDBOX_RESTORE=false"
  skip_step windows-sandbox-start "Start win11-sandbox VM" "ENABLE_SANDBOX_RESTORE=false"
  skip_step sandbox-verify "Verify both sandbox VMs running" "ENABLE_SANDBOX_RESTORE=false"
  skip_step sandbox-host-foundation "Set up Linux sandbox network + dirs" "ENABLE_SANDBOX_RESTORE=false"
  skip_step linux-sandbox-base "Download + verify Linux base image" "ENABLE_SANDBOX_RESTORE=false"
  skip_step linux-sandbox-verify "Run Linux sandbox smoke test" "ENABLE_SANDBOX_RESTORE=false"
fi

print_summary
exit $?
