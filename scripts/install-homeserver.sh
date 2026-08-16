#!/usr/bin/env bash
# Unattended homeserver provisioning for APIARY — the Ubuntu-side
# equivalent of a Windows autounattend.xml. This is the single entry point
# described in issue #518; it covers everything smoke-test-verified so far
# (see docs/research/518-smoke-test-research.md) and is expected to grow.
#
# Scope: this script provisions a MANUALLY installed base Ubuntu Server
# system into a running APIARY homeserver (Docker, NVIDIA/GPU
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
# propagates so run_step still records FAILED correctly. (This comment was
# aspirational until #787's homeserver reinstall found it wasn't true --
# see the inline comment below.)
with_retry() {
  local max="$1" base="$2"; shift 2
  local attempt=1 rc=0
  while (( attempt <= max )); do
    # Must be "$@" && return 0, NOT "if "$@"; then return 0; fi" -- when a
    # plain if/fi (no else) takes neither branch, POSIX defines the if
    # statement's own exit status as zero regardless of the condition's
    # real exit code. That meant `rc=$?` on the next line always read 0,
    # so with_retry could never detect a failure for ANY wrapped command --
    # found live during #787's homeserver reinstall (2026-08-09): every
    # `scp` in step_restore_env_files was genuinely failing (nested
    # ${name}/.env path that never existed on the flat-structured backup
    # host) yet with_retry reported success for all 17 stacks. `&&`
    # short-circuits without touching $? when the command fails, so the
    # following `rc=$?` captures the real code.
    "$@" && return 0
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

for var in GIT_REPO_URL GIT_REF REPO_DIR HOME_WG_ADDRESS \
           VPS_WG_ADDRESS VPS_WG_ENDPOINT VPS_WG_PUBLIC_KEY \
           VPS_SSH_HOST VPS_SSH_PORT VPS_SSH_USER VPS_SSH_KEY ENABLE_GPU_STACK \
           INSTALL_TIMEZONE BACKUP_HOST BACKUP_HOST_USER BACKUP_HOST_KEY BACKUP_HOST_PATH \
           PIHOLE_LAN_IP ENABLE_SANDBOX_RESTORE AUTH_THEME_REPO_URL \
           ARCANE_URL ARCANE_API_TOKEN; do
  if [[ -z "${!var:-}" || "${!var}" == *'<'*'>'* ]]; then
    echo "Config value $var is unset or still a <PLACEHOLDER> in $CONFIG_FILE." >&2
    echo "Fill in every field before running unattended." >&2
    exit 1
  fi
done
# INSTALL_HOSTNAME is intentionally excluded from the loop above and
# allowed to be genuinely empty -- this file's own header comment (and
# install-homeserver.conf.example's) already documented "leave empty to
# keep whatever's already set" as supported, but nothing actually was:
# the validation loop rejected an empty value outright, and even past
# that, step_set_hostname unconditionally called `hostnamectl
# set-hostname ""`, which errors rather than leaving the hostname alone.
# Caught live (#787's actual homeserver reinstall, 2026-08-09) -- worked
# around at the time by filling in the box's real current hostname
# explicitly, but the documented empty-value behavior is real and worth
# actually supporting, not just documenting.
# HOME_WG_PRIVATE_KEY is intentionally allowed to be empty/absent — if the
# original tunnel private key wasn't part of the backup (it wasn't captured
# by the .env-only backup pass, see #518 comment history), step_wireguard_config
# generates a fresh keypair and step_wireguard_sync_vps_peer pushes the new
# public key to the VPS side automatically.
#
# ARCANE_URL/ARCANE_API_TOKEN (#1502): a real bootstrap gap, not just a
# documentation note like the ones above. step_arcane_import_stacks needs
# an already-running Arcane with an API key generated through its own UI
# (Settings -> API Keys, after Arcane's first interactive login -- an
# unattended installer can't complete Arcane's own OIDC/passkey login
# itself). On a truly from-scratch host that also means Arcane has to
# already be installed and reachable before this script gets this far,
# which step_dockge_install does NOT currently do -- it still installs
# plain Dockge (confirmed live, #1502), not Arcane, unlike every already-
# provisioned APIARY homeserver today. Fixing that install/bootstrap gap
# is tracked as an explicit follow-up rather than done here; until it
# lands, a from-scratch run needs Arcane stood up and an API key minted by
# hand before --config can point at a filled-in ARCANE_API_TOKEN.

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
  [[ -n "${INSTALL_HOSTNAME:-}" ]] && hostnamectl set-hostname "$INSTALL_HOSTNAME"
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
    ca-certificates curl dnsutils gnupg lsb-release git jq rsync ufw \
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

# #1388: short-lived Docker veth interfaces vanish before networkd-dispatcher,
# libvirtd, and systemd-resolved get around to inspecting them, producing a
# continuous "not found"/"ethtool ioctl error"/"Failed to determine whether
# the interface is managed" flood at warning/error severity that buries real
# host/network failures -- confirmed live: 16,593 networkd-dispatcher and
# 4,754 libvirtd priority-3 entries in 24 hours, almost entirely veth noise.
#
# networkd-dispatcher has zero configured hook scripts under any
# /etc/networkd-dispatcher/*.d/ on this host (confirmed live), so it does no
# actual work here -- disabling it entirely, rather than trying to filter its
# output, is the clean fix its own noise volume (the majority of the flood)
# deserves. Idempotent to a box where it isn't installed at all.
#
# libvirtd/systemd-resolved still do real work for real interfaces, so they
# stay running; systemd's own LogFilterPatterns= (v253+, this fleet runs
# 259) drops exactly the veth-shaped messages by content before they reach
# journald, leaving every other warning/error -- real NICs, bridges,
# WireGuard, libvirt-managed taps -- fully intact. A broad severity/rate
# suppression was deliberately rejected (see the issue): this is the
# narrowest mechanism systemd offers that's actually message-content-aware.
step_quiet_veth_noise() {
  if systemctl list-unit-files networkd-dispatcher.service 2>/dev/null | grep -q networkd-dispatcher; then
    systemctl disable --now networkd-dispatcher.service || true
  fi

  if systemctl list-unit-files libvirtd.service 2>/dev/null | grep -q libvirtd; then
    mkdir -p /etc/systemd/system/libvirtd.service.d
    cat >/etc/systemd/system/libvirtd.service.d/99-veth-noise.conf <<'EOF'
[Service]
LogFilterPatterns=~ethtool ioctl error on veth[0-9a-f]+: No such device
EOF
  fi

  if systemctl list-unit-files systemd-resolved.service 2>/dev/null | grep -q systemd-resolved; then
    mkdir -p /etc/systemd/system/systemd-resolved.service.d
    cat >/etc/systemd/system/systemd-resolved.service.d/99-veth-noise.conf <<'EOF'
[Service]
LogFilterPatterns=~veth[0-9a-f]+: Failed to determine whether the interface is managed
EOF
  fi

  systemctl daemon-reload
  if systemctl is-active --quiet libvirtd.service 2>/dev/null; then
    systemctl restart libvirtd.service
  fi
  if systemctl is-active --quiet systemd-resolved.service 2>/dev/null; then
    systemctl restart systemd-resolved.service
  fi
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

  # wg0.conf gets an explicit `chmod 600` below, so no umask override is
  # needed here -- and a bare (unscoped) `umask 077` would be actively
  # harmful: umask is a shell-wide setting that persists for the rest of
  # this script's process, not just this function. Found live during
  # #787's homeserver reinstall (2026-08-09): it silently downgraded every
  # file `git clone` wrote in step_clone_repo (Phase 5, runs right after
  # this) from the tracked 100644/100755 modes to 0600/0700, breaking any
  # bind-mounted repo file a container reads as a non-root user --
  # elasticsearch-setup.sh landed at 0600 root:root and the elasticsearch
  # container (runs as a non-root uid) got "Permission denied" trying to
  # read it. The other two umask uses in this file ((umask 027; ...) for
  # postgres-password/bootstrap-admin-password) correctly scope it to a
  # subshell instead -- this one didn't, and there's no reason to: this
  # function already chmods its one sensitive file explicitly.

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

  # #1059 investigation: this must be HOME_WG_ADDRESS (stripped of its /24),
  # not VPS_WG_ADDRESS -- the block being matched is the VPS's own peer
  # entry FOR the home side, so its AllowedIPs is home's tunnel IP
  # (confirmed live against the real VPS config: AllowedIPs = 10.8.0.2/32,
  # not 10.8.0.1/32). Using VPS_WG_ADDRESS here matched zero peer blocks on
  # the real config -- a silent no-op with no error, the exact failure
  # class this function's own comments already describe from #518 (wrong
  # keys, clean `wg show`, 0 bytes received, forever). The match-count
  # guard below now also fails loudly instead of silently no-op-ing if this
  # regresses again.
  local home_ip="${HOME_WG_ADDRESS%%/*}"
  ssh -i "$VPS_SSH_KEY" -p "$VPS_SSH_PORT" -o StrictHostKeyChecking=accept-new \
    -o ConnectTimeout=10 "${VPS_SSH_USER}@${VPS_SSH_HOST}" bash -s -- "$pubkey" "$psk" "$home_ip" <<'REMOTE'
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
matched = 0
for b in blocks:
    if b.startswith('[Peer]') and f"{peer_ip}/32" in b:
        matched += 1
        b = re.sub(r'PublicKey\s*=\s*\S+', f'PublicKey = {new_pub}', b)
        if re.search(r'^PresharedKey\s*=', b, re.MULTILINE):
            b = re.sub(r'PresharedKey\s*=\s*\S+', f'PresharedKey = {new_psk}', b)
        else:
            b = re.sub(r'(PublicKey\s*=\s*\S+\n)', rf'\1PresharedKey = {new_psk}\n', b)
    out.append(b)
# Fail loudly on 0 or >1 matches instead of silently no-op-ing (0 matches)
# or updating the wrong/multiple peers (>1) -- exactly the kind of mistake
# a clean `wg show` and no error would otherwise hide until the next real
# handshake attempt fails.
if matched != 1:
    print(f"expected exactly 1 peer block with AllowedIPs {peer_ip}/32, found {matched}", file=sys.stderr)
    sys.exit(1)
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
    # REPO_DIR can already exist and be non-empty even on a fresh box:
    # other stacks' sshfs mounts live under it (e.g. apiary/logs/suricata,
    # set up by step_sshfs_boot_ordering's fstab entries), and systemd
    # creates a mount unit's mountpoint directory at boot regardless of
    # whether the mount itself actually succeeds. A plain `git clone`
    # refuses to clone into a non-empty directory -- found live during
    # #787's homeserver reinstall (2026-08-09), and only surfaced now
    # because with_retry actually propagates failure correctly (#1078);
    # before that fix this step silently "succeeded" while never cloning
    # anything, and everything downstream cascaded off a missing repo.
    # `git init` + fetch + checkout works fine into a pre-populated
    # directory as long as there's no tracked-path collision (there isn't
    # -- logs/ and state/ aren't part of this repo's tree).
    mkdir -p "$REPO_DIR"
    if [[ ! -d "$REPO_DIR/.git" ]]; then
      git -C "$REPO_DIR" init -q
      git -C "$REPO_DIR" remote add origin "$GIT_REPO_URL"
    fi
    with_retry 3 10 git -C "$REPO_DIR" fetch origin "$GIT_REF"
    git -C "$REPO_DIR" checkout -f -B "$GIT_REF" FETCH_HEAD
  fi
}

# ---------------------------------------------------------------------------
# Phase 6 — Dockge
# ---------------------------------------------------------------------------
  # STALE (#1502): every already-provisioned APIARY homeserver replaced
  # Dockge with Arcane (#1185) months before this migration -- deploy.yml
  # and docker-compose.arcane.yml both assume Arcane, not this. This step
  # was never updated to match, so a genuinely from-scratch install run
  # today still stands up plain Dockge here, then step_arcane_import_stacks
  # (later in this same run) fails outright with nothing at ARCANE_URL to
  # talk to. Tracked as an explicit follow-up (see ARCANE_URL/
  # ARCANE_API_TOKEN's own comment above) rather than fixed inside #1502 --
  # replacing this needs its own Arcane secrets-bootstrap step
  # (ENCRYPTION_KEY/JWT_SECRET/OIDC_CLIENT_SECRET, no *_FILE variant
  # Arcane supports, same shape as step_provision_keycloak_secrets) and
  # verification against a real from-scratch host, which nothing in this
  # change had a safe way to do.
step_dockge_install() {
  mkdir -p /var/dockge/data /var/dockge/stacks
  if docker ps -a --format '{{.Names}}' | grep -qx dockge; then
    return 0
  fi
  # #787: bound to the WireGuard tunnel IP only, matching every other
  # gateway-fronted service (HP_BIND=10.8.0.2, .env.example) and the real
  # VPS-side socat-hp-dockge bridge (TCP4:10.8.0.2:5001). A plain -p
  # 5001:5001 binds 0.0.0.0 -- confirmed live, this made Dockge's own web UI
  # (root-equivalent Docker control via its read-write docker.sock mount)
  # directly reachable from the LAN with zero Keycloak/oauth2-proxy
  # involvement, bypassing the gateway entirely.
  docker run -d --name dockge --restart unless-stopped \
    -p 10.8.0.2:5001:5001 \
    -e DOCKGE_STACKS_DIR=/var/dockge/stacks \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/dockge/data:/app/data \
    -v /var/dockge/stacks:/var/dockge/stacks \
    louislam/dockge:1
}

# ---------------------------------------------------------------------------
# Phase 7 — secret restore from the LAN backup host
# ---------------------------------------------------------------------------
# Maps Dockge stack name -> "<name>.env" file directly under BACKUP_HOST_PATH
# (a flat directory, not "<name>/.env" subdirectories -- confirmed against
# the real backup host live during #787's homeserver reinstall, 2026-08-09).
# 1:1 for everything except pihole, which the backup captured a bare .env for
# (no compose file was ever backed up for it -- see step_pihole_provision,
# which reconstructs a minimal one since it isn't part of this git repo).
ENV_RESTORE_STACKS=(
  honeypot-keycloak honeypot-init honeypot-cowrie honeypot-dionaea honeypot-conpot honeypot-dnp3
  honeypot-http honeypot-multipot honeypot-dashboard honeypot-payload-analysis
  honeypot-tanner honeypot-elk honeypot-utilities honeypot-stack ghidra ghosts
  pihole
)

step_restore_env_files() {
  local failures=0
  for name in "${ENV_RESTORE_STACKS[@]}"; do
    local src="${BACKUP_HOST_PATH}/${name}.env"
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
# #1502: the 32 honeypot-* stacks (STACK_DEFS' old 21 plus the 11 that had
# drifted out of it -- see arcane/manifests/home-production.json's own
# generation history) are no longer symlinked in from a shared
# /var/stacks/apiary checkout. Each one's build context and config now
# lives self-contained under arcane/home/<name>/ (or, for the 6 stacks that
# were already self-contained before this migration -- auth-events-worker,
# llm-worker, ml-worker, analysis/ghidra, sandbox/ghosts, pihole -- at its
# existing path), and Arcane's own directory-aware Git sync owns
# materializing and deploying it, driven by this manifest. The manifest
# also lists those 6 non-honeypot-* stacks (the live host has all 38 under
# Arcane), but step_arcane_import_stacks below only imports the
# honeypot-*-prefixed entries -- the other 6 keep going through their own
# existing dedicated steps (step_pihole_provision, step_ghidra_stack_*,
# step_ml_worker_start, step_llm_worker_selftest,
# step_auth_events_worker_start) for a from-scratch install. Folding those
# into Arcane management too is a deliberate follow-up, not done here:
# each of those steps carries real historical incident fixes (address
# collisions, relative-build-path breakage) that need the same live
# verification this honeypot-* replacement got, and doing that without a
# disposable test host to break wasn't a safe call to make unilaterally
# inside this already-large change.
ARCANE_STACK_MANIFEST="$REPO_DIR/arcane/manifests/home-production.json"

# arcane_api <method> <path> [json-body] -- authenticated call against this
# host's own Arcane instance. ARCANE_URL/ARCANE_API_TOKEN are operator-
# provided config (see install-homeserver.conf.example): an unattended
# installer can't complete Arcane's own interactive OIDC/passkey login, so
# bootstrapping requires a pre-generated API key (Arcane's own UI, Settings
# -> API Keys, after its first login) the same way step_provision_keycloak_secrets
# requires the Keycloak realm to already exist rather than creating one
# from nothing.
arcane_api() {
  local method="$1" path="$2" body="${3:-}"
  local -a curl_args=(-sS -X "$method" "${ARCANE_URL%/}/api${path}" \
    -H "Authorization: Bearer $ARCANE_API_TOKEN" -H "Content-Type: application/json")
  [[ -n "$body" ]] && curl_args+=(-d "$body")
  curl "${curl_args[@]}"
}

step_arcane_import_stacks() {
  [[ -f "$ARCANE_STACK_MANIFEST" ]] || { echo "missing $ARCANE_STACK_MANIFEST"; return 1; }

  # Register the apiary repo if it isn't already (idempotent: Arcane has no
  # upsert-by-name endpoint, so check first). Public HTTPS clone, no
  # credentials needed -- confirmed live against Xore/APIARY.
  local existing_repo_id
  existing_repo_id=$(arcane_api GET /customize/git-repositories \
    | jq -r '.data[] | select(.name=="apiary") | .id' | head -1)
  if [[ -z "$existing_repo_id" ]]; then
    local repo_resp
    repo_resp=$(arcane_api POST /customize/git-repositories \
      "$(jq -n --arg url "$GIT_REPO_URL" \
        '{name:"apiary", url:$url, authType:"none", enabled:true}')")
    existing_repo_id=$(echo "$repo_resp" | jq -r '.data.id')
    [[ -n "$existing_repo_id" && "$existing_repo_id" != "null" ]] || {
      echo "failed to register apiary git repository in Arcane: $repo_resp" >&2
      return 1
    }
  fi

  # environmentId 0 is Arcane's own "Local Docker" environment -- the only
  # one this single-host deployment has (confirmed live: /api/environments
  # returns exactly one entry, id "0", for every APIARY homeserver).
  #
  # Confirmed live during #1502's own migration: Arcane's directory sync
  # refuses to create a project if anything already exists at that path
  # ("a directory with that name already exists; refusing to create a
  # duplicate") -- it fails closed rather than merging into or wiping it,
  # which is good for safety but means step_restore_env_files running
  # before this step (it pre-creates /var/dockge/stacks/<name>/.env for
  # anything the backup had) would block every one of those stacks from
  # ever being imported. Stage any pre-existing .env aside, let Arcane
  # create the directory fresh, then put it back and re-deploy -- the same
  # backup/remove/sync/restore sequence used for every stack in the real
  # #1502 cutover, just automated here instead of run by hand.
  local failures=0 name compose_path
  while IFS=$'\t' read -r name compose_path; do
    local dir="/var/dockge/stacks/$name"
    [[ -f "$dir/compose.yml" ]] && { echo "$name: already synced, skipping"; continue; }

    local staged_env=""
    if [[ -f "$dir/.env" ]]; then
      staged_env="$(mktemp)"
      mv "$dir/.env" "$staged_env"
    fi
    [[ -d "$dir" ]] && rm -rf "$dir"

    echo "-- importing $name via Arcane directory sync"
    local resp status project_id
    resp=$(arcane_api POST /environments/0/gitops-syncs \
      "$(jq -n --arg name "$name" --arg repo "$existing_repo_id" \
             --arg branch "$GIT_REF" --arg path "$compose_path" \
        '{name:$name, repositoryId:$repo, branch:$branch, composePath:$path,
          autoSync:false, syncDirectory:true, syncInterval:300}')")
    status=$(echo "$resp" | jq -r '.data.lastSyncStatus // "unknown"')
    project_id=$(echo "$resp" | jq -r '.data.projectId // empty')

    if [[ -n "$staged_env" ]]; then
      mkdir -p "$dir"
      mv "$staged_env" "$dir/.env"
      chmod 600 "$dir/.env"
      if [[ -n "$project_id" ]]; then
        arcane_api POST "/environments/0/projects/$project_id/up" >/dev/null
      fi
    fi

    if [[ "$status" != "success" && -z "$staged_env" ]]; then
      # Matches this repo's own live experience migrating #1502: a stack
      # whose required secrets aren't in place yet fails its first deploy
      # closed rather than starting broken -- step_bootstrap_missing_envs
      # (below) and the per-stack secret-provisioning steps run right
      # after this one and re-trigger a deploy once real values exist.
      echo "  $name: sync reported '$status' (often expected pre-secrets -- see: $resp)"
      failures=$((failures + 1))
    fi
  done < <(jq -r '.[] | select(.syncName | startswith("honeypot-")) | [.syncName, .dockerComposePath] | @tsv' "$ARCANE_STACK_MANIFEST")

  echo "$failures stack(s) reported a non-success initial sync (see above -- often just missing secrets, not a hard failure)."
  return 0
}

# #1019: arcane/home/honeypot-keycloak/compose.yml's realm-template mount was fixed to an
# absolute /opt/stacks/apiary path, but the login theme
# (KEYCLOAK_THEME_DIR, default /var/dockge/stacks/honeypot-keycloak/theme/
# apiary) isn't part of this repo at all -- it's Xore/auth-backend's
# themes/apiary, presentation-only, checked out separately.
# .github/workflows/deploy.yml's CI path already does this (a dedicated
# `actions/checkout` of Xore/auth-backend, then `rsync --delete` into
# theme/apiary); this step is install-homeserver.sh's equivalent for a
# from-scratch homeserver rebuild, which has no CI runner to do it.
step_stage_keycloak_theme() {
  local theme_repo_dir="$(dirname "$REPO_DIR")/auth-backend"
  if [[ -d "$theme_repo_dir/.git" ]]; then
    with_retry 3 10 git -C "$theme_repo_dir" fetch origin
    git -C "$theme_repo_dir" checkout main
    with_retry 3 10 git -C "$theme_repo_dir" pull --ff-only origin main
  else
    mkdir -p "$(dirname "$theme_repo_dir")"
    with_retry 3 10 git clone --branch main "$AUTH_THEME_REPO_URL" "$theme_repo_dir"
  fi
  local destination="/var/dockge/stacks/honeypot-keycloak/theme"
  install -d -m 755 "$destination"
  rsync -a --delete "$theme_repo_dir/themes/apiary/" "$destination/apiary/"
}

step_provision_keycloak_secrets() {
  # #787: step_provision_stack_dirs only creates an empty secrets/ dir --
  # nothing populated postgres-password/bootstrap-admin-password before this,
  # so a genuinely fresh, unattended install would fail here (Postgres'
  # POSTGRES_PASSWORD_FILE and Keycloak's own entrypoint both read files that
  # never existed). This test/reinstall path resets Keycloak to a known
  # initial admin rather than restoring a prior one -- same "start from
  # zero" treatment as the rest of the honeypot stack's data, not an
  # exception carved out just for identity.
  local dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  install -d -m 750 "$dir"
  if [[ ! -f "$dir/postgres-password" ]]; then
    (umask 027; openssl rand -base64 48 > "$dir/postgres-password")
    echo "generated postgres-password"
  fi
  if [[ ! -f "$dir/bootstrap-admin-password" ]]; then
    (umask 027; printf 'admin123\n' > "$dir/bootstrap-admin-password")
    echo "wrote initial bootstrap-admin-password (admin/admin123 -- rotate after first login)"
  fi
  chown root:root "$dir"/postgres-password "$dir"/bootstrap-admin-password
  chmod 440 "$dir"/postgres-password "$dir"/bootstrap-admin-password
  local env_file="/var/dockge/stacks/honeypot-keycloak/.env"
  if [[ -f "$env_file" ]] && grep -q '^KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME=' "$env_file"; then
    sed -i 's/^KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME=.*/KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME=admin/' "$env_file"
  fi
}

step_bootstrap_missing_envs() {
  # Belt-and-suspenders after step_restore_env_files: any stack that still
  # has no .env at all (backup genuinely never had one, e.g. a stack created
  # after the last backup pass) gets bootstrapped from its .env.example so
  # `docker compose up` doesn't fail outright on a missing required file --
  # it'll be full of CHANGE_ME placeholders and won't be fully functional,
  # but that's a visible, fixable gap instead of a silent compose failure.
  local n=0
  local name compose_path
  while IFS=$'\t' read -r name compose_path; do
    local dir="/var/dockge/stacks/$name"
    [[ -f "$dir/.env" ]] && continue
    # #1502: each stack's .env.example now lives next to its own compose.yml
    # under arcane/home/<name>/ (moved there in the same migration that
    # gave every honeypot-* stack an explicit name: and a self-contained
    # directory) rather than at two special-cased repo-root files plus a
    # generic root fallback.
    local example="$REPO_DIR/$(dirname "$compose_path")/.env.example"
    if [[ -f "$example" ]]; then
      cp "$example" "$dir/.env"
      chmod 600 "$dir/.env"
      n=$((n + 1))
      echo "bootstrapped placeholder .env for $name from ${example#"$REPO_DIR"/}"
    fi
  done < <(jq -r '.[] | select(.syncName | startswith("honeypot-")) | [.syncName, .dockerComposePath] | @tsv' "$ARCANE_STACK_MANIFEST")
  echo "Bootstrapped $n placeholder .env file(s) — review for CHANGE_ME values."
}

step_create_shared_resources() {
  # arcane/home/honeypot-init/compose.yml declares these as external:true. On a genuinely
  # fresh Docker install none of them exist yet, and honeypot-init's
  # containers will fail to even create rather than run and fail --
  # STACK-REBUILD.md documents this exact trap.
  docker network inspect honeynet >/dev/null 2>&1 || docker network create honeynet

  # arcane/home/honeypot-dashboard/compose.yml also declares honeypot-llm as external:true
  # (its query-time embedding call to Ollama), but unlike honeynet it has a
  # real owner: analysis/ghidra/docker-compose.ghidra.yml defines it for
  # real (internal:true, no external:true) and only creates it when
  # ghidra-start runs -- much later than start-remaining, which is what
  # actually starts honeypot-dashboard. Found live during #787's homeserver
  # reinstall (2026-08-09), only visible now that with_retry propagates
  # failure correctly (#1078): "network honeypot-llm declared as external,
  # but could not be found", honeypot-dashboard never came up. --internal
  # matches ghidra's own definition exactly, so when ghidra-start's compose
  # run later reconciles this same network name it finds a config it
  # already agrees with rather than a conflicting one.
  docker network inspect honeypot-llm >/dev/null 2>&1 || docker network create honeypot-llm --internal

  docker volume inspect dionaea-lib >/dev/null 2>&1 || docker volume create dionaea-lib
  docker volume inspect yara-results >/dev/null 2>&1 || docker volume create yara-results

  # arcane/home/honeypot-init/compose.yml's own header comment: "state/init-markers/ must
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
  # #1255's investigation: honeypot-init.env.example already carries
  # MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY placeholders (optional, empty by
  # default), but nothing ever actually enabled the geoip-update Compose
  # profile those gate -- a fresh install with real credentials filled in
  # would still silently end up with no GeoIP databases, no attack-origin
  # map markers, and every ingested document tagged
  # _geoip_database_unavailable_GeoLite2-*. Enable the profile automatically
  # whenever both values are actually filled in; leave it off (with a clear
  # message, not a silent gap) otherwise.
  local init_env="/var/dockge/stacks/honeypot-init/.env"
  # #1226: threat-cidrs-refresh (Spamhaus/Tor/AWS/GCP -- all free, zero-auth
  # sources per refresh-threat-cidrs.sh's own header) has no credential to
  # gate on the way geoip-update below does, so unlike that one it belongs
  # on unconditionally rather than behind an env-driven check. Nothing
  # enabled it before this: a fresh install left threat-cidrs.csv never
  # created at all, so campaigns.go's Provider/Intel classification (and
  # #1218's correlator-worker Providers grouping) silently had no CIDR data
  # to classify against.
  local -a compose_profile_args=(--profile threat-intel)
  if [[ -f "$init_env" ]] \
    && grep -qE '^MAXMIND_ACCOUNT_ID=.+' "$init_env" \
    && grep -qE '^MAXMIND_LICENSE_KEY=.+' "$init_env"; then
    compose_profile_args+=(--profile geoip-update)
    echo "honeypot-init: MAXMIND_ACCOUNT_ID/LICENSE_KEY are set — enabling the geoip-update profile."
  else
    echo "honeypot-init: MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY not set in $init_env —"
    echo "  skipping GeoIP database provisioning. The attack-origin map and every"
    echo "  GeoIP-derived field will stay empty until you fill those in (a free"
    echo "  MaxMind account + license key, see docs/dashboard/geoip/README.md)"
    echo "  and re-run: cd /var/dockge/stacks/honeypot-init && docker compose -f compose.yml --profile geoip-update up -d geoipupdate"
  fi
  if ! (cd /var/dockge/stacks/honeypot-init && with_retry 3 15 docker compose -f compose.yml "${compose_profile_args[@]}" up -d); then
    echo "honeypot-init: docker compose up -d failed" >&2
    return 1
  fi
  # honeypot-init's jobs are one-shots; give them a bounded window to exit 0
  # rather than racing straight into the sensor stacks that assume its log
  # paths/ES templates/persona state already exist. geoipupdate (and
  # threat-cidrs-refresh, same shape) are deliberately long-running
  # (restart: unless-stopped) and excluded from this check -- them still
  # running is the success case, not something to wait out.
  local waited=0
  while (( waited < 120 )); do
    local running
    running=$(docker compose -f /var/dockge/stacks/honeypot-init/compose.yml ps --status running -q 2>/dev/null \
      | xargs -r docker inspect --format '{{.Name}}' 2>/dev/null \
      | grep -vE '/hp-(geoipupdate|threat-cidrs-refresh)$' | wc -l)
    (( running == 0 )) && return 0
    sleep 5
    waited=$(( waited + 5 ))
  done
  echo "honeypot-init still has running containers after 120s — check for the"
  echo "Elasticsearch-not-ready trap described in docs/STACK-REBUILD.md."
  return 1
}

step_start_remaining_stacks() {
  # #1502: Arcane's own directory sync already brought each stack up as
  # part of step_arcane_import_stacks -- this step is now a safety-net
  # re-assertion (idempotent: `up -d --wait` on an already-running,
  # unchanged stack is a no-op), not the primary start mechanism. Kept
  # rather than removed so a secret provisioned by a step *after* the
  # import (e.g. keycloak's, dashboard's) still gets a real `up` against
  # it even if that step didn't call Arcane's own /up endpoint itself.
  local failures=0 name compose_path
  while IFS=$'\t' read -r name compose_path; do
    [[ "$name" == "honeypot-elk" || "$name" == "honeypot-init" ]] && continue
    local dir="/var/dockge/stacks/$name"
    [[ -f "$dir/compose.yml" ]] || continue
    echo "-- $name: docker compose up -d --wait"
    if ! (cd "$dir" && with_retry 3 15 docker compose -f compose.yml up -d --wait); then
      echo "FAILED: $name"
      failures=$((failures + 1))
    fi
  done < <(jq -r '.[] | select(.syncName | startswith("honeypot-")) | [.syncName, .dockerComposePath] | @tsv' "$ARCANE_STACK_MANIFEST")
  [[ $failures -eq 0 ]]
}

# ---------------------------------------------------------------------------
# Phase 8a1 — auth-events-worker (#1066): Keycloak/gateway auth-failure
# telemetry. Runs here, after start-remaining, because it needs hp-keycloak
# actually healthy (to grant its service-account client the view-events
# role) -- `up -d --wait` in the previous step already confirmed that.
# ---------------------------------------------------------------------------
step_provision_events_poller_secrets() {
  local secrets_dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  [[ -f "$secrets_dir/bootstrap-admin-password" ]] || {
    echo "no bootstrap-admin-password at $secrets_dir -- was provision-keycloak-secrets skipped?" >&2
    return 1
  }
  KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  KEYCLOAK_ADMIN_PASSWORD="$(< "$secrets_dir/bootstrap-admin-password")" \
    "$REPO_DIR/keycloak/provision-events-poller.sh"
}

step_provision_dashboard_oidc_secret() {
  # honeypot-dashboard is one of the generic STACK_DEFS stacks
  # step_start_remaining_stacks already started (and it has no secret yet
  # at that point, so it crash-loops on first boot) -- this step runs
  # after that, once Keycloak is actually up, same as
  # step_provision_events_poller_secrets right above. No need to also
  # restart dashboard/dashboard-b here: both have restart: unless-stopped,
  # so their own crash-restart loop picks up the freshly written secret
  # within seconds.
  local secrets_dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  [[ -f "$secrets_dir/bootstrap-admin-password" ]] || {
    echo "no bootstrap-admin-password at $secrets_dir -- was provision-keycloak-secrets skipped?" >&2
    return 1
  }
  KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  KEYCLOAK_ADMIN_PASSWORD="$(< "$secrets_dir/bootstrap-admin-password")" \
    "$REPO_DIR/keycloak/provision-dashboard-oidc-secret.sh"
}

step_auth_events_worker_start() {
  # Same relative-build-context symlink-the-whole-directory reasoning as
  # step_ml_worker_start (docker-compose.yml here also has `build: context: .`).
  # Secrets deliberately do NOT live under this symlinked path -- see
  # docker-compose.yml's own volume-mount comment for why
  # EVENTS_POLLER_SECRETS_DIR is a sibling directory instead.
  local src="$REPO_DIR/auth-events-worker"
  [[ -d "$src" ]] || { echo "no auth-events-worker/ directory in repo"; return 1; }
  rm -rf /var/dockge/stacks/auth-events-worker
  ln -sfn "$src" /var/dockge/stacks/auth-events-worker
  ln -sf "$src/docker-compose.yml" "$src/compose.yml"
  (cd "$src" && with_retry 3 15 docker compose -f compose.yml up -d --wait) || return 1

  # No Docker HEALTHCHECK on this worker either -- same reasoning and same
  # fix as step_ml_worker_start's own comment (#593): poll the log for the
  # line worker.py actually emits once it's genuinely ready, instead of
  # trusting compose's "running" status alone.
  local waited=0 max_wait=60
  while (( waited < max_wait )); do
    if docker logs hp-auth-events-worker 2>&1 | grep -q 'auth-events-worker starting'; then
      echo "auth-events-worker confirmed ready"
      return 0
    fi
    sleep 5
    waited=$(( waited + 5 ))
  done
  echo "auth-events-worker container is running but never logged its startup line within ${max_wait}s" >&2
  return 1
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
# /opt/stacks/apiary, not the pre-#783-rebrand honeypot-stack -- confirmed
# live against the VPS during #787's homeserver reinstall (2026-08-09):
# the old path doesn't exist there anymore, silently failing this mount
# (masked non-fatally without real VPS credentials to notice with, until
# now). NOTE: this same stale honeypot-stack path still appears in ~20
# other files across the repo (docs and other scripts) -- out of scope for
# this fix, tracked separately.
root@${VPS_WG_ADDRESS}:/opt/stacks/apiary/logs/suricata $suricata_dir fuse.sshfs $opts 0 0
root@${VPS_WG_ADDRESS}:/opt/stacks/apiary/logs/portbridge $portbridge_dir fuse.sshfs $opts 0 0
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
# Phase 8b — Pi-hole + DNSCrypt. The LAN backup only captured pihole/.env;
# the complete, tested deployment definition now lives under pihole/.
# ---------------------------------------------------------------------------
step_pihole_provision() {
  local dir="/var/dockge/stacks/pihole"
  mkdir -p "$dir/etc-pihole" "$dir/etc-dnsmasq.d" "$dir/dnscrypt-proxy"

  # Binding 0.0.0.0:53 collides with hp-dns-honeypot, which already publishes
  # 53/udp on 10.8.0.2 (the WireGuard bind IP every honeypot sensor uses,
  # per HP_BIND / CGNAT-DEPLOYMENT.md's "never reachable from your home LAN"
  # design) -- 0.0.0.0 overlaps every interface including that one, so
  # Docker's port allocator refuses the bind. Confirmed live (#518 test run):
  # deterministic "address already in use" on every attempt, not a race.
  # Pihole is real home-LAN infra, not a honeypot component, so it belongs on
  # the actual LAN-facing IP instead. A box with more than one LAN interface
  # (see docs/research/518-smoke-test-research.md's NIC inventory for this
  # deployment's specifics) may have more than one candidate address --
  # which one pihole should actually serve is an operator choice, not
  # something to auto-detect via the default route (that picked the wrong
  # one of two on this box's first pass, confirmed live #518), hence
  # PIHOLE_LAN_IP is an explicit config value, not inferred.
  local lan_ip="$PIHOLE_LAN_IP"
  install -m 0644 "$REPO_DIR/pihole/compose.yml" "$dir/compose.yml"
  install -m 0444 "$REPO_DIR/pihole/dnscrypt-proxy.toml" \
    "$dir/dnscrypt-proxy/dnscrypt-proxy.toml"
  # klutchell/dnscrypt-proxy is a distroless image pinned above and runs as
  # the standard nonroot uid/gid 65532. It must be able to atomically refresh
  # public-resolvers.md in this directory, while the config itself stays
  # read-only.
  chown 65532:65532 "$dir/dnscrypt-proxy"
  sed -i "s/__LAN_IP__/$lan_ip/g" "$dir/compose.yml"
}

step_pihole_start() {
  [[ -f /var/dockge/stacks/pihole/.env ]] || { echo "no pihole .env restored — skipping start"; return 1; }
  (cd /var/dockge/stacks/pihole && with_retry 3 15 docker compose -f compose.yml up -d --wait)
}

step_pihole_verify() {
  local dir="/var/dockge/stacks/pihole"
  local dnscrypt_answer pihole_answer lan_answer

  # Probe each hop separately so an unattended install failure identifies
  # whether the encrypted upstream, Pi-hole forwarding, or LAN bind is bad.
  dnscrypt_answer="$(cd "$dir" && docker compose exec -T dnscrypt \
    dnscrypt-proxy -config /config/dnscrypt-proxy.toml \
    -resolve example.com,127.0.0.1:5053 2>&1)" || return
  pihole_answer="$(docker exec pihole \
    dig @127.0.0.1 example.com A +time=3 +tries=1 +short)" || return
  lan_answer="$(dig @"$PIHOLE_LAN_IP" example.com A +time=3 +tries=1 +short)" || return

  [[ "$dnscrypt_answer" == *"Resolver IP"* ]] || {
    echo "DNSCrypt returned no resolver answer: $dnscrypt_answer" >&2
    return 1
  }
  [[ -n "$pihole_answer" ]] || { echo "Pi-hole returned no recursive answer" >&2; return 1; }
  [[ -n "$lan_answer" ]] || { echo "Pi-hole returned no LAN-side answer" >&2; return 1; }
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

  # #1236: the dashboard's own semantic search (dashboard/main.go's
  # LLM_EMBEDDING_MODEL, default "nomic-embed-text:latest") hits this same
  # ollama instance for embeddings -- a completely different kind of model
  # (embedding, not chat/completion) than the three qualification-gated
  # slots above, so it deliberately isn't in approved-models.json's own
  # benchmark/gate manifest. Without this, semantic search 404'd on every
  # fresh install with "model \"nomic-embed-text:latest\" not found, try
  # pulling it first" until someone happened to pull it by hand.
  docker exec ghidra-ollama-1 ollama pull nomic-embed-text:latest
}

step_ghidra_worker_install() {
  # #636: the two steps above only bring up the Docker containers (ghidra
  # REST API, ollama, statictools) -- confirmed live that this alone leaves
  # automated triage completely non-functional. Nothing actually reads
  # captured binaries and submits them; that's ghidra-worker.py, a
  # host-level systemd service install-analysis-host.sh installs and this
  # script never called. Zero completed analyses and no systemd unit at all
  # were found on a "healthy" fresh install before this step existed.
  #
  # --stack-dir "": tells install-analysis-host.sh to reconcile the compose
  # stack in place from this checkout instead of deploying a second copy to
  # /opt/stacks/ghidra. That path resolves to the exact same already-running
  # Dockge stack step_ghidra_stack_provision set up (both share the "ghidra"
  # compose project name, derived from the directory holding the compose
  # file) -- a second deploy path would just be a second file to keep in
  # sync with this one. `docker compose up -d` against an already-matching
  # project is a safe no-op reconciliation here, not a duplicate deployment.
  #
  # --skip-pull: step_ollama_model_pull above already pulled the pinned
  # model; re-pulling here would just be a redundant round trip to verify a
  # manifest that's already known current.
  "$REPO_DIR/analysis/ghidra/install-analysis-host.sh" --stack-dir "" --skip-pull
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
  (cd "$src" && with_retry 3 15 docker compose -f compose.yml up -d --wait) || return 1

  # #593: `--wait` above only waits for the container to reach "running" --
  # ml-worker has no Docker HEALTHCHECK defined, so this step reported OK on
  # every run even while the container was stuck in its own internal
  # 5-minute Elasticsearch-connect retry loop (a real requirements.txt
  # regression, #599) or had built against a broken dependency set
  # entirely. Neither failure mode makes the container exit or crash-loop
  # at the Docker level, so `--wait` alone can never catch either one.
  # Poll the container's own log for the exact line worker.py emits once
  # it's genuinely ready, instead of trusting compose's exit code.
  local waited=0 max_wait=90
  while (( waited < max_wait )); do
    if docker logs hp-ml-worker 2>&1 | grep -q 'Worker ready\.'; then
      echo "ml-worker confirmed ready (found 'Worker ready.' in logs)"
      return 0
    fi
    sleep 5
    waited=$(( waited + 5 ))
  done
  echo "ml-worker container is running but never logged 'Worker ready.' within ${max_wait}s -- likely stuck retrying a dependency (see #593)" >&2
  return 1
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
  # docs/llm-worker/README.md's Quick Start: bring the container up, then exec
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

step_backup_timer_install() {
  # #1413: analysis/backup-honeypot.sh existed but was never actually wired
  # into anything that would run it -- no systemd timer, no cron entry, zero
  # snapshots in the live honeypot-fs repository despite it being registered
  # on the cluster. Same class of "the script exists but nothing invokes it"
  # gap as ghidra-worker-install above.
  "$REPO_DIR/analysis/install-backup-timer.sh"
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
#
# This phase only restores golden images from backup -- it deliberately does
# NOT install Packer or the PXE build prerequisites (p7zip-full,
# python3-virt-firmware, sbsigntool) or add a build user to the kvm group.
# A from-scratch win11-analysis.qcow2 rebuild is a separate, manual,
# multi-hour production action (see docs/sandbox/windows/IMPLEMENTATION_PLAN.md
# Phase 0) that this unattended install flow should not silently trigger.
# ---------------------------------------------------------------------------
step_libvirt_install() {
  with_retry 3 15 env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    qemu-system-x86 libvirt-daemon-system libvirt-clients bridge-utils \
    virtinst libguestfs-tools ovmf
  systemctl enable --now libvirtd

  # libvirt-daemon-config-nwfilter's postinst only copies the built-in
  # filter templates (clean-traffic, no-mac-spoofing, etc.) from
  # /usr/share/libvirt/nwfilter into /etc/libvirt/nwfilter when the package
  # goes from "never configured" to configured. If the package was already
  # marked configured at a prior version -- e.g. /etc/libvirt was wiped by
  # hand without a full `apt purge` first, which is exactly what happened
  # during #518's teardown-and-reinstall verification -- the postinst takes
  # its "regular upgrade, don't touch anything" branch and silently leaves
  # /etc/libvirt/nwfilter without the defaults. win11-ghosts-kvm.xml,
  # win11-sandbox-kvm.xml and the Linux sandbox network all reference these
  # by name (no-mac-spoofing among them), so a VM define fails outright
  # with "referenced filter '...' is missing" the first time a sandbox step
  # runs -- confirmed live, see #518. Restore them unconditionally here so
  # apt's install-vs-upgrade heuristic can't leave the sandbox chain broken.
  cp -n /usr/share/libvirt/nwfilter/*.xml /etc/libvirt/nwfilter/
  systemctl restart libvirtd
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

  # The loop above only checks whatever .sha256 files happen to exist --
  # silently a no-op for a golden image whose checksum is missing entirely,
  # which defeats the whole "root of trust" point just as surely as a
  # mismatch would. Found live during #787's homeserver reinstall
  # (2026-08-09): only win11-cape.qcow2 had a .sha256 in the actual LAN
  # backup; win11-analysis.qcow2 and win11-ghosts.qcow2 had none at all and
  # were never verified. Require one for every *.qcow2 under golden-images/.
  local qcow2
  while IFS= read -r -d '' qcow2; do
    if [[ ! -f "${qcow2}.sha256" ]]; then
      echo "no .sha256 for golden image: $qcow2 -- backup did not carry one"
      failures=$((failures + 1))
    fi
  done < <(find /var/dockge/sandbox/golden-images -name "*.qcow2" -print0 2>/dev/null)

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
  # confirmation bar per docs/sandbox/ghosts/README.md, but it's slow and this
  # step already follows a `dotnet publish`-from-source container build --
  # run the enrollment test manually after a restore, not on every
  # unattended run.
  bash "$REPO_DIR/sandbox/ghosts/install-host.sh" --skip-enroll-test
}

step_ghosts_vm_start() {
  # win11-ghosts-kvm.xml's <disk> points at vms/win11-ghosts.qcow2 -- a thin
  # qcow2 clone of golden-images/win11-ghosts.qcow2, by its own comment. This
  # step never actually created that clone (unlike
  # step_windows_sandbox_vm_create's equivalent `qemu-img create -b
  # $GOLDEN_IMAGE` for win11-sandbox), so on any box where the disk hadn't
  # already been created some other way it just didn't exist. Found live
  # during #787's homeserver reinstall (2026-08-09): `virsh start
  # win11-ghosts` failed outright -- "Cannot access storage file
  # '/var/dockge/sandbox/vms/win11-ghosts.qcow2': No such file or directory"
  # -- while win11-sandbox came up fine right after, since only it had a
  # create step. sandbox-checksum (run earlier in this same script) already
  # verified the golden image before this step runs, so no second checksum
  # pass here.
  local golden="/var/dockge/sandbox/golden-images/win11-ghosts.qcow2"
  local disk="/var/dockge/sandbox/vms/win11-ghosts.qcow2"
  if [[ ! -e "$disk" ]]; then
    [[ -f "$golden" ]] || { echo "golden image not found: $golden"; return 1; }
    mkdir -p "$(dirname "$disk")"
    qemu-img create -f qcow2 -F qcow2 -b "$golden" "$disk"
  fi
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

run_step clone-repo            "Clone/update APIARY to $REPO_DIR" step_clone_repo
run_step dockge-install        "Install Dockge"                     step_dockge_install

run_step restore-env-files     "Restore .env files from LAN backup" step_restore_env_files
run_step arcane-import-stacks  "Import honeypot-* stacks as Arcane Git syncs" step_arcane_import_stacks
run_step stage-keycloak-theme  "Check out and sync the Keycloak login theme" step_stage_keycloak_theme
run_step bootstrap-missing-envs "Bootstrap any still-missing .env from .example" step_bootstrap_missing_envs
run_step provision-keycloak-secrets "Generate Keycloak secrets, reset bootstrap admin to admin/admin123" step_provision_keycloak_secrets

run_step shared-resources      "Create honeynet + placeholder volumes" step_create_shared_resources
run_step start-elasticsearch   "Start honeypot-elk, wait healthy"   step_start_elasticsearch_first
run_step start-init            "Start honeypot-init, wait for one-shots" step_start_init
run_step start-remaining       "Start remaining sensor/dashboard stacks" step_start_remaining_stacks

run_step provision-events-poller-secrets "Grant auth-events-poller view-events + write its secret" step_provision_events_poller_secrets
run_step provision-dashboard-oidc-secret "Write dashboard's OIDC client secret from Keycloak" step_provision_dashboard_oidc_secret
run_step auth-events-worker-start "Start auth-events-worker" step_auth_events_worker_start

run_step sshfs-install         "Install sshfs, place VPS key"        step_sshfs_install
run_step sshfs-mounts          "Mount VPS Suricata/portbridge logs"  step_sshfs_mounts
run_step sshfs-boot-ordering   "Install WireGuard-aware mount ordering" step_sshfs_boot_ordering

run_step pihole-provision      "Install Pi-hole + DNSCrypt config"  step_pihole_provision
run_step pihole-start          "Start Pi-hole after DNSCrypt ready" step_pihole_start
run_step pihole-verify         "Resolve DNSCrypt, Pi-hole, and LAN"  step_pihole_verify

if [[ "$ENABLE_GPU_STACK" == "true" ]]; then
  run_step ghidra-provision      "Link ghidra compose.yml"            step_ghidra_stack_provision
  run_step ghidra-start          "Start ghidra/ollama stack"          step_ghidra_stack_start
  run_step ollama-model-pull     "Pull pinned Ollama model"           step_ollama_model_pull
  run_step ghidra-worker-install "Install ghidra-worker.py systemd service" step_ghidra_worker_install
  run_step ml-worker-start       "Start ml-worker"                    step_ml_worker_start
  run_step llm-worker-selftest   "Run llm-worker --selftest"          step_llm_worker_selftest
else
  skip_step ghidra-provision "Link ghidra compose.yml" "ENABLE_GPU_STACK=false"
  skip_step ghidra-start "Start ghidra/ollama stack" "ENABLE_GPU_STACK=false"
  skip_step ollama-model-pull "Pull pinned Ollama model" "ENABLE_GPU_STACK=false"
  skip_step ghidra-worker-install "Install ghidra-worker.py systemd service" "ENABLE_GPU_STACK=false"
  skip_step ml-worker-start "Start ml-worker" "ENABLE_GPU_STACK=false"
  skip_step llm-worker-selftest "Run llm-worker --selftest" "ENABLE_GPU_STACK=false"
fi

run_step backup-timer-install  "Install daily Elasticsearch/stack backup timer" step_backup_timer_install
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

# Runs last, unconditionally (self-guarding on whether each service is
# actually installed): needs libvirtd already present when
# ENABLE_SANDBOX_RESTORE=true, and is a correct no-op for that part when it
# is not.
run_step quiet-veth-noise      "Quiet expected Docker veth noise from networkd-dispatcher/libvirtd/systemd-resolved" step_quiet_veth_noise

print_summary
exit $?
