#!/usr/bin/env bash
# Unattended homeserver provisioning for honeypot-stack — the Ubuntu-side
# equivalent of a Windows autounattend.xml. This is the FIRST cut of the
# single install script described in issue #518; it covers what has been
# smoke-test-researched so far (see docs/research/518-smoke-test-research.md)
# and is expected to grow as more of #518's scope gets verified.
#
# Scope: this script provisions a MANUALLY installed base Ubuntu Server
# system into a running honeypot-stack homeserver (Docker, NVIDIA/GPU
# stack, Dockge, WireGuard, the repo checkout, and starting the Compose
# stacks in dependency order). It does NOT partition disks or install the
# OS itself — that's docs/autoinstall/homeserver-user-data.yaml, run once,
# separately, before this script ever sees the box.
#
# Design goals (per #518): a single entry point, live status as it runs,
# and a clear, non-fatal-by-default failure report at the end so a partial
# run can be diagnosed and re-run rather than leaving the operator with
# nothing but a stack trace. Every step is idempotent where practical, so
# re-running after fixing one failure is the expected workflow, not a
# clean-slate requirement.
#
# Usage:
#   sudo ./scripts/install-homeserver.sh --config /path/to/answers.conf
#
# The answers file follows scripts/install-homeserver.conf.example --
# copy it, fill in every <PLACEHOLDER>, keep the filled-in copy OUT of
# version control (it will contain real IPs and a real git remote).

set -uo pipefail

# ---------------------------------------------------------------------------
# Status tracking — every phase reports through run_step so one failure
# doesn't abort the whole run; everything still attempted gets recorded and
# printed in a final summary.
# ---------------------------------------------------------------------------
declare -A STEP_STATUS
declare -a STEP_ORDER
LOG_DIR="/var/log/honeypot-install"
RUN_LOG=""

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*"; }

run_step() {
  local id="$1" desc="$2"
  shift 2
  STEP_ORDER+=("$id")
  log "==> [$id] $desc"
  if "$@" >>"$RUN_LOG" 2>&1; then
    STEP_STATUS["$id"]="OK"
    log "    [$id] OK"
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
    printf '  %-32s %s\n' "$id" "$status"
    [[ "$status" == FAILED* ]] && failed=1
  done
  echo "=========================================================================="
  echo "Full log: $RUN_LOG"
  if [[ $failed -eq 1 ]]; then
    echo "One or more steps FAILED. Fix the underlying issue and re-run this"
    echo "script — completed steps are idempotent and will no-op or repair."
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
    -h|--help)
      echo "Usage: sudo $0 --config /path/to/answers.conf"
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
           VPS_WG_ADDRESS VPS_WG_ENDPOINT HOME_WG_PRIVATE_KEY VPS_WG_PUBLIC_KEY \
           VPS_SSH_HOST VPS_SSH_PORT VPS_SSH_USER VPS_SSH_KEY ENABLE_GPU_STACK \
           INSTALL_TIMEZONE; do
  if [[ -z "${!var:-}" || "${!var}" == *'<'*'>'* ]]; then
    echo "Config value $var is unset or still a <PLACEHOLDER> in $CONFIG_FILE." >&2
    echo "Fill in every field before running unattended." >&2
    exit 1
  fi
done

mkdir -p "$LOG_DIR"
RUN_LOG="$LOG_DIR/install-$(date +%Y%m%dT%H%M%SZ).log"
: >"$RUN_LOG"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
  local ok=0
  for mnt in /var; do
    mountpoint -q "$mnt" || { echo "WARNING: $mnt is not a separate mount — see docs/HOMESERVER-DISK-LAYOUT.md" ; ok=1; }
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
  DEBIAN_FRONTEND=noninteractive apt-get update -y
}

step_base_packages() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg lsb-release git jq rsync ufw \
    xfsprogs nvme-cli openssh-client
}

# ---------------------------------------------------------------------------
# Phase 2 — Docker + Compose plugin
# ---------------------------------------------------------------------------
step_docker_repo() {
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
}

step_docker_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

step_docker_daemon_config() {
  # Matches the live homeserver's /etc/docker/daemon.json: bounded log
  # rotation (containers run forever, unbounded logs will fill /var) and
  # the nvidia runtime registered once the container toolkit is installed
  # (safe to declare even before the toolkit exists — dockerd just won't
  # use it until nvidia-container-runtime is on $PATH).
  cat >/etc/docker/daemon.json <<'EOF'
{
    "log-driver": "local",
    "log-opts": {
        "max-file": "3",
        "max-size": "10m"
    },
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
  DEBIAN_FRONTEND=noninteractive apt-get install -y ubuntu-drivers-common
  ubuntu-drivers autoinstall
}

step_gpu_container_toolkit() {
  curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
    | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
  curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
    | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
    > /etc/apt/sources.list.d/nvidia-container-toolkit.list
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y nvidia-container-toolkit
  nvidia-ctk runtime configure --runtime=docker
  systemctl restart docker
}

step_gpu_verify() {
  nvidia-smi -L || return 1
  docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi -L
}

# ---------------------------------------------------------------------------
# Phase 4 — WireGuard tunnel to the VPS
# ---------------------------------------------------------------------------
step_wireguard_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard
}

step_wireguard_config() {
  install -d -m 0700 /etc/wireguard
  umask 077
  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${HOME_WG_ADDRESS}
PrivateKey = ${HOME_WG_PRIVATE_KEY}
ListenPort = 51820

[Peer]
PublicKey = ${VPS_WG_PUBLIC_KEY}
Endpoint = ${VPS_WG_ENDPOINT}
AllowedIPs = ${VPS_WG_ADDRESS}/32
PersistentKeepalive = 25
EOF
  chmod 600 /etc/wireguard/wg0.conf
  systemctl enable wg-quick@wg0
  systemctl restart wg-quick@wg0
}

step_wireguard_verify() {
  wg show wg0 >/dev/null
}

# ---------------------------------------------------------------------------
# Phase 5 — Dockge
# ---------------------------------------------------------------------------
step_dockge_install() {
  mkdir -p /var/dockge/data /var/dockge/stacks
  docker run -d --name dockge --restart unless-stopped \
    -p 5001:5001 \
    -e DOCKGE_STACKS_DIR=/var/dockge/stacks \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v /var/dockge/data:/app/data \
    -v /var/dockge/stacks:/var/dockge/stacks \
    louislam/dockge:1
}

# ---------------------------------------------------------------------------
# Phase 6 — repo checkout
# ---------------------------------------------------------------------------
step_clone_repo() {
  if [[ -d "$REPO_DIR/.git" ]]; then
    git -C "$REPO_DIR" fetch origin
    git -C "$REPO_DIR" checkout "$GIT_REF"
    git -C "$REPO_DIR" pull --ff-only origin "$GIT_REF"
  else
    mkdir -p "$(dirname "$REPO_DIR")"
    git clone --branch "$GIT_REF" "$GIT_REPO_URL" "$REPO_DIR"
  fi
}

step_env_bootstrap() {
  # Copy every *.env.example to .env where a .env doesn't already exist.
  # This does NOT fill in secrets — it makes the gap visible (a fresh
  # .env full of CHANGE_ME placeholders) rather than leaving stacks
  # unable to start at all with no .env present.
  local n=0
  while IFS= read -r -d '' example; do
    local target="${example%.example}"
    if [[ ! -f "$target" ]]; then
      cp "$example" "$target"
      chmod 600 "$target"
      n=$((n + 1))
    fi
  done < <(find "$REPO_DIR" -maxdepth 2 -name "*.env.example" -print0)
  echo "Bootstrapped $n new .env file(s) from .example templates."
  echo "Review every CHANGE_ME value before starting stacks that need it."
}

# ---------------------------------------------------------------------------
# Phase 7 — start Compose stacks in dependency order
# ---------------------------------------------------------------------------
# Order matches the README's stack table and honeypot-init's role as the
# one-shot bootstrap every sensor depends on (log paths, ES templates,
# Arkime schema, persona validation). ELK before the sensors that ship logs
# to it; dashboard/payload-analysis/utilities after the data sources exist.
COMPOSE_ORDER=(
  docker-compose.init.yml
  docker-compose.elk.yml
  docker-compose.tanner.yml
  docker-compose.cowrie.yml
  docker-compose.dionaea.yml
  docker-compose.conpot.yml
  docker-compose.dnp3.yml
  docker-compose.http.yml
  docker-compose.multipot.yml
  docker-compose.cisco-asa-honeypot.yml
  docker-compose.citrix-honeypot.yml
  docker-compose.rdp-honeypot.yml
  docker-compose.dicompot.yml
  docker-compose.dns-honeypot.yml
  docker-compose.ip-enrichment-worker.yml
  docker-compose.payload-analysis.yml
  docker-compose.dashboard.yml
  docker-compose.utilities.yml
)

step_start_stacks() {
  local failures=0
  for f in "${COMPOSE_ORDER[@]}"; do
    if [[ ! -f "$REPO_DIR/$f" ]]; then
      echo "SKIP (not found): $f"
      continue
    fi
    echo "-- docker compose -f $f up -d --wait"
    if ! (cd "$REPO_DIR" && docker compose -f "$f" up -d --wait); then
      echo "FAILED: $f"
      failures=$((failures + 1))
    fi
  done
  [[ $failures -eq 0 ]]
}

# GPU-dependent stacks live outside the top-level compose list (ml-worker/,
# analysis/ghidra/) and are deliberately NOT auto-started here — per
# llm-worker's own README they're safety-gated one-shot/opt-in processes,
# not always-on services. Verify manually per docs/gpu-llm-analysis-worker.md
# and docs/gpu-ml-worker-acceleration.md once the base stacks are healthy.
step_gpu_stacks_note() {
  echo "GPU-dependent stacks (ml-worker, analysis/ghidra) are not"
  echo "auto-started by this script — see docs/gpu-llm-analysis-worker.md"
  echo "and docs/gpu-ml-worker-acceleration.md for their gated startup"
  echo "procedures."
}

# ---------------------------------------------------------------------------
# Phase 8 — verification
# ---------------------------------------------------------------------------
step_verify_containers_healthy() {
  local unhealthy
  unhealthy=$(docker ps --filter "health=unhealthy" --format '{{.Names}}')
  if [[ -n "$unhealthy" ]]; then
    echo "Unhealthy containers: $unhealthy"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
log "install-homeserver.sh starting — log: $RUN_LOG"

run_step preflight-os        "Confirm Ubuntu"                  step_preflight_os
run_step preflight-disks     "Check disk layout against docs"  step_preflight_disks
run_step hostname-timezone   "Set hostname/timezone"           step_set_hostname

run_step apt-update          "apt-get update"                  step_apt_update
run_step base-packages       "Install base packages"           step_base_packages

run_step docker-repo         "Add Docker apt repo"              step_docker_repo
run_step docker-install      "Install Docker Engine + Compose"  step_docker_install
run_step docker-daemon-config "Write /etc/docker/daemon.json"   step_docker_daemon_config

if [[ "$ENABLE_GPU_STACK" == "true" ]]; then
  run_step gpu-driver           "Install NVIDIA driver"            step_gpu_driver
  run_step gpu-container-toolkit "Install nvidia-container-toolkit" step_gpu_container_toolkit
  run_step gpu-verify           "Verify GPU visible to Docker"     step_gpu_verify
else
  skip_step gpu-driver "Install NVIDIA driver" "ENABLE_GPU_STACK=false"
  skip_step gpu-container-toolkit "Install nvidia-container-toolkit" "ENABLE_GPU_STACK=false"
  skip_step gpu-verify "Verify GPU visible to Docker" "ENABLE_GPU_STACK=false"
fi

run_step wireguard-install    "Install WireGuard"                step_wireguard_install
run_step wireguard-config     "Write wg0.conf and enable tunnel" step_wireguard_config
run_step wireguard-verify     "Verify tunnel is up"              step_wireguard_verify

run_step dockge-install       "Install Dockge"                   step_dockge_install

run_step clone-repo           "Clone/update honeypot-stack"      step_clone_repo
run_step env-bootstrap        "Bootstrap .env files from examples" step_env_bootstrap

run_step start-stacks         "Start Compose stacks in order"    step_start_stacks
run_step gpu-stacks-note      "GPU-worker startup note"          step_gpu_stacks_note

run_step verify-containers    "Check for unhealthy containers"   step_verify_containers_healthy

print_summary
exit $?
