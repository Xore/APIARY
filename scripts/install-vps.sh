#!/usr/bin/env bash
# Unattended VPS provisioning for APIARY -- the public-edge-host equivalent
# of scripts/install-homeserver.sh. Filed as #1059: before this script
# existed, everything that touched the VPS (.github/workflows/deploy.yml's
# vps job, install-homeserver.sh's step_wireguard_sync_vps_peer) assumed
# Docker, WireGuard, and /root/vps already existed, with no record anywhere
# of how they got there -- confirmed live against the real VPS, which was
# clearly set up by hand at some point. A genuinely wiped/reimaged VPS could
# not be brought back up by anything in this repo before this script.
#
# Scope: this script provisions a MANUALLY installed base Ubuntu Server or
# Rocky Linux 9 system. On Rocky, SELinux stays enforcing -- the Compose
# stack's bind mounts use :z/:Z relabelling where needed (see vps/ compose
# files); if a container hits an SELinux denial, check 'ausearch -m avc'
# before disabling enforcing.
# system into a running APIARY VPS edge host (Docker, WireGuard, the
# firewall, the NIC offload fix, the vps/ stack checkout, secret restore
# from the LAN backup, and starting the Compose stack). It does NOT
# partition disks or install the OS itself, and it does NOT issue the
# Cloudflare origin TLS certificate (docs/CGNAT-DEPLOYMENT.md has no
# documented issuance procedure either -- restoring the existing one from
# the LAN backup is the only path this script supports; see step_restore_certs).
#
# Bootstrap order with install-homeserver.sh, for a genuinely fresh pair of
# hosts: run THIS script first. It prints this VPS's fresh WireGuard public
# key at the end -- feed that into install-homeserver.conf's
# VPS_WG_PUBLIC_KEY before running install-homeserver.sh, whose own
# step_wireguard_sync_vps_peer then pushes home's real public key + PSK
# into the placeholder peer entry this script writes below.
#
# Usage:
#   sudo ./scripts/install-vps.sh --config /path/to/answers.conf
#   sudo ./scripts/install-vps.sh --config answers.conf --force-rerun-from docker-install
#   sudo ./scripts/install-vps.sh --config answers.conf --reset-markers   # ignore all markers, redo everything
#
# The answers file follows scripts/install-vps.conf.example -- copy it,
# fill in every <PLACEHOLDER>, keep the filled-in copy OUT of version
# control (it will contain real IPs, keys, and a real git remote).

set -uo pipefail

# ---------------------------------------------------------------------------
# Status tracking / resumability -- identical framework to
# install-homeserver.sh, deliberately not reimplemented differently. See
# that script's own header comment for the full rationale.
# ---------------------------------------------------------------------------
declare -A STEP_STATUS
declare -a STEP_ORDER
LOG_DIR="/var/log/honeypot-install-vps"
MARKER_DIR="/var/lib/honeypot-install-vps/markers"
RUN_LOG=""
FORCE_FROM=""
RESET_MARKERS=0
FORCE_ACTIVE=0

log() { printf '[%s] %s\n' "$(date -Iseconds)" "$*"; }

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

  if [[ -n "$FORCE_FROM" && "$id" == "$FORCE_FROM" ]]; then
    FORCE_ACTIVE=1
  fi

  local marker="$MARKER_DIR/$id.done"
  if [[ $RESET_MARKERS -eq 0 && -f "$marker" && "$FORCE_ACTIVE" -eq 0 ]]; then
    STEP_STATUS["$id"]="SKIPPED (already done -- marker $marker)"
    log "==> [$id] $desc -- SKIPPED (marker present)"
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
    log "    [$id] FAILED (exit $rc) -- see $RUN_LOG"
  fi
}

print_summary() {
  echo
  echo "==================== install-vps.sh summary ===================="
  local failed=0
  for id in "${STEP_ORDER[@]}"; do
    local status="${STEP_STATUS[$id]}"
    printf '  %-28s %s\n' "$id" "$status"
    [[ "$status" == FAILED* ]] && failed=1
  done
  echo "==================================================================="
  echo "Full log: $RUN_LOG"
  if [[ $failed -eq 1 ]]; then
    echo "One or more steps FAILED. Fix the underlying issue and re-run this"
    echo "script -- completed steps are skipped via markers under $MARKER_DIR,"
    echo "so re-running only retries what actually failed. Use"
    echo "--force-rerun-from <step-id> to redo a step whose marker exists but"
    echo "whose result you don't trust."
    return 1
  fi
  echo "All steps completed."
  if [[ -f /etc/wireguard/wg0.conf ]]; then
    echo
    echo "This VPS's WireGuard public key (feed into install-homeserver.conf's"
    echo "VPS_WG_PUBLIC_KEY before running install-homeserver.sh):"
    grep '^PrivateKey' /etc/wireguard/wg0.conf | awk '{print $3}' | wg pubkey
  fi
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
      echo "See scripts/install-vps.conf.example for the template."
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
  echo "Copy scripts/install-vps.conf.example, fill in every" >&2
  echo "<PLACEHOLDER>, and pass it with --config." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

for var in GIT_REPO_URL GIT_REF VPS_WG_ADDRESS HOME_WG_ADDRESS \
           BACKUP_HOST BACKUP_HOST_USER BACKUP_HOST_KEY BACKUP_HOST_PATH; do
  if [[ -z "${!var:-}" || "${!var}" == *'<'*'>'* ]]; then
    echo "Config value $var is unset or still a <PLACEHOLDER> in $CONFIG_FILE." >&2
    echo "Fill in every field before running unattended." >&2
    exit 1
  fi
done
# VPS_WG_PRIVATE_KEY may be left empty -- a fresh keypair is generated if so
# (same convention as install-homeserver.conf's HOME_WG_PRIVATE_KEY).
# HOME_WG_PUBLIC_KEY may also be left empty on a genuinely simultaneous
# fresh-pair bootstrap: a throwaway placeholder key is written to the peer
# entry instead, which install-homeserver.sh's step_wireguard_sync_vps_peer
# then overwrites with the real one once the home side exists. If you
# already know home's real public key (re-provisioning the VPS only, home
# stays untouched), set it here and skip the round-trip.

mkdir -p "$LOG_DIR" "$MARKER_DIR"
RUN_LOG="$LOG_DIR/install-$(date -u +%Y%m%dT%H%M%SZ).log"
: >"$RUN_LOG"

# ---------------------------------------------------------------------------
# Phase 0 -- preflight
# ---------------------------------------------------------------------------
step_preflight_os() {
  . /etc/os-release
  case "$ID" in
    ubuntu) PKG=apt ;;
    rocky|almalinux|rhel) PKG=dnf ;;
    *) echo "Unsupported OS ($ID) -- need ubuntu or rocky/almalinux/rhel" >&2; return 1 ;;
  esac
  echo "Detected $ID -- using $PKG"
}

# ---------------------------------------------------------------------------
# Phase 1 -- base packages
# ---------------------------------------------------------------------------
step_pkg_update() {
  case "$PKG" in
    apt) with_retry 3 10 env DEBIAN_FRONTEND=noninteractive apt-get update -y ;;
    dnf) with_retry 3 10 dnf makecache --refresh -y ;;
  esac
}

step_base_packages() {
  case "$PKG" in
    apt)
      with_retry 3 10 env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release git jq rsync ufw wireguard wireguard-tools \
        openssh-client ethtool
      ;;
    dnf)
      with_retry 3 10 dnf install -y --setopt=install_weak_deps=False \
        ca-certificates curl gnupg git jq rsync firewalld wireguard-tools \
        openssh-clients ethtool tar
      # epel is required for jq on Rocky
      with_retry 3 10 dnf install -y epel-release
      with_retry 3 10 dnf install -y jq
      systemctl enable --now firewalld
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Phase 2 -- Docker + Compose plugin (same upstream repo as
# install-homeserver.sh; daemon.json differs deliberately -- this is a
# public edge host, no GPU, few containers, hardened defaults matter more
# than the wide address-pool/nvidia-runtime tuning the homeserver needs)
# ---------------------------------------------------------------------------
step_docker_repo() {
  case "$PKG" in
    apt)
      install -m 0755 -d /etc/apt/keyrings
      with_retry 3 10 curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc
      chmod a+r /etc/apt/keyrings/docker.asc
      . /etc/os-release
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list
      with_retry 3 10 apt-get update -y
      ;;
    dnf)
      with_retry 3 10 dnf config-manager --add-repo \
        https://download.docker.com/linux/centos/docker-ce.repo
      ;;
  esac
}

step_docker_install() {
  case "$PKG" in
    apt)
      with_retry 3 15 env DEBIAN_FRONTEND=noninteractive apt-get install -y \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      ;;
    dnf)
      with_retry 3 15 dnf install -y \
        docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      ;;
  esac
  systemctl enable --now docker
}

step_docker_daemon_config() {
  # Matches the live VPS's /etc/docker/daemon.json exactly (fetched and
  # diffed against this, not guessed): icc/no-new-privileges/userland-proxy
  # hardening appropriate for a public-facing edge host, live-restore so a
  # dockerd restart/upgrade doesn't take every honeypot listener down with
  # it, bounded log rotation.
  cat >/etc/docker/daemon.json <<'EOF'
{
  "storage-driver": "overlay2",
  "log-driver": "local",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3",
    "compress": "true"
  },
  "icc": false,
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "shutdown-timeout": 15,
  "exec-opts": ["native.cgroupdriver=systemd"],
  "max-concurrent-downloads": 10,
  "max-concurrent-uploads": 10,
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 65535, "Soft": 65535 }
  },
  "features": { "buildkit": true }
}
EOF
  systemctl restart docker
}

# ---------------------------------------------------------------------------
# Phase 3 -- WireGuard. See this script's own header comment for the
# two-phase bootstrap order with install-homeserver.sh -- this VPS's own
# keypair is generated here; the peer entry for home starts as a
# placeholder that install-homeserver.sh's step_wireguard_sync_vps_peer
# overwrites with home's real public key + PSK.
# ---------------------------------------------------------------------------
step_wireguard_config() {
  install -d -m 0700 /etc/wireguard
  umask 077

  local priv="${VPS_WG_PRIVATE_KEY:-}"
  if [[ -z "$priv" ]]; then
    priv="$(wg genkey)"
    echo "Generated a fresh WireGuard private key (no VPS_WG_PRIVATE_KEY in config)."
  fi

  local home_pub="${HOME_WG_PUBLIC_KEY:-}"
  if [[ -z "$home_pub" ]]; then
    # Syntactically valid but not home's real key -- wg-quick accepts any
    # well-formed pubkey, it just won't handshake until the real one lands.
    # step_wireguard_sync_vps_peer (run from the homeserver install)
    # overwrites this. No PresharedKey line here either, for the same
    # reason -- that function adds one if missing (see its own comments).
    home_pub="$(wg genkey | wg pubkey)"
    echo "No HOME_WG_PUBLIC_KEY in config -- wrote a placeholder peer entry."
    echo "Run install-homeserver.sh's step_wireguard_sync_vps_peer against this"
    echo "VPS once the home side exists, or this tunnel will never handshake."
  fi

  local home_ip="${HOME_WG_ADDRESS%%/*}"
  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${VPS_WG_ADDRESS}/24
PrivateKey = ${priv}
ListenPort = 51820
MTU = 1280

[Peer]
PublicKey = ${home_pub}
AllowedIPs = ${home_ip}/32
EOF
  chmod 600 /etc/wireguard/wg0.conf
  systemctl enable wg-quick@wg0
  systemctl restart wg-quick@wg0
}

# ---------------------------------------------------------------------------
# Phase 4 -- firewall. Base rules (admin SSH, WireGuard, Traefik) match the
# real live VPS's ufw state exactly (fetched and diffed against this, not
# copied from docs/CGNAT-DEPLOYMENT.md's "80,443 from Anywhere" instruction,
# which has drifted from reality -- the live host restricts 443 to
# Cloudflare's published ranges only, and has no port 80 rule at all; see
# #1059's follow-up doc-fix note). The honeypot decoy ports themselves come
# from vps/honeypot-firewall.sh, already the single source of truth for
# that list (checked against portbridge's own RULES by
# vps/check-firewall-portbridge-sync.sh) -- deliberately not duplicated
# here.
# ---------------------------------------------------------------------------
step_firewall_base() {
  case "$PKG" in
  apt)
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed

    ufw allow 51820/udp comment 'WireGuard'
    ufw allow "${SSH_ADMIN_PORT:-2222}/tcp" comment 'REAL admin SSH'

    # Cloudflare's published IPv4 ranges (https://www.cloudflare.com/ips-v4/,
    # captured 2026-08-09 from this VPS's own live ufw state) -- Traefik's
    # public HTTPS listener only accepts 443 from these, since Cloudflare
    # proxies every real hostname and a direct-origin connection bypassing it
    # would skip Cloudflare's own WAF/rate-limiting. Cloudflare does add/retire
    # ranges occasionally; re-fetch and diff against the live list if a real
    # request starts getting refused that shouldn't be.
    for cidr in 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 \
                141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 \
                197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 \
                104.24.0.0/14 172.64.0.0/13 131.0.72.0/22; do
      ufw allow from "$cidr" to any port 443 proto tcp comment 'Traefik (Cloudflare)'
    done

    ufw --force enable
    ;;
  dnf)
    # firewalld equivalent of the ufw rule set above. The honeypot decoy
    # ports come from vps/honeypot-firewall.sh (its dnf branch below uses
    # firewall-cmd against the same zone), so this base set must also live
    # in that zone. 'admin_ssh' would collide with the standard ssh service
    # on 22 -- the REAL admin port here is 22 (fresh Rocky install), which
    # firewalld already allows via its built-in ssh service.
    systemctl enable --now firewalld
    firewall-cmd --permanent --zone=public --remove-service=ssh \
      --add-port="${SSH_ADMIN_PORT:-22}/tcp" 2>/dev/null || \
    firewall-cmd --permanent --zone=public --add-port="${SSH_ADMIN_PORT:-22}/tcp"
    firewall-cmd --permanent --zone=public --add-port=51820/udp
    # Cloudflare's published IPv4 ranges -- same list, same rationale as the
    # ufw branch (443 restricted to Cloudflare because everything real is
    # proxied; a direct-origin hit would bypass Cloudflare's WAF).
    for cidr in 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 \
                141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 \
                197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 \
                104.24.0.0/14 172.64.0.0/13 131.0.72.0/22; do
      firewall-cmd --permanent --zone=public \
        --add-rich-rule="rule family=ipv4 source address='$cidr' port port=443 protocol=tcp accept"
    done
    firewall-cmd --reload
    ;;
  esac
}

step_firewall_honeypot_ports() {
  bash "${REPO_DIR}/vps/honeypot-firewall.sh" --backend "$PKG"
  sh "${REPO_DIR}/vps/check-firewall-portbridge-sync.sh" "${REPO_DIR}/vps/docker-compose.yml"
}

# ---------------------------------------------------------------------------
# Phase 5 -- NIC offload fix (#342 -- see vps/disable-nic-hw-gro.sh's own
# header for the full Suricata-truncated-packet story this works around)
# ---------------------------------------------------------------------------
step_nic_gro_fix() {
  sh "${REPO_DIR}/vps/disable-nic-hw-gro.sh" --apply
}

# ---------------------------------------------------------------------------
# Phase 6 -- repo checkout + stage vps/ into /root/vps/, matching
# .github/workflows/deploy.yml's own rsync exactly (same excludes) so a
# fresh install and a CI redeploy converge on the identical result. This
# exclude list must move in lockstep with that workflow's -- #1184 added
# --exclude 'secrets/' there after --delete-delay took down all seven
# oauth2-proxy gateways by deleting the git-ignored, never-present-in-
# checkout secrets/ directory (#2294: this script didn't inherit it, so a
# --force-rerun-from stage-vps-dir replayed the same deletion locally).
# ---------------------------------------------------------------------------
REPO_DIR="/root/apiary-repo"

step_clone_repo() {
  if [[ -d "$REPO_DIR/.git" ]]; then
    with_retry 3 10 git -C "$REPO_DIR" fetch origin
    git -C "$REPO_DIR" checkout "$GIT_REF"
    with_retry 3 10 git -C "$REPO_DIR" pull --ff-only origin "$GIT_REF"
  else
    with_retry 3 10 git clone --branch "$GIT_REF" "$GIT_REPO_URL" "$REPO_DIR"
  fi
}

step_stage_vps_dir() {
  install -d -m 755 /root/vps
  rsync -az --delete-delay \
    --exclude '.env' \
    --exclude 'traefik/certs/' \
    --exclude 'traefik/dynamic.yml' \
    --exclude 'secrets/' \
    "${REPO_DIR}/vps/" /root/vps/
}

# ---------------------------------------------------------------------------
# Phase 7 -- secret restore from the LAN backup host. Mirrors
# install-homeserver.sh's step_restore_env_files mechanism, adapted for the
# VPS's single-directory layout (one .env, one certs/ pair) instead of one
# subfolder per Dockge stack.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Phase 7b -- pin the capture NIC to whatever this machine actually calls it.
#
# Suricata, Zeek and huginn-sidecar all sniff a named interface, and the name
# belongs to the provider and the kernel rather than to us. It was ens6 on
# this VPS until a reboot brought it back as eth0: Zeek and huginn died on
# "Could not find network interface", and Suricata kept running against an
# interface that no longer existed -- the worse failure, because nothing in
# `docker ps` shows it (#1929).
#
# So it is derived rather than assumed, at every boot, from the interface
# carrying the default route. Ordered before docker.service, so Compose
# interpolates a name that is already correct.
# ---------------------------------------------------------------------------
step_capture_interface() {
  install -m 0755 /root/vps/detect-capture-interface.sh /usr/local/sbin/detect-capture-interface.sh
  install -m 0644 /root/vps/apiary-capture-interface.service /etc/systemd/system/apiary-capture-interface.service
  systemctl daemon-reload
  systemctl enable --now apiary-capture-interface.service
  echo "capture interface: $(sed -n 's/^CAPTURE_INTERFACE=//p' /root/vps/.env | tail -1)"
}

step_restore_env() {
  local src="${BACKUP_HOST_PATH}/vps/.env"
  if with_retry 3 5 scp -i "$BACKUP_HOST_KEY" -P 22 -o StrictHostKeyChecking=accept-new \
      -o ConnectTimeout=10 "${BACKUP_HOST_USER}@${BACKUP_HOST}:${src}" /root/vps/.env 2>/dev/null; then
    chmod 600 /root/vps/.env
    echo "restored .env from $src"
  else
    echo "WARNING: no backed-up .env found for VPS at $src -- copy vps/.env.example to"
    echo "/root/vps/.env and fill in every CHANGE_ME by hand before starting the stack."
  fi
}

step_restore_certs() {
  # No documented issuance procedure exists for the Cloudflare origin cert
  # (docs/CGNAT-DEPLOYMENT.md doesn't cover it either) -- restoring the
  # existing one from backup is the only path this script supports. If the
  # backup genuinely has no certs (first-ever install, not a rebuild), this
  # step warns and leaves Traefik unable to serve TLS until a real
  # certificate is issued and placed by hand.
  install -d -m 750 /root/vps/traefik/certs
  local ok=1
  for f in origin.pem origin-key.pem; do
    if ! with_retry 3 5 scp -i "$BACKUP_HOST_KEY" -P 22 -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 "${BACKUP_HOST_USER}@${BACKUP_HOST}:${BACKUP_HOST_PATH}/vps/traefik/certs/${f}" \
        "/root/vps/traefik/certs/${f}" 2>/dev/null; then
      ok=0
    fi
  done
  chmod 600 /root/vps/traefik/certs/origin-key.pem 2>/dev/null || true
  chmod 644 /root/vps/traefik/certs/origin.pem 2>/dev/null || true
  if [[ "$ok" -eq 0 ]]; then
    echo "WARNING: could not restore both origin.pem and origin-key.pem from backup."
    echo "Traefik will not serve TLS until real certificates are placed at"
    echo "/root/vps/traefik/certs/ by hand."
  fi
}

step_prepare_log_dirs() {
  # Found live on a real reinstall (#787): Suricata's pcap-log module
  # (vps/suricata/suricata.yaml's `filename: pcap/log.pcap`) expects
  # /opt/stacks/apiary/logs/suricata/pcap/ to already exist -- it does not
  # create it itself, and nothing else in this repo did either. Missing on
  # a genuinely fresh host (this whole logs/ tree starts empty by design,
  # same as every other piece of honeypot operational data), so
  # hp-suricata exited cleanly every time it hit this and Docker's
  # `restart: unless-stopped` policy silently relaunched it forever --
  # confirmed live at 428 restarts over ~6 hours, RestartCount climbing
  # the whole time, providing zero real IDS coverage that entire window.
  # UID/GID 998 is the `suricata` user's fixed UID baked into the
  # jasonish/suricata image itself (confirmed via `docker exec ... cat
  # /etc/passwd`), not something host-specific -- the bind mount needs a
  # host-side owner matching the container's own numeric UID exactly.
  install -d -m 755 -o 998 -g 998 /opt/stacks/apiary/logs/suricata/pcap
}

step_render_traefik_dynamic() {
  # Same substitution .github/workflows/deploy.yml's dedicated step does
  # (see that workflow's own comment for why this is a plain in-place cat,
  # not rsync or mv -- Traefik's bind mount tracks the inode, not the path).
  [[ -n "${DOMAIN:-}" && "$DOMAIN" != *'<'*'>'* ]] || {
    echo "DOMAIN is unset or still a <PLACEHOLDER> in the config -- refusing to" >&2
    echo "deploy a Traefik config with placeholder domains." >&2
    return 1
  }
  sed "s/honeypot\.example/${DOMAIN}/g" "${REPO_DIR}/vps/traefik/dynamic.yml" \
    > /tmp/dynamic.yml.deployable
  python3 -c "import yaml; yaml.safe_load(open('/tmp/dynamic.yml.deployable'))"
  if grep -q "honeypot.example" /tmp/dynamic.yml.deployable; then
    echo "generated dynamic.yml still contains placeholder domains after substitution" >&2
    return 1
  fi
  cat /tmp/dynamic.yml.deployable > /root/vps/traefik/dynamic.yml
  rm -f /tmp/dynamic.yml.deployable
}

# ---------------------------------------------------------------------------
# Phase 8 -- bring the stack up
# ---------------------------------------------------------------------------
step_compose_up() {
  cd /root/vps || return 1
  { test ! -f .env || chmod 600 .env; }
  docker compose -f docker-compose.yml config --quiet
  docker compose -f docker-compose.yml up -d --build --remove-orphans
}

step_wireguard_verify() {
  # Deliberately interface-only, NOT a handshake check -- unlike
  # install-homeserver.sh's own step_wireguard_verify (which correctly
  # insists on a real handshake, per the #518 incident its comments
  # describe: a clean-looking interface that never actually passes
  # traffic). That stricter check is wrong here on a first-ever fresh-pair
  # bootstrap: this script may be the FIRST of the two to run, writing only
  # a placeholder peer entry (see step_wireguard_config) that cannot
  # possibly handshake until install-homeserver.sh's
  # step_wireguard_sync_vps_peer pushes home's real key. Demanding a
  # handshake here would fail every legitimate first-time run. Once BOTH
  # hosts are provisioned, `wg show wg0` on either end is still the real
  # verification -- this step only confirms wg-quick itself started
  # cleanly.
  local waited=0
  while (( waited < 30 )); do
    if ip link show wg0 &>/dev/null; then
      echo "wg0 interface is up (this does not confirm a handshake -- see this"
      echo "function's own comment for why that check doesn't belong here)."
      return 0
    fi
    sleep 3
    waited=$(( waited + 3 ))
  done
  echo "wg0 interface did not come up within 30s" >&2
  return 1
}

step_verify_containers_healthy() {
  cd /root/vps || return 1
  local unhealthy
  unhealthy="$(docker compose -f docker-compose.yml ps --format '{{.Name}} {{.Status}}' \
    | grep -iE 'unhealthy|restarting' || true)"
  if [[ -n "$unhealthy" ]]; then
    echo "Unhealthy/restarting containers:" >&2
    echo "$unhealthy" >&2
    return 1
  fi
  # The status-text grep above has a real blind spot, found live (#787): a
  # container crash-looping under `restart: unless-stopped` spends nearly
  # all its time in a healthy-looking "Up" state between crashes -- the
  # literal word "Restarting" only appears in `docker compose ps` output
  # during the brief transition itself, easy to miss entirely on a single
  # poll. hp-suricata accumulated 428 silent restarts (a real, undetected
  # startup bug -- see step_prepare_log_dirs) while this check kept
  # passing every time it happened to run. Docker's own RestartCount is a
  # cumulative counter that doesn't have this gap.
  local name count crashed=0
  while IFS= read -r name; do
    [[ -z "$name" ]] && continue
    count="$(docker inspect "$name" --format '{{.RestartCount}}' 2>/dev/null || echo 0)"
    if [[ "$count" =~ ^[0-9]+$ ]] && (( count > 0 )); then
      echo "  ${name}: RestartCount=${count} (crash-looping, even though currently reported healthy/Up)" >&2
      crashed=1
    fi
  done < <(docker compose -f docker-compose.yml ps --format '{{.Name}}')
  if [[ "$crashed" -eq 1 ]]; then
    echo "One or more containers have a nonzero RestartCount -- see above." >&2
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
run_step preflight-os            "Detect OS (ubuntu/rocky) + package manager" step_preflight_os
run_step pkg-update              "Update package index"                    step_pkg_update
run_step base-packages           "Install base packages"                   step_base_packages
run_step docker-repo             "Add Docker repo"                         step_docker_repo
run_step docker-install          "Install Docker Engine + Compose"         step_docker_install
run_step docker-daemon-config    "Write /etc/docker/daemon.json"           step_docker_daemon_config
run_step wireguard-config        "Write wg0.conf and enable tunnel"        step_wireguard_config
run_step firewall-base           "Apply base firewall rules"               step_firewall_base
run_step clone-repo              "Clone/update APIARY to $REPO_DIR"        step_clone_repo
run_step firewall-honeypot-ports "Open honeypot ports (vps/honeypot-firewall.sh)" step_firewall_honeypot_ports
run_step nic-gro-fix             "Disable virtio-net hardware GRO (#342)"  step_nic_gro_fix
run_step stage-vps-dir           "Stage vps/ into /root/vps"               step_stage_vps_dir
run_step restore-env             "Restore .env from LAN backup"            step_restore_env
run_step capture-interface       "Pin the capture NIC to this host's own name" step_capture_interface
run_step restore-certs           "Restore Traefik origin certs from LAN backup" step_restore_certs
run_step render-traefik-dynamic  "Substitute real domain into dynamic.yml" step_render_traefik_dynamic
run_step prepare-log-dirs        "Create host-side log/pcap directories"   step_prepare_log_dirs
run_step compose-up              "docker compose up -d --build --remove-orphans" step_compose_up
run_step wireguard-verify        "Verify wg0 interface is up"              step_wireguard_verify
run_step verify-containers       "Verify no unhealthy/restarting containers" step_verify_containers_healthy

print_summary
exit $?
