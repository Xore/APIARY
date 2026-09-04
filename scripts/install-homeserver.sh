#!/usr/bin/env bash
# Unattended homeserver provisioning for APIARY — the Linux-side
# equivalent of a Windows autounattend.xml. This is the single entry point
# described in issue #518; it covers everything smoke-test-verified so far
# (see docs/research/518-smoke-test-research.md) and is expected to grow.
#
# Scope: this script provisions a MANUALLY installed base Ubuntu Server or
# Rocky Linux 10 system into a running APIARY homeserver (Docker, NVIDIA/GPU
# stack, Arcane, WireGuard, the repo checkout, secret restore, and starting
# the Compose stacks in dependency order). It does NOT partition disks or
# install the OS itself — that's docs/autoinstall/homeserver-user-data.yaml
# on Ubuntu, or a kickstart on Rocky (#2730), run once, separately, before
# this script ever sees the box.
#
# Distro support: every package operation goes through the pkg_* shim rather
# than calling apt-get directly, and $DISTRO_FAMILY (debian|rhel) is resolved
# once at source time. Only genuinely distro-specific things branch on it --
# package names, repository format, and the NVIDIA driver path.
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
           TECHNITIUM_LAN_IP ENABLE_SANDBOX_RESTORE AUTH_THEME_REPO_URL \
           KEYCLOAK_PUBLIC_DOMAIN ARCANE_URL ARCANE_API_TOKEN; do
  if [[ -z "${!var:-}" || "${!var}" == *'<'*'>'* ]]; then
    echo "Config value $var is unset or still a <PLACEHOLDER> in $CONFIG_FILE." >&2
    echo "Fill in every field before running unattended." >&2
    exit 1
  fi
done

# KEYCLOAK_PUBLIC_DOMAIN is the BASE domain -- every public hostname is derived
# from it by prefixing a service label (auth.<domain>, arcane.<domain>,
# dashboard.<domain>, ...). Handing it a hostname that already carries one of
# those labels silently produces a second-level subdomain: the 2026-09-03
# rebuild was configured with "auth.xore.rocks" and generated
# https://arcane.auth.xore.rocks plus issuer https://auth.auth.xore.rocks,
# neither of which resolves or is covered by the wildcard origin certificate
# (*.xore.rocks matches one label only). Nothing downstream validated it, so it
# surfaced as OIDC discovery failures far from the cause. Reject it here.
for label in auth arcane dashboard kibana arkime evebox traefik tanner snare rev; do
  if [[ "$KEYCLOAK_PUBLIC_DOMAIN" == "$label."* ]]; then
    echo "KEYCLOAK_PUBLIC_DOMAIN is \"$KEYCLOAK_PUBLIC_DOMAIN\", which already starts with the" >&2
    echo "service label \"$label.\". This value must be the BASE domain only --" >&2
    echo "the installer derives auth.<domain>, arcane.<domain> and friends from it," >&2
    echo "so this would generate ${label}.${KEYCLOAK_PUBLIC_DOMAIN} (a second-level" >&2
    echo "subdomain that a *.<domain> wildcard certificate does not cover)." >&2
    echo "Use \"${KEYCLOAK_PUBLIC_DOMAIN#"$label".}\" instead." >&2
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
# ARCANE_URL/ARCANE_API_TOKEN (#1502): step_arcane_import_stacks needs an
# already-running Arcane with an API key generated through its own UI
# (Settings -> API Keys, after Arcane's first interactive login -- an
# unattended installer can't complete Arcane's own OIDC/passkey login
# itself). #1504 closed half of this gap: step_arcane_install (formerly
# step_dockge_install) now stands Arcane itself up from
# docker-compose.arcane.yml, so it's installed and reachable before this
# script reaches the import step, rather than the plain Dockge it used to
# install. The remaining, irreducible part is a genuine two-pass bootstrap:
# minting ARCANE_API_TOKEN still requires a first human login, and once
# Keycloak is up that login is OIDC-only, so the very first from-scratch run
# lands Arcane + Keycloak, a human logs in and mints a token, and a second
# run with the filled-in token completes the honeypot-* import. Nothing in
# this installer can complete Arcane's own interactive login for you.
#
# KEYCLOAK_PUBLIC_DOMAIN (#1504): the base domain the honeypot's public
# hostnames hang off (auth.<domain>, arcane.<domain>, ...) -- step_arcane_install
# derives Arcane's own APP_URL and OIDC issuer URL from it for the .env it
# generates, matching the Keycloak realm's own example.invalid -> <domain>
# substitution. Same value as honeypot-keycloak's KEYCLOAK_PUBLIC_DOMAIN.

# BACKUP_HOST_SANDBOX_PATH is only needed when ENABLE_SANDBOX_RESTORE=true --
# don't force every user to fill it in just to skip a 170G+ optional restore.
if [[ "$ENABLE_SANDBOX_RESTORE" == "true" ]]; then
  if [[ -z "${BACKUP_HOST_SANDBOX_PATH:-}" || "${BACKUP_HOST_SANDBOX_PATH}" == *'<'*'>'* ]]; then
    echo "ENABLE_SANDBOX_RESTORE=true but BACKUP_HOST_SANDBOX_PATH is unset or still a <PLACEHOLDER>." >&2
    exit 1
  fi
fi

mkdir -p "$LOG_DIR" "$MARKER_DIR"
RUN_LOG="$LOG_DIR/install-$(date -u +%Y%m%dT%H%M%SZ).log"
: >"$RUN_LOG"

# ---------------------------------------------------------------------------
# Distro shim
# ---------------------------------------------------------------------------
# The homeserver is moving from Ubuntu to Rocky Linux 10, so every package
# operation goes through pkg_* rather than calling apt-get directly. Only the
# places where the two distros genuinely differ -- package names, repository
# format, the NVIDIA driver path -- branch on $DISTRO_FAMILY. Everything else
# (Docker, WireGuard, libvirt, the whole APIARY provisioning flow) is
# identical once the packages are on disk.
#
# Set once, at source time, so a step cannot disagree with preflight.
if [[ -r /etc/os-release ]]; then
  DISTRO_ID="$(. /etc/os-release && echo "${ID:-}")"
  DISTRO_ID_LIKE="$(. /etc/os-release && echo "${ID_LIKE:-}")"
else
  DISTRO_ID=""; DISTRO_ID_LIKE=""
fi

case "$DISTRO_ID" in
  ubuntu|debian)              DISTRO_FAMILY=debian ;;
  rocky|rhel|centos|almalinux|fedora) DISTRO_FAMILY=rhel ;;
  *)
    case " $DISTRO_ID_LIKE " in
      *debian*) DISTRO_FAMILY=debian ;;
      *rhel*|*fedora*) DISTRO_FAMILY=rhel ;;
      *) DISTRO_FAMILY=unknown ;;
    esac
    ;;
esac
export DISTRO_FAMILY

pkg_update() {
  case "$DISTRO_FAMILY" in
    debian) with_retry 3 10 env DEBIAN_FRONTEND=noninteractive apt-get update -y ;;
    rhel)   with_retry 3 10 dnf -y makecache ;;
    *) echo "unsupported distro family: $DISTRO_FAMILY" >&2; return 1 ;;
  esac
}

pkg_install() {
  case "$DISTRO_FAMILY" in
    debian) with_retry 3 15 env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@" ;;
    rhel)   with_retry 3 15 dnf install -y "$@" ;;
    *) echo "unsupported distro family: $DISTRO_FAMILY" >&2; return 1 ;;
  esac
}

# Arcane materializes each stack's directory with its compose file named exactly
# as the manifest's dockerComposePath says -- which is compose.yml for the 33
# honeypot-* stacks but docker-compose.yml for auth-events-worker, llm-worker
# and ml-worker. Steps that hardcoded compose.yml silently did nothing for
# those three (#2817). Resolve it instead of assuming.
stack_compose_file() {
  local dir="$1" f
  for f in compose.yml docker-compose.yml; do
    [[ -f "$dir/$f" ]] && { printf '%s\n' "$f"; return 0; }
  done
  return 1
}

# ---------------------------------------------------------------------------
# Phase 0 — preflight
# ---------------------------------------------------------------------------
step_preflight_os() {
  case "$DISTRO_FAMILY" in
    debian|rhel) : ;;
    *) echo "Unsupported OS '$DISTRO_ID' (need an Ubuntu/Debian or Rocky/RHEL family host)" >&2; return 1 ;;
  esac
  echo "OS: ${DISTRO_ID} (family: ${DISTRO_FAMILY})"
}

# Rocky enforces SELinux and ships firewalld enabled; Ubuntu did neither.
# Both can silently break a honeypot host -- containers hitting EACCES on a
# bind mount, or published sensor ports being filtered. Deliberately REPORTS
# rather than changes: turning off a firewall or SELinux is a security
# decision for the operator, not something an installer should do quietly.
# Non-fatal by design, exactly like step_preflight_disks.
step_preflight_rhel_platform() {
  [[ "$DISTRO_FAMILY" == "rhel" ]] || { echo "not a RHEL-family host, nothing to check"; return 0; }

  local mode="unknown"
  command -v getenforce >/dev/null 2>&1 && mode="$(getenforce 2>/dev/null)"
  echo "SELinux: $mode"
  if [[ "$mode" == "Enforcing" ]]; then
    echo "WARNING: SELinux is enforcing. Compose bind mounts written for Ubuntu"
    echo "         carry no :z/:Z labels, so containers can fail with permission"
    echo "         denied on paths under /var/dockge/stacks. Verify container"
    echo "         health after the run and check 'ausearch -m avc -ts recent'."
  fi

  if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "WARNING: firewalld is active. The Ubuntu build installed ufw but never"
    echo "         enabled it, so this host previously ran with no host firewall."
    echo "         Confirm the sensor ports are actually reachable from outside"
    echo "         before treating the install as good."
  else
    echo "firewalld: inactive"
  fi
  return 0
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
step_pkg_update() {
  pkg_update
}

step_base_packages() {
  # Same tools either way; four of them are simply named differently.
  #   dnsutils      -> bind-utils        (dig, nslookup)
  #   gnupg         -> gnupg2
  #   openssh-client -> openssh-clients  (note the plural)
  #   ufw           -> firewalld         (RHEL's host firewall; see
  #                                       step_preflight_rhel_platform, which
  #                                       reports rather than configures it)
  # lsb-release is Debian-only and unused on RHEL, where /etc/os-release
  # carries the same information.
  case "$DISTRO_FAMILY" in
    debian)
      pkg_install ca-certificates curl dnsutils gnupg lsb-release git jq rsync ufw \
        xfsprogs nvme-cli openssh-client
      ;;
    rhel)
      # EPEL first, and unconditionally: Rocky's own repos do not carry
      # fuse-sshfs (step_sshfs_install) or dkms (the GPU branch). It used to be
      # installed only inside the GPU branch, so a host with
      # ENABLE_GPU_STACK=false reached step_sshfs_install with no repo
      # providing sshfs at all and failed there -- hit live on the 2026-09-03
      # Rocky 10 rebuild ("No match for argument: fuse-sshfs"). Installing it
      # here makes it available to every later step regardless of profile.
      pkg_install epel-release
      pkg_install ca-certificates curl bind-utils gnupg2 git jq rsync firewalld \
        xfsprogs nvme-cli openssh-clients
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Phase 2 — Docker + Compose plugin
# ---------------------------------------------------------------------------
step_docker_repo() {
  case "$DISTRO_FAMILY" in
    debian)
      install -m 0755 -d /etc/apt/keyrings
      with_retry 3 10 curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc
      chmod a+r /etc/apt/keyrings/docker.asc
      . /etc/os-release
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list
      with_retry 3 10 apt-get update -y
      ;;
    rhel)
      # Docker's own CentOS repofile, dropped in verbatim rather than added
      # via `dnf config-manager`: that plugin's syntax changed between dnf4
      # and dnf5, and writing the file works identically on both.
      #
      # Its baseurl interpolates $releasever, which on Rocky resolves to the
      # major version ("10") and not the point release -- checked, because
      # Docker publishes centos/10 but no centos/10.2, so a point-release
      # $releasever would 404 every package.
      with_retry 3 10 curl -fsSL https://download.docker.com/linux/centos/docker-ce.repo \
        -o /etc/yum.repos.d/docker-ce.repo
      chmod 0644 /etc/yum.repos.d/docker-ce.repo
      with_retry 3 10 dnf -y makecache
      ;;
  esac
}

step_docker_install() {
  # Package names are the same on both -- Docker ships them under identical
  # names in the deb and rpm repos.
  pkg_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

step_docker_daemon_config() {
  # Matches the live homeserver's /etc/docker/daemon.json: bounded log
  # rotation (containers run forever, unbounded logs will fill /var), wider
  # default-address-pools (STACK-REBUILD.md documents this box exhausting
  # Docker's default pools once ~15+ Compose projects are up — fix it before
  # that happens rather than after), the nvidia runtime registered once the
  # container toolkit is installed (safe to declare even before the toolkit
  # exists — dockerd just won't use it until nvidia-container-runtime is on
  # $PATH), and a builder GC policy (#2743): `docker builder prune -af`
  # reclaimed 179GB of buildkit cache with zero active entries the day /var
  # hit 96% and took down two ES-backed CI legs (unavailable_shards_exception
  # on primary allocation) -- `builder.gc` is on by default, but dockerd
  # infers its threshold as a *percentage* of the filesystem
  # (defaultReservedSpacePercentage = 10 in moby's builder-next/worker/gc.go;
  # in 29.x the full path is daemon/internal/builder-next/worker/gc.go),
  # which on this 1.8T /var computes to exactly 179GB -- the same 179GB
  # `docker builder prune -af` reclaimed. Exactly, because diskPercentage()
  # rounds as `(total*pct/100 / (1<<30) + 1) * 1e9`: 178 GiB-units + 1, times
  # 1e9. Note that makes it 179 *decimal* GB (166.7 GiB), and that the knob is
  # ReservedSpace -- a floor GC will not prune below -- not a ceiling; the
  # nominal ceiling is the inferred MaxUsedSpace (80% = 1.43 TB). On this host
  # the floor is what binds, so 179GB was the operative target.
  # The GC was working; its inferred
  # threshold was simply far too large for this box. `builder.gc` is buildkit's own
  # supported policy mechanism (no separate systemd timer needed): it runs
  # automatically as part of normal build activity once enabled, keeping
  # cache usage near the explicit values below rather than the inferred
  # default.
  # 20GB is generous for any single build on this box (the largest image
  # here, backend-service's Rust release build, has nowhere near that much
  # unique layer churn) while still well below the 179GB this issue found.
  # Careful with the unit: dockerd parses these values with units.RAMInBytes
  # (confirmed for all three fields, not just the deprecated one --
  # daemon/internal/builder-next/controller.go on the docker-29.x branch
  # calls units.RAMInBytes on ReservedSpace, MaxUsedSpace and MinFreeSpace
  # alike), which is binary, so "20GB" is read as 20 GiB (21,474,836,480 B)
  # and `docker buildx inspect` renders it back as "20GiB". Real reduction
  # from the pre-#2743 inferred floor is 179.0 GB -> 21.5 GB, about 157.5 GB
  # tighter.
  #
  # #2750: `defaultKeepStorage` alone was wrong in two ways. First, setting
  # only it means `reservedSpace != 0` in DefaultGCPolicy's guard below, so
  # the whole percentage-inference block that used to also fill in
  # MaxUsedSpace/MinFreeSpace never runs -- both silently stay 0 (disabled).
  # Confirmed directly against the moby source for the docker-29.x branch
  # (the version actually running here, `docker version` -> 29.7.2),
  # daemon/internal/builder-next/worker/gc.go:
  #   if reservedSpace == 0 && maxUsedSpace == 0 && minFreeSpace == 0 {
  #       reservedSpace = diskPercentage(dstat, defaultReservedSpacePercentage)  // 10%
  #       maxUsedSpace  = diskPercentage(dstat, defaultMaxUsedPercentage)        // 80%
  #       minFreeSpace  = diskPercentage(dstat, defaultMinFreePercentage)        // 20%
  #   }
  # Before #2743 this host had an inferred MinFreeSpace of ~358GB (20% of
  # 1.8T) -- a guard that pruned build cache whenever /var free space fell
  # below that, regardless of what was actually consuming the disk. Setting
  # only defaultKeepStorage silently dropped that guard entirely; buildkit
  # now holds its 20GB cap and never reacts to disk pressure from a
  # non-buildkit source (Elasticsearch growth, a large writable container
  # layer, log growth).
  # Second, `defaultKeepStorage` is deprecated -- confirmed in
  # daemon/config/builder.go's own doc comment ("Deprecated option is now
  # equivalent to DefaultReservedSpace") -- with no deprecation warning
  # logged when set, so a future Docker upgrade could drop the key outright
  # and silently revert to the inferred ~179GB cap on this 1.8T /var while
  # this comment still promised 20GB.
  # Fix: the non-deprecated spelling plus an explicit floor. /var sits at
  # 93% (131G free of 1.8T) as of 2026-08-31 -- tighter than the 90% this
  # script's other guidance assumes -- so 100GB is a real, load-bearing
  # floor here, not a formality: buildkit GC now starts pruning once /var
  # free space drops within about 31GB of that floor, not after the disk is
  # already critical.
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
    },
    "builder": {
        "gc": {
            "enabled": true,
            "defaultReservedSpace": "20GB",
            "defaultMaxUsedSpace": "100GB",
            "defaultMinFreeSpace": "100GB"
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
  case "$DISTRO_FAMILY" in
    debian)
      pkg_install ubuntu-drivers-common
      # `ubuntu-drivers autoinstall` was removed in this box's ubuntu-drivers-common
      # (1:0.10.9, Ubuntu 26.04) -- the CLI now uses `install` with no args to mean
      # "install the recommended driver for every detected device", confirmed via
      # `ubuntu-drivers -h` live on this box. Keep the old subcommand as a fallback
      # in case a different target runs an older ubuntu-drivers-common.
      ubuntu-drivers install || ubuntu-drivers autoinstall
      ;;
    rhel)
      # There is no ubuntu-drivers equivalent, so this is explicit: NVIDIA's
      # CUDA repository plus the `cuda-drivers` meta-package, which pulls the
      # proprietary driver and its DKMS kernel module.
      #
      # dkms lives in EPEL, not in Rocky's own repos, and the module will not
      # build without headers matching the *running* kernel -- so both are
      # installed before the driver rather than letting the driver fail late.
      pkg_install epel-release
      pkg_install dkms gcc make "kernel-devel-$(uname -r)" "kernel-headers-$(uname -r)" \
        || pkg_install dkms gcc make kernel-devel kernel-headers
      with_retry 3 10 curl -fsSL \
        "https://developer.download.nvidia.com/compute/cuda/repos/rhel10/$(uname -m)/cuda-rhel10.repo" \
        -o /etc/yum.repos.d/cuda-rhel10.repo
      chmod 0644 /etc/yum.repos.d/cuda-rhel10.repo
      with_retry 3 10 dnf -y makecache
      # Deliberately `cuda-drivers` (proprietary) and not `nvidia-open`: the
      # open kernel modules only support Turing and newer. This box also holds
      # a Pascal Quadro P2200 alongside the Ada compute card, and while the
      # P2200 is meant to be bound to vfio-pci for the Windows sandbox rather
      # than driven by the host, picking the open modules here would make that
      # card unusable if it ever is needed on the host.
      pkg_install cuda-drivers
      ;;
  esac
}

step_gpu_container_toolkit() {
  case "$DISTRO_FAMILY" in
    debian)
      curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
        | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
      curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
        | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
        > /etc/apt/sources.list.d/nvidia-container-toolkit.list
      with_retry 3 10 apt-get update -y
      ;;
    rhel)
      with_retry 3 10 curl -fsSL \
        https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo \
        -o /etc/yum.repos.d/nvidia-container-toolkit.repo
      chmod 0644 /etc/yum.repos.d/nvidia-container-toolkit.repo
      with_retry 3 10 dnf -y makecache
      ;;
  esac
  pkg_install nvidia-container-toolkit
  nvidia-ctk runtime configure --runtime=docker
  # SELinux blocks a container from touching the GPU device nodes unless the
  # toolkit's own boolean is set. No-op where SELinux is not enforcing.
  if [[ "$DISTRO_FAMILY" == "rhel" ]] && command -v setsebool >/dev/null 2>&1; then
    setsebool -P container_use_devices 1 || echo "WARNING: could not set container_use_devices"
  fi
  systemctl restart docker
}

# One pin, used by both step_gpu_verify and step_arcane_install's #2950 check
# for whether the nvidia runtime actually works on this host.
GPU_SMOKE_IMAGE="nvidia/cuda:12.4.0-base-ubuntu22.04"

step_gpu_verify() {
  nvidia-smi -L || return 1
  docker run --rm --gpus all "$GPU_SMOKE_IMAGE" nvidia-smi -L
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
  # Ubuntu's `wireguard` is a metapackage; RHEL ships the userspace tools as
  # wireguard-tools (the kernel module is in-tree on both).
  case "$DISTRO_FAMILY" in
    debian) pkg_install wireguard ;;
    rhel)   pkg_install wireguard-tools ;;
  esac
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
# Every pattern here is line-anchored with re.M and uses [ \t] rather than
# \s around the '=', deliberately. \s matches newlines, so the previous
# `PresharedKey\s*=\s*\S+` would, on a key line with an EMPTY value, run
# past the end of its own line and swallow the first token of the next one:
#
#   PresharedKey =            ->  PresharedKey = <psk> = 10.8.0.2/32
#   AllowedIPs = 10.8.0.2/32
#
# because \s* crossed the newline and \S+ then matched "AllowedIPs". That is
# not hypothetical -- the live VPS had exactly `PresharedKey = ` with no
# value, and this produced a wg0.conf that wg-quick refused outright:
#   Key is not the correct length or format: `<psk>=10.8.0.2/32'
#   Configuration parsing error
# It then deleted the interface, so the step failed with the tunnel DOWN
# rather than merely unchanged. Measured on the 2026-09-04 rebuild.
#
# \S* (not \S+) so an empty value is matched and replaced in place instead of
# falling through to the insert branch and producing a duplicate key line.
for b in blocks:
    if b.startswith('[Peer]') and f"{peer_ip}/32" in b:
        matched += 1
        b = re.sub(r'^PublicKey[ \t]*=[ \t]*\S*[ \t]*$',
                   f'PublicKey = {new_pub}', b, flags=re.M)
        if re.search(r'^PresharedKey[ \t]*=', b, re.M):
            b = re.sub(r'^PresharedKey[ \t]*=[ \t]*\S*[ \t]*$',
                       f'PresharedKey = {new_psk}', b, flags=re.M)
        else:
            b = re.sub(r'^(PublicKey[ \t]*=[ \t]*\S*[ \t]*)$',
                       rf'\1\nPresharedKey = {new_psk}', b, flags=re.M)
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
# Validate the rewritten config BEFORE restarting. wg-quick's failure mode
# here is to `ip link delete dev wg0` on a parse error, so a bad edit does
# not leave the tunnel merely unchanged -- it takes it DOWN, on the one host
# whose reachability everything else on the homeserver depends on. `wg-quick
# strip` parses without touching the interface, so a malformed file is caught
# while the tunnel is still up and the backup taken above is restored.
if ! wg-quick strip wg0 >/dev/null 2>&1; then
  echo "rewritten $conf does not parse -- restoring the backup, tunnel untouched" >&2
  wg-quick strip wg0 2>&1 | tail -3 >&2 || true
  cp -p "$(ls -1t "$conf".bak.* | head -1)" "$conf"
  exit 1
fi
systemctl restart wg-quick@wg0
# Confirm the interface actually came back; a restart that fails leaves no
# device at all, and the caller should hear about it here rather than three
# steps later when an sshfs mount times out.
ip link show wg0 >/dev/null 2>&1 || { echo "wg0 did not come up after restart" >&2; exit 1; }
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
# Phase 6 — Arcane (#1504: replaces the old step_dockge_install)
# ---------------------------------------------------------------------------
# #1504: every already-provisioned APIARY homeserver replaced Dockge with
# Arcane (#1185) months before #1502's migration -- deploy.yml and
# docker-compose.arcane.yml both assume Arcane. This step stands Arcane up on
# a genuinely from-scratch host so step_arcane_import_stacks (later in this
# same run) has a running instance at ARCANE_URL to import the honeypot-*
# stacks into. It models docker-compose.arcane.yml's own live-verified
# service definition exactly (same image, same WireGuard-only port binding,
# same env-var names) -- that file, not this step, stays the source of truth
# for the service shape; this step only supplies the .env it reads.
#
# Bootstrap ordering (the part that genuinely needed a live host to verify,
# #1504's own caveat): Arcane's REST API -- the only thing this installer
# talks to -- authenticates by the pre-minted ARCANE_API_TOKEN, NOT by an
# OIDC session, so Arcane is fully usable by the installer the moment it's
# healthy here, before Keycloak exists. OIDC (interactive human login) is a
# separate concern that only has to work once a person visits the UI, which
# is necessarily after honeypot-keycloak has itself been imported-and-started
# by step_arcane_import_stacks. So this step writes a *placeholder*
# ARCANE_OIDC_CLIENT_SECRET good enough to satisfy the compose file's `:?`
# guard and start the container; step_provision_arcane_oidc_secret later
# replaces it with the real per-realm secret Keycloak generates on
# --import-realm (same pattern as apiary-dashboard's own client secret --
# see provision-arcane-oidc-secret.sh) and re-ups Arcane.
#
# Unresolved from-scratch chicken-and-egg (#1504, still needs a live call):
# minting ARCANE_API_TOKEN requires a first human login, and that login is
# OIDC-only (OIDC_AUTO_REDIRECT_TO_PROVIDER=true) once Keycloak is up, so a
# truly-first install is inherently two-pass -- see ARCANE_URL/
# ARCANE_API_TOKEN's own comment near the top of this file.
step_arcane_install() {
  mkdir -p /var/dockge/data /var/dockge/stacks
  local dir="/var/dockge/stacks/honeypot-arcane"
  install -d -m 755 "$dir"

  # Arcane's ENCRYPTION_KEY/JWT_SECRET/OIDC_CLIENT_SECRET have no *_FILE
  # variant it supports (confirmed against its own env-var reference, see
  # docker-compose.arcane.yml's inline comment) -- they live in this stack's
  # own .env, generated once here the same "start from zero, don't restore a
  # prior value" way step_provision_keycloak_secrets treats Keycloak's own
  # secrets. Idempotent: an existing .env is left untouched so a re-run never
  # rotates a key out from under an already-encrypted arcane-data volume
  # (rotating ENCRYPTION_KEY would make every stored secret undecryptable).
  local env_file="$dir/.env"
  if [[ ! -f "$env_file" ]]; then
    # Derive the two public URLs Arcane's OIDC needs from the same
    # KEYCLOAK_PUBLIC_DOMAIN the Keycloak realm's own example.invalid ->
    # <domain> substitution uses (arcane.<domain> for redirect URIs,
    # auth.<domain> for the issuer) -- matches docker-compose.arcane.yml's
    # and honeypot-keycloak/compose.yml's own default hostnames.
    local app_url="https://arcane.${KEYCLOAK_PUBLIC_DOMAIN}"
    local issuer_url="https://auth.${KEYCLOAK_PUBLIC_DOMAIN}/realms/apiary"
    (
      umask 077
      cat > "$env_file" <<EOF
# honeypot-arcane -- generated by install-homeserver.sh step_arcane_install
# (#1504). ENCRYPTION_KEY/JWT_SECRET are one-time-generated and MUST NOT be
# rotated once arcane-data holds encrypted secrets. OIDC_CLIENT_SECRET below
# is a bootstrap placeholder -- provision-arcane-oidc-secret.sh overwrites it
# with the real Keycloak-generated value once the realm is imported.
HP_BIND=${HP_BIND:-10.8.0.2}
ARCANE_PORT=${ARCANE_PORT:-3552}
ARCANE_URL=${app_url}
ARCANE_ENCRYPTION_KEY=$(openssl rand -base64 32)
ARCANE_JWT_SECRET=$(openssl rand -hex 32)
OIDC_ISSUER_URL=${issuer_url}
ARCANE_OIDC_CLIENT_SECRET=$(openssl rand -hex 32)
TZ=${INSTALL_TIMEZONE}
EOF
    )
    chmod 600 "$env_file"
    echo "generated honeypot-arcane .env (placeholder OIDC secret -- synced later from Keycloak)"
  else
    echo "honeypot-arcane .env already present -- leaving secrets untouched"
  fi

  # Same "copy the file, don't symlink it" shape deploy.yml's own
  # Synchronize honeypot-arcane step uses -- honeypot-arcane is deliberately
  # NOT one of the Arcane-managed Git syncs (syncing the thing that has to
  # run before any sync can happen is a bootstrap loop, see
  # docs/ARCANE-GIT-SYNC.md), so it's installer-/deploy.yml-managed by a
  # plain file copy from the repo checkout.
  # #2950: the base compose is deliberately GPU-free, because Arcane's optional
  # GPU-monitoring panel needs a *hard* NVIDIA device reservation and Docker
  # refuses to start the container at all without a working nvidia runtime
  # ("could not select device driver \"nvidia\""). Arcane is the control plane
  # that materializes every other stack, so it must be able to start on a host
  # whose GPU driver is absent or not yet loaded -- on the 2026-09-03 rebuild
  # that single reservation blocked the entire install.
  #
  # The overlay is merged in only after confirming the runtime actually works,
  # rather than trusting ENABLE_GPU_STACK: the driver needs a reboot before its
  # kernel module loads, so "GPU requested" and "GPU usable" are different
  # facts, and this step can run in between them.
  #
  # --no-interpolate matters: `config` would otherwise resolve ${...} against
  # this stack's .env and bake ENCRYPTION_KEY/JWT_SECRET/the OIDC secret as
  # literals into a world-readable compose.yml.
  local gpu_overlay="$REPO_DIR/docker-compose.arcane.gpu.yml"
  if [[ "$ENABLE_GPU_STACK" == "true" && -f "$gpu_overlay" ]] \
     && docker run --rm --gpus all "$GPU_SMOKE_IMAGE" true >/dev/null 2>&1; then
    if docker compose -f "$REPO_DIR/docker-compose.arcane.yml" -f "$gpu_overlay" \
         config --no-interpolate > "$dir/compose.yml.tmp" 2>/dev/null; then
      mv "$dir/compose.yml.tmp" "$dir/compose.yml"
      echo "Arcane: GPU monitoring enabled (nvidia runtime verified)"
    else
      rm -f "$dir/compose.yml.tmp"
      cp "$REPO_DIR/docker-compose.arcane.yml" "$dir/compose.yml"
      echo "Arcane: GPU overlay failed to render -- continuing without GPU monitoring" >&2
    fi
  else
    cp "$REPO_DIR/docker-compose.arcane.yml" "$dir/compose.yml"
    echo "Arcane: no usable NVIDIA runtime -- GPU monitoring left off (see #2950)"
  fi
  (cd "$dir" && docker compose -f compose.yml config --quiet \
    && with_retry 3 15 docker compose -f compose.yml up -d --wait)
}

# ---------------------------------------------------------------------------
# Phase 7 — secret restore from the LAN backup host
# ---------------------------------------------------------------------------
# Maps Dockge stack name -> "<name>.env" file directly under BACKUP_HOST_PATH
# (a flat directory, not "<name>/.env" subdirectories -- confirmed against
# the real backup host live during #787's homeserver reinstall, 2026-08-09).
# 1:1 for everything except the DNS stack, which the backup captured a bare .env for
# (no compose file was ever backed up for it -- see step_technitium_provision,
# which reconstructs a minimal one since it isn't part of this git repo).
# Stacks whose .env is restored from the backup host. This used to be a
# hardcoded list of 17 and had silently drifted: the manifest carries 37
# stacks, and the 2026-09-03 rebuild's backup held 38 real .env files, so 20
# stacks with genuine secrets in the backup were never even looked for and got
# .env.example placeholders from step_bootstrap_missing_envs instead
# (honeypot-canarytokens, -beelzebub, -galah, -hellpot, -elasticpot,
# -sentrypeer, -mailoney, -dicompot, -dns-honeypot, -citrix-honeypot,
# -cisco-asa-honeypot, -rdp-honeypot, -endlessh, -dashboard-backend, the five
# workers, ...). Derived from the Arcane manifest now -- the same single source
# of truth step_arcane_import_stacks and step_bootstrap_missing_envs already
# drive off -- so adding a stack there cannot leave its secrets behind again.
#
# honeypot-stack is appended explicitly: it is not in the manifest but does
# hold a real, populated .env on the live host (confirmed during #1609's backup
# pass), so dropping it would lose real configuration.
env_restore_stacks() {
  local manifest="$REPO_DIR/arcane/manifests/home-production.json"
  if [[ -r "$manifest" ]]; then
    { jq -r '.[].syncName' "$manifest"; echo honeypot-stack; } | sort -u
  else
    # Pre-clone fallback only -- the manifest lives in the repo checkout.
    printf '%s\n' honeypot-keycloak honeypot-init honeypot-cowrie honeypot-dionaea \
      honeypot-conpot honeypot-dnp3 honeypot-http honeypot-multipot honeypot-dashboard \
      honeypot-payload-analysis honeypot-tanner honeypot-elk honeypot-utilities \
      honeypot-stack ghidra ghosts technitium
  fi
}

step_restore_env_files() {
  # A missing *individual* .env is a warning -- a stack may genuinely not have
  # existed before the rebuild. But *every* restore failing is not that: it
  # means the backup host, key or path is wrong, and there are no real secrets
  # on this host at all. That case used to return 0 anyway, so the step marked
  # itself done, step_bootstrap_missing_envs filled all 38 stacks in from
  # .env.example placeholders, and the whole stack came up authenticated
  # against nothing with no failed step to show for it. Hit live on the
  # 2026-09-03 Rocky 10 rebuild: BACKUP_HOST_KEY pointed at a key file that did
  # not exist, all 38 scps failed, and the run reported restore-env-files OK.
  # Fail closed instead, and say which of the three inputs to check.
  local restored=0 missing=0
  if [[ ! -r "$BACKUP_HOST_KEY" ]]; then
    echo "BACKUP_HOST_KEY is not readable: $BACKUP_HOST_KEY" >&2
    echo "  Nothing can be restored without it -- fix the path or place the key." >&2
    return 1
  fi
  local name
  while read -r name; do
    [[ -n "$name" ]] || continue
    local src="${BACKUP_HOST_PATH}/${name}.env"
    local dest_dir="/var/dockge/stacks/${name}"
    mkdir -p "$dest_dir"
    if with_retry 3 5 scp -i "$BACKUP_HOST_KEY" -P 22 -o StrictHostKeyChecking=accept-new \
        -o ConnectTimeout=10 "${BACKUP_HOST_USER}@${BACKUP_HOST}:${src}" "$dest_dir/.env" 2>/dev/null; then
      chmod 600 "$dest_dir/.env"
      echo "restored .env for $name"
      restored=$((restored + 1))
    else
      echo "WARNING: no backed-up .env found for $name at $src (may not have existed pre-rebuild)"
      missing=$((missing + 1))
    fi
  done < <(env_restore_stacks)
  echo "restored $restored .env file(s), $missing missing"
  if [[ $restored -eq 0 ]]; then
    echo "FAILED: not a single .env was restored from ${BACKUP_HOST_USER}@${BACKUP_HOST}:${BACKUP_HOST_PATH}" >&2
    echo "  Check BACKUP_HOST / BACKUP_HOST_PATH / BACKUP_HOST_KEY. The path must" >&2
    echo "  hold one <stack>.env per stack (e.g. \$BACKUP_HOST_PATH/honeypot-elk.env)." >&2
    echo "  Continuing would bootstrap every stack from .env.example placeholders." >&2
    return 1
  fi
  return 0
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
# llm-worker, ml-worker, analysis/ghidra, sandbox/ghosts, technitium -- at its
# existing path), and Arcane's own directory-aware Git sync owns
# materializing and deploying it, driven by this manifest.
#
# #1505: of those 6, three (auth-events-worker, llm-worker, ml-worker) are
# now ALSO imported by step_arcane_import_stacks below -- confirmed to have
# no host-local state beyond .env (no bind-mounted persistent directories,
# no ownership requirements a generic directory sync wouldn't already get
# right), so folding them in was safe without a disposable host to verify
# against. Their old dedicated steps (step_auth_events_worker_start,
# step_ml_worker_start, step_llm_worker_selftest) are kept, but trimmed down
# to just the parts Arcane's own sync can't do: readiness verification
# (polling each container's own log line, since neither has a Docker
# HEALTHCHECK Arcane's `up --wait` could rely on alone -- see each step's
# own comment, #593) and, for llm-worker, its actual --selftest invocation.
#
# The other 3 stay fully on their own dedicated steps, deliberately not
# folded in:
#   - technitium (step_technitium_provision/-start/-verify): real host-local state
#     beyond .env -- config/ (zones, settings, blocklists)
#     directory that needs non-root ownership for its distroless image
#     (chown 65532:65532). #1502's own cutover lost this exact state once
#     already (disclosed in that issue's own comments) when it wasn't
#     accounted for -- a generic Arcane directory sync has no way to know
#     about it either.
#   - analysis/ghidra (step_ghidra_stack_provision/-start): needs a second,
#     conditional compose file layered on top (docker-compose.ghidra.gpu.yml,
#     only when ENABLE_GPU_STACK=true) that the Arcane manifest's single
#     dockerComposePath can't express, plus the relative-build-context
#     breakage this step's own comment already documents from the first
#     live attempt to symlink only the compose file instead of the whole
#     directory. GPU-stack correctness is expensive to get wrong and hard
#     to verify without a GPU-enabled disposable host.
#   - sandbox/ghosts (step_ghosts_host_install): ghosts-api's remote Git
#     build context (GHOSTS.git#<ref>:src) hits a confirmed Arcane v2.8.0
#     limitation (#1506 -- its image-prep step only resolves refs under
#     refs/heads/, so a tag or commit SHA both fail) -- not unverified, but
#     confirmed *broken* through Arcane's own directory sync today. Folding
#     this in would trade a working installer step for a non-functional one.
# All three needed the same kind of live verification this honeypot-*
# replacement got before being deemed safe to fold in; pihole/ghidra/ghosts
# either failed that bar for a real reason above, or -- for pihole and
# ghidra specifically -- couldn't be checked at all without a disposable
# test host to break, which wasn't a safe call to make unilaterally.
ARCANE_STACK_MANIFEST="$REPO_DIR/arcane/manifests/home-production.json"

# The four Keycloak provisioner scripts moved under arcane/home/honeypot-keycloak/
# in #1502's per-stack restructure; the installer kept calling them at the
# pre-#1502 top-level $REPO_DIR/keycloak/ path. That made all four steps fail
# with "No such file or directory" on the 2026-09-03 rebuild -- leaving the
# dashboard, Arcane and the events poller without their real OIDC secrets.
# One variable so a single fix keeps covering all four, as their own comments
# intend.
KEYCLOAK_PROVISION_DIR="$REPO_DIR/arcane/home/honeypot-keycloak/keycloak"

# arcane_api <method> <path> [json-body] -- authenticated call against this
# host's own Arcane instance. ARCANE_URL/ARCANE_API_TOKEN are operator-
# provided config (see install-homeserver.conf.example): an unattended
# installer can't complete Arcane's own interactive OIDC/passkey login, so
# bootstrapping requires a pre-generated API key (Arcane's own UI, Settings
# -> API Keys, after its first login) the same way step_provision_keycloak_secrets
# requires the Keycloak realm to already exist rather than creating one
# from nothing.
# Arcane authenticates API keys with its own `X-API-Key` header, NOT
# `Authorization: Bearer`. Sending Bearer returns 401 with an ErrorModel body
# and no `data` field, which every caller below then reads as an empty result
# rather than as an auth failure -- so the import "failed" with an empty error
# message and every downstream step cascaded off it. Measured live on the
# 2026-09-03 Rocky 10 rebuild against Arcane v2.9.0:
#   Authorization: Bearer <key> -> 401 {"title":"Unauthorized",...}
#   X-API-Key: <key>            -> 200 {"success":true,"data":[...]}
arcane_api() {
  local method="$1" path="$2" body="${3:-}"
  local -a curl_args=(-sS -X "$method" "${ARCANE_URL%/}/api${path}" \
    -H "X-API-Key: $ARCANE_API_TOKEN" -H "Content-Type: application/json")
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
    local resp status
    resp=$(arcane_api POST /environments/0/gitops-syncs \
      "$(jq -n --arg name "$name" --arg repo "$existing_repo_id" \
             --arg branch "$GIT_REF" --arg path "$compose_path" \
        '{name:$name, repositoryId:$repo, branch:$branch, composePath:$path,
          autoSync:false, syncDirectory:true, syncInterval:300}')")
    status=$(echo "$resp" | jq -r '.data.lastSyncStatus // "unknown"')

    if [[ -n "$staged_env" ]]; then
      mkdir -p "$dir"
      mv "$staged_env" "$dir/.env"
      chmod 600 "$dir/.env"
    fi
    # #2959: deliberately NO deploy here. This loop walks the manifest in file
    # order, and honeypot-init sorts before honeypot-elk -- so bringing each
    # stack up as it is imported started honeypot-init's one-shot jobs while
    # the stack that defines elasticsearch was still queued behind them in this
    # same loop. They then looped forever on
    #   curl: (6) Could not resolve host: elasticsearch
    # while the import blocked on their `up --wait`, and the whole step
    # deadlocked on itself until honeypot-elk was imported out of band by hand.
    #
    # Deploy order is not this step's job. start-elasticsearch -> start-init ->
    # start-remaining exist precisely to honour the ordering
    # docs/STACK-REBUILD.md documents, they run immediately after this step,
    # and they cover every stack imported here. Syncing without deploying keeps
    # exactly one place responsible for start order.

    if [[ "$status" != "success" ]]; then
      # Reported for every stack now, not only ones without a staged .env: the
      # old carve-out existed because this loop used to deploy, so a stack that
      # had its secrets was expected to come up. Nothing deploys here any more,
      # so a non-success sync means the same thing either way -- and it is
      # informational regardless, since the start-* steps below re-deploy once
      # real secrets are in place.
      echo "  $name: sync reported '$status' (often expected pre-secrets -- see: $resp)"
      failures=$((failures + 1))
    fi
  # #1505: also imports auth-events-worker/llm-worker/ml-worker -- see this
  # file's own header comment (Phase 8) for why those 3 of the 6 non-
  # honeypot-* stacks were safe to fold in and the other 3 (pihole, ghidra,
  # ghosts) deliberately weren't.
  done < <(jq -r '.[] | select((.syncName | startswith("honeypot-")) or (.syncName as $n | ["auth-events-worker","llm-worker","ml-worker"] | index($n) != null)) | [.syncName, .dockerComposePath] | @tsv' "$ARCANE_STACK_MANIFEST")

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
  done < <(jq -r '.[] | select((.syncName | startswith("honeypot-")) or (.syncName as $n | ["auth-events-worker","llm-worker","ml-worker"] | index($n) != null)) | [.syncName, .dockerComposePath] | @tsv' "$ARCANE_STACK_MANIFEST")
  echo "Bootstrapped $n placeholder .env file(s) — review for CHANGE_ME values."
}

# #2498: honeypot-canarytokens' compose interpolates
# ${CANARY_PUBLIC_HOSTNAME:-honeypot.example}, and until now nothing in any
# deploy path ever supplied the real value -- the sed passes reach only
# vps/traefik/dynamic.yml, step_bootstrap_missing_envs copies this stack's
# .env.example verbatim (shipped placeholder included), there is no second
# domain-scoped variable inside this stack's own interpolation scope to chain
# a compose-level fallback onto, and step_restore_env_files can only restore
# what a LAN backup once captured. Every fresh install baked unresolvable
# 'honeypot.example' into every created token unless an operator hand-typed
# the apex afterwards -- the exact same bare-apex string this config already
# knows (and validates non-placeholder, above) as KEYCLOAK_PUBLIC_DOMAIN, and
# the exact string docs/CGNAT-DEPLOYMENT.md instructs typing into this stack's
# .env by hand. Runs AFTER both env steps above so it sees whichever of
# {restored backup, example copy} landed:
#   - key absent                    -> appended with the apex
#   - empty or shipped 'honeypot.example' -> replaced with the apex
#   - anything else                 -> left untouched (a real hand-set override
#                                      always wins; re-runs stay idempotent)
step_seed_canary_public_hostname() {
  # CANARY_STACK_DIR exists purely so the seeding branches can be exercised
  # against a scratch directory in tests; every real invocation takes the
  # default below, matching how every other step addresses stack dirs.
  local env_file="${CANARY_STACK_DIR:-/var/dockge/stacks/honeypot-canarytokens}/.env"
  if [[ ! -f "$env_file" ]]; then
    echo "honeypot-canarytokens has no .env yet -- skipping CANARY_PUBLIC_HOSTNAME seed"
    return 0
  fi
  local current
  current=$(grep -E '^CANARY_PUBLIC_HOSTNAME=' "$env_file" | tail -1 | cut -d= -f2-)
  case "$current" in
    ""|"honeypot.example")
      if grep -qE '^CANARY_PUBLIC_HOSTNAME=' "$env_file"; then
        sed -i "s|^CANARY_PUBLIC_HOSTNAME=.*|CANARY_PUBLIC_HOSTNAME=${KEYCLOAK_PUBLIC_DOMAIN}|" "$env_file"
        echo "seeded CANARY_PUBLIC_HOSTNAME=${KEYCLOAK_PUBLIC_DOMAIN} in honeypot-canarytokens/.env (replaced '${current}')"
      else
        {
          echo ""
          echo "# seeded by install-homeserver.sh (#2498) from KEYCLOAK_PUBLIC_DOMAIN"
          echo "CANARY_PUBLIC_HOSTNAME=${KEYCLOAK_PUBLIC_DOMAIN}"
        } >> "$env_file"
        echo "seeded CANARY_PUBLIC_HOSTNAME=${KEYCLOAK_PUBLIC_DOMAIN} in honeypot-canarytokens/.env (key was absent)"
      fi
      chmod 600 "$env_file"
      ;;
    *)
      echo "honeypot-canarytokens/.env already sets CANARY_PUBLIC_HOSTNAME=${current} -- leaving it alone"
      ;;
  esac
  return 0
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

  # honeypot-cowrie bind-mounts state/honeyfs/{cowrie,cowrie-share} and runs as
  # uid 2000 (its Dockerfile's `USER cowrie`); hp-honeyfs-implant deliberately
  # shares that uid so both can write the same tree -- see honeypot-cowrie's
  # own compose comment on the honeyfs-implant service. Nothing created these
  # directories on the host, so on a from-scratch install Docker made them as
  # root:root and cowrie's entrypoint could not seed the empty mount from
  # honeyfs.dist. Measured on the 2026-09-03 Rocky 10 rebuild -- hp-cowrie
  # crash-looped indefinitely on:
  #   cp: cannot create directory '/cowrie/cowrie-git/honeyfs/./etc': Permission denied
  # No SELinux denial involved (ausearch clean): plain ownership. Create them
  # owned correctly up front rather than letting the bind mount invent them.
  local d
  for d in "$REPO_DIR/state/honeyfs/cowrie" "$REPO_DIR/state/honeyfs/cowrie-share"; do
    install -d -m 755 -o 2000 -g 2000 "$d"
  done
}

step_provision_buildx_cache() {
  # #2822: .github/workflows/containers.yml exports every image's layer
  # cache to type=local under /mnt-1/buildx-cache/<image> when the build
  # lands on this box's self-hosted runners, because the type=gha cache was
  # measured ~2x over GitHub's 10 GB per-repository ceiling and therefore
  # being LRU-evicted while in use.
  #
  # The runners execute as github-ci-runner (systemd User= on the
  # actions.runner.*.supermicro-ci* units), and /mnt-1 is root:root 0755 --
  # so the workflow cannot create this directory itself. Measured live
  # 2026-09-02: `sudo -u github-ci-runner mkdir -p /mnt-1/buildx-cache/x`
  # -> "Permission denied", exit 1, which under a step's default `bash -e`
  # fails every one of the Containers matrix rows. Provisioning it here
  # rather than by hand on the live host is the point: #1609 replays this
  # script on a rebuild, and a hand-made directory would not survive that.
  #
  # 0775 with the runner as group owner (not 0777) so the deploy runner and
  # an interactive admin can also write it without making it world-writable
  # on a filesystem that also holds /mnt-1/benchmarks. setgid keeps
  # per-image subdirectories group-owned as builds create them.
  local cache_dir=/mnt-1/buildx-cache
  local runner_user=github-ci-runner

  if ! id -u "$runner_user" >/dev/null 2>&1; then
    echo "  $runner_user does not exist yet -- creating $cache_dir root-owned;"
    echo "  re-run this step after the CI runners are installed."
    install -d -m 0755 "$cache_dir"
    return 0
  fi

  install -d -m 2775 -o "$runner_user" -g "$runner_user" "$cache_dir"

  # Prove it, rather than assuming install(1) implies the runner can write:
  # the check that was missing is the whole reason this step exists.
  if ! runuser -u "$runner_user" -- test -w "$cache_dir"; then
    echo "  ERROR: $cache_dir is not writable by $runner_user" >&2
    ls -ld "$cache_dir" >&2
    return 1
  fi
  echo "  $cache_dir writable by $runner_user (verified)"
}

step_build_zeek_image() {
  # honeypot-elk's zeek-proxy runs the same Zeek build as the VPS sensor, so
  # both load an identical parser set -- a divergence there would quietly make
  # the two sensors disagree about the same traffic.  The build context stays
  # in vps/zeek rather than being copied into the elk stack, because two
  # copies drift.
  #
  # Arcane syncs one directory per project, so the elk compose cannot use a
  # build: context that escapes its own directory.  It names the local tag
  # with pull_policy: never instead, which means nothing in that compose
  # builds it -- and without pull_policy Arcane tries to `docker pull
  # xore-zeek:local` and fails the entire project deploy on a tag that exists
  # in no registry.  Building it here is what makes that reference resolve on
  # a clean install.
  local ctx="$REPO_DIR/vps/zeek"
  [[ -d "$ctx" ]] || { echo "missing Zeek build context: $ctx" >&2; return 1; }
  docker build -f "$ctx/Containerfile" -t xore-zeek:local "$ctx"
  docker image inspect xore-zeek:local >/dev/null
}

# #2959: start the whole honeypot-elk stack, but only GATE on elasticsearch.
#
# `up -d --wait` waits for every service in the stack, and one of them --
# pcap-sync -- cannot become healthy at this point by construction. Its
# healthcheck asserts that the newest file under /src is recent, and /src is
# the sshfs-backed VPS Suricata pcap directory, which is mounted by
# step_sshfs_mounts. Those mounts need logs/<name> to exist, which
# honeypot-init's log-init job creates, which needs a healthy elasticsearch --
# i.e. this step. The dependency is circular, so on a from-scratch host this
# step burned all three retries and failed every time, on pcap-sync alone,
# while elasticsearch, kibana, evebox, filebeat, zeek-proxy, arkime-capture and
# arkime-viewer all reached Healthy. Measured on the 2026-09-04 rebuild.
#
# Everything still gets started; only the readiness gate is narrowed to the
# service the next step actually depends on. pcap-sync is left to come healthy
# on its own once sshfs-mounts runs -- it has restart: unless-stopped and
# autoheal watches it, and this was confirmed live: the moment the mounts
# appeared it went healthy without intervention.
step_start_elasticsearch_first() {
  cd /var/dockge/stacks/honeypot-elk || return 1
  with_retry 3 15 docker compose -f compose.yml up -d
  with_retry 3 15 docker compose -f compose.yml up -d --wait --no-recreate elasticsearch
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
    echo "  MaxMind account + license key, see docs/GEOIP-THREAT-INTEL.md)"
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

# snare is the one Tanner-group sensor whose log directory must be root-owned.
# honeypot-init's log-init job creates every logs/<sensor> directory uniformly
# as 65534:65534, which is right for all of them except this one, so this runs
# between start-init (which creates the directory) and start-remaining (which
# starts the container that needs it).
#
# The mechanism, which docs/STACK-REBUILD.md already records: hp-snare runs as
# root but with cap_drop: ALL and only SETGID/SETUID added -- deliberately no
# DAC_OVERRIDE, because snare's own check_privileges() runs before it drops
# privileges. Root without DAC_OVERRIDE cannot write a file it does not own,
# so snare's first act, writing /opt/snare/snare.pid, fails:
#
#   PermissionError: [Errno 13] Permission denied: '/opt/snare/snare.pid'
#
# and the container crash-loops (13 restarts before this was caught on the
# 2026-09-04 rebuild). Note the recursion: chowning only the directory is not
# enough once a previous crashing run has already left snare.cfg/.log/.err/.pid
# behind owned by nobody -- measured, the container still failed on the
# pre-existing pid file. The directory is left mode-unchanged; only ownership
# is corrected.
step_fix_snare_ownership() {
  local d="$REPO_DIR/logs/snare"
  [[ -d "$d" ]] || { echo "logs/snare does not exist yet -- did start-init run?"; return 1; }
  chown -R root:root "$d"
  echo "logs/snare (and its contents) set root:root for snare's pre-drop check_privileges()"
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
    # Use the manifest's OWN dockerComposePath basename, not a hardcoded
    # "compose.yml". Arcane materializes each stack's directory with the file
    # named exactly as the manifest says, and three of the stacks this loop
    # covers -- auth-events-worker, llm-worker, ml-worker -- carry
    # docker-compose.yml. Testing for compose.yml therefore skipped all three
    # silently (`|| continue`, no message), so they were never started at all
    # on a from-scratch install. Their dedicated readiness steps below then
    # reported nonsense about containers that had never been created
    # ("running but never logged its startup line"), because `docker logs` on a
    # nonexistent container just fails the grep. That is #2817: llm-worker
    # completely undeployed, zero containers, and nothing saying so.
    local compose_file="${compose_path##*/}"
    [[ -n "$compose_file" ]] || compose_file="compose.yml"
    if [[ ! -f "$dir/$compose_file" ]]; then
      echo "-- $name: no $compose_file in $dir, skipping"
      continue
    fi
    # A stack whose every service sits behind a Compose profile has nothing to
    # start by default: `up` exits non-zero with "no service selected". That is
    # the correct state, not a failure -- honeypot-correlator-worker,
    # -attacker-identity-worker, -payload-inventory-worker and
    # -agent-intrusion-worker are all gated behind the "legacy" profile,
    # deliberately off since the #1628 Go-worker retirement. Counting them as
    # failures put four spurious FAILEDs in the summary of every clean install,
    # which is exactly the expected-noise problem that trains an operator to
    # skim past a real one.
    echo "-- $name: docker compose -f $compose_file up -d --wait"
    local out rc
    out=$( (cd "$dir" && with_retry 3 15 docker compose -f "$compose_file" up -d --wait) 2>&1 ); rc=$?
    printf '%s\n' "$out"
    if (( rc != 0 )); then
      if printf '%s' "$out" | grep -qi 'no service selected'; then
        echo "   $name: all services are profile-gated, nothing to start by default -- skipping"
      else
        echo "FAILED: $name"
        failures=$((failures + 1))
      fi
    fi
  done < <(jq -r '.[] | select((.syncName | startswith("honeypot-")) or (.syncName as $n | ["auth-events-worker","llm-worker","ml-worker"] | index($n) != null)) | [.syncName, .dockerComposePath] | @tsv' "$ARCANE_STACK_MANIFEST")
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
    "$KEYCLOAK_PROVISION_DIR/provision-events-poller.sh"
}

step_provision_dashboard_oidc_secret() {
  # honeypot-dashboard is one of the generic STACK_DEFS stacks
  # step_start_remaining_stacks already started (and it has no secret yet
  # at that point, so it crash-loops on first boot) -- this step runs
  # after that, once Keycloak is actually up, same as
  # step_provision_events_poller_secrets right above. No need to also
  # restart the dashboard here: it has restart: unless-stopped, so its
  # own crash-restart loop picks up the freshly written secret within
  # seconds.
  local secrets_dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  [[ -f "$secrets_dir/bootstrap-admin-password" ]] || {
    echo "no bootstrap-admin-password at $secrets_dir -- was provision-keycloak-secrets skipped?" >&2
    return 1
  }
  KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  KEYCLOAK_ADMIN_PASSWORD="$(< "$secrets_dir/bootstrap-admin-password")" \
    "$KEYCLOAK_PROVISION_DIR/provision-dashboard-oidc-secret.sh"
}

step_provision_arcane_oidc_secret() {
  # #1504: step_arcane_install stood Arcane up with a placeholder OIDC secret
  # (good enough for the API-token-driven import, not for interactive login).
  # Now that Keycloak is up (start-remaining above waited it healthy, same as
  # for dashboard/events-poller right above), fetch the real per-realm
  # `arcane` client secret Keycloak generated on --import-realm and re-up
  # Arcane with it. Path convention deliberately identical to its two sibling
  # provisioner steps above so a single fix covers all three.
  local secrets_dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  [[ -f "$secrets_dir/bootstrap-admin-password" ]] || {
    echo "no bootstrap-admin-password at $secrets_dir -- was provision-keycloak-secrets skipped?" >&2
    return 1
  }
  KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  KEYCLOAK_ADMIN_PASSWORD="$(< "$secrets_dir/bootstrap-admin-password")" \
    "$KEYCLOAK_PROVISION_DIR/provision-arcane-oidc-secret.sh"
}

step_provision_account_console_scopes() {
  # #1697: Keycloak's built-in account-console client is created by
  # --import-realm with no client scopes at all, which makes the account
  # console 403 on its own REST call (#1690). It cannot be fixed in the realm
  # JSON -- see provision-account-console-scopes.sh's header for the two
  # reasons and the measurements behind them -- so it is reconciled here,
  # alongside the sibling provisioners that also exist because the realm
  # format cannot express what they set.
  local secrets_dir="/var/dockge/stacks/honeypot-keycloak/secrets"
  [[ -f "$secrets_dir/bootstrap-admin-password" ]] || {
    echo "no bootstrap-admin-password at $secrets_dir -- was provision-keycloak-secrets skipped?" >&2
    return 1
  }
  KEYCLOAK_ADMIN_USERNAME="${KEYCLOAK_BOOTSTRAP_ADMIN_USERNAME:-admin}" \
  KEYCLOAK_ADMIN_PASSWORD="$(< "$secrets_dir/bootstrap-admin-password")" \
    "$KEYCLOAK_PROVISION_DIR/provision-account-console-scopes.sh"
}

step_fix_apiary_backend_permissions() {
  # apiary-backend's image runs USER nobody (uid 65534) -- deliberately
  # unprivileged, unlike the retired Go dashboard which ran as root and (its
  # own compose comment says explicitly) bypassed file permissions entirely.
  # Every host resource backend-service/backend-service-mounted/backend-
  # worker-payload-inventory touch was provisioned under that old root-bypass
  # assumption and never revisited for #1608/#1612/#1622's cutover to this
  # image. Confirmed live (2026-08-22): `cat /state/dashboard-config.json`
  # inside hp-apiary-backend itself returned Permission denied -- the
  # dashboard's own config/users/audit/threat-intel state was unreadable by
  # the container serving it. Narrow ACL grants (this repo's own existing
  # precedent -- see sandbox/repair-permissions.sh) rather than running these
  # two network-reachable services as root: grants exactly nobody's uid the
  # access it needs, nothing broader. The six honeypot-*/requests/pending
  # spools get the identical grant at their own point of creation (each
  # one's install/process script, not here) since those are host directories
  # this script doesn't own; dashboard-state/dionaea-lib/services-adapter-
  # socket are plain Docker-managed named volumes with no other natural home.
  command -v setfacl >/dev/null 2>&1 || pkg_install acl

  local dashboard_state dionaea_lib adapter_socket
  dashboard_state=$(docker volume inspect dashboard-state --format '{{.Mountpoint}}' 2>/dev/null) || return 0
  dionaea_lib=$(docker volume inspect dionaea-lib --format '{{.Mountpoint}}' 2>/dev/null) || return 0
  adapter_socket=$(docker volume inspect services-adapter-socket --format '{{.Mountpoint}}' 2>/dev/null) || return 0

  # dashboard-state: config/users/audit/intelligence + script-payloads, all
  # root:*00 from the old Go dashboard's root-owned writes. Recursive grant
  # covers what's there today; the default ACL (d:u:...) covers every file
  # either service creates from here on. Explicit mask on every call --
  # combining access and default entries in one `-m` invocation was found
  # live to leave the access mask at `---` (any named entry silently
  # ineffective) despite the entry itself showing correctly in getfacl.
  setfacl -R -m u:65534:rwX "$dashboard_state"
  setfacl -m mask::rwx "$dashboard_state"
  setfacl -m d:u:65534:rwx "$dashboard_state"
  setfacl -m d:mask::rwx "$dashboard_state"

  # dionaea-lib: read-only for backend-service/backend-service-mounted/
  # backend-worker-payload-inventory's PAYLOAD_DIRS reconciliation --
  # read+traverse only, dionaea itself is the only writer. Host-created
  # (owner xore:xore, 0700), not root -- same fix either way.
  setfacl -R -m u:65534:rX "$dionaea_lib"
  setfacl -m mask::rx "$dionaea_lib"
  setfacl -m d:u:65534:rx "$dionaea_lib"
  setfacl -m d:mask::rx "$dionaea_lib"

  # services-adapter-socket: control.sock is recreated by services-adapter
  # (runs as root) on every restart, so a grant on the socket file itself
  # doesn't survive -- the default ACL on its parent directory is what
  # actually persists this across restarts (a new file created in a
  # directory with a default ACL inherits it as its initial ACL). Also
  # grant the current socket directly so this step is effective immediately
  # rather than only after the next services-adapter restart.
  setfacl -m d:u:65534:rw "$adapter_socket"
  setfacl -m d:mask::rw "$adapter_socket"
  [[ -S "$adapter_socket/control.sock" ]] && {
    setfacl -m u:65534:rw "$adapter_socket/control.sock"
    setfacl -m mask::rw "$adapter_socket/control.sock"
  }
  true
}

step_auth_events_worker_start() {
  # #1505: provisioning (materializing the directory, `docker compose up`)
  # is now step_arcane_import_stacks/step_start_remaining_stacks' job, same
  # as any honeypot-* stack -- no more repo-checkout symlink here, which
  # would fight Arcane's own ownership of /var/dockge/stacks/auth-events-worker
  # (a real directory Arcane's sync materializes, not something to replace
  # with a symlink out from under it). This step runs after
  # provision-events-poller-secrets (its secret doesn't exist yet when
  # start-remaining first runs it -- restart: unless-stopped's own
  # crash-loop picks up the freshly written secret within seconds, same
  # reasoning step_provision_dashboard_oidc_secret's own comment already
  # documents for dashboard) and just verifies real readiness.
  #
  # No Docker HEALTHCHECK signal this step can trust alone (#593): poll the
  # log for the line worker.py actually emits once it's genuinely ready,
  # instead of trusting compose's "running" status.
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
  # Debian calls it sshfs; RHEL ships the same FUSE client as fuse-sshfs.
  case "$DISTRO_FAMILY" in
    debian) pkg_install sshfs ;;
    rhel)   pkg_install fuse-sshfs ;;
  esac
  mkdir -p /root/.ssh
  # Skip the copy when the configured key already IS the destination. `install`
  # errors with "are the same file" and, under set -e, fails the whole step --
  # which is what happened on the 2026-09-04 rebuild once VPS_SSH_KEY was
  # pointed at /root/.ssh/strato_vps (the natural value on a host where the key
  # has already been placed). Nothing was actually wrong.
  if [[ "$(readlink -f "$VPS_SSH_KEY" 2>/dev/null)" != "$(readlink -f /root/.ssh/strato_vps 2>/dev/null)" ]]; then
    install -m 600 "$VPS_SSH_KEY" /root/.ssh/strato_vps.tmp
    mv /root/.ssh/strato_vps.tmp /root/.ssh/strato_vps
  else
    echo "VPS_SSH_KEY is already /root/.ssh/strato_vps -- leaving it in place"
  fi
  chmod 600 /root/.ssh/strato_vps
}

# Every VPS-side log directory Filebeat, pcap-sync or the payload pipeline
# needs to see. One entry here is one sshfs mount; a directory missing from
# this list is simply absent on the homeserver, and the consumer that wanted
# it reports no error -- it just finds nothing, forever. That is the failure
# mode #1409 and #1678 both were, so the list is the single place to add to.
#
# #1742 added zeek, zeek-extract, huginn and traefik for the S5 sensing layer.
SSHFS_LOG_DIRS=(suricata portbridge zeek zeek-extract huginn traefik)

step_sshfs_mounts() {
  local dirs=() name dir
  for name in "${SSHFS_LOG_DIRS[@]}"; do
    dir=$(readlink -f "$REPO_DIR/logs/$name")
    [[ -d "$dir" ]] || {
      echo "logs/$name doesn't exist yet -- honeypot-init's log-init job should have created it."
      return 1
    }
    dirs+=("$dir")
  done

  local opts="_netdev,ro,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3,IdentityFile=/root/.ssh/strato_vps,port=2222,allow_other,default_permissions,StrictHostKeyChecking=accept-new"
  # The comment block below is written once; the per-directory lines follow.
  grep -q "read-only VPS log mounts" /etc/fstab || cat >>/etc/fstab <<EOF

# #518: read-only VPS log mounts for Suricata (eve.json + pcap/) and
# portbridge, pulled over the WireGuard tunnel. See docs/SENSORS.md.
# /opt/stacks/apiary, not the pre-#783-rebrand honeypot-stack -- confirmed
# live against the VPS during #787's homeserver reinstall (2026-08-09):
# the old path doesn't exist there anymore, silently failing this mount
# (masked non-fatally without real VPS credentials to notice with, until
# now). NOTE: this same stale honeypot-stack path still appears in ~20
# other files across the repo (docs and other scripts) -- out of scope for
# this fix, tracked separately.
EOF

  # One fstab line per directory, appended only if absent, so re-running the
  # installer after adding a new sensor is safe and additive.
  local i
  for i in "${!SSHFS_LOG_DIRS[@]}"; do
    name="${SSHFS_LOG_DIRS[$i]}"
    dir="${dirs[$i]}"
    grep -q " $dir " /etc/fstab || \
      echo "root@${VPS_WG_ADDRESS}:/opt/stacks/apiary/logs/$name $dir fuse.sshfs $opts 0 0" >>/etc/fstab
  done

  local failed=0
  for dir in "${dirs[@]}"; do
    mountpoint -q "$dir" || mount "$dir" || failed=1
    mountpoint -q "$dir" || { echo "sshfs mount failed: $dir" >&2; failed=1; }
  done
  return "$failed"
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
# Phase 8b — Technitium DNS (replaced Pi-hole 2026-09-03). The LAN backup only
# captured the DNS stack .env; the deployment definition lives under technitium/.
# ---------------------------------------------------------------------------
step_technitium_provision() {
  local dir="/var/dockge/stacks/technitium"
  mkdir -p "$dir/config"

  # Binding 0.0.0.0:53 collides with hp-dns-honeypot, which already publishes
  # 53/udp on 10.8.0.2 (the WireGuard bind IP every honeypot sensor uses,
  # per HP_BIND / CGNAT-DEPLOYMENT.md's "never reachable from your home LAN"
  # design) -- 0.0.0.0 overlaps every interface including that one, so
  # Docker's port allocator refuses the bind (confirmed live, #518).
  # Technitium is real home-LAN infra, not a honeypot component, so it binds
  # the actual LAN-facing IP. TECHNITIUM_LAN_IP is an explicit config value,
  # not inferred from the default route (auto-detection picked the wrong one
  # of two NICs on this box, confirmed live #518).
  local lan_ip="$TECHNITIUM_LAN_IP"
  install -m 0644 "$REPO_DIR/technitium/compose.yml" "$dir/compose.yml"

  # Same ${LAN_IP} interpolation mechanism the old pihole stack used since #1502
  # (a `:?required` var in a port-binding host-IP position broke Arcane's
  # own pre-flight check, see docs/ARCANE-GIT-SYNC.md). Written explicitly so
  # a genuinely fresh install gets the operator-configured address rather
  # than silently falling back to compose's 127.0.0.1 default.
  if [[ ! -f "$dir/.env" && -f "$REPO_DIR/technitium/.env.example" ]]; then
    install -m 0644 "$REPO_DIR/technitium/.env.example" "$dir/.env"
  fi
  if [[ -f "$dir/.env" ]]; then
    if grep -q '^LAN_IP=' "$dir/.env"; then
      sed -i "s|^LAN_IP=.*|LAN_IP=$lan_ip|" "$dir/.env"
    else
      printf 'LAN_IP=%s\n' "$lan_ip" >> "$dir/.env"
    fi
    chmod 600 "$dir/.env"
  fi
}

step_technitium_start() {
  [[ -f /var/dockge/stacks/technitium/.env ]] || { echo "no technitium .env restored — skipping start"; return 1; }
  (cd /var/dockge/stacks/technitium && with_retry 3 15 docker compose -f compose.yml up -d --wait)
}

step_technitium_verify() {
  local dir="/var/dockge/stacks/technitium"
  local container_answer lan_answer

  # Probe each hop separately so an unattended install failure identifies
  # whether the container-internal path or the LAN bind is bad.
  container_answer="$(docker exec technitium-dns \
    dig @127.0.0.1 example.com A +time=3 +tries=1 +short)" || return
  lan_answer="$(dig @"$TECHNITIUM_LAN_IP" example.com A +time=3 +tries=1 +short)" || return

  [[ -n "$container_answer" ]] || { echo "Technitium returned no recursive answer" >&2; return 1; }
  [[ -n "$lan_answer" ]] || { echo "Technitium returned no LAN-side answer" >&2; return 1; }
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
  # #1505: provisioning is now step_arcane_import_stacks/
  # step_start_remaining_stacks' job -- the relative-build-context breakage
  # this step used to work around by symlinking the whole directory
  # (confirmed live, first #518 test run: "failed to read dockerfile: open
  # Dockerfile: no such file or directory") is exactly what Arcane's own
  # directory-aware sync solves generically for every stack, which is the
  # entire point of #1502. Symlinking here now would fight Arcane's
  # ownership of /var/dockge/stacks/ml-worker instead. This step just
  # verifies real readiness.
  #
  # #593: compose's own `--wait` (in step_start_remaining_stacks) only
  # waits for the container to reach "running" -- ml-worker has no Docker
  # HEALTHCHECK defined, so trusting that alone reported OK on every run
  # even while the container was stuck in its own internal 5-minute
  # Elasticsearch-connect retry loop (a real requirements.txt regression,
  # #599) or had built against a broken dependency set entirely. Neither
  # failure mode makes the container exit or crash-loop at the Docker
  # level, so `--wait` alone can never catch either one. Poll the
  # container's own log for the exact line worker.py emits once it's
  # genuinely ready, instead of trusting compose's exit code.
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
  #
  # #1505: runs against Arcane's own materialized directory now, not
  # $REPO_DIR/llm-worker directly -- container_name is fixed (hp-llm-worker)
  # so a stray `up` from the repo checkout would likely still reconcile
  # against the same container rather than duplicate it, but running it
  # from the same directory Arcane manages avoids relying on that and
  # matches step_ghidra_worker_install's own "reconcile in place, don't
  # deploy a second copy" precedent. `up -d --build --wait` on an
  # already-running, unchanged stack is a safe no-op here, same reasoning.
  # Resolve the compose file from the manifest, not by guessing. llm-worker's
  # base docker-compose.yml is the Safe #66 synthetic-only file and forces
  # ES_HOST empty on purpose (#2234); captured-data mode lives in
  # docker-compose.captured-data-deploy.yml, which `include`s both. Starting the
  # base file on a host authorized for captured data gives a container that
  # believes it is in captured-data mode (LLM_ALLOW_CAPTURED_DATA=true) while
  # unable to resolve elasticsearch -- it crash-loops on
  #   configuration error: ES_HOST must be an uncredentialed local/internal HTTP endpoint
  # which is #1751's exact failure, hit again on the 2026-09-04 rebuild.
  local dir="/var/dockge/stacks/llm-worker" cf
  cf="$(jq -r '.[] | select(.syncName=="llm-worker") | .dockerComposePath' \
        "$ARCANE_STACK_MANIFEST" 2>/dev/null)"
  cf="${cf##*/}"
  if [[ -z "$cf" || ! -f "$dir/$cf" ]]; then
    cf="$(stack_compose_file "$dir")" || {
      echo "no compose file in $dir -- was arcane-import-stacks skipped or llm-worker not yet synced?"
      return 1
    }
  fi
  ( cd "$dir" && \
    with_retry 3 15 docker compose -f "$cf" up -d --build --wait && \
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
  docker run --rm --network honeynet curlimages/curl:8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13 -sf \
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
  case "$DISTRO_FAMILY" in
    debian)
      pkg_install qemu-system-x86 libvirt-daemon-system libvirt-clients bridge-utils \
        virtinst libguestfs-tools ovmf
      ;;
    rhel)
      # Same stack, different names throughout: qemu-kvm, libvirt-daemon-kvm,
      # libvirt-client, virt-install, guestfs-tools, edk2-ovmf (the UEFI
      # firmware the Windows sandbox domains boot from).
      pkg_install qemu-kvm libvirt libvirt-daemon-kvm libvirt-client bridge-utils \
        virt-install guestfs-tools edk2-ovmf
      ;;
  esac
  # RHEL 9+ splits libvirtd into modular per-driver daemons and may ship no
  # libvirtd.service at all. Enable whichever this host actually has rather
  # than assuming the monolithic one.
  if systemctl list-unit-files libvirtd.service >/dev/null 2>&1 \
     && systemctl cat libvirtd.service >/dev/null 2>&1; then
    systemctl enable --now libvirtd
  else
    systemctl enable --now virtqemud.socket virtnetworkd.socket virtstoraged.socket \
      || echo "WARNING: could not enable the modular libvirt sockets"
  fi

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

run_step preflight-os          "Confirm supported OS"               step_preflight_os
run_step preflight-disks       "Check disk layout against docs"    step_preflight_disks
run_step preflight-platform    "Report SELinux/firewalld state"     step_preflight_rhel_platform
run_step hostname-timezone     "Set hostname/timezone"              step_set_hostname

run_step pkg-update            "Refresh package metadata"           step_pkg_update
run_step base-packages         "Install base packages"              step_base_packages

run_step docker-repo           "Add Docker package repo"            step_docker_repo
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
run_step arcane-install        "Install Arcane (stack-management UI + import target)" step_arcane_install

run_step restore-env-files     "Restore .env files from LAN backup" step_restore_env_files
run_step arcane-import-stacks  "Import honeypot-* + auth-events-worker/llm-worker/ml-worker as Arcane Git syncs" step_arcane_import_stacks
run_step stage-keycloak-theme  "Check out and sync the Keycloak login theme" step_stage_keycloak_theme
run_step bootstrap-missing-envs "Bootstrap any still-missing .env from .example" step_bootstrap_missing_envs
run_step seed-canary-hostname "Seed honeypot-canarytokens' CANARY_PUBLIC_HOSTNAME from KEYCLOAK_PUBLIC_DOMAIN (#2498)" step_seed_canary_public_hostname
run_step provision-keycloak-secrets "Generate Keycloak secrets, reset bootstrap admin to admin/admin123" step_provision_keycloak_secrets

run_step shared-resources      "Create honeynet + placeholder volumes" step_create_shared_resources
run_step provision-buildx-cache "Create /mnt-1/buildx-cache for the CI runners (#2822)" step_provision_buildx_cache
run_step build-zeek-image      "Build xore-zeek:local for zeek-proxy" step_build_zeek_image
run_step start-elasticsearch   "Start honeypot-elk, wait healthy"   step_start_elasticsearch_first
run_step start-init            "Start honeypot-init, wait for one-shots" step_start_init
# #2959: the sshfs mounts move up here, ahead of start-remaining. They can only
# run after start-init (honeypot-init's log-init job is what creates the
# logs/<name> mount points), but honeypot-elk's pcap-sync reads them, so
# leaving them until after every sensor had started meant pcap-sync sat
# unhealthy for the whole middle of the run and start-elasticsearch could never
# gate on it. Placed at the first point in the run where they can succeed.
run_step sshfs-install         "Install sshfs, place VPS key"        step_sshfs_install
run_step sshfs-mounts          "Mount VPS Suricata/portbridge logs"  step_sshfs_mounts
run_step sshfs-boot-ordering   "Install WireGuard-aware mount ordering" step_sshfs_boot_ordering

run_step fix-snare-ownership   "Set logs/snare root-owned (snare drops caps)" step_fix_snare_ownership
run_step start-remaining       "Start remaining sensor/dashboard stacks" step_start_remaining_stacks

run_step provision-events-poller-secrets "Grant auth-events-poller view-events + write its secret" step_provision_events_poller_secrets
run_step provision-dashboard-oidc-secret "Write dashboard's OIDC client secret from Keycloak" step_provision_dashboard_oidc_secret
run_step fix-apiary-backend-permissions "Grant apiary-backend's nobody uid ACL access to dashboard-state/dionaea-lib/services-adapter-socket" step_fix_apiary_backend_permissions
run_step provision-arcane-oidc-secret "Sync Arcane's real OIDC client secret from Keycloak, re-up" step_provision_arcane_oidc_secret
run_step provision-account-console-scopes "Give Keycloak's account-console client its default scopes (#1697)" step_provision_account_console_scopes
run_step auth-events-worker-start "Start auth-events-worker" step_auth_events_worker_start


run_step technitium-provision  "Install Technitium DNS config"       step_technitium_provision
run_step technitium-start      "Start Technitium DNS"                step_technitium_start
run_step technitium-verify     "Resolve container and LAN"           step_technitium_verify

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
