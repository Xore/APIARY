#!/usr/bin/env bash
# Host performance tuning for a Rocky Linux 10 APIARY homeserver.
#
# Applies five tunings. Each is idempotent and each is the Rocky/RHEL-family
# equivalent of the tweak, not a transliteration of the Debian recipe:
#
#   1. zram swap            zram-generator (Rocky) — there is no zram-config here
#   2. I/O scheduler        persistent udev rule — an echo to sysfs dies at reboot
#   3. trim boot services   conservative allowlist, only what is actually present
#   4. noatime              data mounts only, never / or /boot
#   5. CPU governor         tuned profile (RHEL-idiomatic), sysfs only as fallback
#
# Safety notes that drove the defaults:
#
#   * The disk swap partition is KEPT by default, at a worse priority than
#     zram. APIARY runs models that spill out of the 20 GB card into host RAM;
#     zram compresses, but it cannot hold pages the way a real swap device
#     can, and an OOM mid-sweep costs a whole benchmark run. Pass
#     --replace-swap to turn the disk swap off instead.
#   * noatime is applied only to data mounts. / and /boot are left alone.
#     /etc/fstab is backed up before it is touched.
#   * Nothing here reformats, repartitions, or deletes data.
#
# Usage:
#   sudo ./scripts/tune-rocky10.sh            # apply
#   sudo ./scripts/tune-rocky10.sh --dry-run  # print what would change
#   sudo ./scripts/tune-rocky10.sh --replace-swap
set -uo pipefail

DRY_RUN=0
REPLACE_SWAP=0
RC=0

for arg in "$@"; do
  case "$arg" in
    --dry-run)      DRY_RUN=1 ;;
    --replace-swap) REPLACE_SWAP=1 ;;
    -h|--help)      sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[%s] %s\n' "$(date -Iseconds)" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$(date -Iseconds)" "$*" >&2; RC=1; }
run()  {
  if [[ "$DRY_RUN" == 1 ]]; then printf '  would run: %s\n' "$*"; return 0; fi
  "$@"
}

[[ "$DRY_RUN" == 1 || $EUID -eq 0 ]] || { echo "must run as root (or use --dry-run)" >&2; exit 1; }

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "rocky" ]] || warn "expected Rocky Linux, found '${ID:-unknown}' — continuing, but package names may differ"
fi

# ---------------------------------------------------------------------------
# 1. zram swap
# ---------------------------------------------------------------------------
log "1/5 zram swap"
if ! rpm -q zram-generator >/dev/null 2>&1; then
  run dnf install -y zram-generator || warn "could not install zram-generator"
fi

# Half of RAM, capped at 8G. Compressed pages still occupy real memory, so a
# zram device larger than this competes with the workload it is meant to help.
ram_mb=$(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo)
zram_mb=$(( ram_mb / 2 )); [[ "$zram_mb" -gt 8192 ]] && zram_mb=8192

want_zram="# Managed by scripts/tune-rocky10.sh
[zram0]
zram-size = ${zram_mb}
compression-algorithm = zstd
swap-priority = 100"

if [[ "$(cat /etc/systemd/zram-generator.conf 2>/dev/null)" == "$want_zram" ]]; then
  log "  zram already configured (${zram_mb} MB, zstd)"
else
  log "  configuring zram0: ${zram_mb} MB, zstd, priority 100"
  if [[ "$DRY_RUN" == 1 ]]; then
    printf '  would write /etc/systemd/zram-generator.conf\n'
  else
    printf '%s\n' "$want_zram" > /etc/systemd/zram-generator.conf || warn "could not write zram-generator.conf"
  fi
  run systemctl daemon-reload
  run systemctl restart systemd-zram-setup@zram0.service || warn "zram0 did not start — check 'journalctl -u systemd-zram-setup@zram0'"
fi

# Disk swap keeps a worse (lower) priority than zram so the kernel reaches for
# compressed RAM first and only falls through to disk under real pressure.
if [[ "$REPLACE_SWAP" == 1 ]]; then
  log "  --replace-swap: disabling on-disk swap"
  while read -r dev _type _size _used _prio; do
    [[ "$dev" == /dev/zram* || -z "$dev" ]] && continue
    log "    swapoff $dev"
    run swapoff "$dev" || warn "swapoff $dev failed"
  done < <(tail -n +2 /proc/swaps)
  if grep -qE '^[^#].*\sswap\s' /etc/fstab 2>/dev/null; then
    run cp -a /etc/fstab "/etc/fstab.bak.$(date +%Y%m%dT%H%M%S)"
    if [[ "$DRY_RUN" == 1 ]]; then
      printf '  would comment out the swap line(s) in /etc/fstab\n'
    else
      sed -i -E 's|^([^#].*[[:space:]]swap[[:space:]].*)$|# disabled by tune-rocky10.sh (zram): \1|' /etc/fstab \
        || warn "could not edit /etc/fstab swap entry"
    fi
  fi
else
  log "  keeping on-disk swap as a lower-priority fallback (pass --replace-swap to remove)"
fi

# ---------------------------------------------------------------------------
# 2. I/O scheduler
# ---------------------------------------------------------------------------
# NVMe has its own deep hardware queues, so an extra software scheduler only
# adds latency -> none. SATA SSDs still benefit from light fairness -> kyber
# when available. Rotational disks keep mq-deadline, which is already default.
log "2/5 I/O scheduler"
rule=/etc/udev/rules.d/60-apiary-ioscheduler.rules
want_rule='# Managed by scripts/tune-rocky10.sh
# NVMe: bypass the software scheduler entirely.
ACTION=="add|change", KERNEL=="nvme[0-9]*n[0-9]*", ATTR{queue/scheduler}="none"
# Non-rotational SATA/SAS (SSD): kyber.
ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="kyber"
# Rotational (HDD): mq-deadline.
ACTION=="add|change", KERNEL=="sd[a-z]*", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="mq-deadline"'

if [[ "$(cat "$rule" 2>/dev/null)" == "$want_rule" ]]; then
  log "  udev rule already present"
else
  log "  writing $rule"
  if [[ "$DRY_RUN" == 1 ]]; then
    printf '  would write %s\n' "$rule"
  else
    printf '%s\n' "$want_rule" > "$rule" || warn "could not write $rule"
  fi
  run udevadm control --reload
  run udevadm trigger --subsystem-match=block --action=change || warn "udevadm trigger failed"
fi

for d in /sys/block/*/queue/scheduler; do
  [[ -r "$d" ]] || continue
  disk=$(basename "$(dirname "$(dirname "$d")")")
  case "$disk" in loop*|zram*|sr*) continue ;; esac
  log "  $disk: $(tr -d '\n' < "$d")"
done

# ---------------------------------------------------------------------------
# 3. Trim boot services
# ---------------------------------------------------------------------------
# Deliberately conservative: printing, Bluetooth and the modem manager are the
# only things safe to assume a headless server does not need. Anything else is
# reported for a human to judge rather than disabled automatically.
log "3/5 boot services"
for svc in cups.service cups.socket cups-browsed.service bluetooth.service ModemManager.service; do
  state=$(systemctl is-enabled "$svc" 2>/dev/null)
  case "$state" in
    enabled|enabled-runtime)
      log "  disabling $svc"
      run systemctl disable --now "$svc" || warn "could not disable $svc"
      ;;
    "") : ;;                       # not installed
    *) log "  $svc already $state" ;;
  esac
done

log "  slowest units this boot (review by hand, nothing disabled automatically):"
# Capture first: piping straight into head makes systemd-analyze exit on
# SIGPIPE, which would trip the fallback branch even on success.
blame=$(systemd-analyze blame 2>/dev/null)
if [[ -n "$blame" ]]; then
  printf '%s\n' "$blame" | head -8 | sed 's/^/    /'
else
  log "    (systemd-analyze unavailable)"
fi

# ---------------------------------------------------------------------------
# 4. noatime on data mounts
# ---------------------------------------------------------------------------
# Every read otherwise costs a metadata write. Skips / and /boot so a bad edit
# cannot make the machine unbootable.
log "4/5 noatime on data mounts"
fstab_changed=0
fstab_backed_up=0
while read -r _dev mnt _fs opts _dump _pass; do
  case "$mnt" in
    /|/boot|/boot/efi|none|swap|"") continue ;;
  esac
  [[ "$opts" == *noatime* ]] && { log "  $mnt already noatime"; continue; }
  log "  adding noatime to $mnt"
  if [[ "$DRY_RUN" == 1 ]]; then
    printf '  would rewrite the %s line in /etc/fstab\n' "$mnt"
    continue
  fi
  if [[ "$fstab_backed_up" == 0 ]]; then
    cp -a /etc/fstab "/etc/fstab.bak.$(date +%Y%m%dT%H%M%S)" || warn "could not back up /etc/fstab"
    fstab_backed_up=1
  fi
  # Match on the mountpoint field so only this row is rewritten.
  if awk -v m="$mnt" 'BEGIN{OFS=FS=" "} !/^#/ && $2==m {$4=$4",noatime"} {print}' /etc/fstab > /tmp/fstab.new \
     && [[ -s /tmp/fstab.new ]]; then
    cat /tmp/fstab.new > /etc/fstab && fstab_changed=1
  else
    warn "failed to rewrite fstab row for $mnt"
  fi
  rm -f /tmp/fstab.new
done < <(grep -vE '^\s*(#|$)' /etc/fstab 2>/dev/null)

if [[ "$fstab_changed" == 1 ]]; then
  run systemctl daemon-reload
  log "  fstab updated — noatime takes effect on remount or reboot"
fi

# ---------------------------------------------------------------------------
# 5. CPU governor
# ---------------------------------------------------------------------------
# On RHEL-family the supported lever is tuned, which also survives reboot;
# writing scaling_governor directly does not.
log "5/5 CPU governor"
if ! rpm -q tuned >/dev/null 2>&1; then
  run dnf install -y tuned || warn "could not install tuned"
fi
run systemctl enable --now tuned.service || warn "could not start tuned"

if [[ "$DRY_RUN" == 1 ]]; then
  printf '  would run: tuned-adm profile throughput-performance\n'
elif command -v tuned-adm >/dev/null 2>&1; then
  current=$(tuned-adm active 2>/dev/null | sed -n 's/.*: //p')
  if [[ "$current" == "throughput-performance" ]]; then
    log "  tuned profile already throughput-performance"
  else
    log "  setting tuned profile: ${current:-none} -> throughput-performance"
    tuned-adm profile throughput-performance || warn "tuned-adm failed"
  fi
else
  warn "tuned-adm unavailable; falling back to a non-persistent sysfs write"
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [[ -w "$g" ]] && echo performance > "$g"
  done
fi

gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)
log "  cpu0 governor: ${gov:-unavailable (no cpufreq driver)}"

if [[ "$RC" == 0 ]]; then log "tuning complete"; else log "tuning finished WITH WARNINGS (see above)"; fi
exit "$RC"
