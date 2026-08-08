#!/usr/bin/env bash
# build-supervisor.sh -- runs the golden-image build to completion, unattended.
#
# For #288: every attempt gets a screenshot exactly 60s after it starts, to
# directly confirm it cleared the "Press any key to boot from CD or DVD"
# prompt (the known ~1-in-3 hang point) rather than inferring it from disk
# growth alone. If a whole batch of attempts fails, max_attempts is bumped
# and a new batch starts automatically. Runs until success or until
# STOPFILE appears.
#
# Usage: build-supervisor.sh [attach_pid attach_logfile]
#   attach_pid/attach_logfile: optionally attach to an already-running
#   build-with-retry.sh invocation instead of starting a fresh one for
#   batch 1.
set -uo pipefail

DIR="/mnt-1/github/APIARY/sandbox/windows/packer"
CHECKSUM="sha256:87383f0bb589d2e6f4975354835f0903b4b88ead1b1c71979bf4adc1dbfeabdf"
STOPFILE="/var/dockge/sandbox/STOP_BUILD_SUPERVISOR"
SHOTDIR="/var/dockge/sandbox/build-screenshots"
SUPLOG="/var/dockge/sandbox/build-supervisor.log"
mkdir -p "$SHOTDIR"

log() { echo "$(date -u +%FT%TZ) $*" >> "$SUPLOG"; }

screenshot_for_attempt() {
  local tag="$1"
  sleep 60
  local vnc_port
  vnc_port="$(ss -ltnp 2>/dev/null | grep qemu | grep -oP '127\.0\.0\.1:\K59[0-9]{2}' | head -1 || true)"
  if [[ -n "$vnc_port" ]]; then
    vncsnapshot -allowblank "127.0.0.1:$((vnc_port - 5900))" "$SHOTDIR/retry-${tag}-60s.jpg" >>"$SHOTDIR/screenshot.log" 2>&1
    log "60s-post-start screenshot for ${tag} saved (vnc port ${vnc_port})"
  else
    log "60s-post-start: no VNC port found for ${tag} (already past boot, or failed before the VM came up)"
  fi
}

# Watches a build-with-retry.sh log for new "attempt N/M starting" lines and
# schedules one screenshot 60s after each, until retry_pid exits.
watch_attempts() {
  local logfile="$1" batch="$2" retry_pid="$3"
  local seenfile
  seenfile="$(mktemp)"
  while kill -0 "$retry_pid" 2>/dev/null; do
    if [[ -f "$logfile" ]]; then
      grep -oP 'attempt \K[0-9]+(?=/[0-9]+ starting)' "$logfile" 2>/dev/null | while IFS= read -r n; do
        if ! grep -qx "$n" "$seenfile" 2>/dev/null; then
          echo "$n" >>"$seenfile"
          log "batch ${batch} attempt ${n} started -- scheduling 60s screenshot"
          screenshot_for_attempt "b${batch}-a${n}" &
        fi
      done
    fi
    sleep 5
  done
  rm -f "$seenfile"
}

BATCH=1
MAX_ATTEMPTS=2
INCREMENT=2
MAX_ATTEMPTS_CEILING=10  # see fast-fail guard below
ATTACH_PID="${1:-}"
ATTACH_LOG="${2:-}"

log "supervisor started (pid $$)"

if [[ -n "$ATTACH_PID" && -n "$ATTACH_LOG" ]] && kill -0 "$ATTACH_PID" 2>/dev/null; then
  log "attaching to already-running build (pid=${ATTACH_PID}, log=${ATTACH_LOG}) as batch ${BATCH}"
  watch_attempts "$ATTACH_LOG" "$BATCH" "$ATTACH_PID"
  # ATTACH_PID is not a child of this shell (it was started by a separate,
  # earlier invocation), so `wait` on it always returns 127 regardless of
  # its real exit status -- bash's wait only works on actual children.
  # build-with-retry.sh's own log is the only reliable signal here: it
  # prints "attempt N succeeded" immediately before its one and only exit 0.
  if [[ -f "$ATTACH_LOG" ]] && grep -qP 'attempt \d+ succeeded' "$ATTACH_LOG"; then
    log "batch ${BATCH} SUCCEEDED (attached run). Build complete. Supervisor exiting."
    exit 0
  fi
  log "batch ${BATCH} (attached run) failed. Restarting with increased max_attempts."
  BATCH=$((BATCH + 1))
  MAX_ATTEMPTS=$((MAX_ATTEMPTS + INCREMENT))
fi

while true; do
  if [[ -f "$STOPFILE" ]]; then
    log "stop file present, exiting"
    exit 0
  fi

  LOGFILE="/var/dockge/sandbox/packer-build-b${BATCH}-$(date -u +%Y%m%dT%H%M%SZ).log"
  log "batch ${BATCH}: launching build-with-retry.sh max_attempts=${MAX_ATTEMPTS} -> ${LOGFILE}"
  batch_start=$(date +%s)
  "$DIR/build-with-retry.sh" "$CHECKSUM" "$MAX_ATTEMPTS" >"$LOGFILE" 2>&1 &
  retry_pid=$!

  watch_attempts "$LOGFILE" "$BATCH" "$retry_pid"
  wait "$retry_pid"
  rc=$?
  batch_elapsed=$(( $(date +%s) - batch_start ))

  if [[ $rc -eq 0 ]]; then
    log "batch ${BATCH} SUCCEEDED. Build complete. Supervisor exiting."
    exit 0
  fi

  if [[ -f "$STOPFILE" ]]; then
    log "stop file present after batch ${BATCH} failure, exiting"
    exit 0
  fi

  # Fast-fail guard: a real attempt (VM boot + WinRM wait) takes tens of
  # minutes even when it ultimately fails. If a whole batch of attempts
  # burned through in well under a minute per attempt, every attempt hit
  # the same immediate config/environment error (like the missing-cd-file
  # bug this script had), not a real build -- escalating max_attempts in
  # that case just spins faster, as seen live (228 attempts/batch, ~5h,
  # zero actual builds). Stop and demand a human look rather than escalate.
  avg_s=$(( batch_elapsed / MAX_ATTEMPTS ))
  if (( avg_s < 60 )); then
    log "batch ${BATCH}: all ${MAX_ATTEMPTS} attempts failed in ${batch_elapsed}s total (~${avg_s}s/attempt) -- too fast to be a real build failure. Stopping instead of escalating; check ${LOGFILE} for the real error."
    exit 1
  fi

  if (( MAX_ATTEMPTS >= MAX_ATTEMPTS_CEILING )); then
    log "batch ${BATCH}: all ${MAX_ATTEMPTS} attempts failed and max_attempts is already at the ceiling (${MAX_ATTEMPTS_CEILING}). Stopping instead of escalating further -- this needs a human look, not more retries."
    exit 1
  fi

  log "batch ${BATCH}: all ${MAX_ATTEMPTS} attempts failed (${batch_elapsed}s total). Increasing to $((MAX_ATTEMPTS + INCREMENT)) and restarting."
  MAX_ATTEMPTS=$((MAX_ATTEMPTS + INCREMENT))
  BATCH=$((BATCH + 1))
done
