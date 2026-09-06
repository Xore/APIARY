#!/usr/bin/env bash
# fix-work-ownership.sh -- #3021: a root process that touches a runner's
# _work checkout leaves root-owned files behind that the runner user can
# never clean up itself. actions/checkout@v7 then fails outright on the
# next job scheduled onto that runner:
#
#   File was unable to be removed
#   Error: EACCES: permission denied, unlink '.../__pycache__/foo.pyc'
#
# and keeps failing, in 6-10 seconds, for every job after that -- until
# someone deletes the files by hand.
#
# Two distinct causes are known, both confirmed on 2026-09-05:
#
#   1. The repo's own CI. quality.yml's #159 corpus job ran
#        docker run --rm -v "$PWD:/w" -w /w debian:trixie-slim bash -c \
#          'analysis/ghidra/benchmarks/corpus/ci_verify.sh'
#      as root (ci_verify.sh apt-installs its toolchain), so its python3
#      calls wrote root-owned bytecode straight into the bind-mounted
#      workspace. A root container needs no sudo, which is why grepping the
#      repo for `sudo` found nothing. Fixed at source by #3024
#      (PYTHONDONTWRITEBYTECODE=1 in the container and exported by
#      ci_verify.sh itself).
#   2. A manual #1947 benchmark sweep run as root directly against a runner
#      checkout, outside any repo-tracked workflow -- operator process, not
#      reachable from code.
#
# #3024 closes cause 1 at source. This script is the backstop for cause 2
# and for whatever the next one turns out to be: it makes the *consequence*
# recoverable regardless of what left the mess.
#
# Narrow and idempotent on purpose, matching #2764's compose-drift-ro
# pattern: this only reclaims ownership under one specific runner's own
# _work directory, back to that same runner's own user -- never a general
# chown, never anything outside the path it's given.
#
# Installed as `ExecStartPre=+/path/to/this/script <user> <work-dir>` (the
# leading `+` runs it as root even though the unit's own User= is the
# unprivileged runner account) on each runner's systemd unit, so a checkout
# is never blocked by a mess left by whatever ran before the runner's last
# start.
#
# Usage: fix-work-ownership.sh <runner-user> <work-dir>

set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: $0 <runner-user> <work-dir>" >&2; exit 2; }
runner_user=$1
work_dir=$2

id "$runner_user" >/dev/null 2>&1 || { echo "no such user: $runner_user" >&2; exit 1; }
# Refuse anything that isn't a runner _work directory -- this runs as root
# on every service start, so a bad argument must fail closed rather than
# chown something unintended. Shape first, existence second: a wrong path
# should be rejected loudly whether or not it happens to exist, while a
# correctly-shaped _work that does not exist yet (a freshly registered
# runner that has not taken a job) is simply nothing to do.
case $work_dir in
  /var/lib/github-runners/*/_work) ;;
  *) echo "refusing to touch '$work_dir' -- not a runner _work directory" >&2; exit 1 ;;
esac
[[ -d $work_dir ]] || exit 0

runner_group=$(id -gn "$runner_user")

# chown -h: act on the symlink itself, never on what it points at. `find`
# selects by lstat, but a bare `chown` follows the link and changes the
# *referent's* owner -- and the link, still root-owned, is re-selected on
# every subsequent start. Jobs on this repo do run root containers
# bind-mounted on _work (that is #3024's finding), so without -h a job could
# drop a root-owned symlink pointing anywhere on the host and have this
# script hand that target to the unprivileged runner account, repeatedly.
unreclaimed=()
while IFS= read -r -d '' path; do
  if chown -h "$runner_user:$runner_group" "$path" 2>/dev/null; then
    continue
  fi
  # Ignore the benign race: a path that vanished between find and chown.
  [[ -e $path || -L $path ]] || continue
  unreclaimed+=("$path")
done < <(find "$work_dir" \! -user "$runner_user" -print0)

if (( ${#unreclaimed[@]} > 0 )); then
  # Fail closed, deliberately. An unreclaimable path (an immutable file --
  # `chattr +i` on __pycache__ was seen doing exactly this on 2026-09-05,
  # per #3024 -- or a path on a mount that does not support chown) means the
  # next checkout on this runner dies at EACCES anyway. Under
  # `ExecStartPre=+` a non-zero exit stops the unit, so the runner goes
  # offline in GitHub and its jobs queue, instead of accepting them and
  # failing every one at checkout with a symptom that looks nothing like its
  # cause. Same fail-closed shape as the path guard above.
  echo "could not reclaim ${#unreclaimed[@]} path(s) under $work_dir:" >&2
  for path in "${unreclaimed[@]}"; do
    echo "  $(stat -c '%U:%G %A' -- "$path" 2>/dev/null || echo '?:? ?') $path" >&2
  done
  echo "check for immutable attributes (lsattr) or a mount that refuses chown," >&2
  echo "clear them, then start this runner again." >&2
  exit 1
fi
