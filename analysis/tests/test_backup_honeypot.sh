#!/bin/sh
# #2024: the Keycloak backup must never keep a silently truncated
# keycloak.sql.gz. The original pipeline died here: `pg_dump | gzip` under
# dash has no pipefail, so gzip's exit status masked a dead pg_dump and a
# partial identity-database dump was kept -- with a SHA256SUMS line vouching
# for exactly the wrong bytes. Drives the REAL script end-to-end with
# `docker` shadowed on PATH (compose config/volume/run stubs;
# `exec ... pg_dump` replays either a healthy dump or one dying partway).
#
# Asserts what the issue asks: a partway pg_dump leaves no kept artifact and
# matches the existing loud-failure branch, a healthy dump produces output
# identical to gzipping that same dump directly, nothing is lost when the
# Keycloak container is absent, and stderr carries the reason.
#
# Cases 5-7 cover #2025: retention prunes BEFORE an upstream failure wedges
# the rest of the run, an aborted manual run under umask 022 leaves nothing
# world-readable behind, and failed compose validation leaves no empty stamp
# directory.
#
# Stdlib/tooling only (sh, gzip, sha256sum, grep); runs plain
# `sh analysis/tests/test_backup_honeypot.sh`.

set -u
cd "$(dirname "$0")/.."

SCRIPT=./backup-honeypot.sh

fails=0
t() { # t <shell-condition-text> -- run it, count failures by outcome
  if eval "$1"; then
    echo "ok - $1"
  else
    echo "not ok - $1"
    fails=$((fails + 1))
  fi
}

TD="$(mktemp -d)"
FAIL_DUMP="$TD/faildump"
HEALTHY_DUMP="$TD/healthydump"
FAKE_BIN="$TD/bin"
mkdir -p "$FAKE_BIN"

cleanup() { rm -rf "$TD"; }
trap cleanup EXIT

# --- fixtures ---------------------------------------------------------------
{
  echo "-- PostgreSQL database dump"
  i=0
  while [ $i -lt 4000 ]; do
    echo "COPY data row $i;"
    i=$((i + 1))
  done
  echo "-- PostgreSQL database dump complete"
} > "$HEALTHY_DUMP"
head -c 30000 "$HEALTHY_DUMP" > "$FAIL_DUMP"   # dies without its footer

# --- docker stub ------------------------------------------------------------
# Knobs: KEYCLOAK_UP / PG_DUMP_RC / FAIL_DUMP drive the pg_dump stages,
# COMPOSE_RC simulates failing `compose config` validation, VOLUME_UP lets
# the named-volume loop reach `docker run`, and VOLUME_RUN_RC fails that
# mid-archive (#2025's upstream-failure scenario).
cat > "$FAKE_BIN/docker" <<STUB
#!/bin/sh
[ "\$1" = compose ] && exit \${COMPOSE_RC:-0}
if [ "\$1" = inspect ]; then
  [ "\${KEYCLOAK_UP:-0}" = 1 ]
  exit \$?
fi
[ "\$1" = volume ] && { [ "\${VOLUME_UP:-0}" = 1 ]; exit \$?; }
if [ "\$1" = run ]; then
  exit \${VOLUME_RUN_RC:-0}
fi
if [ "\$1" = exec ]; then
  shift 2
  cat "\$FAIL_DUMP"
  exit \${PG_DUMP_RC:-0}
fi
exit 0
STUB
chmod +x "$FAKE_BIN/docker"

new_case() { # new_case -> prints "<case_dir> <stack_dir>"; caller appends /backups etc.
  _d="$TD/case$3"
  rm -rf "$_d"
  mkdir -p "$_d/stack"
  : > "$_d/stack/compose.yml"
}

run() { # run KEYCLOAK_UP PG_DUMP_RC CASEDIR [stderr-file] [dump-source]
  _up=$1; _rc=$2; _d=$3; _err=${4:-/dev/null}; _dump=${5:-$FAIL_DUMP}
  KEYCLOAK_UP=$_up PG_DUMP_RC=$_rc FAIL_DUMP="$_dump" \
    PATH="$FAKE_BIN:$PATH" RETENTION_DAYS=14 \
    STACK_DIR="$_d/stack" BACKUP_ROOT="$_d/backups" \
    sh "$SCRIPT" > "$_d/dest.txt" 2>"$_err"
}

run_with() { # run_with CASEDIR ENV=VAL... -- arbitrary stub knobs, real rc
  _d=$1
  shift
  env PATH="$FAKE_BIN:$PATH" RETENTION_DAYS=14 \
      STACK_DIR="$_d/stack" BACKUP_ROOT="$_d/backups" \
      "$@" sh "$SCRIPT" >"$_d/dest.txt" 2>"$_d/stderr.txt"
}

seed_stamp() { # seed_stamp CASEDIR DAYS_AGO -> prints the stamp dir name
  _s=$(date -u -d "-$2 days" +%Y%m%dT%H%M%SZ)
  mkdir -p "$1/backups/$_s"
  echo old >"$1/backups/$_s/marker.txt"
  echo "$_s"
}

echo "# case 1: healthy pg_dump"

new_case x x 1
ERR1="$TD/case1/stderr.txt"
run 1 0 "$TD/case1" "$ERR1" "$HEALTHY_DUMP"
DEST="$(cat "$TD/case1/dest.txt")"
t "[ -s '$DEST/keycloak.sql.gz' ]"
t "[ ! -e '$DEST/keycloak.sql' ]"
gzip -dc "$DEST/keycloak.sql.gz" > "$TD/decompressed.sql"
t "cmp -s '$TD/decompressed.sql' '$HEALTHY_DUMP'"
t "grep -q 'keycloak.sql.gz' '$DEST/SHA256SUMS'"
t "[ -s '$DEST/stack-config-state.tar.gz' ]"

echo "# case 2: pg_dump exits nonzero midway"

new_case x x 2
ERR2="$TD/case2/stderr.txt"
run 1 1 "$TD/case2" "$ERR2"
DEST="$(cat "$TD/case2/dest.txt")"
t "[ ! -e '$DEST/keycloak.sql.gz' ]"
t "[ ! -e '$DEST/keycloak.sql' ]"
t "! grep -q 'keycloak.sql' '$DEST/SHA256SUMS'"
t "grep -q 'keycloak backup failed' '$ERR2'"
t "[ -s '$DEST/stack-config-state.tar.gz' ]"

echo "# case 3: rc lost, but footer missing (truncation alone refuses)"

new_case x x 3
head -c 10000 "$HEALTHY_DUMP" > "$TD/footless"
run 1 0 "$TD/case3" "" "$TD/footless"
DEST="$(cat "$TD/case3/dest.txt")"
t "[ ! -e '$DEST/keycloak.sql.gz' ]"
t "[ ! -e '$DEST/keycloak.sql' ]"

echo "# case 4: keycloak container absent -- unchanged behavior"

new_case x x 4
run 0 0 "$TD/case4"
DEST="$(cat "$TD/case4/dest.txt")"
t "[ ! -e '$DEST/keycloak.sql.gz' ]"
t "[ ! -e '$DEST/keycloak.sql' ]"
t "[ -s '$DEST/stack-config-state.tar.gz' ]"

echo "# case 5: a step later in the run fails -- retention already pruned (#2025)"

new_case x x 5
D5="$TD/case5"
STALE=$(seed_stamp "$D5" 20)   # beyond RETENTION_DAYS=14
FRESH=$(seed_stamp "$D5" 1)
run_with "$D5" VOLUME_UP=1 VOLUME_RUN_RC=1
RC5=$?
t "[ $RC5 -ne 0 ]"
t "[ ! -d '$D5/backups/$STALE' ]"
t "[ -f '$D5/backups/$FRESH/marker.txt' ]"
# An aborted run never echoes its destination, so find this run's stamp as
# the lexically-newest surviving directory name (stamps sort as time).
NEWEST=$(cd "$D5/backups" && ls -1 | LC_ALL=C sort | tail -n 1)
DEST="$D5/backups/$NEWEST"
t "[ \"$FRESH\" != '$NEWEST' ]"
# The run got far enough to produce the config tar before dying on its first
# volume tarball, so this is a genuinely partial stamp -- and precisely the
# situation that used to wedge pruning forever once the disk (rather than a
# stub) was what failed.
t "[ -s '$DEST/stack-config-state.tar.gz' ]"
t "[ ! -e '$DEST/SHA256SUMS' ]"

echo "# case 6: hostile umask + aborted run -- loose modes can't outlive the crash (#2025)"

new_case x x 6
D6="$TD/case6"
# The chmod -R go-rwx sat at the very END pre-fix, so any earlier abort --
# here the first volume tarball -- used to leave the completed Keycloak dump
# sitting world-readable forever. Assert against the whole backups root,
# since no echo'd destination exists for an aborted run.
(umask 022 && run_with "$D6" KEYCLOAK_UP=1 PG_DUMP_RC=0 FAIL_DUMP="$HEALTHY_DUMP" \
    VOLUME_UP=1 VOLUME_RUN_RC=1)
RC6=$?
t "[ $RC6 -ne 0 ]"
GZ=$(cd "$D6/backups" && ls -1 */keycloak.sql.gz | head -n 1)
t "[ -n '$GZ' ]"
t "[ -z \"\$(find '$D6/backups' -perm /go+rwx)\" ]"

echo "# case 7: failed validation leaves no empty stamp directory (#2025)"

new_case x x 7
D7="$TD/case7"
run_with "$D7" COMPOSE_RC=3
RC7=$?
t "[ $RC7 -ne 0 ]"
t "[ ! -d '$D7/backups' ]"

echo "----------------------------------------"
if [ "$fails" -eq 0 ]; then
  echo "all checks passed"
else
  echo "$fails check(s) FAILED"
  exit 1
fi
