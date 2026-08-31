#!/usr/bin/env bash
# test_guest_runner_postsample.sh (#2268) -- guest-runner.sh's post-detonation
# block used to leave `set -e` enabled for the rest of the script (the
# header itself only runs with `-uo pipefail`), so a single unguarded
# command failure -- e.g. the `find | sort` artifact-collection step --
# aborted the script and skipped the guest poweroff. This drives the exact
# tail of guest-runner.sh (from the dynamic-execution branch through
# `systemctl poweroff`) with a failing `find` stub and asserts poweroff
# still runs.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "pass: $*"; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
runner_script="$script_dir/../guest-runner.sh"
[[ -f $runner_script ]] || fail "guest-runner.sh not found at $runner_script"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

result="$work/result"
install -d "$result"
: >"$result/files-before.tsv"

stubs="$work/stubs"
install -d "$stubs"

# timeout/strace/setpriv: strip their own flags and exec the real command
# tail (ultimately /bin/true), so the dynamic-execution branch "succeeds"
# without needing strace/setpriv installed in this test environment.
cat >"$stubs/timeout" <<'EOF'
#!/usr/bin/env bash
while [[ $1 == --* ]]; do shift; done
shift
exec "$@"
EOF

cat >"$stubs/strace" <<'EOF'
#!/usr/bin/env bash
while [[ $# -gt 0 && $1 != -- ]]; do shift; done
shift
exec "$@"
EOF

cat >"$stubs/setpriv" <<'EOF'
#!/usr/bin/env bash
while [[ $1 == --* ]]; do shift; done
exec "$@"
EOF

# find: simulate the real-world failure this issue is about (permission
# error, filesystem hiccup, etc.) on the post-execution artifact sweep.
cat >"$stubs/find" <<'EOF'
#!/usr/bin/env bash
echo "stub find: simulated failure" >&2
exit 1
EOF

cat >"$stubs/ps" <<'EOF'
#!/usr/bin/env bash
echo "stub ps"
EOF

cat >"$stubs/ss" <<'EOF'
#!/usr/bin/env bash
echo "stub ss"
EOF

marker="$work/poweroff-called"
cat >"$stubs/systemctl" <<EOF
#!/usr/bin/env bash
echo "\$*" >"$marker"
EOF

chmod +x "$stubs"/*

harness="$work/harness.sh"
{
  echo 'set -uo pipefail'
  echo "result='$result'"
  echo 'wine_route=false'
  echo 'proxy_env=()'
  echo 'runner=(/bin/true)'
  echo 'pcap_pid='
  echo 'stop_instrumentation() { :; }'
  # The tail under test: everything from the dynamic-execution branch
  # through the final `systemctl poweroff`, taken verbatim from the real
  # script so the test tracks whatever guest-runner.sh actually does.
  sed -n '/^if ((\${#runner\[@\]}))/,$p' "$runner_script"
} >"$harness"

PATH="$stubs:$PATH" bash "$harness" || true

[[ -f $marker ]] || fail "systemctl poweroff was never reached after the artifact step failed"
pass "systemctl poweroff ran even though the find|sort artifact step failed"

grep -q 'poweroff' "$marker" || fail "systemctl was called but not with poweroff"
pass "poweroff was the call that landed"

echo "OK: post-sample artifact failure does not skip guest poweroff"
