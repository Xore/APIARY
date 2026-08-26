#!/usr/bin/env bash
# test_collect_lifecycle.sh — every pending record reaches a terminal state,
# and transient trouble stays transient (#2079).
#
# Three ways process_one() used to evade its own deadline or mislabel its
# outcome:
#
# 1. The requested_at parse ran before the MAX_WAIT check, so one corrupt
#    timestamp retried forever (ValueError past the deadline into drain()'s
#    blanket handler every tick) -- no input could age out of the spool.
# 2. A record too corrupt to parse hit the same blanket handler forever.
# 3. git_pull()/build_result() failures that aren't CollectError
#    (CalledProcessError from check=True subprocesses, JSONDecodeError from
#    a committed-but-garbage scanner report) retired as "timeout" -- telling
#    the dashboard Actions was slow when the real evidence was on disk.
#
# No network: find_run/git_pull are stubbed on the module object; only
# process_one()'s own control flow is under test.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "pass: $*"; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

out=$(COLLECT_SCRIPT="$script_dir/collect-results.py" python3 <<'PYEOF'
import importlib.util
import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location("collect_results", os.environ["COLLECT_SCRIPT"])
collect = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect)

work = Path(tempfile.mkdtemp())
clone = work / "clone"
collect.PENDING_DIR = work / "pending"
collect.RESULTS_DIR = work / "results"
collect.GITHUB_CLONE = clone
(clone / "reports" / "scanner").mkdir(parents=True)
collect.PENDING_DIR.mkdir()
collect.RESULTS_DIR.mkdir()

failures = []


def check(cond, name):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        failures.append(name)


def add_pending(sha, requested_at=None, raw=None):
    p = collect.PENDING_DIR / f"{sha}.pending"
    if raw is not None:
        p.write_text(raw)
    else:
        p.write_text(json.dumps({
            "version": 1, "sha256": sha, "commit": "deadbeef",
            "requested_at": requested_at, "sensor": "", "bucket": "",
        }))
    return p


def result_for(sha):
    f = collect.RESULTS_DIR / f"{sha}.json"
    return json.loads(f.read_text()) if f.exists() else None


recent = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")

# --- 1. An unparseable timestamp retires on its first tick. ---
sha = "a" * 64
p = add_pending(sha, "garbage")
outcome = collect.process_one(p)
check(outcome == "timeout", "corrupt requested_at returns timeout on first tick")
check(not p.exists(), "corrupt requested_at record is unlinked")
r = result_for(sha)
check(r is not None and r["exit_status"] == "timeout", "corrupt requested_at writes a terminal record")
check("garbage" in r.get("error", ""), "the terminal record names the offending value")

# --- 2. A record too corrupt to parse at all retires too. ---
sha = "b" * 64
p = add_pending(sha, raw="{this is not json")
outcome = collect.process_one(p)
check(outcome == "timeout", "unreadable record returns timeout on first tick")
check(not p.exists(), "unreadable record is unlinked")
r = result_for(sha)
check(r is not None and r["exit_status"] == "timeout", "unreadable record writes a terminal record")

# --- 3. Old-but-valid timestamps still time out through MAX_WAIT. ---
sha = "c" * 64
old = (datetime.now(timezone.utc) - timedelta(seconds=collect.MAX_WAIT + 60)).isoformat().replace("+00:00", "Z")
p = add_pending(sha, old)
outcome = collect.process_one(p)
check(outcome == "timeout", "valid-but-old requested_at still ages out via MAX_WAIT")
check(not p.exists(), "MAX_WAIT record is unlinked")

# --- 4. Committed-but-corrupt scanner JSON -> failed with reason, not timeout. ---
sha = "d" * 64
(clone / "reports" / "scanner" / f"{sha}.json").write_text("{committed garbage")
collect.find_run = lambda commit: {"id": 7, "html_url": "", "status": "completed", "conclusion": "success"}
collect.git_pull = lambda: "cafef00d"
p = add_pending(sha, recent)
outcome = collect.process_one(p)
check(outcome == "failed", "corrupt committed scanner JSON concludes failed, not retried")
check(not p.exists(), "failed-due-to-corrupt-results record is unlinked")
r = result_for(sha)
check(r is not None and r["exit_status"] == "failed",
      "corrupt committed scanner JSON is recorded as failed, never as timeout")
check("unreadable" in r.get("error", ""), "the failed record carries the real reason")

# --- 5. Transient git transport errors stay on the retry path. ---
sha = "e" * 64


def git_blows_up():
    raise subprocess.CalledProcessError(returncode=128, cmd="git fetch")


collect.git_pull = git_blows_up
p = add_pending(sha, recent)
outcome = collect.process_one(p)
check(outcome == "running", "git CalledProcessError retries instead of retiring")
check(p.exists(), "retrying record stays in the spool")
check(result_for(sha) is None, "no terminal state written for a transient failure")

# --- 6. A missing scanner artifact (CollectError contract) still retries. ---
sha = "f" * 64
collect.git_pull = lambda: "cafef00d"  # artifacts genuinely absent from the clone
p = add_pending(sha, recent)
outcome = collect.process_one(p)
check(outcome == "running", "missing committed artifacts keep retrying per the CollectError contract")
check(p.exists(), "missing-artifact record stays in the spool")

print(f"{'OK' if not failures else 'FAILED'}: {len(failures)} failure(s)")
raise SystemExit(1 if failures else 0)
PYEOF
)

echo "$out"
echo "$out" | grep -q "^FAIL " && fail "lifecycle scenarios failed (see above)"
pass "$(
  echo "$out" | grep -c "^PASS "
) lifecycle scenarios hold"
echo "OK: every poisoned record retires; transient trouble stays transient"
