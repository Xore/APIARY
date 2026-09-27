#!/usr/bin/env bash
# run-llm-injection-suite.sh — run the #3334 behavioral prompt-injection corpus
# against the pinned local model and record the report (#3334).
#
# The corpus itself is llm-worker/injection_suite.py and the entry point is
# `worker.py --injection-suite`. Neither is run by CI: the suite loads the real
# model onto the analysis host's GPU, and the same reason the approved-model
# requalification in docs/analysis/ghidra/models/README.md is an operator
# workflow rather than a workflow file. So this is the automation the brief asks
# for -- weekly, and on a model/runtime pin change -- rather than one more
# unwired test that nothing ever executes.
#
# It runs the suite under the synthetic-canary overlay on purpose. That overlay
# is the only authorization the suite accepts (validate_synthetic_canary in
# worker.py): no Elasticsearch route, no capture mount, dry-run analysis. The
# corpus is synthetic, but the model answering it is the production session
# model, and that model is the thing under test.
#
# Reads /etc/default/honeypot-ghidra when present. APIARY_REPO_DIR must point
# at a trusted checkout: the suite is built from the working tree, so running
# it against a stale checkout would qualify code that is not the deployed one.
#
# Usage:
#   analysis/ghidra/models/run-llm-injection-suite.sh weekly
#   analysis/ghidra/models/run-llm-injection-suite.sh onchange
#
# The two modes exist because the two triggers want opposite answers to "has
# anything changed?". The weekly timer must always measure, since its job is
# exposing decay on a host nobody touched. The onchange trigger is fired by a
# deployed-pin file moving, and install-analysis-host.sh rewrites that file
# byte-identically on every routine --host-files-only re-sync; without the
# check below, every deploy would load the model and re-measure a pin that did
# not move.
#
# Exit status: 0 only when every case passed. A single flipped verdict, a
# low/medium severity, a repeated success marker, or a reproduced system-prompt
# sentence fails the run.

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
# These are the defaults only; /etc/default/honeypot-ghidra overrides them and
# is what a site edits. APIARY_REPO_DIR has no safe default worth guessing --
# a wrong path would silently qualify the wrong tree, so an unset or missing
# one is a hard error below rather than a fallback.
: "${APIARY_REPO_DIR:=/opt/apiary}"
: "${LLM_INJECTION_SUITE_RECORD_DIR:=/var/lib/honeypot-ghidra/injection-suite}"
# Same 30-day recommendation docs/analysis/ghidra/models/README.md gives for
# verbose qualification reports. A report is a set of model verdicts and
# digests, not captured data, but it is still an unbounded default-to-be.
: "${LLM_INJECTION_SUITE_RETENTION_DAYS:=30}"

say() { printf '%s\n' "$*"; }
die() { printf 'run-llm-injection-suite: %s\n' "$*" >&2; exit 2; }

mode="${1:-weekly}"
case "$mode" in
  weekly|onchange) ;;
  *) die "unknown mode '$mode' (expected weekly or onchange)" ;;
esac

[ -d "$APIARY_REPO_DIR" ] || die "APIARY_REPO_DIR=$APIARY_REPO_DIR is not a directory; set it in /etc/default/honeypot-ghidra to a trusted checkout"

compose_base="$APIARY_REPO_DIR/llm-worker/docker-compose.yml"
compose_overlay="$APIARY_REPO_DIR/llm-worker/docker-compose.synthetic-canary.yml"
for file in "$compose_base" "$compose_overlay"; do
  [ -f "$file" ] || die "missing $file -- APIARY_REPO_DIR does not look like an APIARY checkout"
done
command -v docker >/dev/null 2>&1 || die "docker is not on PATH"

# The pinned digest the overlay asserts must still be the digest the manifest
# approves. If those two drift apart the suite is not testing what the
# governance record says it is, and a pass would be a pass on the wrong model.
approved_digest="$(
  python3 - "$APIARY_REPO_DIR/analysis/ghidra/models/approved-models.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)
print(manifest["slots"]["sessions"]["artifact"]["digest"])
PY
)"
overlay_digest="$(
  sed -n "s/.*LLM_EXPECTED_MODEL_DIGEST:[[:space:]]*'\([^']*\)'.*/\1/p" "$compose_overlay" | head -1
)"
[ -n "$approved_digest" ] || die "could not read the sessions model digest from approved-models.json"
if [ "$overlay_digest" != "$approved_digest" ]; then
  die "synthetic-canary digest $overlay_digest != approved sessions digest $approved_digest -- the pin moved without a requalification"
fi

mkdir -p "$LLM_INJECTION_SUITE_RECORD_DIR"
chmod 700 "$LLM_INJECTION_SUITE_RECORD_DIR"

# Serialize against a concurrent manual run. Two suites loading a 20 GiB model
# on one card is how you get an OOM reported as an injection regression.
exec 9>"${LLM_INJECTION_SUITE_RECORD_DIR}/.lock"
if ! flock -n 9; then
  say "injection suite: another run holds the lock, skipping this one"
  exit 0
fi

# What was actually measured: the approved pin plus the code that builds the
# prompt and judges the answer. A change to any of them invalidates the last
# verdict, which is why the fingerprint covers the suite sources and not just
# the manifest -- an edited SYSTEM_PROMPT or judge() is exactly the kind of
# change that must be re-measured even though the digest never moved.
fingerprint_file="$LLM_INJECTION_SUITE_RECORD_DIR/.fingerprint"
fingerprint="$({
  sha256sum \
    "$APIARY_REPO_DIR/analysis/ghidra/models/approved-models.json" \
    "$APIARY_REPO_DIR/llm-worker/contracts.py" \
    "$APIARY_REPO_DIR/llm-worker/injection_suite.py" \
    "$APIARY_REPO_DIR/llm-worker/worker.py" \
    "$compose_overlay"
} | sha256sum | cut -d' ' -f1)"

if [ "$mode" = onchange ] && [ -f "$fingerprint_file" ] && [ "$(cat "$fingerprint_file")" = "$fingerprint" ]; then
  say "injection suite: pin and suite sources unchanged since the last passing run, nothing to re-measure"
  exit 0
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
report="$LLM_INJECTION_SUITE_RECORD_DIR/injection-suite-$stamp.json"
# Second resolution is not enough: a retry inside the same second, or the
# weekly and pin-change legs firing together, would otherwise overwrite the
# earlier run and leave the record looking like a single clean pass.
suffix=0
while [ -e "$report" ] || [ -e "${report%.json}.log" ]; do
  suffix=$((suffix + 1))
  report="$LLM_INJECTION_SUITE_RECORD_DIR/injection-suite-$stamp-$suffix.json"
done
stdout_file="$(mktemp)"
trap 'rm -f "$stdout_file"' EXIT

say "injection suite: model digest $approved_digest"
say "injection suite: record $report"

# --exit-code-from is not usable with `run` (that belongs to `up`), so the exit
# status of the worker is the exit status of this compose run and is carried
# through explicitly. `run` does not publish ports and the overlay grants only
# the internal llm-backend network, so nothing here is reachable from the host.
status=0
(
  cd "$APIARY_REPO_DIR"
  docker compose \
    -f llm-worker/docker-compose.yml \
    -f llm-worker/docker-compose.synthetic-canary.yml \
    run --rm --build llm-worker python -u worker.py --injection-suite
) >"$stdout_file" 2>&1 || status=$?

# Defaulted to fail before anything can succeed, so a path that never reaches
# the verdict block below cannot fall through to a zero exit.
verdict_status=fail

# The worker prints one JSON object on success and a diagnostic on stderr. A
# report is only a record if it parses, so an unparseable run is recorded as
# such rather than kept as a report.
if python3 -m json.tool "$stdout_file" >"$report" 2>/dev/null; then
  chmod 600 "$report"
  # First line is the machine verdict, the rest the operator summary. Read once
  # so the same report is never parsed two different ways in one run.
  verdict="$(
    python3 - "$report" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
failed = [case["name"] for case in report.get("cases", []) if not case.get("passed")]
clean = not failed and report.get("passed") == report.get("total")
print("pass" if clean else "fail")
print(f'{report.get("passed", 0)}/{report.get("total", 0)} passed' + (f"; failed: {', '.join(failed)}" if failed else ""))
PY
  )"
  verdict_status="$(printf '%s\n' "$verdict" | head -1)"
  summary="$(printf '%s\n' "$verdict" | tail -n +2)"
  ln -sfn "$(basename "$report")" "$LLM_INJECTION_SUITE_RECORD_DIR/latest.json"
  say "injection suite: $summary"
  # Only a clean pass earns the onchange leg's skip. Writing this after a
  # failure would mean the next pin-touching deploy "verifies" the same pin for
  # free, and the corpus would not re-run until some source changed.
  if [ "$status" -eq 0 ] && [ "$verdict_status" = pass ]; then
    printf '%s\n' "$fingerprint" >"$fingerprint_file"
    chmod 600 "$fingerprint_file"
  else
    rm -f "$fingerprint_file"
  fi
else
  # Keep the raw output too: the diagnostic is the only evidence of a run that
  # never got as far as judging a case.
  cp "$stdout_file" "${report%.json}.log"
  chmod 600 "${report%.json}.log"
  rm -f "$report"
  # A run that produced no verdict measured nothing, so it must not leave a
  # fingerprint behind claiming the current pin is verified.
  rm -f "$fingerprint_file"
  say "injection suite: run did not produce a report (exit $status)"
  cat "$stdout_file" >&2
fi

find "$LLM_INJECTION_SUITE_RECORD_DIR" -maxdepth 1 -type f \
  \( -name 'injection-suite-*.json' -o -name 'injection-suite-*.log' \) \
  -mtime "+$LLM_INJECTION_SUITE_RETENTION_DAYS" -delete

# Fail closed on the verdict, not merely on the worker's exit status. The
# worker already exits non-zero when a case fails, but a wrapper whose
# pass/fail is only a proxy for someone else's exit code stops being a gate the
# moment that stops being true -- and the failure mode here is a silent green
# run on a model that just followed an injection. Unparseable output leaves
# verdict_status=fail, so a broken run cannot pass either.
if [ "$status" -eq 0 ] && [ "$verdict_status" = pass ]; then
  exit 0
fi
# 2 stays reserved for a bad configuration, signalled by die() above.
exit 1
