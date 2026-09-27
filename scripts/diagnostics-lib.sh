#!/usr/bin/env bash
# diagnostics-lib.sh -- the reporting vocabulary every step in
# .github/workflows/diagnostics.yml shares. Sourced, never executed.
#
# Why this file exists (#3312).
#
# diagnostics.yml ran 160 consecutive scheduled runs in failure, and every one
# of them was filed the same way: a red X, an ::error:: line with nothing on
# its subject, and a body that had to be read to find out whether anything was
# actually broken. Of the conditions it kept naming, most were not faults in
# the pipeline:
#
#   - a service token in a root-owned 0600 .env the runner user cannot read, so
#     the metrics lane had never once been able to see anything (#3338's
#     root-owned helper fixes the read; the lane still stayed red until an
#     operator applied the grant, which a workflow cannot do for them),
#   - a Cloudflare 403 seen only from GitHub-hosted runner address ranges on an
#     endpoint that answers 200 from the VPS,
#   - a declared stand-down of the sandbox isolation stack, which is a standing
#     practice on this host (#3135).
#
# None of those is a reason to stop looking. All of them are a reason to stop
# filing them under the same red X as a dead sensor pipeline, because a run
# that lists five unrelated things under one heading is triaged by ignoring it.
#
# So every finding is categorised, and the category is carried in two places
# that cannot drift apart: the annotation's own title, and one row per finding
# in the ledger the job prints at the end. There are four categories:
#
#   fault           something is wrong with the pipeline or the host. A real
#                   regression. Fatal.
#   runner-config   the check could not run because of how the runner or this
#                   repository's environment is configured: a helper not
#                   installed, a sudoers grant not applied, a secret unset.
#                   Fatal, deliberately -- scripts/verify-deploy.sh already
#                   exits 2 for exactly this case, and folding "could not tell"
#                   into a pass is the one outcome that makes a check worse
#                   than not having it. (#3283 is what that position costs when
#                   it is wrong: Elasticsearch at 1000/1000 shards with every
#                   sensor's events dead-lettered for six days, in a lane whose
#                   only question is whether the pipeline is flowing.)
#                   What changes here is that it is its own category with its
#                   own title, so "this lane has never been able to see
#                   anything" is tellable apart from "the pipeline is broken"
#                   without re-reading the log -- and so the fix is the
#                   operator command, not the symptom.
#   expected        a deliberate, declared absence. Never fatal. `alert`
#                   refuses this category and `note` is the way to record one,
#                   so the ledger can say "this is on purpose" out loud rather
#                   than leaving the reader to infer it from silence.
#   unmeasured      the check did not run, and that is not a pass. Fatal, and
#                   it is the same case scripts/verify-deploy.sh's exit 2 is.
#                   Isolated here because the honest sentence for it is "this
#                   barrier's status is unknown", which is different from every
#                   other claim in the table.
#
# One fatal path per underlying cause. The same condition must not be alerted
# twice under two names: a run that lists one problem five times is as
# untriageable as one that lists it zero times, and the doubled lane is how
# "source-health is not measured" ended up reading as a second broken thing
# rather than as the same gap seen from a different angle.

# Sourced, not run. Running it would exit 0 having done nothing, which is the
# exact shape of a check that passes without having run.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "diagnostics-lib.sh is a library: source it, do not run it." >&2
  exit 64
fi

# The three fatal categories, and the one that is deliberately not fatal.
# The three fatal categories, the one that is deliberately not fatal, and the
# ledger-only one that records a check which ran and found nothing. `ok` is not
# a finding and is never alerted or noted -- it exists so a run that measured
# something and agreed says so in the same table, and so "nothing was
# unmeasured" is as visible as "this is a fault".
# shellcheck disable=SC2034 # read by the step that sources this, not by this file
DIAG_CATEGORIES="fault runner-config unmeasured expected ok"

# #2222: a scheduled run's own red X is the alert, because nobody is reading
# GITHUB_STEP_SUMMARY on a cron trigger. A manual run keeps the browsable
# report-only style -- a human is already looking at it. Each step sets
# is_schedule explicitly; the GITHUB_EVENT_NAME fallback is what keeps a step
# that forgot to still behave.
if [ -z "${is_schedule:-}" ]; then
  if [ "${GITHUB_EVENT_NAME:-}" = "schedule" ]; then
    is_schedule=true
  else
    is_schedule=false
  fi
fi

# Steps run in separate shells, so the ledger is a file rather than a variable.
# RUNNER_TEMP is per job, so the two jobs of this workflow get one ledger each
# -- which is the right granularity: a row names a check, and a check lives in
# one job.
DIAG_LEDGER_ROWS="${RUNNER_TEMP:-/tmp}/diagnostics-ledger.rows"

report() { printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; printf '%s\n' "$*"; }
section() { report ''; report "## $*"; report ''; }

# A table cell is one line and no wider than a screen. GitHub renders a
# newline inside a cell as a broken row, and a pipe inside a cell as a column
# boundary, so both are flattened here rather than at each call site.
diag_cell() {
  printf '%s' "$*" | tr '\n|' '  ' | tr -s ' ' | cut -c1-200
}

# diag_row <category> <check> <finding>
# The ledger row, with no annotation and no exit code. `note` and `alert` are
# built on it; it is also the entry point for a finding some other step's
# output already categorised (the isolation audit carries its own vocabulary
# and is never re-categorised here -- its own footer is the authority).
diag_row() {
  printf '| %s | %s | %s |\n' \
    "$(diag_cell "$1")" "$(diag_cell "$2")" "$(diag_cell "$3")" >> "$DIAG_LEDGER_ROWS"
}

# note <category> <check> <finding>
# A categorised finding that does not redden the run. Two legitimate uses: a
# declared, deliberate absence (`expected`), and a real finding this step is
# deliberately not making fatal -- naming that is the point, because "we chose
# not to make this fatal" is a decision somebody has to be able to see. Any
# other category is a call-site mistake, so it says so out loud instead of
# quietly filing it as something it is not.
note() {
  local category=$1 check=$2
  shift 2
  case "$category" in
    expected)
      report "$*"
      diag_row expected "$check" "$*"
      ;;
    fault | runner-config | unmeasured)
      report "$*"
      diag_row "$category" "$check" "$*"
      printf '::warning title=%s (noted, not fatal): %s::%s\n' "$category" "$check" "$*"
      ;;
    *)
      printf '::error title=Unknown diagnostic category::%s: "%s" is not one of the categories this workflow defines (%s)\n' "$check" "$category" "$DIAG_CATEGORIES"
      diag_row fault "$check" "$* [filed as a fault: the call site named an unknown category, \"$category\"]"
      ;;
  esac
}

# alert <category> <check> <finding>
# A categorised finding that is fatal on a scheduled run (#2222) and still
# reported on a manual one. The category is the annotation's title, so the
# checks list on the run page says which of the four things this is without
# anyone opening the log.
alert() {
  local category=$1 check=$2
  shift 2
  report "$*"
  diag_row "$category" "$check" "$*"
  case "$category" in
    fault | runner-config | unmeasured) ;;
    *)
      # `expected` is the case that matters: an expected absence has no
      # business reddening a run, and if one ever did it would be an accident
      # dressed as a policy. Say so, and stay fatal anyway -- a miscategorised
      # finding must never be able to turn a run green.
      printf '::error title=Wrong category for a fatal finding::%s: "%s" is not a fatal category. An expected state is a note, not an alert -- fix the call site. Staying fatal so a miscategorised finding cannot turn this run green.\n' "$check" "$category"
      ;;
  esac
  if [ "$is_schedule" = "true" ]; then
    printf '::error title=%s: %s::%s\n' "$category" "$check" "$*"
    # shellcheck disable=SC2034 # the step reads this after every alert() call
    schedule_failed=1
  fi
}

# diag_ledger_report
# The whole run on one screen: what was measured, what each finding was, and
# the counts. The counts are the triage. A run with 0 faults and 1
# runner-config row is a healthy host with one misconfigured lane, and the fix
# is an operator command rather than an incident. Counts are derived from the
# rows rather than tallied as they are added, so a row cannot be recorded
# without being counted or counted without being recorded.
diag_ledger_report() {
  local faults=0 runner_config=0 unmeasured=0 expected=0 ok=0 rows=0
  if [ -f "$DIAG_LEDGER_ROWS" ]; then
    rows=$(wc -l < "$DIAG_LEDGER_ROWS")
    faults=$(grep -c '^| fault |' "$DIAG_LEDGER_ROWS" || true)
    runner_config=$(grep -c '^| runner-config |' "$DIAG_LEDGER_ROWS" || true)
    unmeasured=$(grep -c '^| unmeasured |' "$DIAG_LEDGER_ROWS" || true)
    expected=$(grep -c '^| expected |' "$DIAG_LEDGER_ROWS" || true)
    ok=$(grep -c '^| ok |' "$DIAG_LEDGER_ROWS" || true)
  fi
  report ''
  report '## Category ledger (#3312)'
  report ''
  report 'One row per finding, filed under what kind of thing it was. A green run'
  report 'with a nonzero runner-config count is not green -- it is unmeasured.'
  report ''
  report '| category | check | finding |'
  report '| --- | --- | --- |'
  if [ "$rows" -gt 0 ]; then
    while IFS= read -r line; do report "$line"; done < "$DIAG_LEDGER_ROWS"
  else
    report '| -- | -- | nothing to categorise: this run found no fault, no runner-config gap and nothing it could not measure |'
  fi
  report ''
  report "counts: ${ok} check(s) measured and in agreement, ${faults} fault(s), ${runner_config} runner-config gap(s), ${unmeasured} unmeasured, ${expected} expected absence(s)."
  if [ "$faults" -eq 0 ] && [ "$runner_config" -eq 0 ] && [ "$unmeasured" -eq 0 ]; then
    report 'Verdict: every check that could run agreed, and nothing was left unmeasured.'
  else
    report 'Verdict: see the rows above. A run-config gap is an operator command; a fault is an incident.'
  fi
}
