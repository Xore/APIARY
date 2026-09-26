#!/usr/bin/env bash
# scan-image-sbom.sh -- run the repo's Trivy vulnerability policy over a
# CycloneDX SBOM instead of over a live image. #3321.
#
# Why scan the SBOM rather than the image: image-security-scan.yml already
# scans every base image this tree pulls, but it grades the *base* -- the
# packages a CVE would be reported against there. The inventory this issue
# adds describes the built dashboard image, which carries the base plus
# everything COPYed in after it. Grading the SBOM means the scan and the
# inventory are derived from the same file, so "the scan says clean" and "the
# inventory has no such package" cannot disagree, and a CVE response is a
# `trivy sbom` over a retained artefact rather than a rebuild.
#
# The policy flags are image-security-scan.yml's, deliberately identical:
#
#   --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1
#
# --ignore-unfixed keeps "no patch exists yet" out of a count nobody can act
# on, and matching the base-image scan means a digest's finding and a base
# image's finding are graded the same way.
#
# Report-only, like the base-image scan it mirrors, including its refusal to
# confuse "found CVEs" with "measured nothing": trivy exits non-zero for
# both, and those are opposite findings. A broken advisory DB must not read
# as a vulnerable image forever, and it must not red the required Containers
# gate either. Re-arm the hard gate by replacing the final exit with
# `[ "$flagged" -eq 0 ]` once the backlog is clear, exactly as
# image-security-scan.yml documents for itself.
#
# Usage: scan-image-sbom.sh --sbom <file.json> [--name <image>] [--report <file.json>]
set -euo pipefail

# One pin for both scans: delegated to the shared installer rather than
# copied, so a bump cannot land in one workflow and miss the other.
here=$(cd -- "$(dirname -- "$0")" && pwd)
trivy_bin=$("$here/install-trivy.sh" --print-path)

die() {
  echo "scan-image-sbom: $*" >&2
  exit 1
}

sbom=""
name=""
report=""

while [ $# -gt 0 ]; do
  case "$1" in
    --sbom)
      sbom=${2:?--sbom needs a value}
      shift 2
      ;;
    --name)
      name=${2:?--name needs a value}
      shift 2
      ;;
    --report)
      report=${2:?--report needs a value}
      shift 2
      ;;
    -h | --help)
      # Print this file's own leading comment block: a help text that drifts
      # out of date with the code above it is worse than no help text.
      awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$sbom" ] || die "--sbom is required"
[ -f "$sbom" ] || die "no such SBOM: $sbom"
label=${name:-$sbom}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
log=$work/trivy.log
# Always write a report, clean or not: "the scan ran and found nothing" is
# itself the evidence a CVE response wants, and an absent file reads as
# "nobody looked".
: >"$work/trivy.json"

# INFO/WARN go to stderr, the JSON report to stdout.
set +e
"$trivy_bin" sbom \
  --scanners vuln \
  --severity CRITICAL,HIGH \
  --ignore-unfixed \
  --exit-code 1 \
  --format json \
  --no-progress \
  "$sbom" >"$work/trivy.json" 2>"$log"
rc=$?
set -e

flagged=0
unresolved=0
if [ "$rc" -eq 0 ]; then
  echo "scan-image-sbom: $label has no fixable CRITICAL/HIGH vulnerabilities"
else
  sed 's/^/  /' "$log"
  # "Detected SBOM format" is trivy's own confirmation that it parsed the
  # document. Without it, nothing was measured: an unreadable SBOM, a
  # truncated artifact upload, a broken advisory DB. Report that as the
  # coverage gap it is instead of as a vulnerability.
  if grep -q 'Detected SBOM format' "$log"; then
    flagged=1
  else
    unresolved=1
  fi
fi

if [ -n "$report" ]; then
  mkdir -p -- "$(dirname -- "$report")"
  if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$work/trivy.json" 2>/dev/null; then
    cp -f -- "$work/trivy.json" "$report"
  else
    # Still record *that* the scan happened, so the retained artefact pair
    # (SBOM + report) is never silently half-present.
    python3 -c 'import json,sys; json.dump({"SchemaVersion":2,"Results":None,"apiary": {"scan_error": "trivy produced no parseable JSON report; see the job log"}}, open(sys.argv[1],"w"), indent=2)' "$report"
  fi
  echo "scan-image-sbom: report written to $report"
fi

if [ "$unresolved" -gt 0 ]; then
  echo "::warning title=Unscannable SBOM::$label was not scanned -- this is a coverage gap, not a vulnerability result. See the log above."
fi
if [ "$flagged" -gt 0 ]; then
  echo "::warning title=Vulnerable image (from SBOM)::$label has fixable CRITICAL/HIGH vulnerabilities"
  echo "scan-image-sbom: not failing the build (report-only) -- re-arm the gate with [ \"\$flagged\" -eq 0 ] once the backlog is clear."
fi
exit 0
