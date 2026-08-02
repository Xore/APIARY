#!/usr/bin/env bash
# test_collect_results.sh — build_result() actually reflects real scanner
# findings and links a real PDF, against fixtures shaped exactly like real
# Xore/honeypot data (#255).
#
# Before the fix, this failed unconditionally: build_result() read a
# "scanners" key that does not exist in the real schema (the real data nests
# per-scanner results under "results", keyed by scanner class name, with an
# "_ok" flag, not "ok"), so every verdict computed malicious=0/level="clean"
# regardless of what scanners actually found, and it guessed a PDF path
# (nested by bucket, no date, named after the zip's own {sha256}.zip) that
# never matched the real file (flat, date-suffixed, named after the
# *original* captured filename from inside the zip).
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "pass: $*"; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

clone="$work/clone"
sha256="0ba5c04325f7af25a2f6bf4c588dff798d481b0a799b10faac9d4daed7c09c5e"
bucket="PE"

install -d -m 0755 "$clone/reports/scanner" "$clone/reports/pdf/samples" "$clone/samples/$bucket"

# A real committed Xore/honeypot scanner report (fifaconfig.exe, fetched
# 2026-08-02): VirusTotal positives=1/75, MetaDefender positives=1/23,
# MalwareBazaar and HybridAnalysis both "_ok": true with no positives/total
# field at all -- exercises the "some scanners don't carry a count" case too.
cat >"$clone/reports/scanner/$sha256.json" <<JSON
{
  "file": "samples/$bucket/fifaconfig.exe",
  "filename": "fifaconfig.exe",
  "sha256": "$sha256",
  "scanned_at": "2026-07-29T18:30:43Z",
  "results": {
    "VirusTotalScanner": {"source": "virustotal", "positives": 1, "total": 75, "suspicious": 0, "permalink": "https://www.virustotal.com/gui/file/$sha256", "_ok": true},
    "MalwareBazaarScanner": {"source": "malwarebazaar", "permalink": "https://bazaar.abuse.ch/sample/$sha256/", "_ok": true},
    "HybridAnalysisScanner": {"source": "hybrid-analysis", "verdict": "suspicious", "threat_score": 35, "_ok": true},
    "MetaDefenderScanner": {"source": "metadefender", "positives": 1, "total": 23, "_ok": true}
  }
}
JSON

# The zip publish-sample.sh actually pushes -- its own basename must NOT be
# what the PDF path is derived from (that was the bug).
: >"$clone/samples/$bucket/$sha256.zip"

# The real PDF: named after the *original* filename (fifaconfig.exe) + the
# scan date, flat under reports/pdf/samples/ -- not nested by bucket, not
# named after the zip.
: >"$clone/reports/pdf/samples/fifaconfig.exe-2026-07-29.pdf"

result_json=$(GITHUB_CLONE="$clone" python3 <<PYEOF
import importlib.util, json, sys

spec = importlib.util.spec_from_file_location("collect_results", "$script_dir/collect-results.py")
collect_results = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collect_results)

pending = {"sha256": "$sha256", "commit": "deadbeef", "bucket": "$bucket", "requested_at": "2026-07-29T18:00:00Z"}
run = {"id": 1, "html_url": "https://github.com/Xore/honeypot/actions/runs/1"}
result = collect_results.build_result(pending, run, "cafef00d")
print(json.dumps(result))
PYEOF
)

malicious=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['verdict']['malicious'])" "$result_json")
level=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['verdict']['level'])" "$result_json")
total=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['verdict']['total'])" "$result_json")
report_pdf=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['report_pdf'])" "$result_json")
num_scanners=$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1])['scanners']))" "$result_json")
commit=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['commit'])" "$result_json")
report_commit=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['report_commit'])" "$result_json")

[[ "$malicious" == "2" ]] || fail "verdict.malicious = $malicious, want 2 (VirusTotal + MetaDefender both flagged this real sample)"
pass "verdict.malicious reflects the real VirusTotal + MetaDefender detections"

[[ "$level" == "low" ]] || fail "verdict.level = $level, want low"
pass "verdict.level is low, not clean"

[[ "$total" == "98" ]] || fail "verdict.total = $total, want 98 (75 + 23, scanners without a total field contribute 0)"
pass "verdict.total sums correctly across heterogeneous scanner shapes"

[[ "$num_scanners" == "4" ]] || fail "scanners list has $num_scanners entries, want 4"
pass "all 4 scanners normalized, none silently dropped"

[[ "$report_pdf" == "reports/pdf/samples/fifaconfig.exe-2026-07-29.pdf" ]] || \
  fail "report_pdf = $report_pdf, want reports/pdf/samples/fifaconfig.exe-2026-07-29.pdf"
pass "report_pdf resolves to the real per-sample PDF, not the zip's own name"

# commit stays the original push commit (audit trail: "where did I submit
# this"); report_commit is the separate, later commit the PDF actually
# exists at (analyze.yml's own bot commit) -- a raw.githubusercontent.com
# URL built from the push commit 404s, since the PDF isn't there yet.
[[ "$commit" == "deadbeef" ]] || fail "commit = $commit, want the original push commit unchanged"
pass "commit still records the original push commit"
[[ "$report_commit" == "cafef00d" ]] || fail "report_commit = $report_commit, want the resolved post-pull HEAD"
pass "report_commit records where the PDF actually exists, not the stale push commit"

echo "OK: build_result() reflects real scanner findings and links the real PDF"
