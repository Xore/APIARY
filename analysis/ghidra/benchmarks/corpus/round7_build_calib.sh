#!/usr/bin/env bash
# round7_build_calib.sh -- #3086 R1: build the round-7 imatrix calibration set
# at /mnt-1/training/calib/ from corpus-v1 slices, ready to be handed to
# requant_sweep.sh as IMATRIX=... and to export_to_ollama.sh as CALIB_FILE=.
#
# Operational copy: /mnt-1/training/round7_build_calib.sh.
#
# ---------------------------------------------------------------------------
# Sources (plan §6.1/§6.4 -- the test set is off limits, all of it):
#
#   S3/S2 decompiler output   ghidra-captured (S2, host-only) and
#                             ghidra-synthetic (S3) decompilation text.
#                             S3's .c sources live in the repo; their Ghidra
#                             decompilation needs the ghidra service, so those
#                             slices are built on the homeserver over ssh
#                             (pure CPU file work -- no model, no GPU, no
#                             contention with the cold run). Gated: run with
#                             EXEC=1; the default only reports what it would do.
#   sanitised sessions        S1 session text, already sanitised through the
#                             production contracts.py path before it lands in
#                             /mnt-1/training/corpus-v1/ (never leaves the host).
#   REx86 text                S4 entries (Zenodo 15420461, CC-BY-4.0; #847's
#                             internal-split check must pass first).
#   general-text portion      S6 CPT shards already pooled by generate_s6.py.
#
# Everything is drawn from corpus-v1 JSONL manifests written through
# schema.Record, so the decontamination tool (#3082, decontaminate.py) can scan
# this set with the exact logic it uses for the training corpus: exact
# normalised sha256 + 8-word shingle Jaccard against the 17 benchmark programs'
# source, rubric ground truth and phrases, and the claim pool. The 17 test
# programs are additionally excluded at the SOURCE level via
# slices.guard_program_name / the corpus manifest's case list -- a calibration
# file that contains a single hit would poison every imatrix built on it.
#
# Token target: 2-10M tokens (~4 chars/token), sampled round-robin across the
# sources so no single slice dominates. The output is ONE calib.txt plus
# per-source files, a sha256 per file, and a manifest.json recording
# provenance, token estimate, and the decontamination report.
#
# Usage:
#   ssh homeserver 'bash /mnt-1/training/round7_build_calib.sh'          # plan
#   ssh homeserver 'EXEC=1 bash /mnt-1/training/round7_build_calib.sh'   # build
set -euo pipefail

CALIB=${CALIB:-/mnt-1/training/calib}
CORPUS=${CORPUS:-/mnt-1/training/corpus-v1}
REPO=${REPO:-/mnt-1/benchmarks/APIARY-round7}
EXEC=${EXEC:-0}
MIN_TOKENS=${MIN_TOKENS:-2000000}
MAX_TOKENS=${MAX_TOKENS:-10000000}
CHARS_PER_TOKEN=${CHARS_PER_TOKEN:-4}

log() { echo "$(date -u +%FT%TZ) $*"; }
die() { log "ABORT: $*"; exit 1; }

[ -d "$CORPUS" ] || die "no corpus-v1 at $CORPUS"
[ -d "$REPO" ] || die "no repo at $REPO"
command -v python3 >/dev/null || die "no python3"

log "CALIB_BUILD_START corpus=$CORPUS target=${MIN_TOKENS}-${MAX_TOKENS} tokens exec=$EXEC"

# --- S3: generate the synthetic programs into the corpus work area -----------
# Pure CPU file work, safe beside the cold run. The decompilation of S3 that
# plan §6.4 assigns to the host ghidra service is ALSO pure CPU, but it runs
# against ghidra-ghidra-1 -- a live service the cold protocol does not own --
# so it is deliberately NOT automated here: decompile S3 by hand between cold
# legs, drop the outputs in $CORPUS/s3-decomp/, and re-run this script; the
# builder picks them up on the next pass.
S3_SRC="$CORPUS/s3-src"
S3_DECOMP="$CORPUS/s3-decomp"
if [ "$EXEC" = "1" ] && [ ! -f "$S3_SRC/s3_manifest.jsonl" ]; then
  mkdir -p "$S3_SRC"
  (cd "$REPO/analysis/ghidra/training/corpus" && python3 generate_s3.py "$S3_SRC")
  log "S3 sources generated: $(ls "$S3_SRC/src" | wc -l) programs"
fi

# --- assemble the calibration text -----------------------------------------
mkdir -p "$CALIB"
# EXEC=0 must never clobber an existing calibration set with an empty one.
if [ "$EXEC" != "1" ]; then
  log "EXEC=0: planning only. Would assemble from:"
  log "  S2/S3 decompiler text: $S3_DECOMP/  (+ $S3_SRC/src/*.c pre-decompile)"
  log "  S1 sanitised sessions: $CORPUS/s1_manifest.jsonl"
  log "  S4 REx86 text:         $CORPUS/s4_manifest.jsonl"
  log "  S6 general text:       $CORPUS/s6/"
  log "then decontaminate via decontaminate.py and write $CALIB/calib.txt"
  log "CALIB_BUILD_PLAN_COMPLETE"
  exit 0
fi

REPO_CORPUS="$REPO/analysis/ghidra/training/corpus"
CALIB_PY="$CALIB/.build_calib.py"
cat > "$CALIB_PY" <<'PYEOF'
import hashlib, json, random, sys
from pathlib import Path

corpus, calib, repo_corpus = map(Path, sys.argv[1:4])
min_tok, max_tok, cpt = (int(x) for x in sys.argv[4:7])

sources = {}  # name -> list of text chunks

# S3/S2 decompiler output: the decompiled text files, falling back to the C
# sources themselves before decompilation has happened (still corpus-v1, still
# not the test set -- generate_s3.py enforces the name guard).
for d, label in ((corpus / "s3-decomp", "s3-decomp"), (corpus / "s3-src/src", "s3-src")):
    if d.is_dir():
        sources[label] = [p.read_text(errors="replace") for p in sorted(d.rglob("*")) if p.is_file() and p.stat().st_size > 0]
        if sources[label]:
            break

# S1 sanitised sessions / S4 REx86 / S6 general text: corpus-v1 manifests,
# prompt+completion text per Record.
def manifest_texts(manifest, label):
    if not manifest.exists():
        return
    chunks = []
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        text = "\n".join(p for p in (r.get("prompt"), r.get("completion")) if p)
        if text.strip():
            chunks.append(text)
    if chunks:
        sources[label] = chunks

manifest_texts(corpus / "s1_manifest.jsonl", "s1-sessions")
manifest_texts(corpus / "s4_manifest.jsonl", "s4-rex86")
for shard in sorted((corpus / "s6").glob("s6_shard_*.txt")) if (corpus / "s6").is_dir() else []:
    sources.setdefault("s6-general", []).append(shard.read_text(errors="replace"))

if not sources:
    sys.exit("ABORT: no corpus-v1 slices found -- build them first")

# Round-robin across sources so no slice dominates the sample, up to the token
# ceiling. Deterministic order via seed: the same corpus yields the same file.
rng = random.Random(20260906)
pools = {k: rng.sample(v, len(v)) for k, v in sources.items()}
order = sorted(pools)
out_parts, per_source, total_chars = [], {k: 0 for k in order}, 0
i = 0
while total_chars < max_tok * cpt:
    progressed = False
    for k in order:
        if i < len(pools[k]):
            chunk = pools[k][i]
            out_parts.append(f"### source: {k}\n{chunk}")
            per_source[k] += len(chunk)
            total_chars += len(chunk)
            progressed = True
            if total_chars >= max_tok * cpt:
                break
    if not progressed:
        break
    i += 1

est_tokens = total_chars // cpt
if est_tokens < min_tok:
    sys.exit(f"ABORT: corpus yields only ~{est_tokens} tokens, below the {min_tok} floor -- build more slices first")

(calib / "calib.txt").write_text("\n\n".join(out_parts))

# One Record PER SOURCE CHUNK, not one for the whole file: decontaminate.py's
# shingle-Jaccard near-duplicate check compares whole samples against the
# protected documents (the 17 test programs are a few KB each), and a single
# multi-million-token record would dilute any embedded contamination to ~0
# overlap. Per-chunk records give the scan the granularity it needs.
with (calib / ".calib_manifest.jsonl").open("w") as mf:
    mf.write(json.dumps({"id": "round7-calib-meta", "slice": "S6",
                         "family": "calib-meta", "source_path": "calib.txt",
                         "prompt": None, "completion": None, "meta": {}},
                        sort_keys=True) + "\n")
    idx = 0
    for part in out_parts:
        rec = {"id": f"round7-calib-{idx}", "slice": "S6", "family": "calib-text",
               "source_path": "calib.txt", "prompt": None, "completion": part, "meta": {}}
        mf.write(json.dumps(rec, sort_keys=True) + "\n")
        idx += 1

# sha256 per source file, written per-file beside the text and into the manifest
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

manifest = {
    "schema_version": "round7-calib-1",
    "calib_file": "calib.txt",
    "sha256": sha(calib / "calib.txt"),
    "bytes": (calib / "calib.txt").stat().st_size,
    "est_tokens": est_tokens,
    "chars_per_token": cpt,
    "target_tokens": [min_tok, max_tok],
    "sources": {k: {"chunks": len(sources[k]), "chars": per_source[k]} for k in order},
    "seed": 20260906,
}
(calib / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(f"calib.txt: {est_tokens} est tokens from {len(order)} sources: {per_source}")
PYEOF

python3 "$CALIB_PY" "$CORPUS" "$CALIB" "$REPO_CORPUS" "$MIN_TOKENS" "$MAX_TOKENS" "$CHARS_PER_TOKEN" \
  || die "calibration assembly failed"

# --- decontamination: the round7-3 (#3082) tool, unchanged ------------------
# The calibration set is training-adjacent text, so it goes through the same
# protected-document scan as the corpus: the 17 benchmark programs, rubric
# ground truth + phrases, the claim pool. 0 hits or nothing ships.
REPORT="$CALIB/decontamination-report.json"
# Guard against a checkout too shallow to load the protected documents: a
# scan against 0 protected docs always passes and proves nothing. The tool
# derives their paths from its own location inside the repo, so this means
# the repo checkout is incomplete -- abort rather than ship a vacuous report.
ndocs=$(python3 -c "
import sys; sys.path.insert(0, '$REPO_CORPUS')
import decontaminate; print(len(decontaminate.load_protected_corpus()))")
[ "$ndocs" -gt 0 ] || die "decontaminate.py loaded 0 protected documents -- $REPO checkout is incomplete (missing benchmarks corpus src/rubric or claim pool)"
(cd "$REPO_CORPUS" && python3 decontaminate.py "$CALIB/.calib_manifest.jsonl" --out "$REPORT") \
  || die "DECONTAMINATION FAILED -- see $REPORT; do not use this calibration set"
hits=$(python3 -c "import json;print(json.load(open('$REPORT'))['total_hits'])")
[ "$hits" = "0" ] || die "decontamination found $hits hits -- regenerate the set from clean slices"
python3 - "$REPORT" "$CALIB" <<'PYEOF'
import json, sys
report, calib = sys.argv[1], sys.argv[2]
m = json.load(open(f"{calib}/manifest.json"))
m["decontamination"] = {"report": "decontamination-report.json", "total_hits": json.load(open(report))["total_hits"]}
open(f"{calib}/manifest.json", "w").write(json.dumps(m, indent=2, sort_keys=True) + "\n")
PYEOF

rm -f "$CALIB_PY" "$CALIB/.calib_manifest.jsonl"
# sha256 for every file that ships
( cd "$CALIB" && sha256sum calib.txt manifest.json decontamination-report.json > sha256sums.txt )
log "CALIB_BUILD_COMPLETE est_tokens=$(python3 -c "import json;print(json.load(open('$CALIB/manifest.json'))['est_tokens'])")"
log "hand over with: IMATRIX=$CALIB/calib.txt bash requant_sweep.sh"
