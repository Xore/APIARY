# Local model governance

`approved-models.json` is the reviewed source of truth for the three local-model slots: automated Ghidra triage, guarded session analysis, and interactive Rev·Deck assistance. It binds the friendly tag to the exact model digest and metadata, Ollama image, host/GPU/driver, effective request controls, prompt/schema contract hashes, benchmark version, independent case gates, approval date, and the SHA-256 of the archived verbose report.

The manifest is not an installer. None of these tools pull, delete, or replace models, manage containers, or inspect/manage QEMU. A missing or changed artifact is reported as drift.

## Read-only drift status

The installer enables `honeypot-model-drift.timer`. It checks on boot and every five minutes:

```sh
python3 /opt/honeypot-ghidra/models/model-governance.py check-runtime \
  --manifest /opt/honeypot-ghidra/models/approved-models.json \
  --status-file /var/lib/honeypot-ghidra/model-status.json \
  --warn-only
```

The status file contains only state and reason codes. It contains no prompts, model replies, captured data, container paths, or credentials, and is written owner-only mode `0600`. If a dashboard later needs it, expose only the sanitized object through a privileged read-only endpoint; do not mount or relax the host file. `approved`, `drift`, and `unavailable` are advisory states: the service exits successfully with `--warn-only`, so an LLM problem never stops ingestion or deterministic analysis. Omit `--warn-only` in an operator check when drift should produce a non-zero exit status. The command only reads `/api/version`, `/api/tags`, Docker inspection metadata, and `nvidia-smi` telemetry.

## When requalification is mandatory

Run the complete workflow before changing any model tag or digest, Ollama image/version, host GPU or driver, context/output/thinking/temperature/seed/concurrency/keepalive setting, benchmark fixture/scoring rule, prompt contract, or generated response schema. Run it after an unexpected drift warning and before accepting the new state. Also rerun it when an upstream mutable tag is republished even if its name is unchanged. A routine quarterly rerun is recommended to expose host/runtime decay; it does not itself authorize promotion.

## Operator requalification

Use a trusted checkout on the approved analysis host. Stop unrelated GPU-heavy jobs if needed, but do not stop or modify QEMU. The benchmark uses only checked-in synthetic TEST-NET fixtures, talks only to the explicitly supplied local Ollama endpoint, records exact artifacts/settings/timing/RAM/VRAM metadata, and unloads each candidate through Ollama after its slot. It never downloads a model.

Keep verbose replies outside the repository in an operator-only directory with bounded retention (30 days is the recorded recommendation):

```sh
install -d -m 0700 "$HOME/model-qualification"
python3 analysis/ghidra/benchmarks/evaluate-models.py \
  --manifest analysis/ghidra/models/approved-models.json \
  --output "$HOME/model-qualification/issue-158-v2.json"
python3 analysis/ghidra/models/model-governance.py verify-report \
  --manifest analysis/ghidra/models/approved-models.json \
  --report "$HOME/model-qualification/issue-158-v2.json"
sha256sum "$HOME/model-qualification/issue-158-v2.json"
```

Review the raw replies and every failure. Aggregate improvement cannot override a named case's schema, injection, criticality, context, or minimum-score gate. The required regression set includes process-injection prompt text, encoded credential exfiltration, `chpasswd` credential change versus password cracking, Linux versus Windows UAC mapping, and ordinary SSH activity versus SSH session hijacking.

For a candidate model, copy the manifest to a candidate file and edit the candidate's exact artifact and thresholds before running the benchmark against that candidate. Never lower a gate to fit an observed answer without a separate review of the expected security semantics.

## Explicit promotion and rollback

Promotion requires the literal acknowledgement, a reviewed candidate manifest, the exact verbose report, an approval date, and a durable decision-record reference. It verifies all independent gates, derives the report hash itself, and replaces the manifest and generated approval record as one rollback-safe transaction:

```sh
python3 analysis/ghidra/models/model-governance.py promote \
  --candidate-manifest /secure/operator/candidate.json \
  --report "$HOME/model-qualification/issue-158-v2.json" \
  --manifest analysis/ghidra/models/approved-models.json \
  --record docs/analysis/ghidra/models/approval-record.md \
  --backup-dir "$HOME/model-qualification/backups" \
  --approval-date 2026-08-01 \
  --decision-record 'GitHub issue #158 comment and PR review' \
  --approve PROMOTE
```

Commit the manifest and approval record together. Do not commit verbose model replies; keep only their SHA-256 and the safe score/timing summary in the decision record.

Rollback selects a specific backup ID—never "latest"—validates its manifest, preserves the current pair as another restorable backup, and atomically restores both files:

```sh
python3 analysis/ghidra/models/model-governance.py rollback \
  --manifest analysis/ghidra/models/approved-models.json \
  --record docs/analysis/ghidra/models/approval-record.md \
  --backup-dir "$HOME/model-qualification/backups" \
  --backup-id 20260801T120000Z \
  --approve ROLLBACK
```

After promotion or rollback, deploy the two reviewed files, run `check-runtime` without `--warn-only`, and exercise each consumer. Rev·Deck's upstream client does not expose all generation controls; the manifest records those fields as upstream-controlled instead of pretending they are fixed. Its qualification request remains fully fixed and reproducible.
