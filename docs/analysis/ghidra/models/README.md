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

### Post-#2394 GPU-identity states: which are expected, which are not

#2394 made the checker compare GPU identity by UUID rather than enumeration
order, and that added three host-leg codes. Only the first two are expected
during the rollout; the third is a real problem wearing the same shape.

- **`approved_gpu_uuid_missing`** on the `host` leg — *expected.* The deployed manifest copy at `/opt/honeypot-ghidra/models/approved-models.json` still predates the `approved_host.gpu_uuid` field until `install-analysis-host.sh` next runs end to end on that host. The checker reports this distinct, advisory-only code rather than silently comparing whichever GPU enumerates as index 0. It clears itself once the host is redeployed with the current manifest.
- **`host_gpu_uuid_changed`** — *expected for a legacy `--snapshot` only, and this code is overloaded, so check before dismissing.* A snapshot captured before #2394 was written under the older schema and carries no GPU-identity field, so replaying it reads as drift even though nothing on the host changed. But the checker also emits the **same code** when `gpu_uuid` is present and names a *different physical card* than the manifest pins — that is real drift, not a schema artefact, and the field the old schema compared (name, memory, driver) can all still look correct. Tell the two apart by whether the snapshot has a `gpu_uuid` key at all: absent means a legacy replay, present-and-different means the host is not running the approved card. The same per-field construction applies to `host_gpu_changed`, `host_gpu_memory_mib_changed`, `host_driver_changed` and `host_compute_capability_changed`, so treat each of those the same way.
- **`approved_gpu_absent`** — *not expected.* The tool ran, was pointed at the approved UUID explicitly, and no such card exists on the host. Distinct from `gpu_telemetry_unavailable` (which means the telemetry could not be read at all). This one means the approved card is genuinely gone.

## When requalification is mandatory

Run the complete workflow before changing any model tag or digest, Ollama image/version, host GPU or driver, context/output/thinking/temperature/seed/concurrency/keepalive setting, benchmark fixture/scoring rule, prompt contract, or generated response schema. Run it after an unexpected drift warning and before accepting the new state. Also rerun it when an upstream mutable tag is republished even if its name is unchanged. A routine quarterly rerun is recommended to expose host/runtime decay; it does not itself authorize promotion.

## Operator requalification

Use a trusted checkout on the approved analysis host. Stop unrelated GPU-heavy jobs if needed, but do not stop or modify QEMU. The benchmark uses only checked-in synthetic TEST-NET fixtures, talks only to the explicitly supplied local Ollama endpoint, records exact artifacts/settings/timing/RAM/VRAM metadata, and unloads each candidate through Ollama after its slot. It never downloads a model.

Keep verbose replies outside the repository in an operator-only directory with bounded retention (30 days is this doc's own recommendation; no separate retention record covers this directory):

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

Deploying also drops the manifest and the synthetic-canary overlay under `/opt/honeypot-ghidra/models/`, which `honeypot-llm-injection-suite.path` watches. So a promotion or rollback re-runs the behavioral prompt-injection corpus (#3334) against the newly pinned model without anyone remembering to ask, alongside the weekly run that catches decay on a host nobody touched. That corpus is the `sessions`-slot consumer of this manifest; see [`llm-injection-suite-record.md`](../../../llm-injection-suite-record.md).
