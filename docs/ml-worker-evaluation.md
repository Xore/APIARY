# ml-worker detector evaluation

The decision record for the anomaly detectors, mirroring
[`docs/local-llm-model-evaluation.md`](local-llm-model-evaluation.md). The
harness lives in [`ml-worker/benchmarks/`](../ml-worker/benchmarks/README.md)
and was added under [#1794](https://github.com/Xore/APIARY/issues/1794).

Scored measurements and reproducibility metadata go here. Raw reports stay
outside the repository.

## Decision scope

Which detectors fill the `ml-worker` scoring path, and on what evidence.
Today that is a fixed composite:

| detector | weight | score meaning |
|---|---:|---|
| IsolationForest | 0.4 | score in [-1, 0], normalised |
| LSTM autoencoder | 0.4 | normalised reconstruction loss |
| HBOS | 0.2 | normalised outlier score |

Those weights are **not** in scope for this record. A benchmark result may
inform them later; changing them here would change the thing being measured.

## Selection priority

1. **Behaviour before accuracy.** A detector that mishandles abstention, fails
   confidently, or throws on one sensor's schema is disqualified regardless of
   any accuracy figure. Those failures are invisible in AUPRC and serious in
   production.
2. **False-alarm rate at the operating threshold gates promotion**, regardless
   of AUPRC. The alert path has one consumer.
3. Accuracy, once there is a labelled corpus to measure it against.

## Test system

Same host as the LLM benchmark: one NVIDIA RTX 4000 Ada, 20475 MiB, 91 GB RAM.
The GPU is shared with the Ollama slots, which is why inference latency is
reported alongside accuracy rather than ignored.

## Status

### 2026-08-25 — Tier 1 harness landed; Tier 2 blocked

**Tier 1 (behaviour) is live.** `evaluate_detectors.py` runs six contract
checks against a candidate over the per-sensor fixture corpus and emits a
hashed JSON report. It is the first reusable acceptance bar `ml-worker` has
had, and it makes "evaluate this candidate offline" answerable at all.

**Tier 2 (accuracy) is blocked on [#1797](https://github.com/Xore/APIARY/issues/1797).**
There is no labelled corpus. Until BETH is confirmed usable — or ruled out —
this benchmark cannot rank candidates, only reject misbehaving ones. Recorded
plainly rather than shipping a harness that looks like it ranks.

**No candidate has been promoted or rejected on this evidence yet.** The two
deployed detectors have not been run through it as a qualification; doing so is
the next step, along with the live-threshold measurement
(#1794-b) that the alert-budget metric and the promotion gate both need.

## Findings carried in from the research phase

Recorded so they are not rediscovered, each with the reason it matters here.

- **Point-adjusted F1 is banned.** Under the PA protocol a random anomaly score
  becomes state of the art (Kim et al., AAAI 2022,
  [arXiv:2109.05257](https://arxiv.org/abs/2109.05257)). Building the obvious
  metric would have produced a harness that ranks a coin flip above the
  incumbent while looking rigorous.
- **Leakage-free splits are non-negotiable**, and the rule applies to existing
  code: `LSTMAEModel.retrain()` builds overlapping windows per `src_ip`, and
  windowing before the split is worth up to 0.23 macro-F1 and a 67× false-alarm
  difference where it was measured.
- **Seed variance must be reported.** A candidate evaluated elsewhere showed a
  0.0038 F1 gain across three added modalities, presented as progress with no
  variance at all. Independently, the LLM benchmark on this stack measures a
  ±1-point run-to-run spread with model, prompt and seed all fixed — deltas
  under the spread are not results.
- **`iForest` is not the weak link.** BETH's own baselines put it above robust
  covariance, one-class SVM and DoSE by AUROC. A benchmark assuming the deep
  temporal model is the thing to beat starts from the wrong prior — our
  composite already weights IsolationForest at 0.4.
- **Calibration is label-gated.** ECE, Brier and reliability diagrams need a
  probability *and* a ground-truth label; our detectors emit neither. An ECDF
  rank transform makes the three commensurable before blending but is **not**
  calibration. Platt scaling on a held-out labelled split is, and it depends on
  #1797.

## Promotion

Only through the existing versioning and rollback path in
`docs/ml-worker-plan.md` §11.3. Never by hand-editing a deployed checkpoint.
Expected values are never adjusted after seeing a preferred candidate's output.
