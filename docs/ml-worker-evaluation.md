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

**Tier 2 (accuracy) was blocked on [#1797](https://github.com/Xore/APIARY/issues/1797).**
There was no labelled corpus at that point. The date is retained as the
historical Tier 1 landing record; the later BETH verdict below supersedes the
blocked status.

**No candidate has been promoted or rejected on this evidence yet.** The two
deployed detectors have not been run through it as a qualification; doing so is
the next step, along with the live-threshold measurement
(#1794-b) that the alert-budget metric and the promotion gate both need.

### 2026-09-25 — BETH Tier 2 sanity rail is available

`ml-worker/benchmarks/evaluate_accuracy.py beth` now provides the bounded
parallel-corpus rail. It consumes the three published BETH process CSVs as-is,
uses the authors' encoding from `BETH_Dataset_Analysis/dataset.py`, fits on
`train`, uses `val` only for the held-out diagnostic split, and scores `test`
once per declared seed without row re-splitting. It reports AUROC as the
headline, AUPRC alongside it, mean ± standard deviation over at least five
seeds, and each split's `sus` base rate beside every printed metric. A missing
local data directory is a clear CLI error; the harness never downloads data
or fabricates results.

The command is importable and its parser/validation can be tested without the
39.8 MB corpus. Runtime reports record CSV and optional archive MD5s outside the
repository. The report is evidence about the detector architecture/pipeline
only: it is **not** ground truth for deployed traffic and cannot justify a
composite-weight or `ML_ALERT_THRESHOLD` change. The disposition corpus tracked
by [#3295](https://github.com/Xore/APIARY/issues/3295) remains a separate
deployment-labelled source and is not imported here.

### 2026-09-05 — #1797 has ruled; Tier 2 is no longer blocked on it

The paragraph above is superseded. Both [#1794](https://github.com/Xore/APIARY/issues/1794)
and [#1797](https://github.com/Xore/APIARY/issues/1797) are closed, so neither
is a live blocker any more, and Tier 2 has two named label sources instead of
one open question.

**BETH's verdict: usable as a sanity rail, never as ground truth for our
traffic.** Recorded in full on #1797, in short here:

- CC0, downloadable anonymously (39.8 MB archive, 927 MB uncompressed), frozen
  since 2021-07-29 — treat version 3 as final.
- Its labels are real and match the paper: 763,144 / 188,967 / 188,967 rows
  across the three published splits, host-disjoint by construction with the
  attacked host held out of train and val.
- Its features are eBPF process calls (`processId`, `mountNamespace`,
  `eventId`, `returnValue`). Ours are `dst_port`, `payload_entropy`,
  `inter_arrival_log`, GeoIP, Cowrie credentials. **No honest mapping exists in
  either direction**, so this corpus can validate our *architectures* and can
  never validate the *deployment*.
- The DNS/network half is not usable at all: all six `*-dns.csv` files are
  byte-identical, 269 rows total, 21 `sus` / 4 `evil`.
- Adoption protocol (splits as published, the authors' own feature encoding,
  AUROC headline with AUPRC alongside, mean ± std over ≥5 seeds, per-split base
  rates printed beside every number) is written out on #1797 and is what this
  tier should implement.

**The ranking corpus for our own traffic is the disposition corpus, not BETH.**
The operator disposition lifecycle shipped in
[#1968](https://github.com/Xore/APIARY/issues/1968) /
[#2395](https://github.com/Xore/APIARY/issues/2395) is live and accumulating
labels on the traffic the deployed detectors actually score. That is the source
a precision/recall number for this deployment has to come from; BETH is the rail
that catches a pipeline defect before such a number is trusted.

**No change to the composite's 0.4/0.4/0.2 weights or to `ML_ALERT_THRESHOLD`
may be argued from BETH**, per its own decision rule. If our iForest does not
land near the 0.850 AUROC of the paper's Table 3 under the authors' features,
the defect is in our pipeline, not in the dataset.

Wiring Tier 2 — the BETH rail and disposition-corpus calibration — is tracked in
[#2986](https://github.com/Xore/APIARY/issues/2986) under epic
[#1974](https://github.com/Xore/APIARY/issues/1974). It is not tracked by this
paragraph.

### 2026-09-25 — disposition export/census landed; Tier 2 calibration remains gated

`ml-worker/benchmarks/disposition_corpus.py` now exports the closed
operator-disposition population and writes a hashed census outside the
repository. The report carries a canonical-content SHA-256 (the digest field
is excluded from its own hash), so the saved artifact can be independently
verified. It is read-only: open and legacy unlabelled alerts remain in the
full alert denominator but are excluded from the labelled snapshot, and the
command never updates Elasticsearch or synthesises a verdict.

The census is a gate, not a calibration result. A zero-label or single-class
labelled subset is reported as non-calibratable. Even after labels accumulate,
the corpus is **precision-only**: `write_anomaly()` returns before persistence
below `ML_ALERT_THRESHOLD`, so it can describe precision within alerts and
within-alert calibration, but it can never measure deployment recall or
ordinary below-threshold calibration. Any Tier 2 report that consumes this
corpus must repeat that limitation and must not treat unlabelled or absent
events as negatives.

The decision record should receive a result only after a concrete snapshot is
attached to the run and its class/model-state diversity is sufficient. The
live census is therefore not copied into this file as a durable result; rerun
the command against the deployment and retain the generated report and hash.

### 2026-09-27 — Tier 2 wired: BETH rail measured, disposition calibration still unmeasured

[Wire #2986](https://github.com/Xore/APIARY/issues/2986). Two results, and they
are not the same kind of thing, so they are recorded separately.

#### BETH architecture sanity rail — MEASURED, and it fires

`evaluate_accuracy.py beth` was run against the published BETH v3 corpus
obtained anonymously from Kaggle and kept outside the repository.

| | |
|---|---|
| archive | 39.75 MB, MD5 `f7b41dbf3b9dcb6189cdea4cfa5008d4` |
| `labelled_training_data.csv` | MD5 `5abf51688d0167b3212c645ed56094b5` |
| `labelled_validation_data.csv` | MD5 `b1bfd82df03c686f750b82e7f59d56c6` |
| `labelled_testing_data.csv` | MD5 `479638d74691b2f0611df1543d2797e9` |
| run | seeds 1–5, PCA(whiten) + IsolationForest fit on `train`, `test` scored once per seed |
| environment | Python 3.12.14, numpy 2.5.3, pandas 3.0.6, scikit-learn 1.9.1, CPU only |
| published fingerprint | train 763,144 rows / 1,269 sus / 8 hosts · val 188,967 / 786 / 4 hosts · test 188,967 / 171,459 sus + 158,432 evil / 1 host — **verified**, so this is the real corpus and not a re-split |

**AUROC 0.769441 ± 0.026784 · AUPRC 0.965363 ± 0.007247** (mean ± sd over five
seeds; per-split `sus` base rates 0.17% / 0.42% / 90.7% printed beside every
number).

**The sanity gate FAILED.** The paper's iForest reference is ≈0.850 AUROC and
the screening band is ±0.05, i.e. 0.800–0.900. We land 0.769, below the band,
and the command exits non-zero. Per this document's own decision rule, "if our
iForest does not land near the 0.850 AUROC of the paper's Table 3 under the
authors' features, the defect is in our pipeline, not in the dataset" — so this
is an open finding about our Tier 2 pipeline, **not** a deployment accuracy
claim and **not** something BETH is entitled to settle. It is recorded as
unresolved: the harness implements the authors' published encoding and the
published split, and the split fingerprint verified, so the gap is not explained
by the corpus being wrong. Chasing it is a separate piece of work.

Two things this number is **not**: it is not our fleet's accuracy, and it is not
a reason to touch the 0.4/0.4/0.2 weights or `ML_ALERT_THRESHOLD`. BETH's
features are eBPF process calls; ours are `dst_port`/entropy/GeoIP/credentials.

#### Disposition-corpus calibration — NOT MEASURED, here is why

`evaluate_accuracy.py disposition` is implemented and tested: Platt scaling fit
on a `model_state_id`-group-disjoint, timestamp-ordered split and scored once on
a held-out split, with per-seed variance and a hashed report outside the
repository. **No deployment calibration number is recorded here, because none
was measured.** The run needs a labelled snapshot exported from `ml-anomalies`
on the live deployment; no deployment Elasticsearch was reachable from the
machine this was built on, so there is no snapshot to attach. When one exists,
run it and add the result then.

This is the honest state of the record, and it is the same answer the
2026-09-25 entry above already gave: the census is a gate, and a gate that has
not been passed has no result.

#### The rail bites — deliberate breaks

A rail that cannot fail is decoration, so each guard was broken on purpose and
the resulting failure recorded. Reproduced on the real BETH corpus and on
synthetic disposition fixtures:

| break | outcome |
|---|---|
| Invert the anomaly-score direction (the #3097 defect class) | AUROC **0.2306**, gate fires, exit 1 |
| Fit on train+val+test (leakage past the published split) | AUROC **0.5160**, gate fires, exit 1 |
| Replace the calibrator with a constant 0.5 | held-out Brier 0.2500 vs 0.2234 baseline, calibration gate fails on **all 5 seeds**, exit 1 |
| Zero-label snapshot | refused, exit 2 — "will not invent a result" |
| Single-class snapshot | refused, exit 2 |
| All alerts from one `model_state_id` | refused, exit 2 — a checkpoint cannot calibrate itself |
| `composite_score` of 1.4 | refused, exit 2 — not silently clipped |
| Ask for AUROC / AUPRC / recall / point-adjusted F1 on the disposition corpus | all refused |

And the negative control, which matters as much: a **genuinely separable**
snapshot still passes (Brier 0.0356 vs a 0.2800 baseline), because there
saturating to 0/1 is the correct answer. A rail that refused that would be
wrong rather than strict. The same fault injections are committed as tests in
`ml-worker/tests/test_disposition_tier2.py` so they stay proven.

#### What the disposition gates assert

No expected accuracy value is invented anywhere in this tier, because choosing
one after seeing results is the failure it exists to prevent. The assertions
are structural or mathematical:

- **calibration** — on *every* seed the Platt calibrator must beat the cheapest
  honest competitor, a constant emitting the fit split's own positive rate.
  Beating that is a requirement, not a target. (This is the break above.)
- **monotonicity** — where the reliability curve has three or more populated
  bins, higher predicted probability must not correspond to lower observed
  precision. With fewer bins the gate reports *not exercised* rather than
  passed, on the same "a skip is not a pass" rule Tier 1 uses.
- **precision regression** — armed only when the operator passes
  `--precision-floor`. Unarmed is reported as unarmed, never as passed.
- **eligibility** — both classes present, two or more distinct
  `model_state_id` groups, no group straddling the boundary. Non-eligible input
  is refused with exit 2, not scored.

### Scope deliberately left out

- **No deployment recall figure, and none is possible.** Only above-threshold
  alerts are persisted, so this corpus cannot produce one. Reporting a recall
  here would require treating unlabelled and below-threshold events as
  negatives, which is exactly the mistake the census was built to prevent. This
  is why epic #1974's second half stays open.
- **The two deployed detectors were not qualified end-to-end.** #2986 scope
  item 3 asks for that, and the BETH rail is the wrong instrument for it: it
  scores BETH's eBPF features, not `dst_port`/entropy/GeoIP/credentials. The
  live-threshold measurement (#1794-b) also remains undone and is what the
  alert-budget metric needs.
- **No composite-weight or `ML_ALERT_THRESHOLD` change**, per this document's
  standing rule and the BETH rail's own no-promotion clause.


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
  calibration. Platt scaling on a held-out labelled split is — and #1797 settled
  where that split can come from: BETH's published splits make ECE/Brier
  computable for the *architectures*, the #1968/#2395 disposition corpus is the
  only label source for the *deployment*. See the 2026-09-05 status entry.

## Promotion

Only through the existing versioning and rollback path in
`docs/ml-worker-plan.md` §11.3. Never by hand-editing a deployed checkpoint.
Expected values are never adjusted after seeing a preferred candidate's output.
