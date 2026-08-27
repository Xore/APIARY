# ml-worker detector benchmark

The acceptance bar for the anomaly detectors, added under
[issue #1794](https://github.com/Xore/APIARY/issues/1794). Mirrors the shape of
`analysis/ghidra/benchmarks/` deliberately rather than inventing a second
governance model. The decision record is
[`docs/ml-worker-evaluation.md`](../../docs/ml-worker-evaluation.md).

**This produces the ruler, not a detector.**

## Safety properties

- Fixtures are the per-sensor documents from `ml-worker/tests/fixtures.py` —
  already reviewed, already TEST-NET addresses and reserved names. A second
  fixture set would mean two things to keep in step with the sensors.
- The benchmark never trains, downloads, or deploys anything. It calls the
  candidate's scoring path and nothing else.
- No Elasticsearch, no network. Everything is in-process.

## Run

```bash
python3 ml-worker/benchmarks/evaluate_detectors.py \
  --output "$HOME/ml-worker-qualification/tier1.json"
```

Prints per-check results and writes a hashed JSON report. Exit status is
non-zero if any non-skipped check fails.

## Tier 1 — behaviour, which is what this measures

Answers **"does this candidate behave correctly"**, not "is it accurate".
Three of the checks encode failures that are invisible in an accuracy number
and serious in production:

| check | why it exists |
|---|---|
| `abstains_without_history` | Until `SEQ_LEN` events exist for a source (and before any accepted fit) a detector must return `None` (#1969) — *no signal yet*, not *looks normal*. A candidate returning a small-but-nonzero score there asserts normality about a source it has barely seen, and no accuracy metric would ever show it. |
| `abstains_on_inference_failure` | On an inference exception a detector abstains (`None`, #1969): excluded from the composite rather than counted as any vote. A constant placeholder keeping its full ensemble weight is a vote from nothing; a low score reads as "confirmed normal", which is what a broken detector must never give. Skipped on untrained candidates, where pre-fault and post-fault are indistinguishable. |
| `survives_every_sensor_schema` | Dionaea and Conpot documents have gaps the Cowrie-shaped ones do not. A detector that throws on one sensor stops scoring it and the alert count merely drops, which looks like an improvement. |
| `survives_malformed_document` | A document missing its timestamp must not take the worker down. |
| `scores_are_bounded` | When a detector opines at all, a NaN or out-of-range value poisons the weighted composite rather than failing visibly; absence must be `None`, never a low number. |
| `composite_renormalises_over_present_detectors` | Runs production `compute_composite()` against detector-absent cases: absence drops out of numerator AND denominator, an all-absent event composites to 0.0, single-detector opinions stand at face value (#1969). |

**A skipped check is not a passed check.** Skips are counted and reported
separately so a partially-exercised candidate cannot read as a clean one.

## Tier 2 — accuracy, and why it is not here

A labelled ranking corpus, **blocked on
[#1797](https://github.com/Xore/APIARY/issues/1797)**. If BETH does not map onto
our feature extractors, this benchmark ships as Tier 1 only — said out loud
here rather than shipping a harness that quietly cannot rank.

When it lands:

- **AUPRC is the headline.** Anomalies are rare and AUROC flatters under skew.
- AUROC secondary, for comparability with BETH's own published baselines.
- **Alert-budget precision**: precision *and* the absolute alert count per day
  at the operating threshold. That number decides whether the dashboard is
  usable.
- **Seed variance**: mean ± std over ≥ 3 fixed seeds. A delta smaller than the
  seed spread is not a result. Non-negotiable — the LLM side measured a
  ±1-point run-to-run spread on a fixed model and prompt, and single-run
  deltas smaller than that had been read as rankings for months.
- Calibration (ECE, Brier, reliability diagrams) only after Platt scaling on a
  held-out labelled split. An ECDF rank transform makes scores commensurable
  but is **not** calibration; never report ECE on one and call it calibrated.

## Banned metrics

- **Point-adjusted F1.** Under the PA protocol a random anomaly score becomes
  state of the art (Kim et al., AAAI 2022,
  [arXiv:2109.05257](https://arxiv.org/abs/2109.05257)) — PA marks a whole
  segment detected if any single point in it is flagged, rewarding
  trigger-happy detectors. Build the obvious thing and you get a harness that
  ranks a coin flip above the LSTM-AE while looking rigorous. Use **PA%K** with
  K stated if a segment metric is wanted.
- Any metric computed on a random or time-shuffled split.

## Split rule — non-negotiable, and it applies to existing code

1. Partition **first**, then build windows. Never the reverse.
2. Group by `src_ip`; no source appears on both sides.
3. Preserve temporal order; no shuffling across time.
4. Hold the anomalous population out of training entirely.
5. **Disclose the padding convention in the report.** Ours abstain rather than
   pad, which is the safe choice — record it so a future candidate that pads
   instead cannot quietly win on the artifact.

`LSTMAEModel.retrain()` builds overlapping length-15 windows per `src_ip`.
Building those *before* the split reproduces exactly the leakage this rule
exists to prevent — worth up to 0.23 macro-F1 and a 67× false-alarm difference
where it was measured.

## The gate, decided before any candidate is scored

> **A candidate may not be promoted if it raises the false-alarm rate at the
> operating threshold, regardless of AUPRC.**

Empirical, not theoretical: a transformer candidate bought a better-looking
macro-F1 alongside a 0.04% → 2.7% false-alarm rate. The alert path has one
consumer, and drowning it is worse than missing a marginal detection.

Structural parity with the LLM benchmark, where a higher raw score never
overrides a failed injection gate. Expected values are never adjusted after
seeing a preferred candidate's output.

## Out of scope

- Building a new detector. This is the ruler.
- Re-deciding the 0.4/0.4/0.2 composite weights — changing them here would
  change the thing being measured.
- Any live change to the scoring path. The harness is offline.

## A note on the contract

It is **not uniform**, and the harness does not pretend otherwise:
`LSTMAEModel.score()` takes a raw ES `_source` dict, while
`IsoForestModel.score()` takes an already-extracted feature vector. Each
candidate supplies its own adapter. A harness that silently normalised the two
would hide a real difference between the detectors.
