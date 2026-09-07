# HANDOFF-3097 — PR-1: make the scores honest

Branch: `orchestrator/issue-3097-isoforest-sign`, based on `origin/main`. Spec:
`RESEARCH-ml-worker.md` §6 PR-1 steps 1-4, §7 acceptance A1-A4. Issue #3097.

## 1. Sign-inversion fix (root cause)

`IsoForestModel.retrain()` (`ml-worker/models/isolation_forest.py`) anchored both
detectors' calibration "tail" (anomalous side) to raw percentile 99 unconditionally.
Correct for HBOS (pyod: higher `decision_function` = more anomalous), backwards for
IsolationForest (sklearn: lower `score_samples` = more anomalous). A genuinely
anomalous event could therefore score *lower* than routine traffic under the old
`_percentile_normalize` calibration, and every existing test kept passing because none
of them checked direction, only shape/bounds.

Fix:
- `iso_tail = np.percentile(iso_raw_holdout, 1)` (was 99) — the true anomalous tail for
  IsolationForest's sign convention.
- `hbos_tail = np.percentile(hbos_raw_holdout, 99)` — unchanged, already correct.
- New sign assertion before accepting a candidate: reject if `iso_tail > iso_p50` or
  `hbos_tail < hbos_p50` (tail anchor lands on the wrong side of typical). Non-strict
  (`>`/`<`, not `>=`/`<=`) — a tied anchor from a degenerate/near-homogeneous holdout
  is a real but separate case, already handled by `_percentile_normalize`'s neutral-0.5
  fallback, not a sign inversion.

## 2. Test coverage

`tests/test_model_lifecycle.py::TestCalibrationDirectionIsHonest` — drives `retrain()`
on synthetic data with a planted port-scan cluster (10 events, one IP hammering many
ports in one rolling hour) mixed into 120 bulk single-IP-single-port logins. Asserts
the accepted candidate's own calibration anchors sit on the correct side of p50, and
that scoring the planted cluster through the real `extract_features` +
`compute_batch_session_features` pipeline lands near the ceiling (`>= 0.95`) while bulk
sits low (`<= 0.5` median).

Two traps hit while building the bulk fixture, both worth knowing about if this test
ever needs touching again:
- Categorical variance in bulk (e.g. rotating destination ports) gives IsolationForest,
  trained on only ~120 rows, a clean minority branch to isolate as harshly as the
  planted cluster — false-positive-looking failures that are really a sample-size
  artifact, not a direction bug. Fixed by using continuous jitter instead
  (`honeypot.duration`, seeded `random.Random(42)`) for natural spread with no isolable
  subgroup.
- Zero variance in bulk (a single fixed port, no jitter) ties every raw score, so
  `p50 == p99` exactly and `score()` returns the flat neutral 0.5 for everything —
  masks the very thing being tested. Continuous jitter avoids this too.

Also added a 7th Tier-1 contract check to `benchmarks/evaluate_detectors.py`:
`check_score_direction_is_sane` — scores a normal single-command doc and an
anomalous failed-login doc through a trained candidate, fails if the anomalous
doc doesn't score `>=` the normal doc. Skipped (not vacuously passed) for
untrained candidates, matching the existing skip convention. Verified: both
`lstm-ae` and `isolation-forest` candidates in the harness run untrained
(no live retrain in this smoke run) — `score_direction_is_sane` correctly skips
rather than passing vacuously.

## 3. Stratified training (item 3)

Original retrain fetch concatenated sources per index, ascending, and tail-sliced to
`MAX_TRAIN_SAMPLES` — biased toward whichever index/time-of-day fetched or appended
last (Zeek in practice ending up a ~2h sliver of the batch).

- `worker.py`: fetch loop now quotas per index
  (`MAX_TRAIN_SAMPLES // len(SOURCE_INDICES)`), and each index's quota uniformly across
  24 hourly slices of the last 24h, via repeated `fetch_new_events()` calls with varying
  `since`. `es_consume.py`'s vendored fetch engine itself is untouched.
- `isolation_forest.py`: defensive cap over-quota changed from a tail slice
  (`sources[-MAX_TRAIN_SAMPLES:]`) to a head slice (`sources[:MAX_TRAIN_SAMPLES]`) —
  the stratified fetch above is already balanced, so a tail slice would silently
  re-introduce the same bias it fixes upstream.
- `lstm_autoencoder.py`: the `MAX_TRAIN_WINDOWS` cap likewise switched from a tail
  slice to a uniform random sample (`np.random.RandomState(42)`, kept in relative
  order) — same class of skew, same fix shape.

## 4. Metadata (item 4)

`RetrainResult` gained `train_index_counts: Optional[dict]` and
`train_hours: Optional[list]`, threaded through all three `retrain()` return paths
(n<2 early return, exception path, final accept/reject). `worker.py` passes the
per-index counts it computed for the stratified fetch into `retrain()`. Feeds into
`lifecycle.write_version_metadata`'s `*.meta.json` sidecar so an accepted version
records what it was actually trained on.

## Tests run

- `pytest tests/test_model_lifecycle.py` — 70 passed
- `pytest tests/test_worker_fixes.py` — 12 passed
- `pytest tests/test_temporal_features.py` — 10 passed
- `pytest tests/` (full suite) — 292 passed
- `python3 benchmarks/evaluate_detectors.py` — both candidates PASS, new
  `score_direction_is_sane` check wired and skip-behaves correctly untrained

## Not done / out of scope

- `worker.py`'s new stratified-fetch loop has no dedicated unit test of its own (no
  existing test file drives that code path directly — `test_worker_fixes.py` covers
  adjacent `fetch_new_events` bounding, unaffected by this change and still green).
  If a future PR wants direct coverage of the quota/hourly-slice loop itself, that's a
  gap worth filing separately.
