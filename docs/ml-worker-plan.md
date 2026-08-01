# ML Worker — Implementation Plan

> **Status:** `ml-worker/` now has its own Dockge stack
> ([`docker-compose.yml`](../ml-worker/docker-compose.yml) +
> [`docker-compose.ml-worker.gpu.yml`](../ml-worker/docker-compose.ml-worker.gpu.yml),
> mirroring `analysis/ghidra/`) and builds, connects to Elasticsearch, and
> polls without crashing — verified live against a disposable ES 8.13.4
> container (#62). The dashboard still has no `/api/ml/anomalies` endpoint
> and no `ml_anomalies.go`. `extract_features()` still reads the wrong
> schema (see §5.3) and the worker is not deployed anywhere.  
> **Worker location:** [`ml-worker/`](../ml-worker/)  
> **Tracked in:** [#61](https://github.com/Xore/honeypot-stack/issues/61)–[#65](https://github.com/Xore/honeypot-stack/issues/65)
> — see the roadmap table in §12.
>
> **v0.1 audit verdict (#61, 2026-07-31): not runnable, evidenced.**
> `docker build ./ml-worker` failed outright (`pyod`'s `numba` dependency had
> no version compatible with the pinned `numpy==2.5.1` on Python 3.12 —
> reproduced twice, locally and in-container; fixed in #62 by pinning
> `numpy==2.4.6`/`numba==0.66.0`/`llvmlite==0.48.0`). `worker.py`'s
> `SOURCE_INDICES` (`cowrie-*`, `dionaea-*`, `honeypot-network-*`, `conpot-*`,
> `http-honeypot-*`) still match zero indices on the live homeserver: the real
> shape is a unified `honeypot-v2-*` stream (all sensors, disambiguated by
> `event.sensor`) plus `suricata-v2-<type>-*`. And `extract_features()` still
> reads flat top-level fields that don't exist in a real document — sensor
> data is nested under `honeypot.*`/`source.*`/`network.*`, and even those
> aren't uniform across sensors (§5.3). Six more defects (three already
> flagged in `ml-gpu-coordinated-roadmap.md` §1, three new) are proven
> executably in `ml-worker/tests/test_worker_audit.py`. Full writeup:
> [issue #61](https://github.com/Xore/honeypot-stack/issues/61). This is a
> Milestone B rewrite, not a v0.1 polish pass.

---

## Table of Contents

1. [Goal & Scope](#1-goal--scope)
2. [Data Sources](#2-data-sources)
3. [Architecture Overview](#3-architecture-overview)
4. [ML Models Selected](#4-ml-models-selected)
5. [Feature Engineering](#5-feature-engineering)
6. [Worker Pipeline](#6-worker-pipeline)
7. [Elasticsearch Index Design](#7-elasticsearch-index-design)
8. [Dashboard API Contract](#8-dashboard-api-contract)
9. [Dashboard UI Integration](#9-dashboard-ui-integration)
10. [Docker Compose Integration](#10-docker-compose-integration)
11. [Model Lifecycle & Retraining](#11-model-lifecycle--retraining)
12. [Roadmap](#12-roadmap)

---

## 1. Goal & Scope

The **ML Worker** is an autonomous Python service that continuously reads all
events produced by the honeypot stack and detects:

- **Novel attack patterns** — behaviours that have never appeared before and
  don't match any known signature (zero-day surface).
- **Strange/anomalous events** — statistical outliers in attacker behaviour,
  unusual port/protocol combinations, abnormal session lengths, rare payloads,
  unexpected geographic sources.
- **Temporal attack campaigns** — bursts, coordinated scans, staged sequences
  that only become visible as time-series patterns.

The worker writes scored findings to a dedicated Elasticsearch index
(`ml-anomalies`) and the dashboard Go server exposes them via a new API
endpoint, rendering them as a live panel.

**Out of scope for v1:** Supervised classification (requires labelled data).
All v1 models are **unsupervised** — they learn from the live stream with no
ground-truth labels. [web:275][web:283]

---

## 2. Data Sources

The worker ingests from all existing Elasticsearch indices:

| Index pattern | Source | Key fields |
|---------------|--------|------------|
| `cowrie-*` | Cowrie SSH/Telnet honeypot | `src_ip`, `username`, `password`, `command`, `timestamp`, `session` |
| `dionaea-*` | Dionaea multi-protocol honeypot | `src_ip`, `dst_port`, `proto`, `payload_hex`, `timestamp` |
| `honeypot-network-*` | Zeek + Suricata (Filebeat) | `conn.*`, `dns.*`, `http.*`, `tls.*`, `alert.signature` |
| `conpot-*` | Conpot ICS honeypot | `src_ip`, `proto`, `request`, `timestamp` |
| `http-honeypot-*` | HTTP honeypot | `src_ip`, `method`, `uri`, `user_agent`, `timestamp` |

All indices share a common `@timestamp` field used for temporal ordering.

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Honeypot Stack (existing)                                      │
│  Cowrie · Dionaea · Conpot · Zeek/Suricata · HTTP-honeypot      │
│                        │                                        │
│                  Elasticsearch                                  │
│              (indices: cowrie-*, dionaea-*, ...)                │
└────────────────────────┬────────────────────────────────────────┘
                         │  poll every N seconds (scroll API)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│  ML Worker (ml-worker/)                                         │
│                                                                 │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │ Ingestor         │  │ Feature Engineer │  │ Model Engine │  │
│  │ (ES scroll poll) │→ │ (per-source      │→ │              │  │
│  │                  │  │  normalisation)  │  │ IsoForest    │  │
│  └──────────────────┘  └──────────────────┘  │ LSTM-AE      │  │
│                                               │ HBOS         │  │
│  ┌──────────────────┐                         └──────┬───────┘  │
│  │ Model Store      │◄────────── periodic retrain ───┘          │
│  │ (joblib / .pt)   │                                │           │
│  └──────────────────┘                         ┌──────▼───────┐  │
│                                               │ Scorer       │  │
│                                               │ anomaly_score│  │
│                                               │ + explanation│  │
│                                               └──────┬───────┘  │
└──────────────────────────────────────────────────────┼──────────┘
                                                       │ write findings
                                                       ▼
                                           ┌─────────────────────┐
                                           │ ES index:           │
                                           │ ml-anomalies        │
                                           └──────────┬──────────┘
                                                      │
                                           ┌──────────▼──────────┐
                                           │ Dashboard (Go)      │
                                           │ GET /api/ml/anomalies│
                                           │ SSE stream push     │
                                           └──────────┬──────────┘
                                                      │
                                           ┌──────────▼──────────┐
                                           │ Dashboard UI        │
                                           │ ML Anomalies panel  │
                                           └─────────────────────┘
```

---

## 4. ML Models Selected

Three complementary unsupervised models run in parallel — each catches
different anomaly types: [web:275][web:276][web:283][web:292]

### 4.1 Isolation Forest (IsoForest)

- **What it detects:** Point anomalies — single events that are statistically
  isolated from the mass of observed events.
- **Why:** Low computational cost, no distribution assumptions, works well with
  mixed numerical+categorical features after encoding. Proven on network
  logs. [web:276][web:290]
- **Implementation:** `scikit-learn` `IsolationForest` with `contamination=0.01`
  (assume 1% of events are anomalous). Retrained every 6 hours on a 24h
  rolling window.
- **Output:** `anomaly_score` ∈ [-1, 0] where values closer to -1 = more anomalous.

### 4.2 LSTM Autoencoder (LSTM-AE)

- **What it detects:** Temporal/sequential anomalies — sequences of events
  that deviate from learned normal attack patterns over time windows.
- **Why:** Captures time-varying behaviour that point models miss, e.g. a
  slow-scan campaign spread over hours, or a multi-stage attack sequence.
  CNN-BiLSTM-AE achieves 98.1% accuracy on network intrusion detection. [web:292]
- **Implementation:** PyTorch bidirectional LSTM autoencoder. Input: 15-event
  rolling windows per source IP. Anomaly = reconstruction loss above threshold.
- **Output:** `reconstruction_loss` — normalised to [0, 1] anomaly score.

### 4.3 HBOS (Histogram-Based Outlier Score)

- **What it detects:** Per-feature distribution anomalies — e.g. a port
  that receives traffic only once in 10,000 sessions, or a country seen
  for the first time.
- **Why:** Extremely fast, interpretable (identifies which feature caused
  the anomaly), no training convergence required. [web:291]
- **Implementation:** `pyod` library `HBOS`. Run per-index as a lightweight
  first-pass filter before the heavier LSTM-AE.
- **Output:** `hbos_score` — higher = more anomalous (normalised to [0, 1]).

### 4.4 Ensemble Scoring

Final `composite_score` = weighted combination:

```
composite_score = 0.4 × norm(IsoForest) + 0.4 × LSTM_AE + 0.2 × HBOS
```

Only events with `composite_score ≥ 0.75` are written to `ml-anomalies` and
shown on the dashboard (tunable via `ML_ALERT_THRESHOLD` env var).

`worker.py`'s `compute_composite()` is the single source of truth for this
formula (#63) — previously duplicated verbatim at both call sites (the main
loop's threshold gate and `write_anomaly()`'s own recomputation), a silent
drift risk on any future weight tuning.

---

## 5. Feature Engineering

### 5.1 Per-Event Features (IsoForest / HBOS)

| Feature | Source | Encoding |
|---------|--------|----------|
| `hour_of_day` | `@timestamp` | int 0–23 |
| `day_of_week` | `@timestamp` | int 0–6 |
| `src_country_enc` | GeoIP → country code | label encode |
| `dst_port` | Zeek / Dionaea | int |
| `proto_enc` | `tcp/udp/icmp` | one-hot |
| `session_duration_s` | Cowrie `duration` | float |
| `cmd_count` | Cowrie commands per session | int |
| `payload_entropy` | Shannon entropy of payload bytes | float 0–8 |
| `payload_len` | bytes | int |
| `username_len` | Cowrie login attempt | int |
| `password_entropy` | Shannon entropy of password chars | float |
| `failed_logins_1h` | rolling count per src_ip | int |
| `unique_ports_1h` | distinct ports per src_ip last hour | int |
| `is_tor_exit` | static Tor exit node list | bool |
| `is_known_scanner` | Shodan/Censys/ZoomEye ASN list | bool |

### 5.2 Temporal Sequence Features (LSTM-AE)

For each `src_ip`, build a sliding window of the last 15 events:

```python
# Each timestep t in the window:
[
  hour_of_day,         # periodicity
  dst_port_norm,       # port / 65535
  proto_enc,           # 0=tcp, 1=udp, 2=icmp
  payload_entropy,     # 0-8 normalised
  inter_arrival_log,   # log(seconds since prev event from same IP)
  cmd_count_norm,      # commands / max_observed
]
# Shape: (batch, 15, 6)
```

**Implementation status (#63):** `models/lstm_autoencoder.py`'s
`featurise_temporal(src, inter_arrival_s)` builds this vector against the
real schema in §5.3 (reusing `models/isolation_forest.py`'s field readers),
not a flat schema. `payload_entropy` and `cmd_count_norm` stay at documented
neutral defaults for the same reason §5.1's `extract_features()` leaves them
unwired — no sensor emits a consistent raw-payload field or a real
per-session command counter. `inter_arrival_log` is real: `LSTMAEModel`
tracks last-seen-per-`src_ip` state (`_last_seen`) both online (`score()`)
and during batch retraining (`retrain()`, sorted by `@timestamp` per IP so
the computed deltas match what online scoring would have seen).

`LSTMAEModel.score(src)` takes the raw ES `_source` dict directly (the same
contract as `IsoForestModel.extract_features()`) — it previously received a
slice of the unrelated 15-dim IsoForest vector, a positional mismatch that
meant no anomaly was ever actually explained by real temporal behavior. It
returns `0.0` before a src_ip's window has `SEQ_LEN` events (real "not
enough history yet") and a bounded-CPU-fallback `0.5` — this codebase's
established neutral-default convention — if inference itself raises, so a
scoring failure can never silently read as "confirmed normal".

`retrain()` is bounded by `MAX_TRAIN_WINDOWS` (4,000) — mirrors
`MAX_TRAIN_SAMPLES`'s rationale in §5.1: building every overlapping
length-15 window per `src_ip` with no other cap means one IP dominating the
`MAX_TRAIN_SAMPLES`-capped fetch could otherwise produce up to ~20,000
overlapping windows in a single CPU fine-tune cycle. Capping states the
worst case instead of leaving it to emerge from whatever the busiest
attacker happened to send that day.

### 5.3 Real Document Schema Contract (#62 task 32)

The table above describes intended features; it does not describe where
those values actually live in a real Elasticsearch document. `extract_features()`
currently reads none of it correctly (§1's audit verdict) — every source
nests its data under `honeypot.*`/`source.*`/`network.*`/`event.*`, not at
the top level, and the raw field names differ per sensor.

Ground truth for all 5 sources — real sensor logging source read directly
(not assumed), ingest pipeline (`analysis/elasticsearch-setup.sh`'s
`geoip-honeypot`) read directly for what actually gets ECS-promoted — is in
[`ml-worker/tests/fixtures.py`](../ml-worker/tests/fixtures.py), exercised by
[`ml-worker/tests/test_schema_contract.py`](../ml-worker/tests/test_schema_contract.py).
Summary:

| Source | Index | `event.sensor` | Raw fields live under | ECS-promoted |
|---|---|---|---|---|
| Cowrie | `honeypot-v2-*` | `cowrie` (from `eventid` prefix) | `honeypot.*` (Cowrie's own JSONlog: `src_ip`, `dst_port`, `username`, `password`, `input`, `protocol`, ...) | `source.ip`, `destination.port`, `user.name` — **not** `network.protocol` (Cowrie writes `protocol`, pipeline reads `proto`) |
| Dionaea (connection log) | `honeypot-v2-*` | **unset** — `dionaea.json` has no `sensor`/`eventid` field and the pipeline has no further fallback | `honeypot.*` (`log_json.py`: `src_ip`, `dst_port`, `connection.protocol`, ...) | `source.ip`, `destination.port` — but **unfilterable by `event.sensor:dionaea`** |
| Dionaea (incidents) | `honeypot-v2-*` | `dionaea` (static filebeat field on that input) | `honeypot.message` as an **opaque JSON string** — deliberately not field-parsed (`log_incident.py`'s heterogeneous per-origin shape) | none — no structured fields at all |
| Conpot | `honeypot-v2-*` | `conpot-<variant>` (from the log **file path**, not any field) | `honeypot.*` (`json_log.py`: `src_ip`, `dst_port`, `data_type`, `request`, `response`; no `sensor`, no `proto`) | `source.ip`, `destination.port`, `ot.persona` — **not** `network.protocol` (protocol info is in `data_type`) |
| HTTP honeypot | `honeypot-v2-*` | `http-honeypot` (`honeypot.sensor` set directly, this repo's own `main.go`) | `honeypot.*` (flat: `src_ip`, `username`, `password`, `path`, ...) | `source.ip`, `user.name`, `url.path` — the most complete promotion of the 5 |
| Suricata / network | `suricata-v2-<event_type>-*` | `suricata` | `suricata.eve.*` (standard EVE JSON), **not** `honeypot.*` at all | `source.ip`, `destination.ip`, `destination.port`, `network.transport`, `event.category` |

The Dionaea and Conpot `event.sensor` gaps are ingest-pipeline issues, not
`extract_features()` bugs — `extract_features()` can't fix them, but does
need to read `honeypot.*` directly for these two sources rather than relying
on `event.sensor` filtering to even find them. Filed separately as
[#132](https://github.com/Xore/honeypot-stack/issues/132).

---

## 6. Worker Pipeline

```
loop every POLL_INTERVAL seconds (default: 30s):

  1. Scroll new events from all source indices since last checkpoint
     (checkpoint stored in ES index: ml-worker-state)

  2. Normalise & feature-engineer each event
     → DataFrame of shape (N_events, N_features)

  3. HBOS fast filter:
     → Compute hbos_score for all events
     → Pass only events with hbos_score > 0.5 to next stage
     (reduces LSTM-AE workload by ~80%)

  4. IsoForest score remaining events
     → anomaly_score per event

  5. LSTM-AE temporal scoring:
     → Group filtered events by src_ip
     → Build sliding windows of length 15
     → Compute reconstruction_loss per window

  6. Compute composite_score per event

  7. Write events with composite_score ≥ ML_ALERT_THRESHOLD
     to ES index: ml-anomalies
     with fields: source_event_id, source_index, composite_score,
                  model_scores{}, feature_contributions{},
                  explanation, src_ip, @timestamp, severity

  8. Emit SSE notification to dashboard via Redis pub/sub channel
     'ml-anomaly-events'

  9. Update checkpoint in ml-worker-state

  10. Sleep POLL_INTERVAL

Every 6 hours (RETRAIN_INTERVAL):
  - Retrain IsoForest + HBOS on last 24h of all events
  - Fine-tune LSTM-AE on last 24h (5 epochs, low LR)
  - Save new model checkpoint to /models/
  - Log retraining metrics to ES index: ml-worker-metrics
```

---

## 7. Elasticsearch Index Design

### `ml-anomalies` index mapping

```json
{
  "mappings": {
    "properties": {
      "@timestamp":            { "type": "date" },
      "source_event_id":       { "type": "keyword" },
      "source_index":          { "type": "keyword" },
      "src_ip":                { "type": "ip" },
      "src_country":           { "type": "keyword" },
      "composite_score":       { "type": "float" },
      "severity":              { "type": "keyword" },
      "model_scores": {
        "properties": {
          "isolation_forest":   { "type": "float" },
          "lstm_ae":            { "type": "float" },
          "hbos":               { "type": "float" }
        }
      },
      "feature_contributions": { "type": "object", "enabled": false },
      "explanation":           { "type": "text" },
      "event_type":            { "type": "keyword" },
      "dst_port":              { "type": "integer" },
      "proto":                 { "type": "keyword" }
    }
  }
}
```

**Severity mapping:**

| composite_score | severity |
|-----------------|----------|
| 0.75 – 0.85 | `medium` |
| 0.85 – 0.95 | `high` |
| ≥ 0.95 | `critical` |

### `ml-worker-state` index

Stores per-index scroll checkpoints (last processed `@timestamp`) so the
worker resumes cleanly after a restart without reprocessing old events.

---

## 8. Dashboard API Contract

New endpoints to add to `dashboard/main.go`:

```
GET  /api/ml/anomalies
     Query params: limit (default 50), severity, since (ISO timestamp)
     Response: JSON array of ml-anomaly documents

GET  /api/ml/anomalies/stream
     SSE stream — pushes new ml-anomaly documents in real time
     via Redis pub/sub → dashboard SSE (matches existing stream.go pattern)

GET  /api/ml/stats
     Response: { total_anomalies_24h, by_severity, top_src_ips,
                 model_last_retrained, events_processed_total }
```

Response document format:

```json
{
  "@timestamp": "2026-07-26T14:00:00Z",
  "src_ip": "1.2.3.4",
  "src_country": "CN",
  "composite_score": 0.91,
  "severity": "high",
  "explanation": "Unusual port scan pattern: 47 unique ports in 60s from new ASN. Payload entropy 7.8 (max observed: 4.2). First seen from this /24 subnet.",
  "model_scores": {
    "isolation_forest": 0.88,
    "lstm_ae": 0.94,
    "hbos": 0.82
  },
  "feature_contributions": {
    "unique_ports_1h": 0.41,
    "payload_entropy": 0.33,
    "src_country_enc": 0.26
  },
  "source_index": "honeypot-network-2026.07.26",
  "event_type": "conn",
  "dst_port": 8545
}
```

---

## 9. Dashboard UI Integration

Add a new **"ML Anomalies"** panel to the existing dashboard `page.go` /
frontend:

### 9.1 Panel Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  🤖 ML Anomaly Detection                    [last retrained: 2h]│
├──────────┬─────────────────────────────────────────────────────┤
│ CRITICAL │ Composite Score │ Source IP   │ Explanation (truncated)│
│ 0.96     │ ████████████    │ 45.33.12.7  │ 47 unique ports/60s...│
│ HIGH     │ 0.91            │ 218.92.0.11 │ LSTM reconstruction...│
│ HIGH     │ 0.88            │ 91.108.4.1  │ New payload entropy...│
├──────────┴─────────────────────────────────────────────────────┤
│  24h trend: ▁▁▁▂▃▅▆███▆▃▁▁▁▂  │ By severity: 🔴2 🟠14 🟡31  │
└─────────────────────────────────────────────────────────────────┘
```

### 9.2 New Go file: `dashboard/ml_anomalies.go`

Responsible for:
- Querying `ml-anomalies` ES index
- Serving `/api/ml/anomalies` and `/api/ml/stats`
- Connecting to Redis channel `ml-anomaly-events` and forwarding to the
  existing SSE `stream.go` infrastructure
- Rendering the panel template section (matching existing `page.go` style)

---

## 10. Docker Compose Integration

**Rewritten 2026-07-31 (#62).** ml-worker is its own Dockge stack now, not a
service folded into the root `docker-compose.yml`, and the file this section
used to show (`ml-worker/docker-compose.override.yml`, built against a
network named `analysis-net` that never existed anywhere in this
repository — [#61](https://github.com/Xore/honeypot-stack/issues/61)) has
been deleted, not patched. The real files:

- [`ml-worker/docker-compose.yml`](../ml-worker/docker-compose.yml) — the
  CPU-safe base. Joins `honeynet` as an **external** network (the same
  pattern `docker-compose.init.yml` uses, `external: true`, since
  `docker-compose.yml` creates `honeynet` with a fixed, non-project-prefixed
  name precisely so a second stack can attach to it) — ml-worker has to read
  Elasticsearch continuously, unlike `analysis/ghidra/`'s stack, which is
  deliberately loopback-only with no honeynet access because it only ever
  receives samples over a file spool.
- [`ml-worker/docker-compose.ml-worker.gpu.yml`](../ml-worker/docker-compose.ml-worker.gpu.yml) —
  an inert GPU overlay in the same shape as
  `analysis/ghidra/docker-compose.ghidra.gpu.yml` (device reservation only).
  Isolation Forest and HBOS stay CPU-only regardless; nothing in the
  worker's code path uses CUDA until Milestone H
  ([#67](https://github.com/Xore/honeypot-stack/issues/67)), which itself
  requires a measured CPU baseline from this milestone first. Whether that
  phase shares the ghidra stack's `ollama` instance for embeddings or gets
  its own is #67's decision, not assumed here.

No Redis in the base stack. `ml-gpu-coordinated-roadmap.md` §1 decision 1:
Elasticsearch is the initial dashboard transport, and Redis/SSE is added only
if polling cost and latency are measured and shown to be insufficient — see
[#64](https://github.com/Xore/honeypot-stack/issues/64). Do not copy a
network name or a Redis dependency out of this document into a compose file;
read the actual files above.

---

## 11. Model Lifecycle & Retraining

```
Cold start (no data yet):
  → IsoForest / HBOS initialised with synthetic "normal" baseline
    drawn from public honeypot datasets (KDD99, UNSW-NB15 benign subset)
  → LSTM-AE initialised with random weights, warm-up period 2h

Online learning (continuous):
  → HBOS histograms updated incrementally every poll cycle (no refit needed)
  → IsoForest: full retrain every 6h on rolling 24h window
  → LSTM-AE: online fine-tune every 6h (5 epochs, LR=1e-5)

Model versioning:
  → Each retrain writes: /models/isoforest_{timestamp}.joblib
                          /models/lstm_ae_{timestamp}.pt
                          /models/hbos_{timestamp}.joblib
  → Symlinks /models/current/* always point to the active version
  → Last 3 versions retained for rollback

Drift detection:
  → If the rolling anomaly rate exceeds 15% (model may be seeing novelty
    as normal), trigger early retraining and alert the dashboard
```

---

## 12. Roadmap

| Phase | Milestone | Issue |
|-------|-----------|-------|
| **v0.1** | Scaffold: Dockerfile, worker.py, IsoForest, ES write | [#61](https://github.com/Xore/honeypot-stack/issues/61) |
| **v0.2** | HBOS fast filter + feature engineering for all 5 sources | [#62](https://github.com/Xore/honeypot-stack/issues/62) |
| **v0.3** | LSTM-AE temporal model + sequence windowing | [#63](https://github.com/Xore/honeypot-stack/issues/63) |
| **v0.4** | Composite scoring + explanation generation | [#63](https://github.com/Xore/honeypot-stack/issues/63) |
| **v0.5** | Redis pub/sub → dashboard SSE integration | [#64](https://github.com/Xore/honeypot-stack/issues/64) |
| **v0.6** | `dashboard/ml_anomalies.go` + API endpoints | [#64](https://github.com/Xore/honeypot-stack/issues/64) |
| **v0.7** | Dashboard UI panel | [#64](https://github.com/Xore/honeypot-stack/issues/64) |
| **v0.8** | Retraining scheduler + model versioning | [#65](https://github.com/Xore/honeypot-stack/issues/65) |
| **v1.0** | Drift detection + alert threshold tuning UI | [#65](https://github.com/Xore/honeypot-stack/issues/65) |

v0.1 is listed as an issue rather than as done on purpose. `ml-worker/` holds a
Dockerfile, `worker.py`, and a `docker-compose.override.yml`, but it is not a
service in the root Compose file, it has no tests or fixtures, and nothing here
has been observed running against live data. #61 is the audit that decides
whether the scaffold is a v0.1 or a starting point.

**The audit is done, and the answer is starting point.** `ml-worker/` does not
build, would not see any real data if it did (wrong index patterns, wrong
document schema), and its temporal model trains on one feature vector and
scores on a different, incompatible one. See the status callout at the top of
this document and issue #61 for the evidence. `ml-worker/tests/` now exists
and every finding is an executable test, which is the fixture/test deliverable
Milestone B step 2 asks for — but the modularization Milestone B actually
requires (splitting config/ES-access/normalization/features/models/
persistence/orchestration into testable units, fixtures for all five sources,
corrected temporal features) has not been done. That is real, separate work
from this audit.

Read [`ml-gpu-coordinated-roadmap.md`](ml-gpu-coordinated-roadmap.md) before
starting any of these. It supersedes this plan's sequencing and records
corrections to the design below — notably that timestamp-only checkpoints are
not safe, that clipped model scores must not be treated as probabilities, and
that the `0.75` threshold in §4.4 is an assumption rather than a measurement.

---

## References

- Isolation Forest for network anomaly detection: [siForest (arXiv 2024)](https://arxiv.org/pdf/2412.06015.pdf) [web:276]
- LSTM Autoencoder IDS: [CNN-BiLSTM-AE, MDPI 2025, 98.1% F1](https://www.mdpi.com/2079-9692/14/14/2779) [web:292]
- Fusion model (IsoForest + deep learning): [arXiv 2024](https://arxiv.org/pdf/2407.05639.pdf) [web:275]
- HBOS in log anomaly detection: [Comparative study 2025](https://www.scitepress.org/Papers/2025/133670/133670.pdf) [web:291]
- Isolation Forest for web traffic: [MDPI Informatics 2024](https://www.mdpi.com/2227-9709/11/4/83) [web:290]
- See also: [`docs/kvm-network-traffic-analysis.md`](kvm-network-traffic-analysis.md)
