# ML Worker — Implementation Plan

> **Status:** Design document. `ml-worker/` is a scaffold that is not wired into
> Compose and has never been observed running; the dashboard has no
> `/api/ml/anomalies` endpoint and no `ml_anomalies.go`. Everything below
> describes the intended system, not the built one.  
> **Worker location:** [`ml-worker/`](../ml-worker/)  
> **Tracked in:** [#61](https://github.com/Xore/honeypot-stack/issues/61)–[#65](https://github.com/Xore/honeypot-stack/issues/65)
> — see the roadmap table in §12.
>
> **v0.1 audit verdict (#61, 2026-07-31): not runnable, evidenced.**
> `docker build ./ml-worker` fails outright (`pyod`'s `numba` dependency has
> no version compatible with the pinned `numpy==2.5.1` on Python 3.12 —
> reproduced twice, locally and in-container). Even past that, `worker.py`'s
> `SOURCE_INDICES` (`cowrie-*`, `dionaea-*`, `honeypot-network-*`, `conpot-*`,
> `http-honeypot-*`) match zero indices on the live homeserver: the real
> shape is a unified `honeypot-v2-*` stream (all sensors, disambiguated by
> `event.sensor`) plus `suricata-v2-<type>-*`. And `extract_features()` reads
> flat top-level fields that don't exist in a real document — sensor data is
> nested under `honeypot.*`/`source.*`/`network.*`. Six more defects (three
> already flagged in `ml-gpu-coordinated-roadmap.md` §1, three new) are
> proven executably in `ml-worker/tests/test_worker_audit.py`. Full writeup:
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

The ML worker runs as a Docker service on the stack's internal network. That
network is **`honeynet`**. Earlier revisions of this section said `analysis-net`,
a name that came from the four-zone topology in
[`honeypot-network-isolation.md`](honeypot-network-isolation.md) and never
existed in `docker-compose.yml`; `ml-worker/docker-compose.override.yml` was
written against it and is broken as a result —
[#61](https://github.com/Xore/honeypot-stack/issues/61). Do not copy a network
name out of this document into a compose file; read `docker-compose.yml`.

```yaml
# ml-worker/docker-compose.override.yml
services:
  ml-worker:
    build: ./ml-worker
    restart: unless-stopped
    networks: [honeynet]
    depends_on: [elasticsearch, redis]
    volumes:
      - ml-models:/models
    environment:
      - ES_HOST=http://elasticsearch:9200
      - REDIS_URL=redis://redis:6379/0
      - POLL_INTERVAL=30
      - RETRAIN_INTERVAL=21600
      - ML_ALERT_THRESHOLD=0.75
      - LOG_LEVEL=INFO
    security_opt:
      - no-new-privileges:true
    cap_drop: [ALL]
    read_only: true
    tmpfs:
      - /tmp

volumes:
  ml-models:
```

**Redis** is added to the stack as a lightweight pub/sub broker between the
ML worker and the dashboard SSE stream. It requires one additional service
entry in the main `docker-compose.yml`:

```yaml
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    networks: [honeynet]
    command: redis-server --save "" --appendonly no
    cap_drop: [ALL]
```

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
