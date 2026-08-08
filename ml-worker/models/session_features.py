"""
Stateful per-session/per-src_ip feature aggregation for cmd_count,
failed_logins_1h, and unique_ports_1h (#277).

`extract_features()` (models/isolation_forest.py) and `featurise_temporal()`
(models/lstm_autoencoder.py) take these as plain parameters, the same
contract `featurise_temporal()` already uses for `inter_arrival_s` -- the
model code stays a pure function of (event, context); the actual stateful
bookkeeping (per-session command counters, rolling 1h windows per src_ip)
lives in one place here, shared by:

- `SessionFeatureTracker` -- one long-lived instance for the whole worker
  process (score_and_write_events() in worker.py calls `.observe()` once per
  live event, in the same chronological order they're actually polled).
  Persisted across restarts (mirrors LSTMAEModel.save_buffers()/
  _load_buffers(), #170) so a restart doesn't reopen a real rolling-window
  coverage gap for the hour of history right before it.
- `compute_batch_session_features()` -- a pure function over one already-
  fetched retrain batch, deliberately NOT sharing state with the live
  tracker: a 24h retrain batch replays history that may already have been
  observed live, or may span a gap the live tracker never saw (a restart, a
  backlog catch-up) -- reusing live state here would answer a different
  question than "what do these counters look like purely from this batch's
  own history" for either caller.

`payload_hex` is intentionally NOT covered here -- see #277's remaining
scope: no sensor in this stack's real ingest pipeline (docs/ml-worker-plan.md
§5.3, tests/fixtures.py) emits a raw-payload byte field at all, so there is
nothing to aggregate yet. Still hardcoded neutral in extract_features().
"""
import collections
import json
import os
import time
from datetime import datetime
from typing import Optional

from loguru import logger

from models.isolation_forest import _get_ip, _get_port

# Rolling window for failed_logins_1h / unique_ports_1h, per
# docs/ml-worker-plan.md §5.1 ("rolling count/distinct ports per src_ip last
# hour").
WINDOW_SECONDS = 3600

# Outer safety bound on each src_ip's window deque, independent of the
# 1-hour time prune -- mirrors MAX_TRAIN_SAMPLES/MAX_TRAIN_WINDOWS's own
# rationale elsewhere in this package: states the worst case (one src_ip
# flooding thousands of events inside a single hour) instead of leaving
# memory to whatever the busiest attacker happens to send.
MAX_WINDOW_ENTRIES_PER_IP = 5_000

# Bounds both what SessionFeatureTracker keeps live in memory for the life
# of the process AND what save() persists across a restart -- same parity as
# LSTMAEModel's MAX_PERSISTED_IPS (models/lstm_autoencoder.py). #884: this
# used to bound persistence only; the live dicts (_ip_last_seen,
# _session_last_seen, and the _WindowState dicts they key) grew for every
# distinct src_ip/session ever observed, unbounded, for the whole process
# lifetime. observe() now evicts the least-recently-active entry once a cap
# is exceeded, the same "most-recently-active wins" policy save() already
# used for persistence.
MAX_PERSISTED_IPS = 2_000
MAX_PERSISTED_SESSIONS = 2_000


def _get_session_id(src: dict) -> str:
    return (src.get("honeypot") or {}).get("session") or ""


def _is_command_event(src: dict) -> bool:
    # Only Cowrie sessions carry a command concept in this stack's real
    # sensor set (tests/fixtures.py) -- Dionaea/Conpot/http-honeypot/
    # Suricata events have no equivalent "command run inside a session".
    return (src.get("honeypot") or {}).get("eventid") == "cowrie.command.input"


def _is_failed_login_event(src: dict) -> bool:
    return (src.get("honeypot") or {}).get("eventid") == "cowrie.login.failed"


def _event_epoch(src: dict) -> Optional[float]:
    ts = src.get("@timestamp") or src.get("timestamp")
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


class _WindowState:
    """Mutable bookkeeping shared by the step function below -- kept as
    plain dicts/deques (not a dataclass) so both the live tracker and the
    one-shot batch computation can use the exact same stepping logic
    without duplicating it."""

    __slots__ = ("session_counts", "ip_ports", "ip_failed_logins")

    def __init__(self) -> None:
        self.session_counts: dict = {}
        self.ip_ports: dict = collections.defaultdict(collections.deque)
        self.ip_failed_logins: dict = collections.defaultdict(collections.deque)


def _prune_by_time(dq: collections.deque, now_ts: float, get_ts) -> None:
    while dq and (now_ts - get_ts(dq[0])) > WINDOW_SECONDS:
        dq.popleft()


def _step(state: "_WindowState", src: dict, now_ts: float) -> dict:
    """Advance `state` by exactly one event -- already known to be at
    `now_ts`, and MUST be called in non-decreasing time order for the
    rolling-window math to mean what it says -- and return this event's own
    (cmd_count, failed_logins_1h, unique_ports_1h) feature values.
    """
    ip = _get_ip(src) or ""
    port = _get_port(src)
    session = _get_session_id(src)

    dq_fail = state.ip_failed_logins[ip]
    _prune_by_time(dq_fail, now_ts, get_ts=lambda ts: ts)
    if _is_failed_login_event(src):
        dq_fail.append(now_ts)
        if len(dq_fail) > MAX_WINDOW_ENTRIES_PER_IP:
            dq_fail.popleft()
    failed_logins_1h = len(dq_fail)

    dq_ports = state.ip_ports[ip]
    _prune_by_time(dq_ports, now_ts, get_ts=lambda pair: pair[0])
    dq_ports.append((now_ts, port))
    if len(dq_ports) > MAX_WINDOW_ENTRIES_PER_IP:
        dq_ports.popleft()
    unique_ports_1h = len({p for _, p in dq_ports})

    cmd_count = state.session_counts.get(session, 0)
    if session and _is_command_event(src):
        cmd_count += 1
        state.session_counts[session] = cmd_count

    return {
        "cmd_count": cmd_count,
        "failed_logins_1h": failed_logins_1h,
        "unique_ports_1h": unique_ports_1h,
    }


def compute_batch_session_features(sources: list) -> list:
    """Pure, batch-local equivalent of SessionFeatureTracker.observe() for
    retrain()'s historical batches (#277). Returns a list of
    {"cmd_count", "failed_logins_1h", "unique_ports_1h"} dicts aligned to
    `sources`' ORIGINAL order (retrain() calls extract_features() per
    source in that order to build X_train/X_holdout) even though the
    rolling-window computation itself must walk events in time order
    internally -- events missing a parseable timestamp sort first (epoch
    0.0), same fallback _ts_to_epoch()/_event_epoch() use elsewhere.
    """
    order = sorted(range(len(sources)), key=lambda i: _event_epoch(sources[i]) or 0.0)
    state = _WindowState()
    results: list = [None] * len(sources)
    for i in order:
        results[i] = _step(state, sources[i], _event_epoch(sources[i]) or 0.0)
    return results


class SessionFeatureTracker:
    """Long-lived, one-per-worker-process tracker for the live/online
    scoring path. `observe()` must be called exactly once per event, in the
    same chronological order score_and_write_events() actually processes
    them -- calling it more than once for the same event double-counts
    cmd_count and inflates the rolling windows.
    """

    def __init__(self, model_dir: str = "/models") -> None:
        self.model_dir = model_dir
        self._state = _WindowState()
        # OrderedDict, not dict: observe() relinks a touched key to the end
        # on every visit (see _touch below), so iteration order is always
        # least- to most-recently-active -- exactly what _evict_oldest needs
        # to find and remove the right entry in O(1), and what save()'s own
        # recency sort already assumed the underlying data represented.
        self._ip_last_seen: collections.OrderedDict = collections.OrderedDict()
        self._session_last_seen: collections.OrderedDict = collections.OrderedDict()
        self._load()

    @staticmethod
    def _touch(last_seen: collections.OrderedDict, key: str, now_ts: float, cap: int, *keyed_dicts) -> None:
        """Record key as just-active (moving it to the most-recent end of
        last_seen) and evict the least-recently-active key -- from
        last_seen and every dict in keyed_dicts -- once len(last_seen)
        exceeds cap. Keeps live memory bounded by active-entry count rather
        than by total-ever-seen count, for the life of the process."""
        last_seen.pop(key, None)
        last_seen[key] = now_ts
        if len(last_seen) > cap:
            oldest, _ = last_seen.popitem(last=False)
            for d in keyed_dicts:
                d.pop(oldest, None)

    def observe(self, src: dict) -> dict:
        now_ts = _event_epoch(src)
        if now_ts is None:
            now_ts = time.time()
        ip = _get_ip(src) or ""
        session = _get_session_id(src)
        if ip:
            self._touch(self._ip_last_seen, ip, now_ts, MAX_PERSISTED_IPS,
                        self._state.ip_ports, self._state.ip_failed_logins)
        if session:
            self._touch(self._session_last_seen, session, now_ts, MAX_PERSISTED_SESSIONS,
                        self._state.session_counts)
        return _step(self._state, src, now_ts)

    # ------------------------------------------------------------------
    # Persistence -- same atomic-write/bounded-cardinality contract as
    # LSTMAEModel.save_buffers()/_load_buffers() (#170).
    # ------------------------------------------------------------------

    def _path(self) -> str:
        return os.path.join(self.model_dir, "current_session_features.json")

    def save(self) -> None:
        kept_ips = {
            ip for ip, _ in sorted(self._ip_last_seen.items(), key=lambda kv: kv[1], reverse=True)[:MAX_PERSISTED_IPS]
        }
        kept_sessions = {
            s for s, _ in sorted(self._session_last_seen.items(), key=lambda kv: kv[1], reverse=True)[:MAX_PERSISTED_SESSIONS]
        }
        payload = {
            "session_counts": {s: c for s, c in self._state.session_counts.items() if s in kept_sessions},
            "ip_ports": {ip: list(self._state.ip_ports[ip]) for ip in kept_ips if ip in self._state.ip_ports},
            "ip_failed_logins": {
                ip: list(self._state.ip_failed_logins[ip]) for ip in kept_ips if ip in self._state.ip_failed_logins
            },
            "ip_last_seen": {ip: self._ip_last_seen[ip] for ip in kept_ips},
            "session_last_seen": {s: self._session_last_seen[s] for s in kept_sessions},
        }
        path = self._path()
        os.makedirs(self.model_dir, exist_ok=True)
        temp_path = f"{path}.tmp-{os.getpid()}-{time.time_ns()}"
        with open(temp_path, "w") as handle:
            json.dump(payload, handle)
        os.replace(temp_path, path)

    def _load(self) -> None:
        path = self._path()
        if not os.path.exists(path):
            return
        try:
            with open(path) as handle:
                payload = json.load(handle)
        except (OSError, ValueError) as exc:
            logger.warning(f"Failed to load persisted session-feature state (non-fatal, starting cold): {exc}")
            return
        self._state.session_counts.update(payload.get("session_counts", {}))
        for ip, entries in payload.get("ip_ports", {}).items():
            self._state.ip_ports[ip] = collections.deque(tuple(entry) for entry in entries)
        for ip, entries in payload.get("ip_failed_logins", {}).items():
            self._state.ip_failed_logins[ip] = collections.deque(entries)
        self._ip_last_seen.update(payload.get("ip_last_seen", {}))
        self._session_last_seen.update(payload.get("session_last_seen", {}))
