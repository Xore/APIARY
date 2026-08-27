"""#2219 pagination contracts: Keycloak caps every admin-events response at
`max` rows and truncates silently -- HTTP 200, a valid JSON array, nothing
on the wire admitting anything is missing. The single-page fetch dropped
everything past row 1,000 on any busy day (exactly a credential-spray burst
against the SSO front door), fenced that tail behind the watermark forever,
and stayed green throughout.

These tests drive fetch_login_errors through a stubbed HTTP layer standing
in for requests.get (same shape of stub llm-worker's tests/* use: no live
service behind them) and pin four behaviors:

1. a day larger than the page cap drains completely, walking `first`
   forward until a short page arrives;
2. completeness never depends on which end of the day Keycloak orders
   from, nor on window disjointness -- identity comes from event id -> ES
   _id overwrite downstream;
3. a misbehaving server that clamps every request to the same window hits
   the runaway bound: stop loudly, report drained=False, do NOT spin;
4. collect_new_events walks days strictly ascending and halts at the first
   incompletely-drained one, so the checkpoint can never sprint past a gap.
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import worker  # noqa: E402

PAGE_SIZE = 1000


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def synth_day(day_iso: str, count: int) -> list:
    """A synthetic LOGIN_ERROR array for one UTC day: stable unique ids,
    strictly increasing epoch-millis times inside that day."""
    base = int(datetime.fromisoformat(day_iso).replace(tzinfo=timezone.utc).timestamp() * 1000)
    return [{"id": f"{day_iso}-{i:06d}", "time": base + i * 1000, "type": "LOGIN_ERROR"} for i in range(count)]


class FakeKeycloak:
    """Serves `{dateFrom: events}` slicing `[first:first+max]` -- whichever
    order its stored lists carry -- and records every page request."""

    def __init__(self, days: dict):
        self.days = days
        self.calls: list[dict] = []

    def get(self, url, params=None, headers=None, timeout=None):
        params = dict(params or {})
        self.calls.append(params)
        events = self.days.get(params["dateFrom"], [])
        first = int(params.get("first", 0))
        window = events[first : first + int(params["max"])]
        return FakeResponse(window)


class ClampedServer(FakeKeycloak):
    """Misbehaviour stand-in: `first` is ignored, so every request returns
    the same full window regardless of offset."""

    def get(self, url, params=None, headers=None, timeout=None):
        params = dict(params or {})
        self.calls.append(params)
        events = self.days.get(params["dateFrom"], [])
        return FakeResponse(events[: int(params["max"])])


def capture_worker_logs(minimum_level="INFO"):
    logs: list[str] = []

    class _Sink:
        def write(self, message):
            logs.append(message)

        def flush(self):
            pass

    handler_id = worker.logger.add(_Sink(), level=minimum_level)
    return logs, handler_id


@pytest.fixture()
def kc(monkeypatch):
    def install(server):
        monkeypatch.setattr(worker.requests, "get", server.get)
        return server

    yield install


def test_a_day_larger_than_the_cap_drains_completely(kc):
    # 2.5x the documented cap: the case the single-page fetch silently cut
    # off at row 1,000 forever.
    day = "2026-08-20"
    server = kc(FakeKeycloak({day: synth_day(day, 2500)}))

    events, drained = worker.fetch_login_errors("token", day, page_size=PAGE_SIZE, max_pages=50)

    assert drained is True
    assert len(events) == 2500
    assert len({e["id"] for e in events}) == 2500
    # The pager walked `first` deterministically: 1000, then 1000 more,
    # then the short remainder tail.
    assert [int(call["first"]) for call in server.calls] == [0, PAGE_SIZE, 2 * PAGE_SIZE]
    assert all(int(call["max"]) == PAGE_SIZE for call in server.calls)


def test_a_short_first_page_costs_exactly_one_request(kc):
    # The overwhelmingly common shape: one small page, no pager traffic.
    day = "2026-08-21"
    server = kc(FakeKeycloak({day: synth_day(day, 42)}))

    events, drained = worker.fetch_login_errors("token", day, page_size=PAGE_SIZE, max_pages=50)

    assert drained is True
    assert len(events) == 42
    assert len(server.calls) == 1


def test_empty_day_returns_a_single_request_and_stays_quiet(kc):
    # A short-but-empty first page still terminates the walk correctly --
    # no day-of-nothing should ever reach the runaway bound.
    day = "2026-08-22"
    server = kc(FakeKeycloak({}))

    events, drained = worker.fetch_login_errors("token", day, page_size=PAGE_SIZE, max_pages=50)

    assert drained is True
    assert events == []
    assert len(server.calls) == 1


def test_completeness_does_not_depend_on_keycloaks_return_order(kc):
    # Served newest-first (reversed): the pager must not assume ascending
    # timestamps from the API -- the union across `first` offsets has to
    # cover every event regardless. Downstream dedup relies on ids, not
    # positions, so overlap between windows would be harmless too.
    day = "2026-08-23"
    events_in_day = synth_day(day, 2500)
    server = kc(FakeKeycloak({day: list(reversed(events_in_day))}))

    fetched, drained = worker.fetch_login_errors("token", day, page_size=PAGE_SIZE, max_pages=50)

    assert drained is True
    assert {e["id"] for e in fetched} == {e["id"] for e in events_in_day}


def test_a_clamped_server_hits_the_runaway_bound_instead_of_spinning(kc):
    # Keycloak behaving like a clamp (`first` ignored) used to be invisible:
    # every request looked healthy. Now it stops after the bound, reports
    # loudly, and flags the day undrained.
    day = "2026-08-24"
    server = kc(ClampedServer({day: synth_day(day, 1500)}))
    logs, handler = capture_worker_logs("ERROR")
    try:
        events, drained = worker.fetch_login_errors("token", day, page_size=PAGE_SIZE, max_pages=3)
    finally:
        worker.logger.remove(handler)

    assert drained is False
    assert len(events) == 3 * PAGE_SIZE
    assert len(server.calls) == 3
    joined = "\n".join(str(m) for m in logs)
    assert day in joined
    assert "stopping this day incomplete" in joined


def test_heavy_but_healthy_days_leave_an_audit_line_naming_day_and_count(kc):
    # Even with correct pagination, a day that crossed at least one full
    # page boundary deserves an operator-visible counter (#2219's
    # belt-and-braces ask) so history can be audited for past loss without
    # parsing ES document counts.
    day = "2026-08-25"
    kc(FakeKeycloak({day: synth_day(day, 2500)}))
    logs, handler = capture_worker_logs("WARNING")
    try:
        _, drained = worker.fetch_login_errors("token", day, page_size=PAGE_SIZE, max_pages=50)
    finally:
        worker.logger.remove(handler)

    assert drained is True
    joined = "\n".join(str(m) for m in logs)
    assert day in joined
    assert "2500" in joined
    assert "no truncation" in joined


def test_a_small_day_logs_nothing_at_warning_level(kc):
    day = "2026-08-26"
    kc(FakeKeycloak({day: synth_day(day, 12)}))
    logs, handler = capture_worker_logs("WARNING")
    try:
        _, drained = worker.fetch_login_errors("token", day, page_size=PAGE_SIZE, max_pages=50)
    finally:
        worker.logger.remove(handler)

    assert drained is True
    assert logs == []


def test_collect_new_events_filters_sub_day_and_survives_overlapping_refetches(monkeypatch):
    # Day-granularity dateFrom keeps sub-day precision client-side. The
    # second poll deliberately redelivers yesterday's window (a restart
    # spanned midnight); only events above the new checkpoint may come back,
    # keeping the pipeline duplicate-free via the _id-overwrite contract
    # even though fetch windows overlap by design.
    day = datetime(2026, 8, 26, tzinfo=timezone.utc)
    next_day = day + timedelta(days=1)
    day_events = synth_day(day.date().isoformat(), 30)
    checkpoint = day_events[-1]["time"]
    # Overlapping redelivery: half of yesterday again, plus genuinely new rows.
    refetched_old = day_events[:15]
    fresh_tail = [
        {"id": f"{next_day.date().isoformat()}-{i:06d}",
         "time": checkpoint + 10_000 * (i + 1),
         "type": "LOGIN_ERROR"}
        for i in range(5)
    ]

    def fake_fetch(token, date_from, **kwargs):
        if date_from == day.date().isoformat():
            return refetched_old + fresh_tail[:1], True
        return fresh_tail[1:], True

    monkeypatch.setattr(worker, "fetch_login_errors", fake_fetch)

    all_new, fully_drained = worker.collect_new_events(
        "token", checkpoint, day.date(), next_day.date()
    )

    assert fully_drained is True
    assert [e["id"] for e in all_new] == [e["id"] for e in fresh_tail]


def test_collect_new_events_holds_back_at_an_undrained_day(monkeypatch):
    # The checkpoint-honesty rule: the walk must NOT continue past a day
    # whose pager could not finish, or the missing tail of that day gets
    # fenced behind the watermark forever (the original failure mode).
    start = datetime(2026, 8, 24, tzinfo=timezone.utc).date()
    blocked = start + timedelta(days=1)
    after_block = start + timedelta(days=2)
    requested: list[str] = []
    partial_events = synth_day(blocked.isoformat(), 700)[:700]

    def fake_fetch(token, date_from, **kwargs):
        requested.append(date_from)
        if date_from == start.isoformat():
            return synth_day(start.isoformat(), 50), True
        if date_from == blocked.isoformat():
            return partial_events, False
        raise AssertionError(f"must never request past an undrained day: got {date_from}")

    monkeypatch.setattr(worker, "fetch_login_errors", fake_fetch)

    all_new, fully_drained = worker.collect_new_events(
        "token", 0, start, after_block
    )

    assert fully_drained is False
    assert requested == [start.isoformat(), blocked.isoformat()]
    assert len(all_new) == 50 + 700


def test_multi_day_catchup_fully_drains_every_day_before_the_pager_advances(monkeypatch):
    # The normal restart-after-midnight catchup: three stacked days, all
    # drained, all their events above the checkpoint collected in order.
    start = datetime(2026, 8, 22, tzinfo=timezone.utc).date()
    mid = start + timedelta(days=1)
    last = start + timedelta(days=2)

    def fake_fetch(token, date_from, **kwargs):
        count = {"2026-08-22": 40, "2026-08-23": PAGE_SIZE + 17, "2026-08-24": 9}[date_from]
        return synth_day(date_from, count), True

    monkeypatch.setattr(worker, "fetch_login_errors", fake_fetch)

    all_new, fully_drained = worker.collect_new_events("token", 0, start, last)

    assert fully_drained is True
    assert len(all_new) == 40 + PAGE_SIZE + 17 + 9
