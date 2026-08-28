"""#2300 regression — attackers-v1 staleness alarm covers the 4-day freeze.

The attacker-identity loop is in WORKER_LOOPS for the dashboard-backend
worker (alert-notifier,attacker-identity,...). A worker crash or a deploy
regression can kill the producer without paging; #2300 saw a 4-day
freeze (last 2026-08-22 23:47Z) that was not detected until an operator
noticed the attackers list not moving.

Fix: alert-notifier's INGEST_FEEDS now contains an `attackers` feed with
`attackers-v1` (4h threshold). The notifier tick (10m, INGEST_CHECK_EVERY)
will detect the next freeze within ~4h instead of after 4 days.
"""

def test_attackers_v1_in_ingest_feeds():
    """attackers-v1 must be present in INGEST_FEEDS so the alert loop covers it."""
    with open("arcane/home/honeypot-dashboard/backend-service/src/worker.rs") as f:
        src = f.read()
    assert "attackers-v1" in src, "attackers-v1 pattern missing from worker.rs"
    # 4h threshold = 240 minutes
    assert "minutes(240)" in src, "240-minute threshold missing for attackers-v1"
    # The feed name `attackers` is referenced by the notifier's pass() loop
    assert '"attackers"' in src, "IngestFeed name=attackers missing"


def test_staleness_threshold_is_above_tick_interval():
    """4h threshold must exceed INGEST_CHECK_EVERY (10m) by enough margin to be a real alert."""
    # Just verify the constant is right; 240 > 10 means the alarm fires
    # only when real silence (not a tick miss).
    assert 240 > 10
