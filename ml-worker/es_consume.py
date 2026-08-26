"""Shared Elasticsearch consume patterns, gpu_queue.py-style.

Deliberately stdlib-only (this module has ZERO imports) so this exact file
can be vendored as-is into any worker's environment, containerized or not --
the same discipline `analysis/gpu-queue/gpu_queue.py` applies for the GPU
queue. Every vendored copy carries a contract test asserting byte-for-byte
equality with this canonical copy (`analysis/es-consume/fixtures` registries
list every copy; `analysis/es-consume/tests/test_es_consume.py` walks the
registry on every CI run).

Two patterns live behind these functions; docs/ES-CONSUME-PATTERNS.md is the
authoritative description of who uses which and why.

Pattern 1 -- incremental-checkpoint consumer (ml-worker's model):

  Each poll cycle resumes from a persisted *total-order* checkpoint
  {"last_timestamp": str, "seen_ids": [ids processed exactly AT that
  timestamp]}, requeries inclusively (gte, never gt) with those seen_ids
  filtered out of the result, caps how much a single cycle pulls into
  memory, and distinguishes "the fetch failed" from "nothing new" in its
  return shape. The #168 semantics this encodes (see ml-worker/worker.py's
  own history and GitHub issue #168):

  - A bare-timestamp checkpoint with an exclusive `gt` requery permanently
    drops any sibling document sharing the checkpointed timestamp but not
    present in the batch the checkpoint was computed from. Including the
    timestamp's already-processed IDs in the checkpoint and filtering by
    ID fixes that without PIT/search_after machinery.
  - `advance_checkpoint()` recomputes the tuple from a processed batch,
    keeping ONLY the IDs at the batch's maximum timestamp: everything
    strictly earlier can never be requeried once the checkpoint moves past
    it, so seen_ids stays bounded by one timestamp's collision count, not
    by history.

Pattern 2 -- windowed-refetch consumer (see the docs note): full-window
refetch + deterministic-id upsert; this module does not implement it
because it has no nontrivial mechanics to share -- its whole point is that
recomputation replaces state.

Transport injection: the elasticsearch-py method dialect IS the de-facto
transport everywhere in this repo (both scroll users and the PIT/search_after
emulations express paging that way), so pattern 1's engine takes three
callables matching it rather than importing any client:

    search(query_dict)                 -> {"_scroll_id": ..., "hits": {"hits": [...]}}
    scroll_next(previous_scroll_id)    -> same shape
    clear_scroll(scroll_id)            -> ignored return

Failure convention (#188): fetch_events_since returns (events, ok). ok=False
means the transport raised -- distinct from a genuinely empty successful poll
([], True). A scroll failing partway still returns whatever pages were
already read with ok=False, which is safe to checkpoint against per
advance_checkpoint's ordering argument (everything already read sorts at or
before anything not yet read, so advancing only as far as what's in hand
cannot skip anything -- the remainder arrives on the next poll).

Contract tests: analysis/es-consume/tests/test_es_consume.py (canonical),
ml-worker/tests/test_es_consume_vendoring.py (copy validity), and
arcane/home/honeypot-attacker-identity-worker/attacker-identity-worker/
esconsume_test.go drive the SAME fixture stream
(analysis/es-consume/fixtures/es-consume-parity.json) through this module and
through the Go reference implementation, asserting identical consumed-event
sequences and identical resulting checkpoints -- behavioural parity across
languages, the property a vendored-copy byte check cannot give you.
"""

# Every vendored copy of this file, canonical first, repo-root-relative.
VENDORED_COPY_REGISTRY = (
    # Canonical location first; every following entry must match it
    # byte-for-byte. Append a consumer's copy here when vendoring.
    "analysis/es-consume/es_consume.py",
    "ml-worker/es_consume.py",
)


def advance_checkpoint(events, previous):
    """Compute the next checkpoint tuple (#168) from a batch of processed
    events (ascending by @timestamp) and the checkpoint they were fetched
    against. Keeps only the IDs at the NEW max timestamp -- everything
    strictly before it can never be re-queried once the checkpoint advances
    past it (an inclusive requery against the new, later last_timestamp
    excludes anything earlier entirely), so seen_ids stays bounded by
    however many documents happen to share one exact timestamp, not by
    total history.

    Replacement, not append: an empty batch leaves the checkpoint alone
    (returning `previous`, never None), and a batch whose max timestamp
    differs from the stored one overwrites seen_ids wholesale.
    """
    if not events:
        return previous
    max_ts = max(e["_source"].get("@timestamp", "") for e in events)
    if not max_ts:
        return previous
    seen_ids = [e["_id"] for e in events if e["_source"].get("@timestamp") == max_ts]
    return {"last_timestamp": max_ts, "seen_ids": seen_ids}


def build_since_query(since, page_size=500):
    """The incremental poll's query body: an INCLUSIVE range filter (gte --
    exclusive gt is what originally skipped equal-timestamp siblings, #168),
    ascending @timestamp sort (the ordering every downstream safety argument
    rests on), and one page size. Kept next to the engine so the two cannot
    drift; covered shape-wise by each language's own unit tests."""
    return {
        "query": {"range": {"@timestamp": {"gte": since}}},
        "sort":  [{"@timestamp": {"order": "asc"}}],
        "size":  page_size,
    }


def fetch_events_since(search, scroll_next, clear_scroll, since,
                       page_size=500, max_total=None, exclude_ids=None,
                       warn=None):
    """Scroll events at or after `since` (inclusive) through the injected
    transport. Returns (events, ok) -- ok is False when any transport call
    raised, distinct from a genuinely empty (events=[], ok=True) poll (#188:
    the caller could not previously tell "nothing new" apart from "the fetch
    failed", since both came back as an empty list the same way). A scroll
    that fails partway still returns whatever pages were already read with
    ok=False -- safe to checkpoint against per advance_checkpoint's own
    equal-timestamp handling (#168): every event already read sorts at or
    before anything not yet read, so advancing only as far as what's in hand
    can't skip anything, it just leaves the rest for the next poll.

    Inclusive (gte) rather than exclusive (gt) so a caller protecting a
    persisted checkpoint (#168) can safely re-include the exact boundary
    timestamp and filter out only the specific documents already processed
    there via exclude_ids -- gt alone can never distinguish "already
    handled" from "arrived later with the same timestamp" and silently drops
    the latter. exclude_ids is optional: a windowed-refetch caller (or a
    fresh retrain-style backfill with no persisted checkpoint to protect)
    leaves it unset.

    max_total bounds how much this pulls into memory in one call.
    Truncation keeps the EARLIEST max_total events (events[:max_total]):
    combined with the ascending sort that means a capped cycle consumed a
    contiguous prefix of the window, which is exactly what makes advancing
    the checkpoint over a capped batch safe.

    `warn`, when given, receives str(exception) for every swallowed
    transport failure; the calling worker formats the message with its own
    logger so log text stays byte-identical to the pre-extraction code.
    Note the except block wraps ALL of the injected calls -- clear_scroll
    included -- so even a cleanup-phase failure reports (events, False)
    rather than silently pretending the poll fully succeeded.
    """
    if warn is None:
        def warn(_message):
            pass
    exclude_ids = exclude_ids or set()
    events = []
    try:
        resp = search(build_since_query(since, page_size))
        scroll_id = resp["_scroll_id"]
        hits = resp["hits"]["hits"]
        while hits:
            for hit in hits:
                if hit["_id"] in exclude_ids:
                    continue
                events.append(hit)
            if max_total is not None and len(events) >= max_total:
                events = events[:max_total]
                break
            resp = scroll_next(scroll_id)
            scroll_id = resp["_scroll_id"]
            hits = resp["hits"]["hits"]
        clear_scroll(scroll_id)
    except Exception as exc:
        warn(str(exc))
        return events, False
    return events, True
