#!/usr/bin/env python3
"""Contract tests for es_consume.py -- the shared ES consume patterns
(#1971). Plain stdlib script, same style as analysis/gpu-queue/test_gpu_queue.py:
no pytest, no elasticsearch, runs in seconds.

Three layers are checked here:

  1. Vendoring registry  -- every copy listed in es_consume.py's
     VENDORED_COPY_REGISTRY matches the canonical module byte-for-byte,
     the gpu_queue.py discipline (llm-worker's GPUQueueVendoringTests is
     the per-consumer precedent). A copy that drifts silently forks the
     pattern this whole effort exists to unify.

  2. Behavioural parity  -- the fixture stream in ../fixtures/ drives the
     Python engine; arcane/home/honeypot-attacker-identity-worker/
     attacker-identity-worker/esconsume_test.go drives the Go reference
     engine through the SAME stream and asserts the SAME expected outputs.
     This file cannot assert the Go half directly (it runs via that
     module's `go test ./...` job), but any expectation edit here MUST be
     mirrored there -- disagreement between engines breaks both suites'
     shared-fixture contract on purpose.

  3. Query-shape units    -- build_since_query() is what actually reaches
     Elasticsearch on every poll; an exclusive `gt` here resurrects the
     #168 bug regardless of how correct the engine is.

Usage: python3 analysis/es-consume/tests/test_es_consume.py
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The canonical module imports its vendored siblings by repo-relative path;
# walk upward so the suite also works when invoked from another directory.
ROOT = HERE
for _ in range(6):
    if (ROOT / "analysis/es-consume/es_consume.py").exists():
        break
    ROOT = ROOT.parent
else:
    print("cannot locate analysis/es-consume above", HERE)
    sys.exit(1)

sys.path.insert(0, str(ROOT / "analysis/es-consume"))
import es_consume  # noqa: E402

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


def hit(id_, timestamp):
    return {"_id": id_, "_source": {"@timestamp": timestamp}}


# ---------------------------------------------------------------- layer 1

def test_vendored_copies_match_canonical():
    canonical = (ROOT / "analysis/es-consume/es_consume.py").read_bytes()
    for rel in es_consume.VENDORED_COPY_REGISTRY:
        path = ROOT / rel
        if not path.exists():
            check(False, f"registry entry exists: {rel}")
            continue
        check(path.read_bytes() == canonical, f"byte-for-byte vs canonical: {rel}")


# ---------------------------------------------------------------- layer 2

def load_fixture():
    return json.loads((HERE / ".." / "fixtures" / "es-consume-parity.json").read_text())


class _InjectableFailure(Exception):
    pass


def make_transport(pages):
    """Adapt fixture pages to the engine's search/scroll_next/clear_scroll
    seam: first page from search(), each later one from scroll_next(); a
    page with ok=false raises at exactly that point."""
    state = {"index": -1}

    def response(page):
        if not page["ok"]:
            raise _InjectableFailure(page.get("error", "injected failure"))
        state["index"] += 1
        return {"_scroll_id": f"scroll-{state['index']}",
                "hits": {"hits": page["hits"]}}

    def search(_query):
        state["index"] = -1
        return response(pages[0])

    def scroll_next(_scroll_id):
        return response(pages[state["index"] + 1])

    def clear_scroll(_scroll_id):
        state["cleared"] = True

    state["cleared"] = False
    return search, scroll_next, clear_scroll, state


def run_case(case):
    initial = case["initial_checkpoint"]
    pages = case["pages"]
    transport = make_transport(pages)
    events, ok = es_consume.fetch_events_since(
        transport[0], transport[1], transport[2],
        initial["last_timestamp"],
        max_total=case["max_total"],
        exclude_ids=set(initial["seen_ids"]),
    )
    final = es_consume.advance_checkpoint(events, initial)
    return ok, [e["_id"] for e in events], final


def test_parity_fixtures():
    fixture = load_fixture()
    for case in fixture["cases"]:
        name = case["name"]
        try:
            ok, consumed, final = run_case(case)
        except Exception as exc:  # noqa: BLE001 -- report as failure, not crash
            check(False, f"{name}: engine raised {exc!r}")
            continue
        check(ok == case["expected_ok"], f"{name}: ok flag")
        check(consumed == case["expected_consumed_ids"], f"{name}: consumed event sequence")
        check(final == case["expected_final_checkpoint"], f"{name}: resulting checkpoint")


def test_empty_batch_keeps_previous_checkpoint_identity():
    previous = {"last_timestamp": "2026-08-01T10:00:00Z", "seen_ids": ["k"]}
    check(es_consume.advance_checkpoint([], previous) is previous,
          "advance over an empty batch returns the caller's own checkpoint object")


# ---------------------------------------------------------------- layer 3

def test_query_shape_is_inclusive_ascending_bounded():
    query = es_consume.build_since_query("2026-08-01T10:00:00Z", page_size=123)
    rng = query["query"]["range"]["@timestamp"]
    check("gte" in rng and "gt" not in rng,
          "range filter is inclusive gte -- exclusive gt re-skips nothing and loses equal-timestamp siblings (#168)")
    check(rng["gte"] == "2026-08-01T10:00:00Z", "since passes through verbatim")
    check(query["sort"] == [{"@timestamp": {"order": "asc"}}],
          "ascending @timestamp sort -- the ordering every safety argument depends on")
    check(query["size"] == 123, "page size honoured")


def main():
    print("es_consume.py contract tests")
    test_vendored_copies_match_canonical()
    test_parity_fixtures()
    test_empty_batch_keeps_previous_checkpoint_identity()
    test_query_shape_is_inclusive_ascending_bounded()
    if fails:
        print(f"\n{len(fails)} FAILED")
        for f in fails:
            print(f"  FAIL {f}")
        sys.exit(1)
    print("\nall checks passed")


if __name__ == "__main__":
    main()
