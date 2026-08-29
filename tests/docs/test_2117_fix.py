"""#2117 regression -- llm-search's kNN query pins embedding_model.

/api/v1/llm-search embedded the operator's query with whatever model
LLM_EMBEDDING_MODEL names right now, but its kNN query against
Elasticsearch never filtered on the embedding_model field llm-worker
stamps on every embedded document (worker.py: `document.update({"embedding":
..., "embedding_model": ..., "embedding_model_digest": ...})`). A model
swap -- a deliberate env edit, or the nomic-embed-text:latest tag floating
to a new build under the same name -- left the index holding vectors from
two incompatible spaces, and search silently ranked across both:
plausible-looking cosine scores, wrong ranking, no error anywhere.

Fix (backend-service/src/llm_search.rs): knn_body() adds a `term` filter
on embedding_model inside knn.filter.bool.filter (a restrictive AND, not
an optional `should`), using the exact same `model` variable search()
already passed to embed() -- one source of truth for "what model produced
this query vector," not two identifiers that could drift apart. The
digest field (embedding_model_digest) was considered and rejected for the
read path: resolving it would require an extra Ollama /api/tags round
trip on every search request that the write side's OllamaClient.embed()
has no equivalent to reuse, whereas the model name is already the exact
string search() uses to embed the query -- no extra network call, no new
failure mode. A search that comes back empty after filtering stays
available:true, with a note when foreign-model docs exist, instead of
silently falling back to an unfiltered query.
"""

import re

LLM_SEARCH_RS = "arcane/home/honeypot-dashboard/backend-service/src/llm_search.rs"


def _read():
    with open(LLM_SEARCH_RS) as f:
        return f.read()


def test_knn_filter_has_term_clause_on_embedding_model():
    """The kNN query must filter on embedding_model, not just doc_type."""
    src = _read()
    assert '{"term": {"embedding_model": model}}' in src, (
        "knn_body must carry a term filter on embedding_model"
    )


def test_query_vector_model_and_filter_model_are_the_same_identifier():
    """The model that embeds the query and the model in the kNN filter must
    be the same variable -- not two separately-sourced identifiers that a
    future edit could let drift apart."""
    src = _read()
    embed_call = re.search(r"embed\(&base,\s*&(\w+),\s*&text\)", src)
    knn_call = re.search(r"knn_body\(&(\w+),\s*&vector,\s*limit\)", src)
    assert embed_call, "could not find the embed() call site in search()"
    assert knn_call, "could not find the knn_body() call site in search()"
    assert embed_call.group(1) == knn_call.group(1), (
        "embed() and knn_body() must be called with the same model variable, "
        f"got {embed_call.group(1)!r} vs {knn_call.group(1)!r}"
    )


def test_filter_context_is_restrictive_not_a_scoring_hint():
    """The embedding_model clause must live inside knn.filter.bool.filter
    (a restrictive AND), never bool.should -- `should` would make the model
    match optional and let cross-model documents back into ranked results,
    recreating the exact bug #2117 reported."""
    src = _read()
    assert '"filter": {"bool": {"filter": [' in src, (
        "embedding_model term must sit inside a restrictive bool.filter clause"
    )
    assert '"should"' not in src, (
        "a `should` clause would make the embedding_model match optional, not restrictive"
    )


def test_empty_after_filter_reports_available_true_without_fallback():
    """A filtered-out result must return a clear empty response, never a
    silent retry of the kNN query without the embedding_model filter."""
    src = _read()
    assert "return Json(empty_hits_response(foreign_count));" in src, (
        "the empty-after-filter path must return the explicit empty response"
    )
    assert 'fn empty_hits_response' in src and '"available": true' in src, (
        "empty_hits_response must still report available: true (filtered-out, not failed)"
    )
    # Exactly one call site building the kNN body, and it always carries the
    # model filter -- no second, unfiltered query path to fall back to.
    assert src.count("knn_body(&model") == 1, (
        "knn_body must be called exactly once, always with the model filter"
    )
