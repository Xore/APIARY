"""Opt-in web-search tooling for the benchmark harness.

Imported lazily by `chat()` only when a `tools` argument is passed, so a default
run never touches this module and the request body stays byte-identical to the
no-tools path. That matters: a corpus run must not silently change shape because
a capability was added.

Fetched page text DOES reach the model's answer. That is a deliberate owner
decision, and it costs reproducibility -- the same prompt against the same model
can differ between runs purely because a search index moved. Any run that uses
tools must record `tools_used`, or two runs are not comparable.

Local models served through Ollama frequently do NOT populate the structured
`tool_calls` field; they emit the call as assistant text, usually as a JSON
object. So a loop that only reads `tool_calls` silently does nothing on exactly
the roster this benchmark cares about. `extract_call` accepts both: the
structured field when present, otherwise a JSON object parsed out of the text.
"""

from __future__ import annotations

import json
from typing import Any

_SEARCH_BACKEND = None
_FETCH_BACKEND = None


def set_search_backend(fn) -> None:
    """Install (query, limit) -> [{title, url, description}] for web_search."""
    global _SEARCH_BACKEND
    _SEARCH_BACKEND = fn


def set_fetch_backend(fn) -> None:
    """Install (url) -> str for web_fetch. None restores the stdlib fetcher."""
    global _FETCH_BACKEND
    _FETCH_BACKEND = fn


MAX_TOOL_ROUNDS = 3
MAX_FETCH_CHARS = 12000
MAX_TOOL_RESULT_CHARS = 4000

SEARCH_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": (
            "Search the public web. Returns titles, URLs and snippets. Use it for "
            "documentation, advisories, API references and version facts."
        ),
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "The search query."}},
            "required": ["query"],
        },
    },
}

FETCH_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "web_fetch",
        "description": "Fetch one http or https URL and return its readable text, truncated.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string", "description": "Absolute URL."}},
            "required": ["url"],
        },
    },
}

DEFAULT_TOOLS = (SEARCH_TOOL, FETCH_TOOL)


def search_results(query: str, limit: int = 5) -> str:
    """A real web search, returned as a compact text block.

    The search backend is injectable because the benchmark cannot assume a
    particular agent runtime: `set_search_backend(fn)` takes a callable
    (query, limit) -> list[dict] with title/url/description keys. Without one,
    the tool reports that it is unavailable rather than failing the run.
    """
    backend = _SEARCH_BACKEND
    if backend is None:
        return "web_search unavailable: no search backend configured on this host"
    try:
        rows = backend(query, limit)
    except Exception as exc:  # tooling is optional; never fail a run on it
        return f"web_search unavailable: {type(exc).__name__}: {exc}"
    if not rows:
        return "no results"
    return "\n".join(
        f"- {r.get('title', '')}\n  {r.get('url', '')}\n  {r.get('description', '')}"
        for r in rows[:limit]
    )


def fetch_text(url: str) -> str:
    from urllib.parse import urlparse
    scheme = urlparse(url).scheme
    if scheme not in ("http", "https"):
        return f"refused: only http and https are allowed, got {scheme!r}"
    backend = _FETCH_BACKEND
    if backend is None:
        return _html_to_text(urlopen_text(url))
    try:
        return backend(url)[:MAX_FETCH_CHARS]
    except Exception as exc:
        return f"web_fetch unavailable: {type(exc).__name__}: {exc}"


def urlopen_text(url: str, timeout: int = 25) -> str:
    """Fetch raw HTML with the standard library. There is no other dependency."""
    import urllib.request
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (compatible; apiary-benchmark/1.0)"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


_TAG = __import__("re").compile(r"<[^>]+>")
_SCRIPT = __import__("re").compile(r"<(script|style)\b[^>]*>.*?</\1>", __import__("re").S | __import__("re").I)


def _html_to_text(raw: str) -> str:
    import re as _re
    stripped = _SCRIPT.sub(" ", raw)
    stripped = _re.sub(r"<br\s*/?>|</p>|</div>|</li>|</h[1-6]>", "\n", stripped, flags=_re.I)
    return _re.sub(r"\n{3,}", "\n\n", _TAG.sub(" ", stripped)).strip()


def run_tool(name: str, args: dict[str, Any]) -> str:
    if name == "web_search":
        return search_results(str(args.get("query", "")))
    if name == "web_fetch":
        return fetch_text(str(args.get("url", "")))
    return f"unknown tool: {name}"


def extract_call(message: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Pull a tool call out of a model turn, structured or textual.

    Returns (name, arguments) or None. A text-emitted call is the common case
    here, not the edge case.
    """
    calls = message.get("tool_calls")
    if calls:
        fn = (calls[0] or {}).get("function", {}) if isinstance(calls[0], dict) else {}
        name = fn.get("name")
        raw = fn.get("arguments")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = {"query": raw}
        if name:
            return str(name), raw if isinstance(raw, dict) else {}
    text = (message.get("content") or "").strip()
    if text.startswith("{"):
        try:
            value = json.loads(text)
        except ValueError:
            return None
        if not isinstance(value, dict):
            return None
        name = value.get("name") or value.get("tool") or value.get("function")
        args = value.get("arguments") or value.get("parameters") or value.get("args")
        if name and isinstance(args, dict):
            return str(name), args
    return None


def conduct_tool_rounds(request_json, url: str, body: dict[str, Any],
                        first_response: dict[str, Any],
                        max_rounds: int | None = None) -> dict[str, Any]:
    """Drive the assistant/tool exchange and return the final model response.

    `request_json` is the harness's own transport, injected rather than
    reimplemented so timeout and cap handling stay in exactly one place.
    `body` is not mutated.
    """
    rounds = MAX_TOOL_ROUNDS if max_rounds is None else max_rounds
    transcript_turns: list[dict[str, Any]] = []
    response = first_response
    history = list(body.get("messages") or [])
    for _ in range(rounds):
        message = response.get("message") or {}
        call = extract_call(message)
        if not call:
            break
        name, args = call
        result = run_tool(name, args)
        transcript_turns.append({"tool": name, "arguments": args, "result": result[:2000]})
        history.append({"role": "assistant", "content": message.get("content") or ""})
        history.append(tool_result_turn(name, result))
        followup = dict(body)
        followup["messages"] = history
        followup["stream"] = False
        response = request_json(url, followup)
    if transcript_turns:
        response = dict(response)
        response["tool_turns"] = transcript_turns
    return response


def tool_result_turn(name: str, result: str) -> dict[str, Any]:
    """Ollama takes a tool result as a user turn carrying `tool_name`."""
    return {
        "role": "user",
        "content": result[:MAX_TOOL_RESULT_CHARS],
        "tool_name": name,
    }