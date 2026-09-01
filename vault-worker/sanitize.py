"""Redaction/bounding primitives for attacker-supplied text reaching a vault note.

Ported from llm-worker/contracts.py's sanitize_text (the same regex set,
the same <untrusted_data> delimiter-escaping, the same bounded-truncation
shape) per #2289's decision that vault notes get problem_reports.rs's
bound-and-redact posture. Not imported directly across the two workers'
Docker build contexts -- each worker directory in this repo is already a
self-contained build context (see llm-worker/Dockerfile's own `COPY
contracts.py worker.py`) -- so this is a deliberate, attributed copy of the
tested primitives rather than a new implementation. Keep this in sync with
llm-worker/contracts.py's sanitize_text if that regex set changes.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CLOSE_DELIMITER_RE = re.compile(r"</\s*untrusted_data\s*>", re.IGNORECASE)
_OPEN_DELIMITER_RE = re.compile(r"<\s*untrusted_data\s*>", re.IGNORECASE)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*([=:])\s*([^\s'\";]{1,512})"
)
_CREDENTIAL_URL_RE = re.compile(r"(?i)(https?://)([^/\s:@]+):([^/\s@]+)@")
_CHPASSWD_CREDENTIAL_RE = re.compile(
    r"(?i)(\b(?:echo|printf)\s+)([\"']?)([a-z_][a-z0-9_.-]{0,31}):([^|\"'\r\n]{1,512})(\2)(\s*\|\s*chpasswd\b)"
)


@dataclass(frozen=True)
class SanitizedText:
    text: str
    truncated: bool
    input_sha256: str


def _redact_secrets(value: str) -> str:
    value = _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", value)
    value = _CREDENTIAL_URL_RE.sub(r"\1[REDACTED]@", value)
    return _CHPASSWD_CREDENTIAL_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}:[REDACTED]{m.group(5)}{m.group(6)}",
        value,
    )


def sanitize_text(value: object, max_chars: int) -> SanitizedText:
    """Bound and neutralize one untrusted value without interpreting it.

    Applied to every attacker-derived string before it can reach a note
    body -- summaries, IOCs, highlights pulled from the analysis indices.
    Structured metadata (hashes, IPs, campaign ids, timestamps) does not
    go through this: it is copied as-is per #2289's redaction posture.
    """
    raw = value if isinstance(value, str) else str(value or "")
    digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()
    cleaned = _CONTROL_RE.sub("", raw)
    cleaned = _OPEN_DELIMITER_RE.sub("< untrusted_data>", cleaned)
    cleaned = _CLOSE_DELIMITER_RE.sub("< /untrusted_data>", cleaned)
    cleaned = _redact_secrets(cleaned)
    truncated = len(cleaned) > max_chars
    if truncated:
        suffix = "\n[TRUNCATED]"
        cleaned = cleaned[: max(0, max_chars - len(suffix))] + suffix
    return SanitizedText(cleaned, truncated, digest)


def sanitize_list(values: list[object], max_chars: int, max_items: int) -> list[str]:
    """Bound a list of untrusted short strings (e.g. IOCs), item-wise."""
    out = []
    for v in list(values or [])[:max_items]:
        out.append(sanitize_text(v, max_chars).text)
    return out
