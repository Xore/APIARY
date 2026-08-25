"""Full-conversation transcript records for benchmark model calls (issue #1805).

A score is a lossy summary of an answer. The questions that actually decide
model selection here -- "what did this model say that the other missed", "does
the security fine-tune surface a behaviour the base model never mentions" --
live in the answer text and cannot be reconstructed from a number. Re-running
is not a substitute: model tags, quants, sampling and prompts all drift, so a
re-run answers a different question than the original.

Two things #1805's claim-pool scoring requires are simply impossible if
transcripts are discarded:

1. Rescoring earlier rounds against a later, enlarged claim pool -- which needs
   the earlier models' original answers.
2. Computing unique-contribution retroactively, since "did this model find
   something no other model did" is defined against the set of models that ran
   and changes when a model is added later.

So the raw text is the durable artifact and the score is derived from it, not
the other way round.

Storage is split by data provenance, not by convenience:

- `synthetic` -- #159's corpus binaries and `evaluate-models.py`'s fixtures
  (TEST-NET addresses, reserved names, fake credentials, reviewed before
  commit). Committed to the repo under `docs/benchmarks/runs/<date>-<run_id>/`
  so rounds stay comparable across time. There is no secret in them.
- `captured` -- runs against real honeypot data. These contain real attacker
  IPs and payloads, so they are written outside the repository with bounded
  retention and the issue carries only aggregates and pointers. Writing them
  into the working tree is refused here rather than left to reviewer vigilance.

This partly supersedes `docs/analysis/ghidra/benchmarks/README.md`, which tells
the operator to preserve the raw report outside the repository for everything.
That rule was written when the report was a score summary; it still governs
`captured` runs, and `synthetic` runs now commit their transcripts instead.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "apiary-benchmark-transcript-v1"

PROVENANCE_SYNTHETIC = "synthetic"
PROVENANCE_CAPTURED = "captured"
PROVENANCES = (PROVENANCE_SYNTHETIC, PROVENANCE_CAPTURED)

# Tier A: objdump disassembly, what record_baseline.py has always fed models.
# Tier B: real Ghidra headless JSON, what production actually sees.
# Tier C: Ghidra output refined by LLM4Decompile-Ref (x86/x86-64 only).
TIERS = ("A", "B", "C")

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SYNTHETIC_ROOT = REPO_ROOT / "docs" / "benchmarks" / "runs"

TRANSCRIPT_FILENAME = "transcripts.jsonl"
RUN_FILENAME = "run.json"


def sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str | None:
    """Hash a reproducibility input. Missing files record as null, not as an
    exception -- an absent corpus manifest is a fact about the run worth
    storing, and must not abort a round that does not depend on it."""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def new_run_id() -> str:
    """Sortable, collision-resistant, and readable in a directory listing."""
    return f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.urandom(4).hex()}"


def default_operator() -> str:
    return os.environ.get("APIARY_OPERATOR") or os.environ.get("USER") or "unknown"


@dataclass(frozen=True)
class Reproducibility:
    """The keys that make a stored answer re-interpretable later.

    Every one of these silently changes what a model was shown. Recording them
    beside the answer is what makes a score change six months from now
    attributable rather than mysterious -- the #568 stale-assumption failure,
    one layer down.
    """

    tier: str = "A"
    corpus_manifest_sha256: str | None = None
    ghidra_cache_key: str | None = None
    rubric_version: str | None = None
    claim_pool_version: str | None = None
    prompt_contract: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"unknown tier: {self.tier}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "corpus_manifest_sha256": self.corpus_manifest_sha256,
            "ghidra_cache_key": self.ghidra_cache_key,
            "rubric_version": self.rubric_version,
            "claim_pool_version": self.claim_pool_version,
            "prompt_contract": self.prompt_contract,
        }


@dataclass
class RunMetadata:
    benchmark: str
    provenance: str = PROVENANCE_SYNTHETIC
    operator: str = field(default_factory=default_operator)
    run_id: str = field(default_factory=new_run_id)
    started_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    # A misconfigured run is never edited away; it is superseded by a new run
    # that names it here, because later scores depend on the original text.
    supersedes: str | None = None
    notes: str | None = None

    def __post_init__(self) -> None:
        if self.provenance not in PROVENANCES:
            raise ValueError(f"unknown provenance: {self.provenance}")

    @property
    def directory_name(self) -> str:
        return f"{self.started_at[:10]}-{self.run_id}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "operator": self.operator,
            "benchmark": self.benchmark,
            "provenance": self.provenance,
            "supersedes": self.supersedes,
            "notes": self.notes,
        }


def _is_inside_repo(path: Path) -> bool:
    try:
        path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        return False
    return True


class TranscriptWriter:
    """Appends one JSONL record per model call.

    JSONL rather than one large object so a run appends as it goes and a diff
    between two runs stays readable. An interrupted round therefore still
    leaves every answer it did obtain.
    """

    def __init__(self, root: str | os.PathLike[str], run: RunMetadata) -> None:
        self.run = run
        self.directory = Path(root).expanduser() / run.directory_name
        if run.provenance == PROVENANCE_CAPTURED and _is_inside_repo(self.directory):
            raise ValueError(
                "refusing to write captured-data transcripts inside the repository: "
                f"{self.directory}. Real session transcripts contain attacker IPs and "
                "payloads; write them to an operator-only path with bounded retention."
            )
        self.path = self.directory / TRANSCRIPT_FILENAME
        if self.path.exists():
            raise ValueError(
                f"{self.path} already exists; a stored transcript is never rewritten. "
                "Record a new run with supersedes=<old run_id> instead."
            )
        self.directory.mkdir(parents=True, exist_ok=True)
        if run.provenance == PROVENANCE_CAPTURED:
            os.chmod(self.directory, 0o700)
        self.count = 0
        self._handle = self.path.open("a", encoding="utf-8")
        (self.directory / RUN_FILENAME).write_text(
            json.dumps(run.as_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def record(
        self,
        *,
        slot: str,
        case: str,
        workflow: str | None,
        model: dict[str, Any],
        request_body: dict[str, Any],
        reproducibility: Reproducibility,
        response: dict[str, Any] | None = None,
        parsed: Any = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        """Store one (run_id, slot, case, model, workflow) exchange.

        `request_body` is the literal dict posted to Ollama, messages included,
        so the prompt is recorded as *sent* rather than reconstructed from the
        fixtures -- a prompt you have to rebuild is a prompt you cannot trust.

        A failure is a measurement, not a gap: timeouts, refusals and malformed
        JSON are stored with the same fidelity as a success. For a derestricted
        round a refusal *is* the result.
        """
        messages = request_body.get("messages", [])
        raw_content = None if response is None else response.get("content")
        record = {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run.run_id,
            "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operator": self.run.operator,
            "benchmark": self.run.benchmark,
            "provenance": self.run.provenance,
            "slot": slot,
            "case": case,
            "workflow": workflow,
            "model": model,
            "request": {
                "system_prompt": next((m["content"] for m in messages if m.get("role") == "system"), None),
                "user_prompt": next((m["content"] for m in messages if m.get("role") == "user"), None),
                "body": request_body,
                "body_sha256": sha256_json(request_body),
            },
            "response": {
                "raw": raw_content,
                "parsed": parsed,
                "parse_ok": parsed is not None,
            },
            "timing": {
                "wall_seconds": (response or {}).get("wall_seconds"),
                "prompt_tokens": (response or {}).get("prompt_tokens"),
                "output_tokens": (response or {}).get("output_tokens"),
                "tokens_per_second": (response or {}).get("tokens_per_second"),
                "done_reason": (response or {}).get("done_reason"),
            },
            "reproducibility": reproducibility.as_dict(),
            # Populated by #1805-f's claim extraction, so an adjudicated verdict
            # can always be traced back to the sentence that produced it.
            "claim_ids": [],
            "outcome": "error" if error else "ok",
            "error": error,
        }
        self._handle.write(json.dumps(record, sort_keys=True) + "\n")
        self._handle.flush()
        self.count += 1
        return record

    def close(self) -> dict[str, Any]:
        self._handle.close()
        summary = {
            **self.run.as_dict(),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "record_count": self.count,
            "transcripts": str(self.path),
            "transcripts_sha256": sha256_file(self.path),
        }
        (self.directory / RUN_FILENAME).write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return summary

    def __enter__(self) -> "TranscriptWriter":
        return self

    def __exit__(self, *_exc: object) -> None:
        if not self._handle.closed:
            self.close()


@dataclass
class SlotRecorder:
    """The per-slot handle threaded through the scorers.

    Bundles what every call in a slot shares -- the writer, the resolved model
    artifact, and the reproducibility keys -- so the scoring functions gain one
    parameter rather than six, and so a slot cannot accidentally record a
    different model than the one it evaluated.
    """

    writer: TranscriptWriter | None
    slot: str
    model: dict[str, Any]
    reproducibility: Reproducibility

    def record(
        self,
        *,
        case: str,
        workflow: str | None,
        request_body: dict[str, Any],
        response: dict[str, Any] | None = None,
        parsed: Any = None,
        error: str | None = None,
    ) -> None:
        if self.writer is None:
            return
        self.writer.record(
            slot=self.slot,
            case=case,
            workflow=workflow,
            model=self.model,
            request_body=request_body,
            reproducibility=self.reproducibility,
            response=response,
            parsed=parsed,
            error=error,
        )
