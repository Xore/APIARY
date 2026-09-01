#!/usr/bin/env python3
"""Knowledge-store vault-ingest worker (#1634 stage 2, gated by #2289).

Renders one deterministic markdown note per entity into the vault directory,
consuming the analysis indices docs/PIPELINES.md documents: the five
es-results-importer sinks (ghidra/sandbox/cape/revdeck/github-analysis-v1,
one payload entity keyed by file.hash.sha256) plus llm-analysis (session and
payload doc_types, one llm-session entity per session_id, and a contribution
to the same payload entity for doc_type "payload").

Idioms deliberately reused from llm-worker/worker.py rather than reinvented:
checkpointed scroll consumption via search_after (load_checkpoint /
save_checkpoint, mirroring llm-worker's STATE_INDEX checkpoint pattern);
sha256-keyed note filenames so a re-render overwrites the same file instead
of creating a duplicate; bounding + secret-stripping (sanitize.py, ported
from llm-worker/contracts.py's sanitize_text) applied to every attacker-
supplied string before it reaches a note body, per #2289's redaction
posture. No Ollama call is made anywhere in this worker -- v1 renders
deterministically from analysis results llm-worker has already produced,
so "expected-digest pinning on any Ollama call" (the fourth idiom #2290
names) has nothing to pin against; it applies starting at #2292, the first
stage that calls a completion model.

Batch-run on an interval (main loop below), never per-event: a capture
flood advances the checkpoint by at most VAULT_MAX_DOCS_PER_CYCLE per
source index per cycle, so the vault can't be swamped by a burst.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from elasticsearch import Elasticsearch, NotFoundError

from sanitize import sanitize_list, sanitize_text

STATE_INDEX = "knowledge-vault-state-v1"

PIPELINE_INDICES = [
    "ghidra-analysis-v1",
    "sandbox-analysis-v1",
    "cape-analysis-v1",
    "revdeck-analysis-v1",
    "github-analysis-v1",
]
LLM_ANALYSIS_INDEX = "llm-analysis"
ALL_SOURCE_INDICES = PIPELINE_INDICES + [LLM_ANALYSIS_INDEX]

EPOCH = "1970-01-01T00:00:00.000Z"


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))


def natural_key_hash(natural_key: str) -> str:
    """Stable filename key for an entity, per #2289's note-shape decision."""
    return hashlib.sha256(natural_key.encode("utf-8")).hexdigest()


@dataclass
class Config:
    es_host: str
    enabled: bool
    dry_run: bool
    allow_captured_data: bool
    output_dir: Path
    poll_interval: int
    max_docs_per_cycle: int
    max_text_chars: int
    max_list_items: int

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            es_host=os.getenv("ES_HOST", "http://elasticsearch:9200").rstrip("/"),
            enabled=env_bool("VAULT_ENABLED", False),
            dry_run=env_bool("VAULT_DRY_RUN", True),
            allow_captured_data=env_bool("VAULT_ALLOW_CAPTURED_DATA", False),
            output_dir=Path(os.getenv("VAULT_OUTPUT_DIR", "/vault")),
            poll_interval=env_int("VAULT_POLL_INTERVAL_SECONDS", 900, 60, 86400),
            max_docs_per_cycle=env_int("VAULT_MAX_DOCS_PER_CYCLE", 500, 1, 20000),
            max_text_chars=env_int("VAULT_MAX_TEXT_CHARS", 4000, 200, 50000),
            max_list_items=env_int("VAULT_MAX_LIST_ITEMS", 30, 1, 500),
        )

    def validate_mode(self) -> None:
        """Same two-flag-beyond-dry-run gate as llm-worker's LLM_ENABLED +
        LLM_ALLOW_CAPTURED_DATA (llm-worker/worker.py Config.validate_mode),
        per #2289's decision that the vault worker needs an equivalent
        explicit opt-in."""
        if self.dry_run:
            return
        if not (self.enabled and self.allow_captured_data):
            raise ValueError(
                "non-dry-run mode requires both VAULT_ENABLED=true and "
                "VAULT_ALLOW_CAPTURED_DATA=true; #2289 owns that authorization"
            )


def frontmatter_dump(fields: dict[str, Any]) -> str:
    return "---\n" + yaml.safe_dump(fields, sort_keys=False, default_flow_style=False) + "---\n"


def frontmatter_load(text: str) -> dict[str, Any] | None:
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    if end == -1:
        return None
    try:
        loaded = yaml.safe_load(text[4:end])
    except yaml.YAMLError:
        return None
    return loaded if isinstance(loaded, dict) else None


def atomic_write(path: Path, content: str) -> bool:
    """Write content to path, returning True iff the file's content changed.

    A checkpoint-gated re-render already keeps redundant writes rare (see
    module docstring), but this still avoids a needless mtime bump / extra
    disk write when a cycle happens to re-derive byte-identical content.
    """
    existing = path.read_text() if path.exists() else None
    if existing == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    tmp.write_text(content)
    os.replace(tmp, path)
    return True


class VaultIndex:
    """Cheap in-memory index over already-rendered notes' frontmatter, used
    to compute #2289's structural links (shared hash / IP / campaign) fresh
    on every render -- no separate link table to go stale."""

    def __init__(self, vault_dir: Path):
        self.by_hash: dict[str, set[str]] = {}
        self.by_ip: dict[str, set[str]] = {}
        self.by_campaign: dict[str, set[str]] = {}
        self._load(vault_dir)

    def _load(self, vault_dir: Path) -> None:
        if not vault_dir.exists():
            return
        for note_path in vault_dir.glob("*.md"):
            fm = frontmatter_load(note_path.read_text(errors="replace"))
            if not fm:
                continue
            stem = note_path.stem
            for h in fm.get("file_hashes") or []:
                self.by_hash.setdefault(h, set()).add(stem)
            for ip in fm.get("source_ips") or []:
                self.by_ip.setdefault(ip, set()).add(stem)
            campaign = fm.get("campaign_id")
            if campaign:
                self.by_campaign.setdefault(campaign, set()).add(stem)

    def related(self, stem: str, hashes: list[str], ips: list[str], campaign: str | None) -> list[str]:
        found: set[str] = set()
        for h in hashes:
            found |= self.by_hash.get(h, set())
        for ip in ips:
            found |= self.by_ip.get(ip, set())
        if campaign:
            found |= self.by_campaign.get(campaign, set())
        found.discard(stem)
        return sorted(found)

    def register(self, stem: str, hashes: list[str], ips: list[str], campaign: str | None) -> None:
        for h in hashes:
            self.by_hash.setdefault(h, set()).add(stem)
        for ip in ips:
            self.by_ip.setdefault(ip, set()).add(stem)
        if campaign:
            self.by_campaign.setdefault(campaign, set()).add(stem)


class VaultWorker:
    def __init__(self, config: Config, es: Elasticsearch | None = None):
        self.config = config
        self.es = es or Elasticsearch(config.es_host, request_timeout=30)
        self.index = VaultIndex(config.output_dir)

    def ensure_state_index(self) -> None:
        if not self.es.indices.exists(index=STATE_INDEX):
            self.es.indices.create(
                index=STATE_INDEX,
                mappings={
                    "properties": {
                        "kind": {"type": "keyword"},
                        "last_timestamp": {"type": "date"},
                        "last_seq_no": {"type": "long"},
                        "last_id": {"type": "keyword"},
                        "updated_at": {"type": "date"},
                    }
                },
            )

    def load_checkpoint(self, source_index: str) -> tuple[str, int]:
        """Returns (last @timestamp, last _seq_no) sort-key pair.

        Tiebreak deliberately uses `_seq_no`, not `_id`: Elasticsearch
        disallows sorting/search_after on `_id` unless fielddata is
        explicitly (and expensively) enabled for it -- verified live against
        a scratch 9.5.2 cluster while testing this worker, which failed
        every scroll with `search_phase_execution_exception: Fielddata
        access on the _id field is disallowed`. `_seq_no` is a per-shard
        monotonic doc-values field with no such restriction and gives the
        same "definitely advances, never skips a tied timestamp" guarantee.
        """
        try:
            src = self.es.get(index=STATE_INDEX, id=f"checkpoint-{source_index}")["_source"]
            return src.get("last_timestamp", EPOCH), src.get("last_seq_no", -1)
        except NotFoundError:
            return EPOCH, -1

    def save_checkpoint(self, source_index: str, timestamp: str, seq_no: int, doc_id: str) -> None:
        self.es.index(
            index=STATE_INDEX,
            id=f"checkpoint-{source_index}",
            document={
                "kind": "checkpoint",
                "last_timestamp": timestamp,
                "last_seq_no": seq_no,
                "last_id": doc_id,
                "updated_at": iso_now(),
            },
        )

    def scroll_new(self, source_index: str) -> list[dict[str, Any]]:
        """One page of docs newer than the checkpoint, oldest-first, capped
        at max_docs_per_cycle -- the batch-run safety valve the issue names."""
        last_ts, last_seq_no = self.load_checkpoint(source_index)
        body: dict[str, Any] = {
            "size": self.config.max_docs_per_cycle,
            "sort": [{"@timestamp": "asc"}, {"_seq_no": "asc"}],
            "query": {"match_all": {}},
            "seq_no_primary_term": True,
        }
        if last_seq_no >= 0:
            body["search_after"] = [last_ts, last_seq_no]
        try:
            result = self.es.search(index=source_index, **body)
        except Exception as error:  # noqa: BLE001 - a missing/empty index is not fatal
            logging.warning("scroll against %s failed: %s", source_index, error)
            return []
        return result["hits"]["hits"]

    # -- payload entity (ghidra/sandbox/cape/revdeck/github + llm payload docs) --

    def render_payload_note(self, sha256: str) -> bool:
        sections: list[str] = []
        source_doc_ids: list[str] = []
        source_indices: set[str] = set()
        timestamps: list[str] = []

        for pipeline_index in PIPELINE_INDICES:
            try:
                result = self.es.search(
                    index=pipeline_index,
                    query={"term": {"file.hash.sha256": sha256}},
                    size=1,
                )
            except Exception:  # noqa: BLE001 - index may not exist yet
                continue
            hits = result["hits"]["hits"]
            if not hits:
                continue
            hit = hits[0]
            source = hit["_source"]
            source_doc_ids.append(hit["_id"])
            source_indices.add(pipeline_index)
            if source.get("@timestamp"):
                timestamps.append(source["@timestamp"])
            sections.append(self._pipeline_section(pipeline_index, source))

        try:
            result = self.es.search(
                index=LLM_ANALYSIS_INDEX,
                query={"bool": {"filter": [{"term": {"doc_type": "payload"}}, {"term": {"payload_sha256": sha256}}]}},
                size=1,
            )
            hits = result["hits"]["hits"]
        except Exception:  # noqa: BLE001
            hits = []
        if hits:
            hit = hits[0]
            source = hit["_source"]
            source_doc_ids.append(hit["_id"])
            source_indices.add(LLM_ANALYSIS_INDEX)
            if source.get("@timestamp"):
                timestamps.append(source["@timestamp"])
            sections.append(self._llm_assessment_section("LLM assessment (payload)", source))

        if not sections:
            return False

        stem = f"payload-{natural_key_hash(sha256)}"
        hashes = [sha256]
        # No pipeline doc in PIPELINE_INDICES or the llm-analysis "payload"
        # doc_type carries a source IP directly (verified against the live
        # field shapes on the homeserver) -- correlating a payload to the
        # IPs of sessions that downloaded it is a real join across
        # llm-analysis's "session" doc_type but out of scope for this pass;
        # left empty rather than guessed. See HANDOVER.md residual risk.
        ips: list[str] = []
        related = self.index.related(stem, hashes, ips, None)

        frontmatter = {
            "entity_type": "payload",
            "entity_id": sha256,
            "source_index": sorted(source_indices),
            "source_doc_ids": source_doc_ids,
            "file_hashes": hashes,
            "source_ips": ips,
            "campaign_id": None,
            "first_seen": min(timestamps) if timestamps else None,
            "last_seen": max(timestamps) if timestamps else None,
            "enrichment_status": "rendered",
            "rendered_at": iso_now(),
        }
        body = f"# Payload {sha256}\n\n" + "\n".join(sections)
        if related:
            body += "\n## Linked notes\n\n" + "\n".join(f"- [[{r}]]" for r in related) + "\n"

        changed = atomic_write(self.config.output_dir / f"{stem}.md", frontmatter_dump(frontmatter) + "\n" + body)
        self.index.register(stem, hashes, ips, None)
        return changed

    def _pipeline_section(self, pipeline_index: str, source: dict[str, Any]) -> str:
        name = pipeline_index.removesuffix("-analysis-v1").capitalize()
        exit_status = source.get("exit_status", "unknown")
        lines = [f"## {name} analysis\n", f"- exit status: `{exit_status}`"]
        if pipeline_index == "ghidra-analysis-v1":
            capa = source.get("ghidra", {}).get("capa", {})
            caps = capa.get("capabilities") or []
            if caps:
                lines.append("- capa capabilities:")
                for cap in caps[: self.config.max_list_items]:
                    lines.append(f"  - {sanitize_text(cap.get('name', ''), 200).text}")
        elif pipeline_index == "sandbox-analysis-v1":
            lines.append(f"- risk level: `{source.get('risk_level', 'unknown')}`")
            lines.append(f"- risk score: `{source.get('risk_score', 'unknown')}`")
        lines.append("")
        return "\n".join(lines)

    # -- llm-session entity --

    def render_session_note(self, hit: dict[str, Any]) -> bool:
        source = hit["_source"]
        session_id = source.get("session_id") or hit["_id"]
        stem = f"llm-session-{natural_key_hash(session_id)}"

        hashes = [source["payload_sha256"]] if source.get("payload_sha256") else []
        ips = [source["src_ip"]] if source.get("src_ip") else []
        related = self.index.related(stem, hashes, ips, None)

        frontmatter = {
            "entity_type": "llm-session",
            "entity_id": session_id,
            "source_index": [LLM_ANALYSIS_INDEX],
            "source_doc_ids": [hit["_id"]],
            "file_hashes": hashes,
            "source_ips": ips,
            "campaign_id": None,
            "first_seen": source.get("@timestamp"),
            "last_seen": source.get("@timestamp"),
            "enrichment_status": "rendered",
            "rendered_at": iso_now(),
        }
        body = f"# Session {session_id}\n\n" + self._llm_assessment_section("Assessment", source)
        if related:
            body += "\n## Linked notes\n\n" + "\n".join(f"- [[{r}]]" for r in related) + "\n"

        changed = atomic_write(self.config.output_dir / f"{stem}.md", frontmatter_dump(frontmatter) + "\n" + body)
        self.index.register(stem, hashes, ips, None)
        return changed

    def _llm_assessment_section(self, heading: str, source: dict[str, Any]) -> str:
        m = self.config.max_text_chars
        summary = sanitize_text(source.get("summary", ""), m).text
        iocs = sanitize_list(source.get("iocs") or [], 300, self.config.max_list_items)
        lines = [
            f"## {heading}\n",
            f"- intent: `{source.get('intent') or 'unknown'}`",
            f"- severity: `{source.get('severity') or 'unknown'}`",
            "",
            "<untrusted_data>",
            summary,
            "</untrusted_data>",
            "",
        ]
        if iocs:
            lines.append("- IOCs observed:")
            lines.extend(f"  - `{ioc}`" for ioc in iocs)
        lines.append("")
        return "\n".join(lines)

    # -- one cycle over every source index --

    def run_once(self) -> dict[str, int]:
        self.config.validate_mode()
        rendered = 0
        touched_payload_hashes: set[str] = set()
        session_hits: list[dict[str, Any]] = []
        docs_scanned = 0

        for source_index in PIPELINE_INDICES:
            hits = self.scroll_new(source_index)
            docs_scanned += len(hits)
            for hit in hits:
                sha256 = hit["_source"].get("file", {}).get("hash", {}).get("sha256")
                if sha256:
                    touched_payload_hashes.add(sha256)
            if hits and not self.config.dry_run:
                last = hits[-1]
                self.save_checkpoint(source_index, last["_source"]["@timestamp"], last["_seq_no"], last["_id"])

        llm_hits = self.scroll_new(LLM_ANALYSIS_INDEX)
        docs_scanned += len(llm_hits)
        for hit in llm_hits:
            doc_type = hit["_source"].get("doc_type")
            if doc_type == "payload" and hit["_source"].get("payload_sha256"):
                touched_payload_hashes.add(hit["_source"]["payload_sha256"])
            elif doc_type == "session":
                session_hits.append(hit)
        if llm_hits and not self.config.dry_run:
            last = llm_hits[-1]
            self.save_checkpoint(LLM_ANALYSIS_INDEX, last["_source"]["@timestamp"], last["_seq_no"], last["_id"])

        if not self.config.dry_run:
            for sha256 in touched_payload_hashes:
                if self.render_payload_note(sha256):
                    rendered += 1
            for hit in session_hits:
                if self.render_session_note(hit):
                    rendered += 1
            # Second pass over payload notes touched this cycle: a payload
            # rendered before its session arrived in the same cycle would
            # otherwise never pick up the backlink, since the session note
            # didn't exist yet when the payload was first written and
            # nothing re-touches that payload hash on a later cycle unless
            # a new analysis result for it shows up. Re-rendering after
            # every session in this cycle has registered itself makes intra-
            # cycle links symmetric without a separate link table.
            for sha256 in touched_payload_hashes:
                self.render_payload_note(sha256)

        return {
            "docs_scanned": docs_scanned,
            "payload_notes_touched": len(touched_payload_hashes),
            "session_notes_touched": len(session_hits),
            "notes_written": rendered,
            "dry_run": self.config.dry_run,
        }


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def main() -> int:
    configure_logging()
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="run a single cycle and exit")
    args = parser.parse_args()

    config = Config.from_env()
    worker = VaultWorker(config)
    if not config.dry_run:
        worker.ensure_state_index()

    if args.once:
        result = worker.run_once()
        logging.info("cycle complete: %s", result)
        return 0

    while True:
        try:
            result = worker.run_once()
            logging.info("cycle complete: %s", result)
        except Exception:  # noqa: BLE001 - one bad cycle must not kill the loop
            logging.exception("vault worker cycle failed")
        time.sleep(config.poll_interval)


if __name__ == "__main__":
    sys.exit(main())
