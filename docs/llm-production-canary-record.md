# Local LLM production U1 canary record

> Date: 2026-08-01
>
> Scope: issue #83, authorized bounded U1 session analysis only
>
> U2 payload analysis and daily reports: **disabled**

The one-shot canary ran on the homeserver against captured Cowrie session
events. This record intentionally contains no captured commands, source
addresses, session identifiers, credentials, or model narrative derived from
the capture.

## Pinned contract

- Ollama image:
  **ollama/ollama:0.32.0@sha256:57f573b47f1f71ebb445789f279fe3e596a8beab182f7cf486db9205bad87c5a**
- model: **qwen3.5:4b**
- model digest:
  **2a654d98e6fba55d452b7043684e9b57a947e393bbffa62485a7aac05ee4eefd**
- worker/schema/prompt: **0.3.0 / 2 / session-v2**
- inference: 8192 context, thinking disabled, temperature 0, seed 66
- canary bounds: 2,000 events per cycle, one model job, one result, 30-second
  keep-alive

## Acceptance results

| Check | Sanitized observation | Status |
|---|---|---|
| Bounded execution | One cycle read 2,000 events and wrote exactly one U1 result; payload and report counts were zero | PASS |
| Output contract | Strict JSON/schema validation passed; prompt was not truncated; completion ended normally | PASS |
| Factuality | Password change, SSH-key persistence, and Linux ATT&CK mappings were distinguished correctly after deterministic grounding | PASS |
| Credential redaction | Every derived-state command using chpasswd contained the redaction marker; no credential value was retained | PASS |
| Model pin | Runtime digest matched the approved digest exactly | PASS |
| Latency/tokens | 2.728 seconds; 1,013 prompt tokens and 94 output tokens | PASS |
| Isolation | All three attached networks were internal; worker had zero ports, zero mounts, read-only rootfs, and all capabilities dropped | PASS |
| Idle unload | Ollama reported no loaded models after 35 seconds; GPU compute memory returned to 0 MiB | PASS |
| Ingestion independence | Elasticsearch stayed healthy; Filebeat and ML stayed running; raw event ingestion continued advancing | PASS |
| Rollback | Exited worker and its temporary project network were removed; the one advisory result was retained | PASS |

## Defects found and closed during the canary

1. Cowrie's live schema stores container identities in **event.sensor**;
   stable **honeypot.eventid** values are now used to select session events.
2. Elasticsearch 8.13 returned no data-stream hits with **_id** as a sort key.
   The bounded idempotent canary uses timestamp ordering; issue #132 owns a
   stronger promoted cursor.
3. A **user:password piped to chpasswd** form bypassed the original assignment
   redactor. The credential portion is now removed before state or inference.
4. The model confused a password change with password cracking. Prompt rules
   and deterministic correction now require actual cracking-tool evidence.
5. The model proposed Windows UAC bypass and ordinary SSH-session hijacking
   mappings for Linux persistence. Platform- and evidence-incompatible IDs
   are now removed, with grounded replacements where applicable.

The disposable derived indices were deleted between rejected runs. Raw
honeypot data streams were never modified. The final accepted advisory result
remains in **llm-analysis**; U2 and daily-report processing remain off.
