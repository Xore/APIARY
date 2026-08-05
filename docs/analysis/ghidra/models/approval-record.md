# Approved local-model qualification record

This file is generated with the reviewed manifest. Model promotion is explicit; runtime drift never edits it.

| Slot | Exact model | Approval date | Archived report SHA-256 | Decision record |
|---|---|---|---|---|
| ghidra | `qwen3:14b@sha256:bdbd181c33f2ed1b31c972991882db3cf4d192569092138a7d29e973cd9debe8` | 2026-08-05 | `70c394e808ba4a2e4a187432e25f19457d941a7f2963667cdcf7bd016cef0b2d` | GitHub issue #636, correcting runtime.environment.OLLAMA_CONTEXT_LENGTH to match the already-deployed 32768 value (missed in the original #568 promotion; caught live by honeypot-model-drift.timer after install-analysis-host.sh was actually run end to end for the first time) |
| revdeck | `qwen3:14b@sha256:bdbd181c33f2ed1b31c972991882db3cf4d192569092138a7d29e973cd9debe8` | 2026-08-05 | `70c394e808ba4a2e4a187432e25f19457d941a7f2963667cdcf7bd016cef0b2d` | GitHub issue #636, correcting runtime.environment.OLLAMA_CONTEXT_LENGTH to match the already-deployed 32768 value (missed in the original #568 promotion; caught live by honeypot-model-drift.timer after install-analysis-host.sh was actually run end to end for the first time) |
| sessions | `qwen3:14b@sha256:bdbd181c33f2ed1b31c972991882db3cf4d192569092138a7d29e973cd9debe8` | 2026-08-05 | `70c394e808ba4a2e4a187432e25f19457d941a7f2963667cdcf7bd016cef0b2d` | GitHub issue #636, correcting runtime.environment.OLLAMA_CONTEXT_LENGTH to match the already-deployed 32768 value (missed in the original #568 promotion; caught live by honeypot-model-drift.timer after install-analysis-host.sh was actually run end to end for the first time) |

Rollback restores a specifically named backup; no latest/automatic selection is allowed.
