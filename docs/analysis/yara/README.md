# YARA scanner sidecar

> **Location:** this is the operator doc, not the tree itself. The scanner
> lives at `arcane/home/honeypot-payload-analysis/analysis/yara/` — moved
> there by #1502 when the honeypot-payload-analysis stack became
> self-contained. Every path below is relative to that directory, and
> compose commands run from `arcane/home/honeypot-payload-analysis/`.
> `scripts/check-yara-corpus.sh` knows both locations already.

A networkless, non-executing scanner over hash-addressed captures. `scanner.py`
walks the payload roots on an interval and writes `results.json`; the dashboard
reads that file and never runs yara itself.

The container is `network_mode: none`, `read_only: true`, and rules are baked in
at image build (`COPY rules /rules`). It cannot fetch anything at runtime — by
design, since it reads live malware.

## The rule corpus

| Path | Origin |
| --- | --- |
| `rules/honeypot.yar` | Ours. Edit freely |
| `rules/upstream/` | Vendored from [`Xore/Honeypot`](https://github.com/Xore/Honeypot) `yara-rules/`. **Do not edit** — changes here are lost on the next sync |
| `rules/index.yar` | Generated include list. What the scanner loads |
| `rules/upstream.lock` | The pinned upstream commit and a hash of the vendored tree |
| `rules/upstream/DROPPED` | Upstream files this corpus does **not** include, with yara's reason |

`scripts/check-yara-corpus.sh` enforces in CI that `rules/upstream/` still
matches the lock and that `index.yar` names exactly the vendored files. It
skips cleanly if nothing has been vendored.

## Updating the corpus

```bash
arcane/home/honeypot-payload-analysis/analysis/yara/sync-yara.sh   # --dry-run to see what would change
```

Needs `yara` or `yarac` on PATH; it refuses to run without one. Then rebuild the
sidecar so the new rules are actually loaded. Compose resolves the service name
only from inside the stack directory:

```bash
cd arcane/home/honeypot-payload-analysis
docker compose build yara-scanner && docker compose up -d yara-scanner
```

### Why files get dropped

yara loads a rule set or refuses to start — one bad rule disables scanning
entirely rather than degrading to "everything except that rule". So the sync
compiles every file before adopting it and drops the ones that fail, rather than
handing the scanner a corpus that will not load. Two things get a file dropped:

- **It does not compile.** As of the pinned commit, four of upstream's six
  curated files declare strings their conditions never reference, which yara
  treats as an error. `rules/upstream/DROPPED` has the details; they come back
  automatically once upstream fixes them and the sync is re-run.
- **It redefines a rule name** already used by `honeypot.yar` or an
  earlier-sorted upstream file. A duplicate identifier is also a hard error.

Validation uses the same yara the sidecar ships (Alpine's), because "does it
compile" is only a useful answer from the compiler that will load it.

## Reading the results

`results.json` carries two fields beyond the per-sample matches:

- `corpus_sha256` — hashes every rule file, not just `index.yar`. Since the
  index is a list of filenames, `rules_sha256` would not move when upstream
  changed every rule but no filename.
- `auto_rules` — names defined under `upstream/auto/`. These are generated from
  observed samples and are broad by construction (`AutoGen_Exe` fires on three
  of twenty stock .NET strings, so it matches most .NET binaries). Treat an auto
  hit as "seen something like this before", not as a family identification.
