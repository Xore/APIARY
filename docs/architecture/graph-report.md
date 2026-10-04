# Knowledge graph — index

[← back to docs map](../README.md) · [System architecture](../ARCHITECTURE.md)

An auto-generated map of this repository: every file, function, type and test,
grouped into communities by what it touches. Two artifacts are published here:

| Artifact | What it is |
|---|---|
| [`graphify-out/graph.html`](../../graphify-out/graph.html) | explorable graph viewer — open it in a browser, search, filter by community |
| [`graphify-out/2026-10-04/GRAPH_REPORT.md`](../../graphify-out/2026-10-04/GRAPH_REPORT.md) | the dated human-readable report: hubs, communities, cohesion, suggested questions |

**Generated:** 2026-10-04 from commit `d6bc1c61`.

**Scope:** 13,087 files, ~62.4M words, 189,112 nodes, 371,885 edges, 9,070
communities. AST-only extraction — no model was called, so the run cost
nothing and node identity is exact. ~95% of edges are extracted from source,
5% inferred at 0.85 average confidence.

The viewer is a **community meta-graph**, not all 189k nodes: anything above the
5000-node visualization limit is aggregated one node per community, so you get
1101 nodes and 1,217 cross-community edges. Node size is community member count.
Click a node to expand what lives inside it.

## What is not published

The run produces ~890 MB. Only the two reader-facing artifacts above are
committed; the rest is regenerable and stays out of git.

| Path | Size | Why not |
|---|---|---|
| `graphify-out/graph.json` | 282 MB | the full graph. Too large for git; `graphify path` / `explain` read it locally |
| `graphify-out/cache/` | 311 MB | AST cache, rebuild index. Machine-local, per-machine derived |
| `graphify-out/2026-10-*/graph.json` | 282 MB | same, per run date |
| `graphify-out/manifest.json` | 3.4 MB | a path→metadata index of every scanned file. Nothing consumes it, and `graphify update` rewrites it — a 3.4 MB diff per run for a file no reader opens |
| `graphify-out/2026-10-*/manifest.json` | 3.4 MB | same, per run date |
| `.graphify_*.json`, `*.sig`, `.graphify_root` | ~7 MB | cluster labels, signature and analysis sidecars. Intermediates, not reader output |

Everything above is listed in `.gitignore`, so a `git add -A` cannot pull a
282 MB blob into the public repository.

## Regenerating

```sh
graphify update .     # AST-only, no API cost
```

`graphify update .` re-extracts code files and rewrites `graph.json`,
`GRAPH_REPORT.md` and the viewer. Semantic extraction (the doc/paper/image
corpus) is a separate, model-backed pass — this repo's graph is AST-only, so a
plain `update` is the whole cost.

If you change code, re-run it. The report records the commit it was built from
so staleness is checkable:

```sh
git rev-parse HEAD                       # compare against the stamp in the report
```

To rebuild only the viewer from an existing `graph.json`, without re-extracting:

```sh
graphify export html --graph graphify-out/graph.json \
  --labels graphify-out/.graphify_labels.json --node-limit 5000
```

## Caveats

- **The graph is stale by construction once code lands.** Both published
  artifacts carry the commit they were built from. Treat them as a map of
  `d6bc1c61`, not of `HEAD`.
- **Vendored trees dominate the corpus.** `sandbox/ghosts/vendor/` and the
  bundled frontend libraries appear as their own communities. They are real
  nodes, not noise, but they are not ours to maintain.
- **Community names are labels, not truth.** `.graphify_labels.json` is
  regenerated per run and the assignment shifts when the graph shifts.