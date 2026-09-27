# #3163 — sentinel-r3: the access wall is down, the measurement never ran

Scope: items 1-4 of #3163 (pull and serve, Tier A zero-token smoke, cold
scoring on the #3087 driver, record in the comparison matrix). The licence
blocker is gone — Niklas accepted the Glyph Proprietary License and supplied an
authorized read token — so the honest question is no longer "is this model
reachable" but "what was actually measured".

**Nothing was measured. There is no score for `sentinel-r3`, and none is
recorded in `docs/benchmarks/matrices/round7-cold-baseline.json`.** This note
records what *was* verified, and the exact commands that produce the score on
the host that can produce it. It deliberately contains no score, because
inventing or importing one is what the #3106 acceptance checklist forbids.

## 1. What the token actually unlocks (verified 2026-09-27)

Verified on this box with the token read from its `0600` file inside the
process. The token was never printed, echoed, logged, or passed on a command
line, and nothing in this repository contains it.

- `hf auth whoami` → `user=iamxore`.
- `model_info("glyphsoftware/sentinel-r3-gguf", files_metadata=True)` →
  `gated: auto`, and the three published files, with exact sizes:

  | file | bytes | size | LFS sha256 |
  |---|---|---|---|
  | `Sentinel-R3-Q4_K_M.gguf` | 16,547,401,600 | 15.41 GiB | `c2be33fb2ea64c29…` |
  | `Sentinel-R3-Q5_K_M.gguf` | — | 17.91 GiB | `0ad5dce04d0d6509…` |
  | `Sentinel-R3-Q8_0.gguf` | — | 26.63 GiB | `527018e91b8b041b…` |

  These confirm the roster's own estimates at
  `analysis/ghidra/benchmarks/corpus/models_round7.txt:35-37` (~16GB / ~19GB /
  ~29GB).

- A 1 MiB ranged GET of the Q4_K_M blob returned **HTTP 206**,
  `Content-Range: bytes 0-1048575/16547401600`, and the first four bytes are
  `GGUF`.

That last probe is the one that matters and is stronger than what the issue
claimed. `model_info` returning a file list only proves the *metadata* endpoint
answers; a gated repo can list files and still reject every byte of the blob.
HTTP 206 with GGUF magic proves the token authorizes the **weight download**,
which is the gate the roster comment at
`analysis/ghidra/benchmarks/corpus/models_round7.txt:37-40` was actually worried
about.

## 2. Why the pull did not happen here

`hf download --local-dir …` is not this project's pull mechanism, so the exact
command from the issue does not apply. Weights land in an Ollama blob store,
and the repo names that store in two places:

- `analysis/ghidra/benchmarks/corpus/preseed_ollama_config_blob.sh:28` —
  `OLLAMA_BLOB_DIR=/var/lib/docker/volumes/ghidra_ollama_models/_data/models/blobs`
- `analysis/ghidra/benchmarks/corpus/sweep_extra.sh:240` —
  `docker exec ghidra-ollama-1 ollama pull "$TAG"`

So the pull target is the `ghidra_ollama_models` Docker volume on the benchmark
host. It does not exist on this box. Enumerated:

| precondition | status here |
|---|---|
| `ghidra-ollama-1` container | absent (also absent as a stopped container) |
| `ghidra_ollama_models` volume | absent (`docker volume ls` has no match) |
| `ollama` binary | not installed |
| `/var/benchmarks` (round-7 clone at pin `32dbdeb1`, Tier B cache) | absent |
| GPU | none — no `nvidia-smi`; approved host is an RTX 4000 Ada, 20475 MiB, cc 8.9 |

**Disk, as a bare number.** `hf` would place a default-location download under
`~/.cache/huggingface/hub`, which is on `/home`:

```
/home   available 6,182,137,856 bytes (5.76 GiB)   needed 16,547,401,600 bytes (15.41 GiB)
        shortfall 10,365,263,744 bytes (9.65 GiB)
```

Per #3163's instruction to stop rather than half-download when the box lacks
disk, no full download was attempted. `hf` was pointed nowhere and
`--local-dir` was deliberately not invented.

## 3. A real gap the next operator will hit

`preseed_ollama_config_blob.sh` fetches the ollama-compat config blob with bare
`curl` and **no `Authorization` header** (lines 35 and 51). For an ungated repo
that is fine. For `glyphsoftware/sentinel-r3-gguf`, which is `gated: auto`, it
is not: the manifest and blob requests will be rejected, and the script will
report `NOMANIFEST` or `FETCHFAIL` before `ollama pull` is ever reached.

This is not speculative — it follows from the two unauthenticated `curl` calls
plus the `gated: auto` verified in §1. Whoever runs the pull needs the token
available to that step, most simply by running the pull with `HF_TOKEN` in the
`ghidra-ollama-1` environment. The zero-token property #3106 asked about still
holds, because it is a property of *serving*: once the blob is in the store,
`ollama run` reads it locally and never contacts HF. The token is needed once,
at pull time.

## 4. The three commands, and the hardware they need

Run on the benchmark host — the one with `ghidra-ollama-1` and the approved
RTX 4000 Ada. None can run here.

**Pull** (matches `sweep_extra.sh:236-246`, including the preseed):

```bash
printf '%s\n' 'hf.co/glyphsoftware/sentinel-r3-gguf:q4_k_m' \
  | bash analysis/ghidra/benchmarks/corpus/preseed_ollama_config_blob.sh
HF_TOKEN=… docker exec ghidra-ollama-1 ollama pull \
  hf.co/glyphsoftware/sentinel-r3-gguf:q4_k_m
```

**Tier A zero-token smoke** — the existing harness, unmodified, per
`analysis/ghidra/benchmarks/corpus/round7_smoke.sh:19-21`:

```bash
TAG=hf.co/glyphsoftware/sentinel-r3-gguf:q4_k_m \
  BASE=/var/benchmarks REPO=/var/benchmarks/APIARY-round7 \
  bash analysis/ghidra/benchmarks/corpus/round7_smoke.sh
```

The harness reads its model from `$TAG` and already stops the tag before and
after each tier, so the run is cold. Note the smoke sweeps tier A *and* tier B;
tier B additionally needs the 17-entry cache from `round7_cache.sh`.

**Cold scoring on the #3087 driver** —
`analysis/ghidra/benchmarks/corpus/round7_coldrun.sh` (its own header reads
`#3079 / #3087`):

```bash
LIST=/var/benchmarks/sentinel-only.txt \
  BASE=/var/benchmarks/round7-sentinel \
  REPO=/var/benchmarks/APIARY-round7 \
  GHIDRA_CACHE=/var/benchmarks/tierb-cache-round7 \
  bash analysis/ghidra/benchmarks/corpus/sweep_extra.sh
```

Driving `sweep_extra.sh` directly with a one-tag list is what #3163 asks for
("cold-score on the #3087 driver") and avoids re-measuring the whole roster.
It has the same preconditions `round7_coldrun.sh:54-66` enforces, and will
abort rather than run on the wrong vintage, a missing cache, or a busy card.

**Hardware required:** an NVIDIA RTX 4000 Ada Generation, 20475 MiB VRAM,
compute capability 8.9, driver 595.84 — the host pinned in
`analysis/ghidra/models/approved-models.json` under `approved_host`, and the
card every other row of the matrix was measured on. Q4_K_M at 15.41 GiB fits
20475 MiB at `CONTEXT 32768`; Q8_0 at 26.63 GiB does not, which is why the
roster pins Q4_K_M.

## 5. Where the score will be recorded

`docs/benchmarks/matrices/round7-cold-baseline.json` is the round-7 comparison
matrix. It is **not** edited here, deliberately:

- it is a completed aggregation — 367 records, 182 cells, snapshotted
  2026-09-13, and `round7_coldrun.sh:28-29` treats one vintage as one table;
- every row carries real `run_id`, `digest_short` and `sha256`, and the
  benchmarks README is explicit that provenance is load-bearing rather than
  hygiene. A row for a model that was never scored would assert a run that did
  not happen;
- its `_meta.state` already records `5 PULL_FAILED (UNMEASURABLE-pull)` for
  that run. `sentinel-r3` was added to the roster on 2026-09-09
  (`f9c0259b`, #3154), four days *before* the 2026-09-13 aggregation, carries
  no row, and its roster comment predicted exactly this failure — "pull needs an
  authorized HF token on the serving host or it fails the same way". It is
  therefore among those unmeasured tags. The per-tag reasons live in
  `/var/benchmarks/round7/failures.txt` (`sweep_extra.sh:243`), which is on
  the benchmark host and is not tracked in this repository.

When the commands in §4 run, the score belongs in that matrix as a new row with
its own run ids, or in a new table if the pin has moved — never inferred from a
comparable model.

## 6. Not asserted

- No score, no ranking, no placement for `sentinel-r3` anywhere.
- No claim that the model *serves* correctly. §1 proves the bytes are
  downloadable; nothing here proves `ollama run` produces coherent output, which
  is what the Tier A smoke in §4 exists to check. (The `deephat` candidate in
  `recreate-local-tags.sh:26-29` is the precedent for a GGUF that pulls fine
  and fails to serve.)
- No change to the roster line, which #3106 shipped and which is correct.
