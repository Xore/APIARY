# Round 7 — train and requantise with Unsloth, serve with Ollama, score on a fresh three-slot benchmark

**Written** 2026-09-06 from live inspection of `homeserver`, every open benchmark
issue, and the current Unsloth / llama.cpp / Ollama documentation. Sits beside
`2026-09-05-1947-resume-plan.md`, which remains the authority on the #1947 sweep
itself; this plan starts where that one ends. Epic: **#3079**. Children:
**#3080–#3088** (§12).

**Why this file is in the repo.** `/mnt-1/benchmarks/` has been wiped once
(#2971) and mis-restored once; three phase scripts were lost because they were
never committed (#2985). Anything whose loss costs GPU-hours lives in git. Same
rule for everything this round produces: configs, manifests, run cards,
calibration-set hashes, decontamination reports.

---

## 1. Where we are — measured, not assumed (2026-09-06)

### 1.1 The #1947 sweep is finishing

| phase | what | state at 09:30Z |
|---|---|---|
| 1 | main roster, 38 models, both tiers | complete |
| 2 | extra roster, 52 entries | **settled 09:01Z — 49 measured, 3 unmeasured** |
| 3 | clean f16 ladder, 7 self-quant tags (#2245, `requant_sweep.sh` PR #3042) | **scoring now**: gemma-4-26B-A4B Q3/Q4/Q5 done, Ornith-35B IQ3_M/Q3_K_S/Q3_K_M/Q4_K_M in progress, ~2 h left |
| 4 | ghidra cold cohort (#1805-c) | measured; PR #2641 stays DRAFT, regenerated at synthesis |
| cold | full-roster cold re-run (`coldrun.sh`, PR #3058) into `1947cold/` | **armed** — `chain_cold.sh` fires when every phase-3 tag has both tier files; N=2 → 3 → 5, ~97 tags, **2–4 days of GPU** |
| 2.5 / 5 | harmony re-run (#2279), sessions + Rev·Deck slots | still blocked — `gptoss_rerun.sh` and `slots_sweep.sh` never rewritten (#2985) |

Result files: 184 Tier A, 178 Tier B in `1947full/`. The work area now also
holds `f16work/` (110 G of self-quant GGUFs), `keep/…:src` aliases so the
sweep's `ollama rm` no longer destroys weights, and a live `vram_samples.tsv`.

### 1.2 What the matrix says, and why it cannot answer the next question

Top of the field, Tier B / Tier A, 14 cases, max 69, contended regime, N=2:

| model | B | A |
|---|---|---|
| `huihui-qwen3.6-35b-a3b-abliterated:q3_k` (35 B MoE) | 64 | 66 |
| `Gemma-4-12B-OBLITERATED:Q4_K_M` (12 B) | 64 | 66 |
| `ThinkingCap-Qwen3.6-27B-MTP` | 64 | 65 |
| `observerx-qwen3.8-27b-heretic`, `huihui-qwen3.8-27b-abliterated`, `gemma-4-26B-A4B heretic:q3_k_m`, `Titus-CybersecurityLLM-v1.0` | 64 | 64 |
| `XORTRON 27B i1-Q4_K_M`, **`Ornith-1.0-35B heretic:Q4_K_M`** | 64 | 63 |
| `ravenx-cyberagent-35b:Q4_K_M` | 63/64 | 64 |
| … eleven more at 62–63 … | | |
| **`qwen3:14b` (incumbent, all three slots)** | **62** | **60** |
| `qwen2.5-coder:7b-instruct-q4_K_M` (#159 baseline) | 60 | 56 |

Two facts fall out of it:

1. **The top is saturated.** Sixteen models from 12 B dense to 35 B MoE sit
   within one point of each other. The self-quant ladder scored today says the
   same thing from the other side: gemma-4-26B-A4B at **Q3_K_M / Q4_K_M / Q5_K_M
   = 62 / 62 / 62** on Tier B. Bits do not move the score; the model does. A
   training gain of two or three points — the realistic size of one — is
   invisible on a 14-case rubric whose top is a plateau.
2. **The best rows spill.** `Ornith-1.0-35B` Q4_K_M is 22 GB on disk and runs
   6.7 min/run against 2.1 for a resident model doing identical work; the 27 B
   class at 17–19 GB is marginal at ctx 32768 where the weights budget is
   ~16–17 GB. Published quants stop where our card cannot use them — the exact
   gap #2245 was written about.

Neither is fixed by pulling one more tag. Both are the subject of this round.

### 1.3 Hardware and toolchain, verified live

| | state |
|---|---|
| GPU | RTX 4000 Ada, 20 475 MiB, `sm_89`, driver 610.57.04 (CUDA 13.3 UMD); the Quadro P2200 in the same box is the sandbox VM's and must never be handed to a training container |
| CPU / RAM | Xeon Gold 5220R 24c/48t; **93 GB, 6 × 16 GiB, channels E/F still empty** — the DIMM order from the resume plan has not happened |
| disk | `/var` 6.1 T free (Ollama blobs), `/mnt-1` 1.6 T free (work area) |
| Ollama | 0.32.13 in `ghidra-ollama-1`, `OLLAMA_MAX_LOADED_MODELS=1`, ctx 32768 — the qualified runtime; 0.33.3 requalification is #2969 |
| llama.cpp | `ghcr.io/ggml-org/llama.cpp:full` pulled 2026-09-05: `convert_hf_to_gguf.py`, `llama-imatrix`, `llama-quantize` (`--imatrix`, `--tensor-type`), `llama-gguf-split` |
| Hugging Face | token present on the host since 2026-09-05; cache at `~/.cache/huggingface` with the two ladder bases |
| training | **nothing** — no torch, no pip, Python 3.12 host; `nvidia-container-toolkit` 1.20 works (Ollama uses it) |

---

## 2. Decisions taken 2026-09-06 (operator)

| question | decision | consequence |
|---|---|---|
| which Unsloth capabilities | **all four** — SFT/QLoRA, RL (DPO → GRPO) with the scorer as reward, continued pretraining, dynamic requant (imatrix + per-tensor bits) | §3 maps each to an issue |
| "bigger models" | requant the 27–35 B class to GPU-resident **and** the 100 B+ RAM-offload class (123 B / 218 B) | §7 R2; GLM-4.6 357 B stays a measured rejection |
| training data | a separate, decontaminated corpus; real captured ES data allowed as input, never leaves the host; captured slices use a **local teacher**; synthetic slices may use **open-weight frontier teachers via OpenRouter** | §6 |
| compute | **local card only**, queued behind the cold re-run; above 14 B only at the VRAM edge (#3088, gated) | §9 |
| harness for round 7 | **main's 17-case / 79 rubric + pooled claims + all three slots, one new pin** | §8; `a99e765` numbers become historical context |

---

## 3. Unsloth versus Ollama — what each one is for

Ollama **does not train**, cannot make imatrix quants, and imports LoRA
adapters only for Llama and Gemma-2 architectures. Unsloth **does not serve**
production traffic. They are not alternatives; they are two ends of one
pipeline, with llama.cpp in the middle.

| capability | Unsloth (library, Apache-2.0; Studio/CLI AGPL) | llama.cpp (`:full` image) | Ollama 0.32.13 |
|---|---|---|---|
| fine-tuning: SFT, LoRA/QLoRA, full FT | yes — custom Triton kernels, ~2× speed / ~70 % less VRAM vs plain TRL | no | **no** |
| RL: GRPO / GSPO / Dr-GRPO / DAPO, DPO / ORPO / KTO / SimPO, reward models | yes, vLLM colocated for generation, "standby" weight sharing | no | no |
| continued pretraining (embeddings + lm_head trainable, separate embedding LR) | yes | no | no |
| long-context tricks | async gradient checkpointing to system RAM, tiled MLP (~40 % less activation memory), chunked cross-entropy, FP8 | — | — |
| merge adapter into base | `save_pretrained_merged` (16-bit; 4-bit merge is lossy) | `convert_lora_to_gguf.py` (adapter as GGUF LoRA) | `ADAPTER` in a Modelfile — Llama / Gemma-2 only |
| GGUF conversion | `save_pretrained_gguf` (clones and builds llama.cpp on first use — slow, fails mid-save) | `convert_hf_to_gguf.py` — the reliable path | `FROM ./dir` safetensors import for a fixed list of archs |
| quantisation | delegates to llama.cpp; publishes Dynamic 3.0 recipes and per-model `imatrix_unsloth.dat` | `llama-imatrix` + `llama-quantize --imatrix --tensor-type` — **the actual mechanism behind "dynamic" quants** | `ollama create --quantize` — q4_K_M / q4_K_S / q8_0 only, no imatrix |
| serving | vLLM for RL rollouts only | `llama-server` | **yes** — the qualified runtime, the drift-checked digest, the three slots |

### What "use Unsloth to the fullest" means here

| Unsloth capability | use in this round | issue |
|---|---|---|
| QLoRA on dynamic 4-bit bases (`unsloth-bnb-4bit`) | per-slot and multi-slot adapters on the incumbent's own weights and two other students | #3084 |
| continued pretraining (`UnslothTrainer`, `embed_tokens` + `lm_head`, `embedding_learning_rate`) | domain language shift on decompiler output and sessions before SFT; CPT-only rows measured | #3083 |
| `train_on_responses_only`, packing, fixed seeds | every SFT run | #3084 |
| async gradient checkpointing (`use_gradient_checkpointing="unsloth"`), tiled MLP | the 32 k-context ghidra adapter; the 27 B edge attempt | #3084, #3088 |
| DPO (`DPOTrainer` path) | injection-resistance pairs, rejection-sampled from the student | #3085 |
| GRPO with vLLM standby, programmatic rewards | the harness's own judges as reward on training-side prompts | #3085 |
| `save_pretrained_merged("merged_16bit")` | every export; never `merged_4bit` | #3080 |
| GGUF + auto-generated Ollama Modelfile | template diffed against the base's Modelfile before `ollama create` | #3080 |
| Dynamic-3.0 methodology (imatrix + per-tensor bits) reproduced with llama.cpp | ladders for the 27–35 B and 100 B+ classes, and the trained models' own ladders | #3086 |
| Unsloth's published `imatrix_unsloth.dat` | the second imatrix in the "our calibration set vs theirs" comparison | #3086 |
| gpt-oss-20b native MXFP4 training path | the one 20 B-class model trainable on 20 GB | #3084 |
| Trackio / run cards | every run's loss, reward, VRAM peak, tokens/s committed | all |

Not used, and why: Unsloth Studio (GUI; AGPL, and nothing here needs a UI),
multi-GPU (one card), vision / audio fine-tuning (all three slots are text),
Unsloth's in-library llama.cpp build (replaced by the pinned image).

---

## 4. The hardware envelope: what trains, what serves

### 4.1 Training — Unsloth's published minimums, applied to 20 GB

| params | QLoRA 4-bit | LoRA 16-bit | on this card |
|---|---|---|---|
| 7–9 B | 5–6.5 GB | 19–24 GB | QLoRA comfortable; 16-bit LoRA only at 7 B |
| **14 B** | **8.5 GB** | 33 GB | **QLoRA comfortable, incl. 32 k-context runs with tiled MLP** |
| 20 B (gpt-oss, MXFP4) | ~12.8–14 GB | — | **fits** via Unsloth's native path |
| **27 B** | **22 GB** | 64 GB | **over by ~2 GB** — the edge attempt (#3088) with activation offload, batch 1, short sequences |
| 32 B | 26 GB | 76 GB | no |
| MoE (26B-A4B, 30B-A3B, 35B-A3B) | **not recommended** by Unsloth in 4-bit (bitsandbytes gap); 16-bit LoRA 60 GB+ | — | **no** — these are requant targets, not students |

Source: Unsloth requirements page and the `faster-moe` guide (2026-09). GRPO on
14 B is stated feasible with vLLM colocated and standby mode.

So the **students** are `Qwen/Qwen3-14B` (the incumbent's exact weights),
`gpt-oss-20b`, and `Gemma-4-12B` (its derestricted variant is joint top of the
matrix from a 12 B). The 27–35 B class that leads the matrix is **served, not
trained**, on this card.

### 4.2 Serving — the weights budget has not changed

Ada 20 475 MiB; KV cache at the production ctx 32768 costs 3–5 GB on a
14–35 B model (`qwen3:14b`: 9.3 GB on disk, 14 GB resident; gemma-4-26B-A4B
Q5_K_M: 19 GB served at 5 %/95 % CPU/GPU). **Fully-resident weights budget:
~16–17 GB.** Every ladder in §7 brackets that line, because the question is
whether an imatrix + mixed-precision quant keeps a 35 B-class score inside it.

RAM offload stays allowed and reported (#1795 rule): the 218 B row served at
57 GB, 65 %/35 % CPU/GPU, ~50 min/run; the 123 B row at 44 GB. The two empty
DIMM slots (channels E/F — a bandwidth change, see the resume plan §2.4) make
those rows faster, not possible. They also matter for **training**: Unsloth's
gradient-checkpoint offload puts activations in system RAM.

---

## 5. The pipeline, step by step, with the container that runs each step

```
 (1) train        Unsloth container, Ada UUID only        adapter (LoRA safetensors)
 (2) merge        Unsloth container                       merged_16bit  (never merged_4bit)
 (3) convert      llama.cpp:full image                    convert_hf_to_gguf.py --outtype f16
 (4) calibrate    llama.cpp:full image, GPU               llama-imatrix -f calib.txt -o imatrix.dat
 (5) quantise     llama.cpp:full image                    llama-quantize --imatrix … [--tensor-type re=type] LEVEL
 (6) create       ghidra-ollama-1                         ollama create <tag> -f Modelfile   (template copied from the base, diffed)
 (7) score        pinned harness, cold protocol           record_baseline.py A/B · claims.py · evaluate-models.py sessions,revdeck
 (8) promote      model-governance.py promote             fresh approval record, one PR per slot, production verification
```

- Steps 2–3 are CPU work and can run **while the cold re-run holds the card**.
  Step 4 is GPU (fast, minutes per base). Steps 1, 5 (CPU), 7 queue behind the
  sweep (§9).
- Every export writes a `manifest.json`: base repo + revision, adapter sha256,
  merged sha256, GGUF sha256 per level, imatrix sha256 + calibration-set hash,
  both image digests, the Ollama digest after `create`. That is the training
  analogue of `approved-models.json`'s runtime block.
- The Modelfile diff at step 6 is mandatory. Unsloth writes a Modelfile with
  the *training* template next to the GGUF; production templates come from
  `ollama show --modelfile <base>`. A mismatch (Qwen3 thinking tags, Gemma turn
  markers, EOS) is the single most common cause of a fine-tune that scores
  below its base.

Owner of steps 1–6 as a script: **#3080** (`export_to_ollama.sh`).

---

## 6. Training data: the rules before the sources

### 6.1 The test set is off limits — all of it

The corpus's 17 programs (`xor_decode_loop` … `file_write_persist`), **at any
toolchain or optimisation level**, their decompiled text in `tierb-cache/`,
their rubric keyword groups, the adjudicated claim pool `tier-a-v1.json`,
every transcript under `docs/benchmarks/runs/`, and the `evaluate-models.py`
session / Rev·Deck fixtures are excluded from training data, calibration text
and RL prompts. **A decontamination report (exact hash + MinHash / 8-gram
near-duplicate scan, 0 hits) is a deliverable of #3082 and a precondition for
quoting any round-7 score.** A model that has seen the test set scores a
memory, not a capability.

### 6.2 Provenance rules, unchanged from the benchmark's own

| data | may it enter training? | may it leave the host? | where it lives |
|---|---|---|---|
| captured sessions / binaries (ES `honeypot-v*`, `ghidra-analysis-v1`) | yes, sanitised through the production `contracts.py` path | **never** — not git, not Hugging Face, not an API teacher | `/mnt-1/training/corpus-v1/` 0700 |
| synthetic programs written for this corpus | yes | yes (OpenRouter teacher), reviewed for TEST-NET / reserved names / fake credentials like the fixtures | sources committed; built artefacts on the host |
| REx86 (Zenodo 15420461, CC-BY-4.0) | yes — check its internal split first (#847) | public already | host |
| public RE corpora | only with a permissive licence, recorded | — | host |
| adapters / merged weights | — | private HF repo optional (operator, default off); mirrored per P8 of the resume plan | `/mnt-1/training/runs/` |

### 6.3 Teachers

- **Captured slices: local teacher only.** The best local models by the matrix
  (`Ornith-1.0-35B`, `Qwen3.6-35B-A3B`, `gemma-4-26B-A4B`), N=3, majority-agreed
  labels in the production contracts (`SessionAnalysis`, `ghidra-triage-v1`).
- **Synthetic slices: open-weight frontier teachers through OpenRouter**
  (DeepSeek V4, Qwen3.8 large, GLM-5.3, Kimi K3 — permissive licences, so
  distillation raises no terms question). N=2 agreement. Key lives on the host
  in a 0600 env file; never in the repo or an issue. Expected cost for a few
  thousand samples at ~7 k tokens each: tens of USD.
- What "frontier API teacher" is and is not: the teacher writes the target
  answers the student imitates. The Claude Code CLI can be scripted headless,
  but it is rate-limited, agentic and not built for bulk labelling; the
  vendor's Messages API would be the proper path — and vendor terms restrict
  training on outputs. Not chosen for this round.

### 6.4 Slices (owner #3082)

S1 sessions-captured · S2 ghidra-captured · S3 ghidra-synthetic (≥ 60 new C
programs across the rubric's behaviour families, built with `build_corpus.py`'s
toolchain × opt-level matrix) · S4 revdeck-rex86 · S5 injection pairs (new
phrasings, filtered by `injection_gate` / contracts / `polarity`) · S6 CPT text
· a 10 % dev split **by program / session**, never by row.

---

## 7. The experiment ladder

Each row is a measured artefact on the round-7 pin, with a named control.

| id | experiment | student / base | control | owner |
|---|---|---|---|---|
| **T0** | pipeline proof: REx86 adapter → merge → GGUF → Ollama | `unsloth/Qwen2.5-Coder-7B` @ `5762507e…` + the #160 adapter | the base at Q8_0 and Q4_K_M; #160's PEFT deltas | #3081 |
| **T1** | continued pretraining on S6, CPT-only rows | Qwen3-14B, gpt-oss-20b, Gemma-4-12B | untouched base, same quant | #3083 |
| **T2** | SFT QLoRA, one adapter per slot | the three students | untouched base, same quant | #3084 |
| **T2′** | T2 from the T1 checkpoint | where T1 finished | T2 | #3084 |
| **T3** | SFT QLoRA, one multi-slot adapter | the three students | T2 | #3084 |
| **T4** | DPO on S5 + rejection-sampled pairs | best T2/T3 per student | its SFT parent | #3085 |
| **T5** | GRPO, rewards = schema · injection gate · polarity · training-side pooled claims | best T4 per student | T4 | #3085 |
| **T6** | 27 B dense QLoRA at the VRAM edge | Qwen3.8-27B / Qwen3.6-27B derestricted | base, same quant — or a recorded OOM | #3088 (gated) |
| **R1** | calibration set + imatrix per base; ours vs Unsloth's published `imatrix_unsloth.dat` | — | — | #3086 |
| **R2** | dynamic ladders: Ornith-35B, Qwen3.8/3.6-27B, Qwen3.6-35B-A3B, gemma-4-31B; XORTRON 123 B, GLM-4.6-REAP 218 B | per base | phase-3 plain K-quant at matched file size; the as-published quant | #3086 |
| **R3** | every trained artefact at Q8_0 / Q6_K / Q4_K_M / imatrix IQ4_XS | — | base at the same level | #3086 recipe, #3080 script |

Reading rule: **a trained model is compared twice** — against its own base at
the same quant (isolates training) and against the incumbent (isolates the
promotion decision). **A requant is compared twice** — against the as-published
quant and against phase 3's plain level at matched size (isolates the recipe).

---

## 8. Round 7 — the benchmark (owner #3087)

- **Pin.** `main` at the commit the round starts on; recorded in every result
  and the write-up; never moved mid-round. `resume_phases.sh`-style guard.
- **Ghidra slot.** `record_baseline.py --tier A` / `--tier B`, 17 cases / 79,
  `tierb-cache` regenerated for 17 cases on the current `ghidra-ghidra-1`
  (`GHIDRA_VERSION` exported — #2983), injection gate v3 paired verdicts,
  **plus** pooled-claims scoring with `claims.py` against `tier-a-v1.json`
  extended by this round's adjudication (state `pool_version`).
- **Sessions and Rev·Deck.** `evaluate-models.py --slots sessions,revdeck` —
  #1947 phase 5, finally, as `slots_sweep.sh` committed beside the corpus
  scripts (closes that leg of #2985).
- **Protocol (PR #3058, unchanged).** Cold slot; `STOP_WORKERS=1`; N=2 → 3 → 5
  with `UNRESOLVED`; `UNMEASURED` / `UNMEASURABLE` markers, never zeros;
  `keep_and_sample.sh`; `uptime` per run; `KEEP_WEIGHTS_ABOVE_GB`; transcripts
  committed for synthetic runs, outside the repo for captured ones.
- **Rows.** Controls (`qwen3:14b`, the #159 baseline, the cold matrix's top 8
  re-scored on the 17-case pin) + every T/R artefact above.
- **Decision metric** (#2245 step 4): within noise on quality at better decode
  speed, or better quality at equal speed; `schema_ok` ≥ base; injection gate
  `resisted` on every injection case; no polarity regression; the slot's
  `evaluate-models.py` gates green. Winners promote only via
  `model-governance.py promote` with a fresh approval record — never a hand
  edit — one PR per slot, then verification on documents indexed *after* the
  deploy (the #1947 body's own lesson).
- **Write-up.** `docs/benchmarks/<date>-round7-results.md`: one table per slot,
  both comparisons per row, residency and speed columns, the injection axis per
  the v3 protocol, decontamination pointer, pin, pool version, Ghidra cache key,
  uptime range. #1804, #2245, #356/#1523 updated with what the round settled.

---

## 9. Sequencing against one GPU

```
 today      phase 3 scoring finishes (~2 h) → chain_cold.sh fires the cold re-run (2–4 days)
 no GPU     #3080 toolchain (build, no smoke test yet) · #3082 corpus v1 build + S3 OpenRouter labels
            · #3081 merge + convert (CPU) · #3086 calibration sets · #3087 drivers written
 GPU frees  #3080 smoke test · #3082 local-teacher labels · #3081 scoring
            · #3086 imatrix + ladders (short) · #3083 CPT · #3084 SFT · #3085 DPO → GRPO
            · #3087 scores every artefact as it lands, one pin, cold
 gated      #3088 27 B edge attempt
```

Rules that make this safe:

1. **Every chain waits on a positive condition.** `chain_round7.sh` waits for
   "every cold roster tag has both tier files or `UNMEASURED`, and no
   `coldrun.sh` / `sweep_extra.sh` / `record_baseline.py` is alive" — the
   `chain_cold.sh` pattern — never on `nvidia-smi` looking idle. Two waiters on
   "idle" fire in the same poll window and double-book the card.
2. **The training container has no restart policy and exits between runs.**
   `nvidia-smi --query-compute-apps` empty is part of every leg's completion
   check; the cold protocol assumes an empty card.
3. **Training legs run sequentially in the same window**, and the chain log
   records which leg holds the card and since when.
4. **Nothing above stops the cold re-run.** Its numbers are the regime-uniform
   baseline the round-7 comparison needs.

Wall-clock, to be measured not assumed: tokens/s per student on this card is
the first number #3083 records, and it decides how much CPT and SFT are
affordable. Order-of-magnitude expectations from Unsloth's figures on Ada-class
cards: a 14 B QLoRA epoch over a few thousand 8 k samples is hours, not days;
CPT over 100 M tokens is a day-scale job.

---

## 10. Toolchain details and the pitfalls that are already known

- **Image.** `unsloth/unsloth` on Docker Hub (PyTorch 2.11 + CUDA 12.8, SASS
  includes `sm_89`, driver ≥ 570.26 — we run 610.57). Pin **by digest**. If it
  lags its own docs, build from a pinned `nvidia/cuda:12.8` base with
  `uv pip install "unsloth==2026.9.2" vllm --torch-backend=auto` (2026.9.2 is the
  PyPI release of 2026-09-02; the `v0.1.80x-beta` GitHub releases are Unsloth
  Studio, a different product) and record every resolved version in
  `analysis/ghidra/training/TOOLCHAIN.md`.
- **GPU wiring.** `device_ids: ["GPU-18a00c7e-670a-c305-a2aa-20e3a71917a3"]`
  exactly as `docker-compose.ghidra.gpu.yml` does — never `--gpus all` (#1539).
  `--ipc=host --ulimit memlock=-1`. No docker socket, no `/var/dockge`, no
  sandbox mounts; loopback only; `HF_HOME=/mnt-1/hf-cache`.
- **Ollama arch support.** `qwen3_5_moe` (Ornith) and `gemma4` GGUFs already
  run on 0.32.13 here — measured. Newer archs (Qwen3.8-Next, GLM-5.x) need
  0.33.x+; that is #2969's requalification, not this round's business. Ollama
  pulls single-file GGUF repos from Hugging Face directly but **rejects sharded
  GGUFs** — `llama-gguf-split --merge` first, then `ollama create`.
- **`merged_4bit` is lossy.** 16-bit merge, then quantise the GGUF.
- **Chat template / EOS mismatch** is Unsloth's own #1 cause of degraded
  exports. Qwen3: production runs `thinking: false`; train non-thinking data
  with `enable_thinking=False` in the template and keep the template in the
  Modelfile. Gemma-4: the vision tower is dropped on GGUF export ("Has vision
  encoder, but it will be ignored") — fine, all three slots are text.
- **New tokens / formats**: `embed_tokens` and `lm_head` in `target_modules`
  with `embedding_learning_rate` ≈ lr/10 (CPT path); drop `embed_tokens` first
  on OOM.
- **Unsloth's in-library GGUF save clones and builds llama.cpp** on first use.
  Not on this host: the pinned `:full` image does steps 3–5.
- **Ollama `ADAPTER`** imports Llama / Gemma-2 safetensors adapters only.
  Merging is the rule for every student here.
- **`ollama create --quantize`** is q4_K_M / q4_K_S / q8_0 from F16/BF16/F32
  input, no imatrix — never the quality path.

---

## 11. Risks

| risk | mitigation |
|---|---|
| training data contaminated with the test set | #3082's decontamination scan, 0 hits, committed before any score is quoted |
| a fine-tune scores below its base because of the template, not the training | Modelfile diff in `export_to_ollama.sh`; T0 proves the seam before any training |
| the round's gains are inside the noise | 17-case rubric + pooled claims + three slots; N=2 → 3 → 5; every row vs its own base at the same quant |
| GPU double-booking corrupts the cold matrix | positive-condition chains; no restart policy; empty-card check per leg |
| captured data leaks via a teacher API or a Hub push | captured slices are local-teacher only and never leave `/mnt-1/training`; the OpenRouter key lives in a 0600 host file |
| a sharded or wrong-template GGUF fails silently in Ollama | `manifest.json` per export, `ollama show --modelfile` diff, one-case smoke score per artefact |
| work lost to another work-area wipe | everything committed except weights; weights mirrored per the resume plan's P8 |
| Ollama 0.32.13 cannot load a newer student's GGUF | students are Qwen3 / gpt-oss / Gemma-4 — all already served on 0.32.13 here; anything else goes through #2969 first |

---

## 12. Issue map

| issue | round7 | what | GPU |
|---|---|---|---|
| **#3079** | epic | this plan, the decisions, the order | — |
| #3080 | 1 | Unsloth toolchain container, Ada-only wiring, `export_to_ollama.sh`, smoke test | smoke only |
| #3081 | 2 | T0 — REx86 adapter through the whole seam, scored vs base and #160 | scoring |
| #3082 | 3 | corpus v1: six slices, dev split, teachers, decontamination report | local-teacher labels |
| #3083 | 4 | T1 — continued pretraining, CPT-only rows | yes |
| #3084 | 5 | T2 / T2′ / T3 — SFT QLoRA per slot and multi-slot, exported at equal bits | yes |
| #3085 | 6 | T4 / T5 — DPO then GRPO with the harness's judges as reward | yes |
| #3086 | 7 | R1 / R2 / R3 — calibration sets, dynamic ladders incl. 100 B+, the trained models' ladders | yes |
| #3087 | 8 | round-7 driver: new pin, three slots, cold protocol, `chain_round7.sh`, write-up, promotion | yes |
| #3088 | 9 | T6 — 27 B dense at the VRAM edge, or a recorded rejection | gated |

Dependencies: 1 → {2, 4, 5, 6, 7}; 3 → {4, 5, 6}; 2 green before 5 scores;
5 → 6; 8 consumes every row; 9 gated on 5's result and the operator.

Related, unchanged: #1947 (the matrix this extends), #2245 (the plain ladder =
this round's control), #1804, #2279 / #2985, #356 / #1523, #2969, #3023.

---

## 13. Still needed from the operator

1. **OpenRouter key** on the homeserver in a 0600 env file (path chosen by
   #3082; never in the repo). Needed for the S3 labels only.
2. **2 × 16 GiB DDR4-2933/2666 registered ECC RDIMM** into `DIMME1` + `DIMMF1`
   (resume plan §2.4). Not a blocker; it makes the 100 B+ rows and the
   activation-offload training faster.
3. **Private Hugging Face repos** for adapters — default **off**; say so if
   wanted. Captured-derived data never goes there regardless.
4. **The 27 B edge attempt (#3088)** opens only on your call after #3084's
   first result.

---

## 14. Runbook

```bash
# is the card free, and who holds it
ssh homeserver 'nvidia-smi --query-compute-apps=pid,used_memory --format=csv; \
  pgrep -af "coldrun.sh|sweep_extra.sh|record_baseline.py|requant_sweep.sh|chain_"'

# state of the cold re-run (must be complete before any training leg)
ssh homeserver 'tail -5 /mnt-1/benchmarks/coldchain.log; ls /mnt-1/benchmarks/1947cold/ | wc -l'

# training work area layout (created by #3080)
#   /mnt-1/training/corpus-v1/   /mnt-1/training/calib/   /mnt-1/training/runs/<run>/
#   /mnt-1/training/pools/train-v1.json      /mnt-1/hf-cache/
# operational copies of every script live beside the benchmark ones in /mnt-1/benchmarks/
# and are committed under analysis/ghidra/training/ and analysis/ghidra/benchmarks/corpus/

# export one run to Ollama (owner #3080)
ssh homeserver 'bash /mnt-1/training/export_to_ollama.sh /mnt-1/training/runs/<run> <tag> Q8_0 Q4_K_M IQ4_XS'
ssh homeserver 'docker exec ghidra-ollama-1 ollama show --modelfile <tag>'   # diff against the base's

# score a tag on the round-7 pin (owner #3087)
ssh homeserver 'cd /mnt-1/benchmarks && LIST=/mnt-1/benchmarks/models_round7.txt RESULTS=/mnt-1/benchmarks/round7 \
  STOP_WORKERS=1 bash round7_sweep.sh'
```

---

## 15. How agents work this round — grit, rtk, gh

Three tools, not one. Every child issue is worked under all three.

### grit — mandatory for any parallel work in this repository

`grit` 0.4.0 is installed and initialised at the repository root (index in
`.grit/registry.db`). It locks at the **function / symbol level**, so two agents
editing different functions of `sweep_extra.sh` or `train.py` never collide,
and it replaces bare `git worktree add` isolation. One grit agent name per
subagent (`issue-3080-coder`, `issue-3082-corpus`, …), never shared.

```bash
grit gc                                                # session start: clear expired locks
grit status                                            # who holds what
grit symbols --file 'analysis/ghidra/benchmarks/corpus/*'   # or analysis/ghidra/training/*
grit plan  -a issue-<N>-coder -i "<intent>"            # search + dependencies BEFORE claiming
grit claim -a issue-<N>-coder -i "<intent>" <file>::<symbol> [<file>::<symbol> …]
#   --with-deps  read-locks callees        --queue  wait on a contested symbol
#   creates .grit/worktrees/issue-<N>-coder/ — edit ONLY the claimed symbols, ONLY there
grit heartbeat -a issue-<N>-coder --ttl 900            # long-running legs
grit done -a issue-<N>-coder                           # auto-commit, rebase, serialized merge, release
```

- The orchestrator claims **before** dispatching a coder, from the symbols the
  fix will touch; `grit plan` first so dependency read-locks do not surprise
  another agent.
- `grit done` is never issued from two orchestrator threads at once. If it
  reports uncommitted changes in the main checkout, commit or set them aside
  there first; the agent branch is kept.
- New files have no symbols yet: claim the neighbours you touch (the compose
  file, the README, the sibling script), and **re-run `grit init` after the
  merge** so the new symbols are indexed for the next agent.
- Relative-path dependencies (`path = "../x"`, `-r ../requirements.txt`) break
  inside `.grit/worktrees/`; use absolute paths.
- After any large merge to `main`, `grit init` again.

### rtk — every shell command goes through it

The shell hook rewrites every command to its `rtk` form (`git status` →
`rtk git status`) and cuts the output to what matters. Do not bypass it.
`rtk proxy <cmd>` only when the raw, unfiltered output is genuinely needed
(reading a whole run log); long outputs go to a file under the job's tmp
directory and are read selectively. `rtk gain --history` goes into the
end-of-issue report so the token cost of the work is visible.

### gh — the repository conventions, unchanged

Check `gh issue view <n>` **and** `gh pr list --search "<n>"` before claiming
(the repo is worked through several tools at once); claim with the
`in-progress` label, assignee, and a comment; post a status comment at every
milestone; push → PR → wait for CI → `gh pr merge <n> --squash --delete-branch`
on green; `Closes #N` in the commit; file a new issue for anything out of scope
instead of widening the task; audit issue state at the end of a batch; never
mention AI tooling in commits, PRs, comments or issues; never put credentials or
real production domains in an issue.

### Concurrency

**At most two agents at once**, each with its own grit agent name and its own
issue. Only one of them may hold the GPU, and only through the positive-condition
chain of §9.

---

The one sentence to keep: **Unsloth makes the weights, llama.cpp makes the
bits, Ollama serves them, and the benchmark decides — on a pin, cold, with the
test set never seen — and the agents doing it claim with grit, run through rtk,
and ship through gh.**
