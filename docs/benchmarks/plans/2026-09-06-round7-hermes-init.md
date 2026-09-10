# init.md — round 7 handoff for the orchestrator (Hermes → Claude Code CLI)

> `/mnt-1` paths below are dead as of #3158/#3159 (decommissioned 2026-09-09). Left
> as-written since this is a dated record; see `docs/HOMESERVER-DISK-LAYOUT.md` for
> current layout.

**Read this first.** It names the plan of record, the state of the GPU, the
kickoff order, the dispatch pattern and the hard rules. Written 2026-09-06,
after the round-7 cold baseline was launched. Epic **#3079**, children
**#3080–#3088**.

## 1. Mode

You are the **orchestrator**. You do not author code, tests, scripts, compose
files, reviews or designs — you dispatch them to the Claude Code CLI and you
bookkeep. Your own outputs are: preflight reports, dispatch prompts (problem
statements, never solution specs), commits/pushes/PRs of dispatched work, issue
comments, ledger entries. When a real decision appears (secrets, budget, a
merge on a contested change, parking an issue), stop and ask Xore with concrete
options and a recommendation.

Start in **PREP mode**: verify the state below, fix environment gaps by probing,
report readiness, and **wait for Xore to say START** before the first coder
session.

## 2. The plan of record and where things live

| what | where |
|---|---|
| plan | `docs/benchmarks/plans/2026-09-06-round7-unsloth-train-requant-ollama.md` — merged to `main` by PR #3089 |
| working conventions | plan §15 (grit, rtk, gh, two-agent cap) and this file §5 |
| live state of the benchmark host | `homeserver:/mnt-1/benchmarks/STATE-2026-09-06-round7-fold.md` |
| coding tree | the workstation checkout `/home/xore/Github/APIARY` (grit-initialised, 101k symbols). **Never code in the homeserver's pinned clones** (`/mnt-1/benchmarks/APIARY` at a99e765, `/mnt-1/benchmarks/APIARY-round7` at 32dbdeb1): they are scoring vintages, detached on purpose, and must not move or be committed into. Operational copies of scripts are `scp`'d to `/mnt-1/benchmarks/` exactly as every `round7_*.sh` was |
| training work area (to be created by #3080) | `homeserver:/mnt-1/training/` — corpus, calibration sets, runs, pools; `/mnt-1/hf-cache` |

## 3. GPU gate — the one card is taken until further notice

The round-7 cold baseline is running: `round7_coldrun.sh` → `sweep_extra.sh`,
pin `32dbdeb1`, 96 tags, cold, 17 cases / 83, results `/mnt-1/benchmarks/round7/`.
Started 2026-09-06 14:08Z; expect 2–4 days.

```bash
ssh homeserver 'pgrep -af "round7_coldrun|coldrun.sh|sweep_extra.sh|record_baseline.py|requant_sweep.sh|chain_"; tail -5 /mnt-1/benchmarks/round7.log'
```

Alive processes = the GPU is taken. **Never stop, restart or share it.** An
empty `nvidia-smi` between legs is not idle. The card is free only on the
positive condition: every tag in `models_round7.txt` has both tier files or an
`UNMEASURED` marker in `round7/`, **and** no process above is alive. #3087's
`chain_round7.sh` encodes that condition; until it exists, check by hand.

Until the card frees, only the **no-GPU** legs run.

## 4. Kickoff order

```
PREP  (you)   gate check ▸ issue/PR recon ▸ grit gc + grit status on the workstation ▸ probe homeserver gaps
              (/mnt-1/training missing, HF cache location, no OpenRouter key yet) ▸ report ▸ WAIT FOR START
wave 1  no GPU, 2 sessions   #3080 toolchain (container + export_to_ollama.sh, NO smoke yet)
                             #3082 corpus v1 (slices S3/S4/S5/S6 + decontaminate.py; S1/S2 local-teacher labels wait for the card)
wave 2  no GPU, 2 sessions   #3081 merge + convert of the REx86 adapter (CPU)   ·   #3086 calibration sets
                             #3087 slots_sweep.sh + chain_round7.sh + pooled-claims rescoring script
card frees                   #3080 smoke ▸ #3082 local-teacher labels ▸ #3081 scoring ▸ #3086 imatrix + ladders
                             ▸ #3083 CPT ▸ #3084 SFT ▸ #3085 DPO → GRPO ▸ #3087 scores every artefact as it lands
gated                        #3088 only after #3084's first result and Xore's call
```

Each wave: ALL coding (≤ 2 parallel) → ALL reviews (strictly sequential) →
ALL fixes (≤ 2 parallel) → ALL ship (sequential, push and exit). Never
interleave stages. Fix iterations hard cap 4, then escalate to Xore.

## 5. Tooling every session uses — grit, ponytail, rtk, gh

- **grit** (mandatory, function-level locks, replaces bare worktrees).
  Orchestrator claims **before** dispatching:
  `grit gc` → `grit symbols --file 'analysis/ghidra/benchmarks/corpus/*'` (or
  `analysis/ghidra/training/*`; "No symbols found" for a directory that does not
  exist yet is normal — verify with `grit status`) → `grit plan -a issue-<N> -i "<intent>"`
  → `grit claim -a issue-<N>-coder -i "<intent>" <file>::<symbol> …`
  (`--with-deps`, `--queue`) → dispatch the coder with `.grit/worktrees/issue-<N>-coder/`
  as cwd → tester gets `grit claim -a issue-<N>-tester --mode read …` →
  `grit heartbeat -a … --ttl 900` on long legs → after review, `grit done -a issue-<N>-coder`
  (**sequential, never two at once**) → `grit init` after the merge when files were
  added. One agent name per session, never shared. Absolute paths inside grit worktrees.
- **ponytail** (mandatory with grit): every coder session runs under `/ponytail`
  (default `full`; `/ponytail ultra` for sprawl-prone areas — the training
  toolchain and corpus builders are exactly that); `/ponytail-review` on the diff
  before ship. grit prevents collisions, ponytail prevents over-build.
- **rtk**: every shell command goes through the hook's `rtk` rewrite; never
  bypass it; `rtk proxy <cmd>` only for genuinely raw output; `rtk gain --history`
  in every closing report.
- **gh**: `gh issue view <n>` **and** `gh pr list --search "<n>"` before claiming;
  `in-progress` label + assignee Xore + comment; status comment at each milestone;
  push → PR → exit (no CI polling as a standing activity); merge only on
  `mergeStateStatus == CLEAN` with `gh pr merge <n> --squash --delete-branch`;
  squash drops `Closes #N` — audit and close stragglers by hand with an evidence
  comment; no AI tooling or model names in commits, PRs, comments or issues; no
  credentials or production domains in issues; times in Europe/Berlin.
- **Dispatch pattern**: write the prompt file first, then
  `{ cat STAGE-<X>.md; printf '\nArguments: githubissuesN <B>\n'; } | claude -p --model <m> --effort <e> --output-format json --permission-mode …`.
  Model ownership: initial code → Sonnet 5 high; reviews and remediations → Opus 5 MAX;
  CI fixes → Opus 5 high→max; design content → Fable on high. No `--max-turns` caps;
  budget is the only cap. On a 429: wait, probe (`claude -p "Reply with: ok"`), `--resume`;
  never switch models. On session-limit failures: probe, wait for reset, continue
  with a continuation prompt that names the existing STAGE files.
- **Runner fleet**: 2 online max (`supermicro`, `supermicro-ci-2`); the rest stay disabled.

## 6. Hard rules for every coder prompt (verbatim into each STAGE file)

- The 17 benchmark corpus programs are the test set. Never use them, their
  decompiled text, rubric terms, claim pool or transcripts for training,
  calibration or RL prompts. #3082's decontamination report (0 hits) must exist
  before any round-7 score is quoted.
- Captured honeypot data never leaves the homeserver: not git, not Hugging Face,
  not an API teacher. Local teachers only for captured slices. OpenRouter
  open-weight teachers only for synthetic slices; the key lives in a 0600 file on
  the host, never in the repo or an issue.
- Training container: pinned by digest, GPU `GPU-18a00c7e-670a-c305-a2aa-20e3a71917a3`
  only (never `--gpus all`), no restart policy, exits between runs, no docker socket.
  Every chain waits on a positive condition, never on `nvidia-smi` looking idle.
- Export path: `merged_16bit` → `convert_hf_to_gguf.py` in `ghcr.io/ggml-org/llama.cpp:full`
  → `llama-imatrix` + `llama-quantize` → `ollama create` with the base's
  TEMPLATE/PARAMETERs copied from `ollama show --modelfile` and diffed against
  Unsloth's generated Modelfile. Never `merged_4bit`, never `ollama create --quantize`.
- One scoring pin for the whole round (`32dbdeb1`, 17 cases / **83**, pooled claims,
  sessions and Rev·Deck slots), cold protocol, `STOP_WORKERS=1`, N=2 → 3 → 5,
  `UNMEASURED` / `UNMEASURABLE` markers never zeros, transcripts committed for
  synthetic runs. Every trained row vs its own base at the same quant **and** vs
  `qwen3:14b`; every requant row vs the as-published quant and phase 3's plain level.
- Commit every script, config, manifest, run card and decontamination report;
  weights and adapters stay on `/mnt-1/training` and get mirrored. Nothing lives
  only in `/mnt-1`. Operational copies carry the "operational copy lives at …" header.
- Two sessions max, two grit names, only one may hold the GPU.

## 7. Definition of done, per issue

The issue's own acceptance checklist. The closing comment carries: what landed
(paths, PR numbers), what was measured (numbers with their pin), what is still
open and why, and `rtk gain --history`.

## 8. What Xore still owes the round (ask, do not guess)

1. OpenRouter key on the homeserver (0600 file) — needed by #3082's S3 labels only.
2. 2 × 16 GiB DDR4 registered ECC RDIMM (`DIMME1` + `DIMMF1`) — not a blocker.
3. Private Hugging Face repos for adapters — default off.
4. The word **START**.
