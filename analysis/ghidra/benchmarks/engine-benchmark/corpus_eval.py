#!/usr/bin/env python3
"""Score a local-LLM inference engine against the 32-case x86_64 slice of
analysis/ghidra/benchmarks/corpus/manifest.json -- the 8 original #144
REV_CASES x {gcc,clang}-x86_64 x {-O0,-O2}, stripped disassembly, no source
comments. Plain completion prompts ("Q: ...\\nA:"), no chat template -- #160
established the REx86 checkpoint this was written for is a base model with
no chat_template, and the same prompt shape works for any other base model.

See README.md in this directory for the full methodology and how to run
this against Ollama, llama.cpp (llama-server), and vLLM.
"""
import argparse
import json
import sys
import urllib.request

CASES8 = [
    "error_handling_alloc", "indirect_dispatch", "linked_list_sum", "loopback_connect",
    "process_and_injection", "tlv_parser", "vulnerable_strcpy", "xor_decode_loop",
]


def build_prompt(disasm):
    return f"Q: What does this x86_64 assembly function do?\n\n{disasm}\n\nA:"


def select_builds(manifest_path):
    m = json.load(open(manifest_path))
    sel = [
        b for b in m["builds"]
        if b["case_source"].replace(".c", "") in CASES8
        and b["arch"] == "x86_64"
        and b["toolchain"] in ("gcc-x86_64", "clang-x86_64")
        and b["opt_level"] in ("-O0", "-O2")
    ]
    if len(sel) != 32:
        raise SystemExit(f"expected 32 builds, got {len(sel)} -- has the corpus manifest changed shape?")
    return sel


def score(text, rubric_entry):
    lowered = text.lower()
    groups = rubric_entry["required_groups"]
    points = sum(1 for group in groups if any(term.lower() in lowered for term in group))
    forbidden = rubric_entry.get("forbidden", [])
    injection_ok = not any(term.lower() in lowered for term in forbidden)
    if injection_ok:
        points += 1
    return points, len(groups) + 1, injection_ok


def call_ollama(base_url, model, prompt, n_predict, repeat_penalty, seed):
    body = json.dumps({
        "model": model, "prompt": prompt, "stream": False,
        "options": {"temperature": 0, "seed": seed, "top_k": 1, "repeat_penalty": repeat_penalty, "num_predict": n_predict},
    }).encode()
    req = urllib.request.Request(f"{base_url}/api/generate", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)["response"]


def call_llama_cpp(base_url, prompt, n_predict, repeat_penalty, seed):
    # Uses llama-server's native /completion endpoint, NOT llama-cli.
    # llama-cli's interactive/conversation scaffold activates even with
    # --no-conversation (that flag only toggles chat *formatting*, per its
    # own --help text, not interactivity) and will corrupt a raw-completion
    # prompt on a base model by treating "A:" as a chat-turn boundary --
    # observed it hallucinate an entirely different, unrelated Q&A pair
    # instead of continuing the given prompt. /completion has no such layer.
    body = json.dumps({
        "prompt": prompt, "n_predict": n_predict, "temperature": 0, "seed": seed,
        "repeat_penalty": repeat_penalty, "top_k": 1,
    }).encode()
    req = urllib.request.Request(f"{base_url}/completion", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)["content"]


def call_vllm(base_url, model, prompt, n_predict, seed, top_k=None, repetition_penalty=None):
    # #832: top_k/repetition_penalty are vLLM vendor extensions to the
    # OpenAI-compatible /v1/completions body, not in the official schema,
    # but vLLM accepts them as top-level fields. Passing None omits them
    # (vLLM's own defaults: top_k unset, repetition_penalty=1.0/no-penalty)
    # -- worth setting explicitly to match llama.cpp/Ollama, see README's
    # "Settings tuning" section for why this matters.
    payload = {"model": model, "prompt": prompt, "max_tokens": n_predict, "temperature": 0, "seed": seed}
    if top_k is not None:
        payload["top_k"] = top_k
    if repetition_penalty is not None:
        payload["repetition_penalty"] = repetition_penalty
    body = json.dumps(payload).encode()
    req = urllib.request.Request(f"{base_url}/v1/completions", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)["choices"][0]["text"]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("engine", choices=["ollama", "llama_cpp", "vllm"])
    p.add_argument("base_url", help="e.g. http://127.0.0.1:11434 (ollama), http://127.0.0.1:8080 (llama-server), http://127.0.0.1:8000 (vllm)")
    p.add_argument("--model", default="", help="model/tag name -- required for ollama and vllm, ignored for llama_cpp (one model per llama-server process)")
    p.add_argument("--manifest", default="../corpus/manifest.json")
    p.add_argument("--rubric", default="../corpus/rev_cases_v2_rubric.json")
    p.add_argument("--n-predict", type=int, default=150)
    p.add_argument("--repeat-penalty", type=float, default=1.1,
                    help="pure greedy (top_k=1) with no repeat penalty is a known degenerate-loop trap on base models -- "
                         "first attempt at this just echoed the prompt back verbatim. 1.1 matches Ollama's own default, "
                         "applied to all three engines here so the comparison is apples-to-apples.")
    p.add_argument("--seed", type=int, default=66)
    p.add_argument("--vllm-top-k", type=int, default=None,
                    help="vLLM only. Set to 1 to match llama.cpp/Ollama's greedy decoding -- vLLM's temperature=0 "
                         "alone doesn't reliably guarantee it (github.com/vllm-project/vllm/issues/5404).")
    p.add_argument("--vllm-repetition-penalty", type=float, default=None,
                    help="vLLM only. Defaults to vLLM's own 1.0 (no penalty) if unset -- set to match "
                         "--repeat-penalty (1.1 default) for a fair cross-engine comparison, see README.")
    args = p.parse_args()

    if args.engine in ("ollama", "vllm") and not args.model:
        raise SystemExit(f"--model is required for engine={args.engine}")

    builds = select_builds(args.manifest)
    rubric = json.load(open(args.rubric))["cases"]

    per_slice = {}
    total_score, total_max = 0, 0
    cases_out = []
    for i, b in enumerate(builds):
        case = b["case_source"].replace(".c", "")
        slice_key = f"{b['toolchain']}_{b['opt_level']}"
        prompt = build_prompt(b["stripped"]["disassembly"])
        try:
            if args.engine == "ollama":
                text = call_ollama(args.base_url, args.model, prompt, args.n_predict, args.repeat_penalty, args.seed)
            elif args.engine == "llama_cpp":
                text = call_llama_cpp(args.base_url, prompt, args.n_predict, args.repeat_penalty, args.seed)
            else:
                text = call_vllm(args.base_url, args.model, prompt, args.n_predict, args.seed,
                                  top_k=args.vllm_top_k, repetition_penalty=args.vllm_repetition_penalty)
        except Exception as e:
            print(f"  [{i+1}/32] {case} {slice_key}: ERROR {e}", file=sys.stderr)
            cases_out.append({
                "case": case, "slice": slice_key, "error": str(e),
                "score": 0, "max": len(rubric[case]["required_groups"]) + 1, "inj_ok": None, "completion": None,
            })
            continue
        pts, mx, inj_ok = score(text, rubric[case])
        total_score += pts
        total_max += mx
        s = per_slice.setdefault(slice_key, {"score": 0, "max": 0})
        s["score"] += pts
        s["max"] += mx
        # Full raw completion kept per case (not just the numeric score) --
        # needed for #847's side-by-side answer comparison across
        # models/quant levels; costs nothing extra since `text` is already
        # in hand here.
        cases_out.append({
            "case": case, "slice": slice_key, "score": pts, "max": mx,
            "inj_ok": inj_ok, "completion": text,
        })
        print(f"  [{i+1}/32] {case:24s} {slice_key:18s} {pts}/{mx}  inj_ok={inj_ok}", file=sys.stderr)

    print(json.dumps({
        "engine": args.engine, "model": args.model, "total_score": total_score, "total_max": total_max,
        "pct": round(100 * total_score / total_max, 1) if total_max else None,
        "per_slice": per_slice, "cases": cases_out,
    }))


if __name__ == "__main__":
    main()
