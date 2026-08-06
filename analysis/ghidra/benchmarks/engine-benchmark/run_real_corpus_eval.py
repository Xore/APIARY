#!/usr/bin/env python3
"""Score an engine against a small real-payload corpus: actual honeypot
captures, not synthetic fixtures. Scored by evidence grounding rather than
an externally-authored ground truth: does the model's free-text answer
correctly describe behavior implied by the real, mechanically-extracted
evidence it was shown (imports/strings/sections), rather than guessing at
malware family or intent. This matches #159's own stated evaluation
principle ("supported facts versus inference... evidence grounding matters
more than lexical similarity") applied to real rather than synthetic input.

This intentionally does NOT try to score "is the classification correct" --
there is no trustworthy external label for arbitrary live captures without
running a second, independent analysis (capa, sandbox detonation, etc.) and
trusting *that* as ground truth, which just moves the goalposts. Grounding
(did the model correctly cite real evidence in front of it) is the one
thing that can be checked with zero assumptions.

Usage:
    python3 run_real_corpus_eval.py llama_cpp http://127.0.0.1:8080 \\
        --evidence-dir ./evidence --rubric ./example-rubric.json

Producing the evidence directory (never commit real samples -- see README.md):
    python3 extract_evidence.py /path/to/captured.bin ./evidence/<sha256>.evidence.json
"""
import argparse
import glob
import json
import os
import sys
import urllib.request


def build_prompt(evidence):
    imports = "\n".join(f"  {imp}" for imp in evidence["imports"])
    interesting_strings = [s for s in evidence["strings_sample"] if len(s) < 40][:15]
    strings_block = "\n".join(f"  {s}" for s in interesting_strings) or \
        "  (no short human-readable strings found; sample dominated by high-entropy/encoded data)"
    sections = ", ".join(f"{s['name']}(entropy={s['entropy']})" for s in evidence["sections"])
    kind = "DLL" if evidence["is_dll"] else "EXE"
    return (
        f"Q: A captured Windows PE32 {kind} was analyzed. Based on this evidence, "
        f"describe what the program does and any suspicious behavior.\n\n"
        f"IMPORTS ({evidence['imports_count']}):\n{imports}\n\n"
        f"NOTABLE STRINGS:\n{strings_block}\n\n"
        f"SECTIONS: {sections}\n\n"
        f"A:"
    )


def score(text, required_groups):
    lowered = text.lower()
    hits = []
    for entry in required_groups:
        label, terms = entry["label"], entry["terms"]
        hit = any(t.lower() in lowered for t in terms)
        hits.append((label, hit))
    points = sum(1 for _, hit in hits if hit)
    return points, len(required_groups), hits


def call_ollama(base_url, model, prompt, n_predict, repeat_penalty, seed):
    body = json.dumps({
        "model": model, "prompt": prompt, "stream": False,
        "options": {"temperature": 0, "seed": seed, "top_k": 1, "repeat_penalty": repeat_penalty, "num_predict": n_predict},
    }).encode()
    req = urllib.request.Request(f"{base_url}/api/generate", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)["response"]


def call_llama_cpp(base_url, prompt, n_predict, repeat_penalty, seed):
    body = json.dumps({
        "prompt": prompt, "n_predict": n_predict, "temperature": 0, "seed": seed,
        "repeat_penalty": repeat_penalty, "top_k": 1,
    }).encode()
    req = urllib.request.Request(f"{base_url}/completion", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)["content"]


def call_vllm(base_url, model, prompt, n_predict, seed):
    body = json.dumps({
        "model": model, "prompt": prompt, "max_tokens": n_predict, "temperature": 0, "seed": seed,
    }).encode()
    req = urllib.request.Request(f"{base_url}/v1/completions", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as r:
        return json.load(r)["choices"][0]["text"]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("engine", choices=["ollama", "llama_cpp", "vllm"])
    p.add_argument("base_url")
    p.add_argument("--model", default="")
    p.add_argument("--evidence-dir", default=".", help="directory of *.evidence.json files produced by extract_evidence.py")
    p.add_argument("--rubric", required=True, help="JSON file: {\"required_groups\": [{\"label\": str, \"terms\": [str, ...]}, ...]}")
    p.add_argument("--n-predict", type=int, default=180)
    p.add_argument("--repeat-penalty", type=float, default=1.1)
    p.add_argument("--seed", type=int, default=66)
    args = p.parse_args()

    if args.engine in ("ollama", "vllm") and not args.model:
        raise SystemExit(f"--model is required for engine={args.engine}")

    files = sorted(glob.glob(os.path.join(args.evidence_dir, "*.evidence.json")))
    if not files:
        raise SystemExit(f"no *.evidence.json found in {args.evidence_dir} -- run extract_evidence.py first")
    required_groups = json.load(open(args.rubric))["required_groups"]

    total_score, total_max = 0, 0
    for i, path in enumerate(files):
        evidence = json.load(open(path))
        sample_id = os.path.basename(path).split(".")[0]
        prompt = build_prompt(evidence)
        try:
            if args.engine == "ollama":
                text = call_ollama(args.base_url, args.model, prompt, args.n_predict, args.repeat_penalty, args.seed)
            elif args.engine == "llama_cpp":
                text = call_llama_cpp(args.base_url, prompt, args.n_predict, args.repeat_penalty, args.seed)
            else:
                text = call_vllm(args.base_url, args.model, prompt, args.n_predict, args.seed)
        except Exception as e:
            print(f"  [{i+1}/{len(files)}] {sample_id}: ERROR {e}", file=sys.stderr)
            continue
        pts, mx, hits = score(text, required_groups)
        total_score += pts
        total_max += mx
        print(f"  [{i+1}/{len(files)}] {sample_id}  {pts}/{mx}  {hits}", file=sys.stderr)
        print(f"      output: {text[:200]!r}", file=sys.stderr)

    print(json.dumps({
        "engine": args.engine, "model": args.model, "total_score": total_score, "total_max": total_max,
        "pct": round(100 * total_score / total_max, 1) if total_max else None,
        "n_samples": len(files),
    }))


if __name__ == "__main__":
    main()
