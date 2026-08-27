#!/usr/bin/env python3
"""Extract imports/strings/sections from a real captured PE payload into a
JSON evidence file, for use by real_corpus_eval.py. Purely mechanical,
deterministic extraction -- no classification or family guessing here.
String selection (>=6 printable chars, 200 longest, deduplicated) matches
the production ai_triage evidence_shown convention (see ghidra-analysis-v1
docs / analysis/ghidra/worker) so real-corpus prompts look like what the
production triage pipeline actually shows a model, not a bespoke format.
The matching 150-import budget is applied at presentation time, in
run_real_corpus_eval.build_prompt (ghidra-worker.py's GHIDRA_TRIAGE_MAX_IMPORTS),
while this file deliberately records every import: it stays a complete
mechanical artifact, and only presentation decides how much of it a model sees.
Import order follows PE capture order rather than production's alphabetical
sort of its deduplicated set -- kept mechanical here, noted where it diverges.

Requires: pip install pefile
"""
import argparse
import json
import re

import pefile


def extract(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
    ])

    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace") if entry.dll else "?"
            for imp in entry.imports:
                name = imp.name.decode(errors="replace") if imp.name else f"ordinal_{imp.ordinal}"
                imports.append(f"{dll}!{name}")

    with open(path, "rb") as f:
        data = f.read()

    strings = sorted(set(re.findall(rb"[\x20-\x7e]{6,}", data)), key=len, reverse=True)
    strings = [s.decode("ascii") for s in strings[:200]]

    sections = [
        {
            "name": s.Name.decode(errors="replace").strip("\x00"),
            "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "entropy": round(s.get_entropy(), 3),
        }
        for s in pe.sections
    ]

    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "imports": imports,
        "imports_count": len(imports),
        "strings_sample": strings,
        "sections": sections,
        "size": len(data),
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input_file", help="path to the captured PE payload")
    p.add_argument("output_json", help="path to write the evidence JSON to")
    args = p.parse_args()

    result = extract(args.input_file)
    json.dump(result, open(args.output_json, "w"), indent=2)
    print(
        f"{args.input_file}: {result['imports_count']} imports, "
        f"{len(result['strings_sample'])} strings, {len(result['sections'])} sections"
    )


if __name__ == "__main__":
    main()
