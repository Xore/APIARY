"""Executable semantic verification for the cases that have a harness/*.c.

#159 asks for "semantic equivalence or executable checks where safe and
applicable." Static disassembly plus a human-authored rubric is the whole
corpus's normal contract; this is the "where safe and applicable" half --
actually running the compiled code against known inputs/outputs, across
every architecture this corpus builds for, via native execution (x86_64,
i686) or QEMU user-mode emulation (aarch64, mipsel, armhf; confirmed working
end to end against a real cross-compiled dynamically-linked binary, not
assumed from a static-linking shortcut).

Deliberately does NOT cover every case in the corpus. Two categories are
excluded, both on purpose, not by oversight -- see EXCLUDED below for why
each one specifically is excluded, not just "behavior fixtures in general."
harness/*.c documents, for the intentionally-vulnerable cases it does cover,
why each harness only exercises the non-buggy path.

Usage: run inside the corpus-build container (needs every cross-compiler
build_corpus.py needs, plus qemu-user):
    python3 /work/verify_semantics.py
"""
import json
import subprocess
from pathlib import Path

import build_corpus

SRC_DIR = Path("/src")
# A sibling of /src, not /work/harness -- each harness/*.c includes its case
# with a relative "../src/<case>.c", matching this script's own repo layout
# (corpus/harness/x_harness.c -> ../src/x.c -> corpus/src/x.c). That only
# resolves correctly inside the container if harness/ sits next to /src the
# same way, not under /work.
HARNESS_DIR = Path("/harness")
OUT_DIR = Path("/work/semantic-checks")

# A representative slice, not the full 5-level spread build_corpus.py uses --
# this is a correctness check on the compiled code, not a provenance
# artifact in its own right, and running 12 cases x 10 toolchains x 5 opt
# levels would be 600 executions for no additional confidence over 2 levels
# spanning the range (unoptimized vs. optimized) already gives.
OPT_LEVELS = ["-O0", "-O2"]

# Maps each toolchain's arch to how to run its binary. None means run it
# directly (native or kernel-level compat, both confirmed working against a
# real cross-compiled dynamically-linked test binary before this script was
# written against them). A (qemu binary, sysroot) pair means user-mode
# emulation, with -L pointing at the same cross sysroot the toolchain
# itself was installed with.
RUNNERS = {
    "x86_64": None,
    # i686 needs QEMU too, same as the other three cross architectures --
    # its ELF interpreter is baked in at the cross sysroot's own path
    # (/usr/i686-linux-gnu/lib/ld-linux.so.2), which is not where a native
    # execve() looks (/lib/ld-linux.so.2, which does not exist on this
    # x86_64 host at all). A first version of this script assumed the
    # kernel's IA32 compat mode was enough on its own and left this None;
    # it was not -- confirmed by a real ENOENT from posix_spawn, not
    # inferred.
    "i686": ("qemu-i386", "/usr/i686-linux-gnu"),
    "aarch64": ("qemu-aarch64", "/usr/aarch64-linux-gnu"),
    "mipsel": ("qemu-mipsel", "/usr/mipsel-linux-gnu"),
    "armhf": ("qemu-arm", "/usr/arm-linux-gnueabihf"),
}

# Every case with a harness/<case>.c is covered somehow (below). These two
# are deliberately absent from harness/ entirely, not skipped at run time:
#
#   process_and_injection -- forks and execv's /bin/true. Technically inert
#   (hardcoded target, no injection surface), but actually spawning a child
#   process is not something an automated corpus-verification script should
#   do for a check that has no numeric result to assert beyond "returned a
#   pid or -1" -- there is nothing here executing the binary would prove
#   that reading the source doesn't already establish.
#
#   loopback_connect -- opens a real TCP socket and calls connect(). Loop-
#   back-only and safe by the fixture's own design, but a real network
#   syscall is still not something this script should trigger automatically
#   just to confirm a socket() call compiles -- same reasoning as above.
EXCLUDED = {
    "process_and_injection": "forks and execs a real child process; nothing to assert beyond pid != -1",
    "process_witness_probe": "same fork/execv shape as process_and_injection (#2694 witness twin); same reason",
    "loopback_connect": "opens a real network socket/connect(); no assertion needs a live syscall",
}


def run_one(case: str, harness_src: Path, toolchain: dict, opt: str) -> dict:
    stem = f"{case}__{toolchain['name']}__{opt.lstrip('-')}"
    exe_path = OUT_DIR / stem
    cc = toolchain["cc"]
    cmd = cc + [opt, "-g", "-Wno-format-security", str(harness_src), "-o", str(exe_path)]
    compile_result = subprocess.run(cmd, capture_output=True, text=True)
    if compile_result.returncode != 0:
        return {"case": case, "toolchain": toolchain["name"], "opt_level": opt,
                "stage": "compile", "passed": False, "output": compile_result.stderr}

    runner = RUNNERS[toolchain["arch"]]
    if runner is None:
        run_cmd = [str(exe_path)]
    else:
        qemu, sysroot = runner
        run_cmd = [qemu, "-L", sysroot, str(exe_path)]
    try:
        run_result = subprocess.run(run_cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"case": case, "toolchain": toolchain["name"], "opt_level": opt,
                "stage": "execute", "passed": False, "output": "timed out after 30s"}

    output = run_result.stdout + run_result.stderr
    passed = run_result.returncode == 0 and "PASS" in run_result.stdout
    return {"case": case, "toolchain": toolchain["name"], "opt_level": opt,
            "stage": "execute", "passed": passed,
            "exit_code": run_result.returncode, "output": output.strip()}


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    harnesses = sorted(HARNESS_DIR.glob("*_harness.c"))
    covered = {h.stem[:-len("_harness")] for h in harnesses}

    all_sources = {p.stem for p in SRC_DIR.glob("*.c")}
    unaccounted = all_sources - covered - set(EXCLUDED)
    if unaccounted:
        raise SystemExit(
            f"cases with neither a harness nor a recorded exclusion reason: {sorted(unaccounted)} "
            f"-- add a harness/<case>_harness.c or an EXCLUDED entry explaining why not"
        )

    results = []
    for harness_src in harnesses:
        case = harness_src.stem[: -len("_harness")]
        for toolchain in build_corpus.TOOLCHAINS:
            for opt in OPT_LEVELS:
                result = run_one(case, harness_src, toolchain, opt)
                results.append(result)
                status = "PASS" if result["passed"] else "FAIL"
                print(f"{status}  {case:26s} {toolchain['name']:14s} {opt}")

    failed = [r for r in results if not r["passed"]]
    report = {
        "checked": len(results),
        "failed": len(failed),
        "cases_covered": sorted(covered),
        "cases_excluded": EXCLUDED,
        "results": results,
    }
    with open(OUT_DIR / "semantic_checks.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n{len(results)} executions, {len(failed)} failed, "
          f"{len(covered)} cases covered, {len(EXCLUDED)} cases excluded (see EXCLUDED)")
    if failed:
        for r in failed:
            print(f"  FAIL {r['case']} {r['toolchain']} {r['opt_level']}: {r['output'][:200]}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
