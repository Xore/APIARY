import hashlib
import json
import subprocess
from pathlib import Path

SRC_DIR = Path("/src")
OUT_DIR = Path("/work/corpus")
OUT_DIR.mkdir(parents=True, exist_ok=True)

TOOLCHAINS = [
    {
        "name": "gcc-x86_64",
        "arch": "x86_64",
        "compiler": "gcc",
        "target_triple": "x86_64-linux-gnu",
        "cc": ["gcc"],
    },
    {
        "name": "clang-x86_64",
        "arch": "x86_64",
        "compiler": "clang",
        "target_triple": "x86_64-linux-gnu",
        "cc": ["clang", "--target=x86_64-linux-gnu"],
    },
    {
        "name": "gcc-aarch64",
        "arch": "aarch64",
        "compiler": "gcc",
        "target_triple": "aarch64-linux-gnu",
        "cc": ["aarch64-linux-gnu-gcc"],
    },
    # clang-aarch64: was the first named gap in #159's own follow-up list --
    # gcc-aarch64 existed but nothing checked clang produced comparable
    # output on the same architecture. clang's cross-target support reuses
    # whatever gcc-<triple> cross package is installed (its libc headers and
    # binutils), so no extra sysroot flag is needed once the gcc-aarch64
    # entry above already pulled that package in.
    {
        "name": "clang-aarch64",
        "arch": "aarch64",
        "compiler": "clang",
        "target_triple": "aarch64-linux-gnu",
        "cc": ["clang", "--target=aarch64-linux-gnu"],
    },
    # i686 (32-bit x86), mipsel, and armhf: the second named gap -- #159
    # asked for a 32-bit x86 entry plus "one additional architecture," and
    # explicitly left the choice of that fourth architecture undecided.
    # Built both mipsel and armhf rather than picking one: mipsel is the
    # historically dominant architecture for router/IoT botnet malware (the
    # Mirai family and its many derivatives overwhelmingly target MIPS home
    # routers, matching this honeypot's own captured-sample profile), armhf
    # covers the broader modern embedded/IoT surface (IP cameras, newer
    # routers, general Cortex-A devices) -- #195 names both as capa's
    # coverage gap, not just one.
    {
        "name": "gcc-i686",
        "arch": "i686",
        "compiler": "gcc",
        "target_triple": "i686-linux-gnu",
        "cc": ["i686-linux-gnu-gcc"],
    },
    {
        "name": "clang-i686",
        "arch": "i686",
        "compiler": "clang",
        "target_triple": "i686-linux-gnu",
        "cc": ["clang", "--target=i686-linux-gnu"],
    },
    {
        "name": "gcc-mipsel",
        "arch": "mipsel",
        "compiler": "gcc",
        "target_triple": "mipsel-linux-gnu",
        "cc": ["mipsel-linux-gnu-gcc"],
    },
    {
        "name": "clang-mipsel",
        "arch": "mipsel",
        "compiler": "clang",
        "target_triple": "mipsel-linux-gnu",
        "cc": ["clang", "--target=mipsel-linux-gnu"],
    },
    {
        "name": "gcc-armhf",
        "arch": "armhf",
        "compiler": "gcc",
        "target_triple": "arm-linux-gnueabihf",
        "cc": ["arm-linux-gnueabihf-gcc"],
    },
    {
        "name": "clang-armhf",
        "arch": "armhf",
        "compiler": "clang",
        "target_triple": "arm-linux-gnueabihf",
        "cc": ["clang", "--target=arm-linux-gnueabihf"],
    },
]

OPT_LEVELS = ["-O0", "-O2"]

# #159's "Provenance and ground truth" section requires every case to record
# "whether the case is suitable for training, validation, or test only," and
# to "keep test-only cases separated so later fine-tuning cannot contaminate
# evaluation." Every one of these 8 cases has already been used as scored
# evaluation data (rev_cases_v2_rubric.json, run against #160's REx86
# comparison) -- none of them has ever been shown to a model as a training
# example. Tagging any of them "train" now would be retroactively wrong, not
# just premature, so all 8 are "test" until new cases are added specifically
# as train/validation material. The split is recorded per case (not per
# build variant): every toolchain/opt-level/strip combination of one case
# gets the same split, since splitting a single case's own variants across
# train and test would let a model see the same underlying case in both
# and leak exactly the case-level knowledge the split exists to prevent.
CASE_SPLITS = {
    "error_handling_alloc.c": "test",
    "indirect_dispatch.c": "test",
    "linked_list_sum.c": "test",
    "loopback_connect.c": "test",
    "process_and_injection.c": "test",
    "tlv_parser.c": "test",
    "vulnerable_strcpy.c": "test",
    "xor_decode_loop.c": "test",
}

# Maps each non-native arch to the cross binutils prefix that can actually
# read its object files -- confirmed necessary, not just tidy: the host's
# plain `objdump`/`strip` silently mis-decode a foreign-architecture object
# (objdump -f reported "architecture: UNKNOWN!" on an aarch64/mips/arm
# object read with the native x86_64 objdump, even though the object itself
# was valid -- the target-specific tool read the same file correctly).
CROSS_TOOL_PREFIX = {
    "aarch64": "aarch64-linux-gnu",
    "i686": "i686-linux-gnu",
    "mipsel": "mipsel-linux-gnu",
    "armhf": "arm-linux-gnueabihf",
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def objdump_for(arch: str) -> str:
    prefix = CROSS_TOOL_PREFIX.get(arch)
    return f"{prefix}-objdump" if prefix else "objdump"


def strip_for(arch: str) -> str:
    prefix = CROSS_TOOL_PREFIX.get(arch)
    return f"{prefix}-strip" if prefix else "strip"


def compiler_version(cc: list[str]) -> str:
    result = subprocess.run(cc + ["--version"], capture_output=True, text=True, check=True)
    return result.stdout.splitlines()[0].strip()


def normalize_disassembly(text: str, path: Path) -> str:
    # objdump's first line echoes the absolute path it was given, which
    # differs by build directory/machine and would otherwise make two
    # deterministic builds look byte-different for a reason that has
    # nothing to do with the compiled code.
    lines = text.splitlines()
    if lines and str(path) in lines[0]:
        lines[0] = lines[0].replace(str(path), path.name)
    return "\n".join(lines)


def build_one(src: Path, toolchain: dict, opt: str) -> dict:
    stem = f"{src.stem}__{toolchain['name']}__{opt.lstrip('-')}"
    obj_path = OUT_DIR / f"{stem}.o"
    cc = toolchain["cc"]
    cmd = cc + [opt, "-g", "-fno-asynchronous-unwind-tables", "-c", str(src), "-o", str(obj_path)]
    subprocess.run(cmd, check=True, capture_output=True, text=True)

    stripped_path = OUT_DIR / f"{stem}.stripped.o"
    stripped_path.write_bytes(obj_path.read_bytes())
    subprocess.run([strip_for(toolchain["arch"]), "--strip-all", str(stripped_path)], check=True)

    disasm_unstripped = normalize_disassembly(subprocess.run(
        [objdump_for(toolchain["arch"]), "-d", "--source", str(obj_path)],
        capture_output=True, text=True, check=True,
    ).stdout, obj_path)
    disasm_stripped = normalize_disassembly(subprocess.run(
        [objdump_for(toolchain["arch"]), "-d", str(stripped_path)],
        capture_output=True, text=True, check=True,
    ).stdout, stripped_path)

    return {
        "case_source": src.name,
        "split": CASE_SPLITS[src.name],
        "toolchain": toolchain["name"],
        "arch": toolchain["arch"],
        "compiler": toolchain["compiler"],
        "compiler_version": compiler_version(cc),
        "target_triple": toolchain["target_triple"],
        "opt_level": opt,
        "compile_command": " ".join(cmd),
        "unstripped": {
            "path": obj_path.name,
            "sha256": sha256_of(obj_path),
            "size": obj_path.stat().st_size,
            "disassembly": disasm_unstripped,
        },
        "stripped": {
            "path": stripped_path.name,
            "sha256": sha256_of(stripped_path),
            "size": stripped_path.stat().st_size,
            "disassembly": disasm_stripped,
        },
    }


def main():
    sources = sorted(SRC_DIR.glob("*.c"))
    unassigned = [src.name for src in sources if src.name not in CASE_SPLITS]
    if unassigned:
        raise SystemExit(
            f"CASE_SPLITS has no train/validation/test assignment for: {', '.join(unassigned)} "
            f"-- add one before building, per #159's provenance requirement"
        )

    manifest = []
    errors = []
    for src in sources:
        for toolchain in TOOLCHAINS:
            for opt in OPT_LEVELS:
                try:
                    entry = build_one(src, toolchain, opt)
                    manifest.append(entry)
                    print(f"OK  {src.name:30s} {toolchain['name']:14s} {opt}")
                except subprocess.CalledProcessError as exc:
                    errors.append({
                        "case_source": src.name,
                        "toolchain": toolchain["name"],
                        "opt_level": opt,
                        "stderr": exc.stderr,
                    })
                    print(f"ERR {src.name:30s} {toolchain['name']:14s} {opt}: {exc.stderr[:200]}")

    with open(OUT_DIR / "manifest.json", "w") as f:
        json.dump({"builds": manifest, "errors": errors}, f, indent=2)

    print(f"\n{len(manifest)} builds succeeded, {len(errors)} failed")


if __name__ == "__main__":
    main()
