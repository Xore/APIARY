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
]

OPT_LEVELS = ["-O0", "-O2"]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def objdump_for(arch: str) -> str:
    return "aarch64-linux-gnu-objdump" if arch == "aarch64" else "objdump"


def strip_for(arch: str) -> str:
    return "aarch64-linux-gnu-strip" if arch == "aarch64" else "strip"


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
    manifest = []
    errors = []
    for src in sorted(SRC_DIR.glob("*.c")):
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
