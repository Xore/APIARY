#!/usr/bin/env python3
"""Static checks on 40-fakenet.ps1's dependency install line (#2545).

flare-fakenet-ng ships no root requirements.txt -- only setup.py's
install_requires and a test-only test/requirements.txt -- so
`pip install -r "$fn\\requirements.txt"` always failed, and under
$ErrorActionPreference='Continue' with no $LASTEXITCODE check the failure
was invisible: FakeNet's runtime deps (pyopenssl, cryptography, pydivert)
never installed and every listener died on import at startup.

No pwsh available in CI/dev here, so this is a text-level check on the
script rather than an execution test: it locates the FakeNet dependency
pip-install line, asserts it does not reference the nonexistent
requirements.txt, asserts it names the actual runtime deps (or installs
the package itself so setup.py's install_requires resolves them), and
asserts the very next non-comment/non-blank line inspects $LASTEXITCODE
so a failed install halts provisioning loudly instead of crashing FakeNet
hours later at boot.

Usage: sandbox/windows_kimi/tests/test_40_fakenet_provision.py
"""
import re
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "provision" / "40-fakenet.ps1"

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


def find_pip_install_lines(lines):
    return [i for i, line in enumerate(lines) if re.search(r"pip install", line)]


def next_meaningful_line(lines, start):
    for line in lines[start + 1:]:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    return ""


def test_no_requirements_txt_install():
    lines = SCRIPT.read_text().splitlines()
    broken = [
        line for line in lines
        if "pip install" in line and "requirements.txt" in line
    ]
    check(
        not broken,
        f"no pip install line references the nonexistent upstream requirements.txt, found: {broken}",
    )


def test_fakenet_deps_installed_explicitly():
    lines = SCRIPT.read_text().splitlines()
    dep_lines = [
        i for i in find_pip_install_lines(lines)
        if "pydivert" in lines[i] or re.search(r'pip install --quiet "\$fn"', lines[i])
    ]
    check(len(dep_lines) == 1, f"exactly one FakeNet dependency install line found (got {len(dep_lines)})")
    if dep_lines:
        install_line = lines[dep_lines[0]]
        names_all_deps = "pydivert" in install_line
        installs_package = re.search(r'pip install --quiet "\$fn"', install_line) is not None
        check(
            names_all_deps or installs_package,
            "install line either names pyopenssl/cryptography/pydivert explicitly "
            "or installs the package itself (setup.py install_requires)",
        )
        if names_all_deps:
            for dep in ("pyopenssl", "cryptography", "pydivert"):
                check(dep in install_line, f"install line names '{dep}'")


def test_exit_code_checked_after_dep_install():
    lines = SCRIPT.read_text().splitlines()
    dep_lines = [
        i for i in find_pip_install_lines(lines)
        if "pydivert" in lines[i] or re.search(r'pip install --quiet "\$fn"', lines[i])
    ]
    check(len(dep_lines) == 1, "found the FakeNet dependency install line to check for a LASTEXITCODE guard")
    if dep_lines:
        nxt = next_meaningful_line(lines, dep_lines[0])
        check(
            "$LASTEXITCODE" in nxt,
            f"line immediately after the install checks $LASTEXITCODE, got: {nxt!r}",
        )


def main():
    test_no_requirements_txt_install()
    test_fakenet_deps_installed_explicitly()
    test_exit_code_checked_after_dep_install()
    if fails:
        print(f"\n{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
