#!/usr/bin/env python3
"""Static checks on the twin's noise-generator HTTPS story (#2546).

Mirror of sandbox/windows_kimi's #2449 fix, adapted to this tree's layout:
config/fakenet.ini set UseSSL=Yes on the 443 listener, but nothing staged a
CA the guest trusts -- FakeNet minted a throwaway temp_certs root every
start, PowerShell's Invoke-WebRequest validates strictly, and every tagged
HTTPS noise request (~70% of GETs, 100% of the POST canary branch) failed
certificate verification. The failure was invisible: noise-gen.ps1 wrapped
every request in a bare `try { } catch { }` with no counting.

The fix: packer/scripts/04-tools.ps1 generates a static persona CA once per
build and imports it into LocalMachine\\Root; config/fakenet.ini's [HTTPS]
section points the listener at that same pair (static_ca + ca_cert/ca_key)
instead of relying on UseSSL alone; and noise-gen.ps1 counts ok/failed
requests per burst and appends a summary line to noise-stats.log, so a dead
TLS story is visible in an output stream instead of indistinguishable from
steady success.

No pwsh available in CI/dev here, so this is a text-level check on the
scripts rather than an execution test -- same convention as
sandbox/windows_kimi/tests/test_40_fakenet_provision.py.

Usage: sandbox/windows/tests/test_08_traffic_noise_tls.py
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOISE_SCRIPT = ROOT / "packer" / "scripts" / "08-traffic-noise.ps1"
TOOLS_SCRIPT = ROOT / "packer" / "scripts" / "04-tools.ps1"
FAKENET_INI = ROOT / "config" / "fakenet.ini"

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


def https_section(ini_text):
    """Return the [HTTPS] section body (up to the next [section] or EOF)."""
    m = re.search(r"^\[HTTPS\]\s*$(.*?)(?=^\[|\Z)", ini_text, re.M | re.S)
    return m.group(1) if m else ""


def test_fakenet_ini_trusts_static_ca():
    section = https_section(FAKENET_INI.read_text())
    check(bool(section), "config/fakenet.ini has an [HTTPS] section")
    check(
        re.search(r"(?im)^\s*UseSSL\s*=\s*Yes\s*$", section) is not None,
        "[HTTPS] still sets UseSSL = Yes",
    )
    check(
        re.search(r"(?im)^\s*static_ca\s*=\s*Yes\s*$", section) is not None,
        "[HTTPS] sets static_ca = Yes (not a throwaway temp_certs root every start)",
    )
    for key in ("ca_cert", "ca_key"):
        check(
            re.search(rf"(?im)^\s*{key}\s*=\s*\S+", section) is not None,
            f"[HTTPS] points {key} at a real path",
        )


def test_tools_script_generates_and_trusts_the_ca():
    text = TOOLS_SCRIPT.read_text()
    check(
        "persona-ca.crt" in text and "persona-ca.key" in text,
        "04-tools.ps1 generates the same persona-ca.crt/.key pair fakenet.ini references",
    )
    check(
        "CertificateRequest" in text,
        "04-tools.ps1 builds the CA with a certificate API, not just hand-waving UseSSL",
    )
    check(
        re.search(r"certutil\s+-addstore\s+-f\s+Root\s+\$caCert", text) is not None,
        "04-tools.ps1 imports the generated CA into LocalMachine Root",
    )


def test_noise_gen_counts_failures_instead_of_swallowing_them():
    text = NOISE_SCRIPT.read_text()
    m = re.search(r"\$gen = @'(.*?)'@", text, re.S)
    check(m is not None, "found the embedded noise-gen.ps1 heredoc")
    gen = m.group(1) if m else ""

    # Send-NoiseDns's own `catch {}` is deliberately left bare (DNS lookups
    # aren't part of the TLS-trust canary), matching windows_kimi's fix --
    # but the GET and POST *request* branches must each count into
    # windowOk/windowFail, not swallow failures the same way.
    bare_catches = re.findall(r"catch\s*\{\s*\}", gen)
    check(
        len(bare_catches) == 1,
        f"exactly one bare 'catch {{}}' remains (Send-NoiseDns only); found {len(bare_catches)}",
    )
    check(
        len(re.findall(r"windowFail\+\+", gen)) >= 2,
        "both the GET and the always-https POST branch increment $script:windowFail on failure",
    )
    check(
        "windowOk" in gen,
        "noise-gen.ps1 tracks per-burst ok counts",
    )
    check(
        "noise-stats.log" in gen,
        "noise-gen.ps1 appends the per-burst summary to a log file, not just Write-Host",
    )


def main():
    test_fakenet_ini_trusts_static_ca()
    test_tools_script_generates_and_trusts_the_ca()
    test_noise_gen_counts_failures_instead_of_swallowing_them()
    if fails:
        print(f"\n{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
