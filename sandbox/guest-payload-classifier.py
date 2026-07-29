#!/usr/bin/env python3
"""Content-based payload classifier used inside each disposable guest."""

import json
import struct
import sys
from pathlib import Path


def result(code, label, platform, category, analysis_path, dynamic):
    return {
        "code": code,
        "label": label,
        "platform": platform,
        "category": category,
        "analysis_path": analysis_path,
        "dynamic": dynamic,
    }


def contains_any(value, *needles):
    return any(needle in value for needle in needles)


def payload_text(data):
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16le", "replace")
    return data.removeprefix(b"\xef\xbb\xbf").decode("utf-8", "replace")


def pe_is_dll(data):
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != b"PE\0\0":
            return False
        characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]
        return bool(characteristics & 0x2000)
    except (IndexError, struct.error):
        return False


def elf_is_library(data):
    try:
        byteorder = "<" if data[5] == 1 else ">"
        elf_type = struct.unpack_from(byteorder + "H", data, 16)[0]
        return elf_type == 3 and b"/lib" not in data[:65536]
    except (IndexError, struct.error):
        return False


def classify(data):
    if data.startswith(b"MZ"):
        if pe_is_dll(data):
            return result("pe-dll", "Windows DLL", "Windows", "library",
                          "PE forensics and Wine DLL detonation", True)
        return result("pe-exe", "Windows PE executable", "Windows", "executable",
                      "PE forensics and Wine detonation", True)
    if data.startswith(b"\x7fELF"):
        if elf_is_library(data):
            return result("elf-library", "Linux ELF shared object", "Linux", "library",
                          "ELF static metadata; library is not invoked automatically", False)
        return result("elf-exe", "Linux ELF executable", "Linux", "executable",
                      "Native Linux detonation under strace", True)

    text = payload_text(data[:1024 * 1024])
    lower = text.lower()
    head = lower[:65536]
    first = head[:256].strip()
    if first.startswith("<?php"):
        return result("php", "PHP script", "Cross-platform", "script", "PHP CLI under strace", True)
    if (contains_any(head, "wscript.createobject", "createobject(", "wscript.shell", "on error resume next")
            and contains_any(head, "dim ", "set ", "wscript.", "cscript")):
        return result("vbscript", "Windows VBScript", "Windows", "script",
                      "Wine cscript.exe under strace", True)
    if contains_any(head, "@echo off", "%comspec%", "setlocal", "cmd.exe /c", "cmd /c "):
        return result("batch", "Windows batch script", "Windows", "script",
                      "Wine cmd.exe under strace", True)
    if contains_any(head, "powershell", "invoke-webrequest", "invoke-expression",
                    "frombase64string", "new-object net.webclient", "$env:", "param("):
        return result("powershell", "PowerShell script", "Windows", "script",
                      "Wine PowerShell route with static fallback", True)
    if (contains_any(head, "wscript.", "activexobject(", "cscript.exe")
            and contains_any(head, "function", "var ", "eval(", "createobject")):
        return result("jscript", "Windows JScript", "Windows", "script",
                      "Wine cscript.exe JScript engine under strace", True)
    if first.startswith("#!") and contains_any(first, "/sh", "/bash", "/dash", "/zsh", "/ksh"):
        return result("shell", "POSIX shell script", "Linux", "script", "Bash under strace", True)
    if first.startswith("#!") and "python" in first:
        return result("python", "Python script", "Cross-platform", "script", "Python 3 under strace", True)
    if first.startswith("#!") and contains_any(first, "node", "javascript"):
        return result("javascript", "JavaScript / Node.js script", "Cross-platform", "script",
                      "Node.js under strace", True)
    if (contains_any(head, "import os", "import sys", "subprocess.", "__name__ ==")
            and contains_any(head, "def ", "print(", "python")):
        return result("python", "Python script", "Cross-platform", "script", "Python 3 under strace", True)
    if contains_any(head, "#!/bin/", "curl ", "wget ", "chmod +x", "/dev/tcp/", "export path="):
        return result("shell", "POSIX shell command/script", "Linux", "script", "Bash under strace", True)
    if (contains_any(head, "require(", "module.exports", "process.env", "const ", "let ")
            and contains_any(head, "function", "=>", "console.", "eval(")):
        return result("javascript", "JavaScript / Node.js script", "Cross-platform", "script",
                      "Node.js under strace", True)

    signatures = (
        (b"%PDF-", result("pdf", "PDF document", "Cross-platform", "document",
                          "Static document metadata and strings", False)),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", result("ole", "OLE / legacy Office document", "Windows",
                                                     "document", "Static document metadata and strings", False)),
        (b"PK\x03\x04", result("zip", "ZIP / OOXML / JAR archive", "Cross-platform", "archive",
                              "Static archive metadata and strings", False)),
        (b"Rar!\x1a\x07", result("rar", "RAR archive", "Cross-platform", "archive",
                                "Static archive metadata and strings", False)),
        (b"7z\xbc\xaf\x27\x1c", result("7z", "7-Zip archive", "Cross-platform", "archive",
                                      "Static archive metadata and strings", False)),
        (b"\x1f\x8b", result("gzip", "Gzip-compressed data", "Cross-platform", "archive",
                            "Static compressed-file metadata and strings", False)),
    )
    for signature, identified in signatures:
        if data.startswith(signature):
            return identified
    sample = data[:8192]
    printable = sum(byte in b"\r\n\t" or 0x20 <= byte < 0x7F for byte in sample)
    if sample and printable * 100 // len(sample) >= 85:
        return result("text", "Plain-text artifact", "Unknown", "text",
                      "Static text, IOC, deobfuscation, and YARA analysis", False)
    return result("binary", "Unknown binary data", "Unknown", "binary",
                  "Static binary metadata, strings, hashes, and YARA analysis", False)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: guest-payload-classifier.py SAMPLE")
    data = Path(sys.argv[1]).read_bytes()
    print(json.dumps(classify(data), indent=2))


if __name__ == "__main__":
    main()
