#!/usr/bin/env python3
"""Emit bounded PE metadata without loading or executing the sample."""

import datetime
import json
import pathlib
import sys

import pefile


MAX_DLLS = 128
MAX_SYMBOLS_PER_DLL = 256
MAX_EXPORTS = 512
MAX_SECTIONS = 96


def clean(value, limit=256):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return "".join(ch if ch.isprintable() else "\ufffd" for ch in str(value))[:limit]


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: guest-pe-forensics.py SAMPLE")
    sample = pathlib.Path(sys.argv[1])
    pe = pefile.PE(str(sample), fast_load=True)
    pe.parse_data_directories()

    imports = []
    imported_names = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:MAX_DLLS]:
        symbols = []
        for item in entry.imports[:MAX_SYMBOLS_PER_DLL]:
            name = clean(item.name if item.name else f"ordinal:{item.ordinal}")
            symbols.append(name)
            imported_names.append(name.lower())
        imports.append({"dll": clean(entry.dll), "symbols": symbols})

    exports = []
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir:
        for item in export_dir.symbols[:MAX_EXPORTS]:
            exports.append(clean(item.name if item.name else f"ordinal:{item.ordinal}"))

    sections = []
    for section in pe.sections[:MAX_SECTIONS]:
        sections.append(
            {
                "name": clean(section.Name.rstrip(b"\0"), 32),
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "entropy": round(float(section.get_entropy()), 3),
                "characteristics": f"0x{int(section.Characteristics):08x}",
            }
        )

    timestamp = ""
    try:
        timestamp = datetime.datetime.fromtimestamp(
            int(pe.FILE_HEADER.TimeDateStamp), datetime.timezone.utc
        ).isoformat()
    except (OverflowError, OSError, ValueError):
        pass

    api_groups = {
        "process injection": {
            "virtualallocex",
            "writeprocessmemory",
            "createremotethread",
            "ntmapviewofsection",
            "queueuserapc",
        },
        "process execution": {
            "createprocessa",
            "createprocessw",
            "shellexecutea",
            "shellexecutew",
            "winexec",
        },
        "network transfer": {
            "urldownloadtofilea",
            "urldownloadtofilew",
            "internetopena",
            "internetopenw",
            "winhttpopen",
            "wsaconnect",
        },
        "registry modification": {
            "regsetvalueexa",
            "regsetvalueexw",
            "regcreatekeyexa",
            "regcreatekeyexw",
        },
        "credential access": {
            "cryptunprotectdata",
            "lsaenumeratelogonsessions",
            "minidumpwritedump",
        },
        "anti-analysis": {
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "ntqueryinformationprocess",
            "gettickcount",
        },
    }
    suspicious = {}
    imported = set(imported_names)
    for group, names in api_groups.items():
        matches = sorted(imported.intersection(names))
        if matches:
            suspicious[group] = matches

    signature_present = False
    try:
        security_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_index]
        signature_present = bool(security.VirtualAddress and security.Size)
    except (AttributeError, IndexError, KeyError):
        pass
    payload = {
        "detected": True,
        "machine": f"0x{int(pe.FILE_HEADER.Machine):04x}",
        "pe_type": "PE32+" if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else "PE32",
        "compile_timestamp": timestamp,
        "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
        "subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
        "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "imphash": clean(pe.get_imphash(), 64),
        "signature_present": signature_present,
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "suspicious_imports": suspicious,
        "warnings": [clean(item, 512) for item in pe.get_warnings()[:50]],
        "truncated": (
            len(getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])) > MAX_DLLS
            or len(getattr(export_dir, "symbols", [])) > MAX_EXPORTS
            or len(pe.sections) > MAX_SECTIONS
        ),
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
