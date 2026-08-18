//! Content-based payload classification, ported from dashboard/payload_kind.go.
//! Deliberately content-based, not filename-based: captured artifacts are
//! stored under their SHA-256. `code` values are shared with sandbox
//! submission's target routing (determine_sandbox_target in
//! sandbox_submit.rs) and the Payload Workbench orchestrator.
//!
//! The PE/ELF checks hand-roll the two narrow header fields this needs
//! (COFF Characteristics for the DLL bit; ELF e_type + PT_INTERP presence)
//! instead of pulling in a full binary-parsing crate — this crate has none
//! today and the fields in question are a handful of fixed offsets.

use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct PayloadClassification {
    pub code: String,
    pub label: String,
    pub platform: String,
    pub category: String,
    pub analysis_path: String,
    pub dynamic: bool,
}

fn kind(
    code: &str,
    label: &str,
    platform: &str,
    category: &str,
    analysis_path: &str,
    dynamic: bool,
) -> PayloadClassification {
    PayloadClassification {
        code: code.into(),
        label: label.into(),
        platform: platform.into(),
        category: category.into(),
        analysis_path: analysis_path.into(),
        dynamic,
    }
}

/// COFF FileHeader.Characteristics bit for IMAGE_FILE_DLL.
const IMAGE_FILE_DLL: u16 = 0x2000;

/// Reads the COFF Characteristics field of a PE file, if the header is
/// well-formed enough to locate it. None means "could not parse" — the
/// same fallback Go's `pe.NewFile` failure path takes.
fn pe_characteristics(data: &[u8]) -> Option<u16> {
    if data.len() < 0x40 {
        return None;
    }
    let lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    // 4-byte "PE\0\0" signature, then the 20-byte COFF header; Characteristics
    // is its last field (Machine 2 + NumberOfSections 2 + TimeDateStamp 4 +
    // PointerToSymbolTable 4 + NumberOfSymbols 4 + SizeOfOptionalHeader 2 =
    // 18 bytes in, 2 bytes wide).
    let sig_end = lfanew.checked_add(4)?;
    let characteristics_start = sig_end.checked_add(18)?;
    let characteristics_end = characteristics_start.checked_add(2)?;
    if characteristics_end > data.len() || sig_end > data.len() {
        return None;
    }
    if &data[lfanew..sig_end] != b"PE\0\0" {
        return None;
    }
    Some(u16::from_le_bytes(
        data[characteristics_start..characteristics_end].try_into().ok()?,
    ))
}

const ET_DYN: u16 = 3;
const PT_INTERP: u32 = 3;

/// Reads e_type and scans program headers for PT_INTERP. None means "could
/// not parse" — same fallback posture as the PE side.
fn elf_is_dyn_without_interpreter(data: &[u8]) -> Option<bool> {
    if data.len() < 20 {
        return None;
    }
    let is_64 = match data[4] {
        1 => false, // ELFCLASS32
        2 => true,  // ELFCLASS64
        _ => return None,
    };
    let little_endian = match data[5] {
        1 => true,
        2 => false,
        _ => return None,
    };
    // Every sample this stack captures is x86/x86_64 (little-endian); a
    // big-endian ELF is exotic enough here that "could not parse" (elf-exe
    // fallback) is an acceptable simplification, matching this classifier's
    // general "best-effort, never fatal" posture.
    if !little_endian {
        return None;
    }
    let u16_at = |off: usize| -> Option<u16> { Some(u16::from_le_bytes(data.get(off..off + 2)?.try_into().ok()?)) };
    let u32_at = |off: usize| -> Option<u32> { Some(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?)) };
    let u64_at = |off: usize| -> Option<u64> { Some(u64::from_le_bytes(data.get(off..off + 8)?.try_into().ok()?)) };

    let e_type = u16_at(16)?;
    let (e_phoff, e_phentsize, e_phnum): (u64, u16, u16) = if is_64 {
        (u64_at(32)?, u16_at(54)?, u16_at(56)?)
    } else {
        (u32_at(28)? as u64, u16_at(42)?, u16_at(44)?)
    };
    if e_type != ET_DYN {
        return Some(false);
    }
    let mut has_interp = false;
    for i in 0..e_phnum as u64 {
        let base = e_phoff.checked_add(i * e_phentsize as u64)?;
        let base = usize::try_from(base).ok()?;
        let p_type = u32_at(base)?;
        if p_type == PT_INTERP {
            has_interp = true;
            break;
        }
    }
    Some(!has_interp)
}

fn has_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn mostly_text(text: &[u8]) -> bool {
    if text.is_empty() {
        return false;
    }
    let total = text.len().min(8192);
    let printable = text[..total]
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (b >= 0x20 && b < 0x7f))
        .count();
    total > 0 && printable * 100 / total >= 85
}

/// UTF-16LE BOM decode (mirrors Go's normalizedPayloadText) or UTF-8 BOM
/// strip, capped to 1MiB — same cap Go uses before any text heuristic runs.
fn normalized_text(data: &[u8]) -> Vec<u8> {
    let data = &data[..data.len().min(1 << 20)];
    if data.len() >= 2 && data[0] == 0xff && data[1] == 0xfe {
        let mut units = Vec::with_capacity((data.len() - 2) / 2);
        let mut i = 2;
        while i + 1 < data.len() {
            units.push(u16::from_le_bytes([data[i], data[i + 1]]));
            i += 2;
        }
        return char::decode_utf16(units)
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect::<String>()
            .into_bytes();
    }
    data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data).to_vec()
}

pub fn classify_payload(data: &[u8]) -> PayloadClassification {
    if data.len() >= 2 && &data[..2] == b"MZ" {
        return match pe_characteristics(data) {
            Some(characteristics) if characteristics & IMAGE_FILE_DLL != 0 => kind(
                "pe-dll",
                "Windows DLL",
                "Windows",
                "library",
                "PE forensics and Wine DLL detonation",
                true,
            ),
            Some(_) => kind(
                "pe-exe",
                "Windows PE executable",
                "Windows",
                "executable",
                "PE forensics and Wine detonation",
                true,
            ),
            None => kind(
                "pe-exe",
                "Windows PE/DOS executable",
                "Windows",
                "executable",
                "PE forensics and Wine detonation",
                true,
            ),
        };
    }
    if data.len() >= 4 && &data[..4] == [0x7f, b'E', b'L', b'F'] {
        if elf_is_dyn_without_interpreter(data) == Some(true) {
            return kind(
                "elf-library",
                "Linux ELF shared object",
                "Linux",
                "library",
                "ELF static metadata; library is not invoked automatically",
                false,
            );
        }
        return kind(
            "elf-exe",
            "Linux ELF executable",
            "Linux",
            "executable",
            "Native Linux detonation under strace",
            true,
        );
    }

    let text_bytes = normalized_text(data);
    let text = String::from_utf8_lossy(&text_bytes).to_string();
    let lower = text.to_lowercase();
    let head = &lower[..lower.len().min(65536)];
    let first = &head[..head.len().min(256)];
    let first_trimmed = first.trim();

    if first_trimmed.starts_with("<?php") {
        return kind(
            "php",
            "PHP script",
            "Cross-platform",
            "script",
            "PHP CLI under strace",
            true,
        );
    }
    if has_any(
        head,
        &[
            "wscript.createobject",
            "createobject(",
            "wscript.shell",
            "on error resume next",
        ],
    ) && has_any(head, &["dim ", "set ", "wscript.", "cscript"])
    {
        return kind(
            "vbscript",
            "Windows VBScript",
            "Windows",
            "script",
            "Wine cscript.exe under strace",
            true,
        );
    }
    if has_any(head, &["@echo off", "%comspec%", "setlocal", "cmd.exe /c", "cmd /c "]) {
        return kind(
            "batch",
            "Windows batch script",
            "Windows",
            "script",
            "Wine cmd.exe under strace",
            true,
        );
    }
    if has_any(
        head,
        &[
            "powershell",
            "invoke-webrequest",
            "invoke-expression",
            "frombase64string",
            "new-object net.webclient",
            "$env:",
            "param(",
        ],
    ) {
        return kind(
            "powershell",
            "PowerShell script",
            "Windows",
            "script",
            "Wine PowerShell route with static fallback",
            true,
        );
    }
    if has_any(head, &["wscript.", "activexobject(", "cscript.exe"])
        && has_any(head, &["function", "var ", "eval(", "createobject"])
    {
        return kind(
            "jscript",
            "Windows JScript",
            "Windows",
            "script",
            "Wine cscript.exe JScript engine under strace",
            true,
        );
    }
    if first_trimmed.starts_with("#!") && has_any(first, &["/sh", "/bash", "/dash", "/zsh", "/ksh"]) {
        return kind(
            "shell",
            "POSIX shell script",
            "Linux",
            "script",
            "Bash under strace",
            true,
        );
    }
    if first_trimmed.starts_with("#!") && first.contains("python") {
        return kind(
            "python",
            "Python script",
            "Cross-platform",
            "script",
            "Python 3 under strace",
            true,
        );
    }
    if first_trimmed.starts_with("#!") && has_any(first, &["node", "javascript"]) {
        return kind(
            "javascript",
            "JavaScript / Node.js script",
            "Cross-platform",
            "script",
            "Node.js under strace",
            true,
        );
    }
    if has_any(head, &["import os", "import sys", "subprocess.", "__name__ =="])
        && has_any(head, &["def ", "print(", "python"])
    {
        return kind(
            "python",
            "Python script",
            "Cross-platform",
            "script",
            "Python 3 under strace",
            true,
        );
    }
    if has_any(
        head,
        &["#!/bin/", "curl ", "wget ", "chmod +x", "/dev/tcp/", "export path="],
    ) {
        return kind(
            "shell",
            "POSIX shell command/script",
            "Linux",
            "script",
            "Bash under strace",
            true,
        );
    }
    if has_any(head, &["require(", "module.exports", "process.env", "const ", "let "])
        && has_any(head, &["function", "=>", "console.", "eval("])
    {
        return kind(
            "javascript",
            "JavaScript / Node.js script",
            "Cross-platform",
            "script",
            "Node.js under strace",
            true,
        );
    }

    if data.len() >= 5 && &data[..5] == b"%PDF-" {
        return kind(
            "pdf",
            "PDF document",
            "Cross-platform",
            "document",
            "Static document metadata and strings",
            false,
        );
    }
    if data.len() >= 8 && data[..8] == [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] {
        return kind(
            "ole",
            "OLE / legacy Office document",
            "Windows",
            "document",
            "Static document metadata and strings",
            false,
        );
    }
    if data.len() >= 4 && data[..4] == [b'P', b'K', 3, 4] {
        return kind(
            "zip",
            "ZIP / OOXML / JAR archive",
            "Cross-platform",
            "archive",
            "Static archive metadata and strings",
            false,
        );
    }
    if data.len() >= 8 && data[..8] == [b'R', b'a', b'r', b'!', 0x1a, 0x07, 0x00] {
        return kind(
            "rar",
            "RAR archive",
            "Cross-platform",
            "archive",
            "Static archive metadata and strings",
            false,
        );
    }
    if data.len() >= 6 && data[..6] == [b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c] {
        return kind(
            "7z",
            "7-Zip archive",
            "Cross-platform",
            "archive",
            "Static archive metadata and strings",
            false,
        );
    }
    if data.len() >= 2 && data[..2] == [0x1f, 0x8b] {
        return kind(
            "gzip",
            "Gzip-compressed data",
            "Cross-platform",
            "archive",
            "Static compressed-file metadata and strings",
            false,
        );
    }
    if mostly_text(&text_bytes) {
        return kind(
            "text",
            "Plain-text artifact",
            "Unknown",
            "text",
            "Static text, IOC, deobfuscation, and YARA analysis",
            false,
        );
    }
    kind(
        "binary",
        "Unknown binary data",
        "Unknown",
        "binary",
        "Static binary metadata, strings, hashes, and YARA analysis",
        false,
    )
}
