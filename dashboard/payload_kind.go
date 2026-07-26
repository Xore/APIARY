package main

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// payloadClassification is deliberately content based because captured
// artifacts are stored under their SHA-256 rather than their original name.
// Code values are shared with the disposable guest classifier.
type payloadClassification struct {
	Code         string
	Label        string
	Platform     string
	Category     string
	AnalysisPath string
	Dynamic      bool
}

func payloadKind(code, label, platform, category, path string, dynamic bool) payloadClassification {
	return payloadClassification{Code: code, Label: label, Platform: platform, Category: category, AnalysisPath: path, Dynamic: dynamic}
}

func classifyPayload(data []byte) payloadClassification {
	if len(data) >= 2 && bytes.Equal(data[:2], []byte("MZ")) {
		if f, err := pe.NewFile(bytes.NewReader(data)); err == nil {
			defer f.Close()
			if f.FileHeader.Characteristics&0x2000 != 0 {
				return payloadKind("pe-dll", "Windows DLL", "Windows", "library", "PE forensics; DLL is not invoked automatically", false)
			}
			return payloadKind("pe-exe", "Windows PE executable", "Windows", "executable", "PE forensics and Wine detonation", true)
		}
		return payloadKind("pe-exe", "Windows PE/DOS executable", "Windows", "executable", "PE forensics and Wine detonation", true)
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		if f, err := elf.NewFile(bytes.NewReader(data)); err == nil {
			defer f.Close()
			if f.Type == elf.ET_DYN && !elfHasInterpreter(f) {
				return payloadKind("elf-library", "Linux ELF shared object", "Linux", "library", "ELF static metadata; library is not invoked automatically", false)
			}
		}
		return payloadKind("elf-exe", "Linux ELF executable", "Linux", "executable", "Native Linux detonation under strace", true)
	}

	text := normalizedPayloadText(data)
	lower := strings.ToLower(text)
	head := lower[:min(len(lower), 65536)]
	first := head[:min(len(head), 256)]
	switch {
	case strings.HasPrefix(strings.TrimSpace(first), "<?php"):
		return payloadKind("php", "PHP script", "Cross-platform", "script", "PHP CLI under strace", true)
	case hasAny(head, "wscript.createobject", "createobject(", "wscript.shell", "on error resume next") &&
		hasAny(head, "dim ", "set ", "wscript.", "cscript"):
		return payloadKind("vbscript", "Windows VBScript", "Windows", "script", "Wine cscript.exe under strace", true)
	case hasAny(head, "@echo off", "%comspec%", "setlocal", "cmd.exe /c", "cmd /c "):
		return payloadKind("batch", "Windows batch script", "Windows", "script", "Wine cmd.exe under strace", true)
	case hasAny(head, "powershell", "invoke-webrequest", "invoke-expression", "frombase64string", "new-object net.webclient", "$env:", "param("):
		return payloadKind("powershell", "PowerShell script", "Windows", "script", "Wine PowerShell route with static fallback", true)
	case hasAny(head, "wscript.", "activexobject(", "cscript.exe") &&
		hasAny(head, "function", "var ", "eval(", "createobject"):
		return payloadKind("jscript", "Windows JScript", "Windows", "script", "Wine cscript.exe JScript engine under strace", true)
	case strings.HasPrefix(strings.TrimSpace(first), "#!") &&
		hasAny(first, "/sh", "/bash", "/dash", "/zsh", "/ksh"):
		return payloadKind("shell", "POSIX shell script", "Linux", "script", "Bash under strace", true)
	case strings.HasPrefix(strings.TrimSpace(first), "#!") && strings.Contains(first, "python"):
		return payloadKind("python", "Python script", "Cross-platform", "script", "Python 3 under strace", true)
	case strings.HasPrefix(strings.TrimSpace(first), "#!") && hasAny(first, "node", "javascript"):
		return payloadKind("javascript", "JavaScript / Node.js script", "Cross-platform", "script", "Node.js under strace", true)
	case hasAny(head, "import os", "import sys", "subprocess.", "__name__ ==") &&
		hasAny(head, "def ", "print(", "python"):
		return payloadKind("python", "Python script", "Cross-platform", "script", "Python 3 under strace", true)
	case hasAny(head, "#!/bin/", "curl ", "wget ", "chmod +x", "/dev/tcp/", "export path="):
		return payloadKind("shell", "POSIX shell command/script", "Linux", "script", "Bash under strace", true)
	case hasAny(head, "require(", "module.exports", "process.env", "const ", "let ") &&
		hasAny(head, "function", "=>", "console.", "eval("):
		return payloadKind("javascript", "JavaScript / Node.js script", "Cross-platform", "script", "Node.js under strace", true)
	}

	switch {
	case len(data) >= 5 && bytes.Equal(data[:5], []byte("%PDF-")):
		return payloadKind("pdf", "PDF document", "Cross-platform", "document", "Static document metadata and strings", false)
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}):
		return payloadKind("ole", "OLE / legacy Office document", "Windows", "document", "Static document metadata and strings", false)
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 3, 4}):
		return payloadKind("zip", "ZIP / OOXML / JAR archive", "Cross-platform", "archive", "Static archive metadata and strings", false)
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}):
		return payloadKind("rar", "RAR archive", "Cross-platform", "archive", "Static archive metadata and strings", false)
	case len(data) >= 6 && bytes.Equal(data[:6], []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}):
		return payloadKind("7z", "7-Zip archive", "Cross-platform", "archive", "Static archive metadata and strings", false)
	case len(data) >= 2 && bytes.Equal(data[:2], []byte{0x1f, 0x8b}):
		return payloadKind("gzip", "Gzip-compressed data", "Cross-platform", "archive", "Static compressed-file metadata and strings", false)
	case mostlyText(text):
		return payloadKind("text", "Plain-text artifact", "Unknown", "text", "Static text, IOC, deobfuscation, and YARA analysis", false)
	default:
		return payloadKind("binary", "Unknown binary data", "Unknown", "binary", "Static binary metadata, strings, hashes, and YARA analysis", false)
	}
}

func elfHasInterpreter(f *elf.File) bool {
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return true
		}
	}
	return false
}

func normalizedPayloadText(data []byte) string {
	data = data[:min(len(data), 1<<20)]
	if len(data) >= 2 && data[0] == 0xff && data[1] == 0xfe {
		u16 := make([]uint16, 0, (len(data)-2)/2)
		for i := 2; i+1 < len(data); i += 2 {
			u16 = append(u16, binary.LittleEndian.Uint16(data[i:i+2]))
		}
		return string(utf16.Decode(u16))
	}
	return string(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
}

func hasAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func mostlyText(text string) bool {
	if text == "" {
		return false
	}
	printable := 0
	total := min(len(text), 8192)
	for _, b := range []byte(text[:total]) {
		if b == '\n' || b == '\r' || b == '\t' || b >= 0x20 && b < 0x7f {
			printable++
		}
	}
	return total > 0 && printable*100/total >= 85
}
