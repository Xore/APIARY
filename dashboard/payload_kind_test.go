package main

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestClassifyPayloadRoutes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		code string
	}{
		{"shell", []byte("#!/usr/bin/env bash\ncurl https://example.invalid/a\n"), "shell"},
		{"vbscript", []byte("On Error Resume Next\nDim x\nSet x = CreateObject(\"WScript.Shell\")\n"), "vbscript"},
		{"batch", []byte("@echo off\r\nsetlocal\r\ncmd.exe /c whoami\r\n"), "batch"},
		{"python", []byte("#!/usr/bin/python3\nimport os\nprint(os.getcwd())\n"), "python"},
		{"javascript", []byte("#!/usr/bin/env node\nconst os = require(\"os\"); console.log(os.hostname());\n"), "javascript"},
		{"pdf", []byte("%PDF-1.7\n"), "pdf"},
		{"zip", []byte{'P', 'K', 3, 4, 0, 0, 0, 0}, "zip"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyPayload(test.data); got.Code != test.code {
				t.Fatalf("classifyPayload() code = %q (%s), want %q", got.Code, got.Label, test.code)
			}
		})
	}
}

func TestClassifyUTF16PowerShell(t *testing.T) {
	units := utf16.Encode([]rune("param($Path)\r\nInvoke-WebRequest $Path\r\n"))
	data := []byte{0xff, 0xfe}
	for _, unit := range units {
		var raw [2]byte
		binary.LittleEndian.PutUint16(raw[:], unit)
		data = append(data, raw[:]...)
	}
	if got := classifyPayload(data); got.Code != "powershell" {
		t.Fatalf("classifyPayload() = %#v, want powershell", got)
	}
}

func TestClassifyPEDLL(t *testing.T) {
	data := make([]byte, 512)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[0x84:], 0x14c)
	binary.LittleEndian.PutUint16(data[0x94:], 0)
	binary.LittleEndian.PutUint16(data[0x96:], 0x2000)
	if got := classifyPayload(data); got.Code != "pe-dll" || got.Dynamic {
		t.Fatalf("classifyPayload() = %#v, want static pe-dll", got)
	}
}
