package main

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
	"time"
)

func TestGhidraPageRendersWithPopulatedGPUQueue(t *testing.T) {
	s := searchTestStore(t)
	tmpl, err := template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate)
	if err != nil {
		t.Fatalf("dashboard template does not parse: %v", err)
	}
	data := ghidraPageData{
		Generated: time.Now(),
		Status:    ghidraQueueStatus{Configured: true},
		GPUQueue: []gpuQueueJob{
			{
				ID: "job-abc123", JobType: "ghidra-triage",
				Ref: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
				Model: "qwen3:14b", EstimatedVRAMib: 14500, Status: "queued",
				RequestedAt: "2026-08-05T15:00:00Z", Attempts: 0,
			},
			{
				ID: "job-def456", JobType: "ghidra-triage",
				Ref: "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"[:64],
				Model: "qwen3:14b", EstimatedVRAMib: 14500, Status: "running",
				RequestedAt: "2026-08-05T14:55:00Z", Attempts: 1,
			},
			{
				ID: "job-ghi789", JobType: "ghidra-triage",
				Ref: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"[:64],
				Model: "qwen3:14b", EstimatedVRAMib: 14500, Status: "failed",
				RequestedAt: "2026-08-05T14:50:00Z", Attempts: 3, Error: "model produced no usable answer",
				AbortRequested: true,
			},
		},
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "ghidra", &data); err != nil {
		t.Fatalf("template execution failed: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"GPU queue", "deadbeefdeadbeef", "queued", "running", "failed",
		"qwen3:14b", "Abort", "abort requested",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
	// Abort form must only appear for the queued row, not running/failed.
	if strings.Count(out, `action="/gpu-queue/abort"`) != 1 {
		t.Errorf("expected exactly one abort form (only the queued job), got %d",
			strings.Count(out, `action="/gpu-queue/abort"`))
	}
}
