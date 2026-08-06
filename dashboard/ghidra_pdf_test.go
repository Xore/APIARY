package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newGhidraReportTestStore is newReportTestStore plus a real ghidra result
// file on disk, for #814's ghidra-report pipeline tests -- mirrors
// newPayloadReportTestStore's shape in payload_pdf_test.go.
func newGhidraReportTestStore(t *testing.T, hash string, result ghidraResult) *store {
	t.Helper()
	s := newReportTestStore(t)
	dir := t.TempDir()
	result.SHA256 = hash
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hash+"_ghidra.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	return s
}

func sampleGhidraResult() ghidraResult {
	return ghidraResult{
		RequestedAt: "2026-08-06T10:00:00Z",
		StartedAt:   "2026-08-06T10:00:05Z",
		CompletedAt: "2026-08-06T10:04:30Z",
		ExitStatus:  "completed",
		Functions: []ghidraFunction{
			{Address: "0x401000", Name: "main", Signature: "int main(void)", Size: 128},
		},
		Strings: []string{"/bin/sh", "usage: %s [args]"},
		Imports: []string{"libc.so.6::system", "libc.so.6::strcpy"},
		AITriage: &ghidraTriage{
			Workflow: "capa+strings", FamilyGuess: "mirai-variant", RiskLevel: "high",
			Behaviors: []string{"spawns a shell", "static network indicators present"},
			Model:     "qwen3:14b", EvidenceShown: "2/2 imports, 2/2 strings",
		},
	}
}

// TestGenerateGhidraReportThroughPipeline proves the ghidra template turns a
// real result file into a themed PDF that actually contains its evidence --
// the ghidra counterpart to TestGeneratePayloadReportThroughPipeline.
func TestGenerateGhidraReportThroughPipeline(t *testing.T) {
	hash := strings.Repeat("a", 64)
	s := newGhidraReportTestStore(t, hash, sampleGhidraResult())

	def := reportDefinition{
		Name: "Ghidra check", Template: "ghidra", Theme: "dark",
		Scope: reportScope{Hash: hash},
	}
	if err := validateDefinitionFields(def); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pdf, title, err := s.renderDefinitionPDFBytes(def)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if title != "Ghidra Static Analysis Report" {
		t.Fatalf("title = %q", title)
	}
	text := string(pdf)
	for _, want := range []string{"Ghidra Static Analysis Report", hash, "main", "mirai-variant"} {
		if !strings.Contains(text, want) {
			t.Fatalf("ghidra report missing %q", want)
		}
	}
}

// TestGenerateGhidraReportRejectsUnknownHash proves an unresolvable hash
// fails validation instead of producing an empty/misleading PDF.
func TestGenerateGhidraReportRejectsUnknownHash(t *testing.T) {
	s := newGhidraReportTestStore(t, strings.Repeat("a", 64), sampleGhidraResult())
	def := reportDefinition{
		Name: "x", Template: "ghidra", Theme: "dark",
		Scope: reportScope{Hash: strings.Repeat("b", 64)},
	}
	if _, _, err := s.renderDefinitionPDFBytes(def); err == nil {
		t.Fatal("expected an error for a hash with no ghidra result")
	}
}

// TestReportTemplateCatalogIncludesGhidra guards against #814's template
// silently disappearing from the catalog the designer UI reads.
func TestReportTemplateCatalogIncludesGhidra(t *testing.T) {
	template, ok := reportTemplateByID("ghidra")
	if !ok || !template.Ghidra {
		t.Fatalf("ghidra template missing or not marked Ghidra: %+v", template)
	}
}

// TestValidateDefinitionFieldsGhidraSharesPayloadScopeRules proves the
// ghidra template is validated exactly like payload (Scope.Hash required,
// Scope.Job and Elements forbidden) rather than accidentally falling
// through to the free-form default case.
func TestValidateDefinitionFieldsGhidraSharesPayloadScopeRules(t *testing.T) {
	base := reportDefinition{Name: "x", Template: "ghidra", Theme: "dark"}
	if err := validateDefinitionFields(base); err == nil {
		t.Fatal("expected an error for a ghidra definition with no scope.hash")
	}
	withJob := base
	withJob.Scope = reportScope{Hash: strings.Repeat("a", 64), Job: "some-job"}
	if err := validateDefinitionFields(withJob); err == nil {
		t.Fatal("expected an error for a ghidra definition carrying scope.job")
	}
	withElements := base
	withElements.Scope = reportScope{Hash: strings.Repeat("a", 64)}
	withElements.Elements = []string{elementCover}
	if err := validateDefinitionFields(withElements); err == nil {
		t.Fatal("expected an error for a ghidra definition carrying elements")
	}
}
