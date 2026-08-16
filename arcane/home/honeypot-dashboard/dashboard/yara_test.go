package main

import (
	"net/http/httptest"
	"testing"
)

// yaraESClientFor returns an *esClient pointed at a stub serving
// docsByIndex, for tests that call yara.go's functions directly (they take
// an explicit *esClient parameter, not the package-level esResultsClient
// esResultsClientFor points at -- see cape.go/ghidra.go's own
// two-tier loadX()/loadXES(es) split for the same convention).
func yaraESClientFor(t *testing.T, docsByIndex map[string][]map[string]any) *esClient {
	t.Helper()
	srv := httptest.NewServer(esResultsStub(t, docsByIndex))
	t.Cleanup(srv.Close)
	return newESClient(srv.URL, "")
}

func TestYaraSummaryReadsESExclusively(t *testing.T) {
	es := yaraESClientFor(t, map[string][]map[string]any{
		"yara-analysis-v1": {
			{"yara": map[string]any{
				"sha256": shaA, "matches": []string{"susp_string"}, "source": "dionaea",
				"size": 123, "scanned_at": "2026-08-11T00:00:00Z", "report_updated_at": "2026-08-11T00:05:00Z",
			}},
			{"yara": map[string]any{
				"sha256": shaB, "matches": []string{}, "source": "cowrie", "size": 45,
				"scanned_at": "2026-08-10T00:00:00Z", "report_updated_at": "2026-08-11T00:05:00Z",
			}},
		},
	})

	status := yaraSummary(es)
	if !status.Enabled {
		t.Fatal("Enabled = false, want true (ES answered successfully)")
	}
	if status.Samples != 2 {
		t.Errorf("Samples = %d, want 2", status.Samples)
	}
	if status.Matched != 1 {
		t.Errorf("Matched = %d, want 1", status.Matched)
	}
	if status.Errors != 0 {
		t.Errorf("Errors = %d, want 0", status.Errors)
	}
	if status.Updated != "2026-08-11T00:05:00Z" {
		t.Errorf("Updated = %q, want the report_updated_at value", status.Updated)
	}
}

func TestYaraSummaryCountsErrorsAndMissingIndexIsNotEnabled(t *testing.T) {
	es := yaraESClientFor(t, map[string][]map[string]any{
		"yara-analysis-v1": {
			{"yara": map[string]any{"sha256": shaA, "matches": []string{}, "error": "sample exceeds byte scan limit"}},
		},
	})
	status := yaraSummary(es)
	if status.Errors != 1 {
		t.Errorf("Errors = %d, want 1", status.Errors)
	}

	// es == nil (no identity/ES configured at all) must not panic and must
	// report Enabled=false, the same "not configured" signal every other
	// #1103 loader gives rather than a zero-value that looks like "scanned,
	// found nothing."
	disabled := yaraSummary(nil)
	if disabled.Enabled {
		t.Error("Enabled = true with a nil *esClient, want false")
	}
}

func TestYaraForLooksUpBySHA256CaseInsensitively(t *testing.T) {
	es := yaraESClientFor(t, map[string][]map[string]any{
		"yara-analysis-v1": {
			{"yara": map[string]any{"sha256": shaA, "matches": []string{"eicar_test"}, "source": "dionaea"}},
		},
	})
	s := &store{es: es}

	upper := shaA
	for i, r := range upper {
		if r >= 'a' && r <= 'f' {
			upper = upper[:i] + string(r-32) + upper[i+1:]
		}
	}

	sample := s.yaraFor(upper)
	if len(sample.Matches) != 1 || sample.Matches[0] != "eicar_test" {
		t.Errorf("yaraFor(%q) = %+v, want the eicar_test match", upper, sample)
	}

	byHash := s.yaraForSHA(shaA)
	if byHash.SHA256 != shaA {
		t.Errorf("yaraForSHA(%q) = %+v, want SHA256 = %s", shaA, byHash, shaA)
	}

	miss := s.yaraFor(shaB)
	if len(miss.Matches) != 0 || miss.SHA256 != "" {
		t.Errorf("yaraFor(%q) (never scanned) = %+v, want a zero-value yaraSample", shaB, miss)
	}
}
