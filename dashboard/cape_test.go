package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCapeResult(t *testing.T, dir, sha string, row map[string]any) {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sha+"_cape.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// capeSearchNamespaceStub answers es.searchNamespace's own request shape --
// see revdeckSearchNamespaceStub's doc comment in revdeck_test.go for the
// underlying contract; this is the same pattern for cape-analysis-v1's own
// "cape" field name.
func capeSearchNamespaceStub(t *testing.T, docs []map[string]any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		type hit struct {
			Source struct {
				Cape map[string]any `json:"cape"`
			} `json:"_source"`
		}
		hits := make([]hit, 0, len(docs))
		for _, d := range docs {
			var h hit
			h.Source.Cape = d
			hits = append(hits, h)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	}
}

func TestLoadCapeResults(t *testing.T) {
	srv := httptest.NewServer(capeSearchNamespaceStub(t, []map[string]any{
		{"sha256": shaA, "version": 1, "exit_status": "ok", "cape_status": "reported",
			"completed_at": "2026-08-08T17:16:22+00:00", "score": 42.0},
		{"sha256": shaB, "version": 1, "exit_status": "error", "error": "task 10 ended in state 'failed_analysis'",
			"completed_at": "2026-08-08T18:00:00+00:00"},
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	rows := loadCapeResults()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	// Newest first.
	if rows[0].SHA256 != shaB {
		t.Errorf("rows are not newest-first: got %s first", rows[0].SHA256[:8])
	}
	if rows[0].ExitStatus != "error" || rows[0].Error == "" {
		t.Errorf("failed result lost its error: %+v", rows[0])
	}
	if rows[1].Score == nil || *rows[1].Score != 42.0 {
		t.Errorf("successful result did not decode its score: %+v", rows[1])
	}
}

func TestLoadCapeResultsAbsentIsEmpty(t *testing.T) {
	t.Setenv("CAPE_RESULTS_DIR", "")
	if rows := loadCapeResults(); rows != nil {
		t.Fatalf("expected nil rows with no results dir configured, got %+v", rows)
	}
}

func TestCapeDataNotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CAPE_RESULTS_DIR", dir)
	if _, err := capeData(shaA); err == nil {
		t.Fatal("expected an error for a hash with no CAPE result")
	}
	if _, err := capeData(""); err == nil {
		t.Fatal("expected an error for an empty hash")
	}
}

func TestCapeDataFindsMatchingResultAndParsesSummary(t *testing.T) {
	srv := httptest.NewServer(capeSearchNamespaceStub(t, []map[string]any{
		{"sha256": shaA, "version": 1, "exit_status": "ok", "cape_status": "reported",
			"completed_at": "2026-08-08T17:16:22+00:00", "score": 0.0,
			"report": map[string]any{
				"info": map[string]any{
					"machine": map[string]any{"label": "win11-cape"},
					"package": "generic", "route": "drop", "timeout": false, "duration": 317,
				},
				"malscore": 0.0, "malstatus": nil,
				"behavior": map[string]any{
					"summary": map[string]any{"files": []string{"C:\\Windows\\Temp\\x.dat"}},
					"processes": []map[string]any{
						{"process_id": 1000, "process_name": "sample.exe", "parent_id": 500,
							"first_seen": "2026-08-08 17:11:06", "calls": []map[string]any{{"api": "NtOpenKey"}, {"api": "NtClose"}}},
					},
				},
			},
		},
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)
	data, err := capeData(shaA)
	if err != nil {
		t.Fatal(err)
	}
	if data.Detail == nil || data.Detail.SHA256 != shaA {
		t.Fatalf("capeData did not find the matching result: %+v", data)
	}
	if data.Summary == nil {
		t.Fatal("capeData did not parse a report summary")
	}
	if data.Summary.Machine != "win11-cape" || data.Summary.Duration != 317 {
		t.Errorf("summary did not decode info.*: %+v", data.Summary)
	}
	if len(data.Summary.Processes) != 1 || data.Summary.Processes[0].CallCount != 2 {
		t.Errorf("summary did not decode process call count: %+v", data.Summary.Processes)
	}
	if data.Summary.TotalCalls != 2 {
		t.Errorf("TotalCalls = %d, want 2", data.Summary.TotalCalls)
	}
	if len(data.Summary.SummaryKeys) != 1 || data.Summary.SummaryKeys[0] != "files" {
		t.Errorf("SummaryKeys = %+v, want [files]", data.Summary.SummaryKeys)
	}
}

// TestCapeResultScoreDereferencesPointer (#319): confirmed live that
// text/template's printf verb does not dereference a *float64 -- this
// locks ScoreDisplay's own behavior in so a future refactor back to an
// inline printf can't reintroduce it silently.
func TestCapeResultScoreDereferencesPointer(t *testing.T) {
	score := 42.0
	r := &capeResult{Score: &score}
	if got := r.ScoreDisplay(); got != "42" {
		t.Errorf("ScoreDisplay() = %q, want %q", got, "42")
	}
	if !r.ScoreIsRisky() {
		t.Error("ScoreIsRisky() = false for a non-zero score")
	}

	var nilResult *capeResult
	if got := nilResult.ScoreDisplay(); got != "0" {
		t.Errorf("nil receiver ScoreDisplay() = %q, want %q", got, "0")
	}
	if nilResult.ScoreIsRisky() {
		t.Error("nil receiver ScoreIsRisky() = true, want false")
	}
}

// TestCapeResultZeroScoreIsNotRisky (#319): the actual live bug this
// guards against -- a Go template's {{if}} on a non-nil pointer only
// checks nil-ness, not the value. A confirmed-benign malscore of 0.0 (a
// non-nil *float64) must not read as risky, the same way task 9 in the
// #318 verification run genuinely scored 0.0.
func TestCapeResultZeroScoreIsNotRisky(t *testing.T) {
	zero := 0.0
	r := &capeResult{Score: &zero}
	if r.ScoreIsRisky() {
		t.Error("ScoreIsRisky() = true for a genuine 0.0 score -- would highlight a clean result as risky")
	}
	if got := r.ScoreDisplay(); got != "0" {
		t.Errorf("ScoreDisplay() = %q, want %q", got, "0")
	}

	r2 := &capeResult{Score: nil}
	if r2.ScoreIsRisky() {
		t.Error("ScoreIsRisky() = true for a never-scored (nil) result")
	}
}

func TestCountJSONArrayElements(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int
	}{
		{"empty", "", 0},
		{"empty array", "[]", 0},
		{"three elements", `[{"api":"a"},{"api":"b"},{"api":"c"}]`, 3},
		{"not an array", `{"a":1}`, 0},
		{"nested arrays don't over-count", `[{"arguments":[1,2,3]},{"arguments":[4,5]}]`, 2},
	}
	for _, c := range cases {
		if got := countJSONArrayElements(json.RawMessage(c.raw)); got != c.want {
			t.Errorf("%s: countJSONArrayElements(%q) = %d, want %d", c.name, c.raw, got, c.want)
		}
	}
}

func TestServeCapeAPI(t *testing.T) {
	srv := httptest.NewServer(capeSearchNamespaceStub(t, []map[string]any{
		{"sha256": shaA, "version": 1, "exit_status": "ok", "cape_status": "reported",
			"completed_at": "2026-08-08T17:16:22+00:00"},
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	r := httptest.NewRequest(http.MethodGet, "/api/cape/"+shaA, nil)
	w := httptest.NewRecorder()
	serveCapeAPI(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var got capeResult
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("response was not valid JSON: %v", err)
	}
	if got.SHA256 != shaA {
		t.Errorf("got.SHA256 = %q, want %q", got.SHA256, shaA)
	}
}

func TestServeCapeAPINotFound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CAPE_RESULTS_DIR", dir)

	for _, path := range []string{"/api/cape/" + shaA, "/api/cape/not-a-hash", "/api/cape/"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		serveCapeAPI(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("path %q: status = %d, want 404", path, w.Code)
		}
	}
}

// TestLoadCapeResultsIgnoresLocalFile (#1103): a local *_cape.json file
// present alongside a configured CAPE_RESULTS_DIR must never be read --
// loadCapeResults reads Elasticsearch exclusively now.
func TestLoadCapeResultsIgnoresLocalFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CAPE_RESULTS_DIR", dir)
	writeCapeResult(t, dir, shaA, map[string]any{
		"version": 1, "sha256": shaA, "exit_status": "ok", "cape_status": "local-only",
		"completed_at": "2026-08-08T09:00:00+00:00",
	})

	srv := httptest.NewServer(capeSearchNamespaceStub(t, []map[string]any{
		{"sha256": shaB, "exit_status": "ok", "cape_status": "es-sourced",
			"completed_at": "2026-08-08T10:00:00+00:00"},
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	rows := loadCapeResults()
	if len(rows) != 1 || rows[0].SHA256 != shaB || rows[0].CapeStatus != "es-sourced" {
		t.Fatalf("expected only the ES-sourced result, got %+v", rows)
	}
}

// TestLoadCapeResultsESFailureYieldsNoResults (#1103): loadCapeResults reads
// Elasticsearch exclusively now -- an ES error means "no results this
// cycle," not a reason to fall back to a local file that happens to exist.
func TestLoadCapeResultsESFailureYieldsNoResults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CAPE_RESULTS_DIR", dir)
	writeCapeResult(t, dir, shaA, map[string]any{
		"version": 1, "sha256": shaA, "exit_status": "ok", "cape_status": "local-only",
		"completed_at": "2026-08-08T09:00:00+00:00",
	})
	withESResultsClient(t, "http://127.0.0.1:1") // nothing listening

	if rows := loadCapeResults(); rows != nil {
		t.Fatalf("expected no results when ES fails, got %+v -- must not fall back to the local file", rows)
	}
}

// TestLoadCapeStatus (#319 follow-up): matches loadGhidraStatus's own test
// table -- same status.json shape, same staleness/live-recheck rules,
// deliberately kept in lockstep since capeQueueStatus/loadCapeStatus are a
// close copy of ghidraQueueStatus/loadGhidraStatus.
func TestLoadCapeStatus(t *testing.T) {
	t.Run("unconfigured", func(t *testing.T) {
		t.Setenv("CAPE_RESULTS_DIR", "")
		if s := loadCapeStatus(); s.Configured {
			t.Error("unset results dir should report Configured=false")
		}
	})

	t.Run("configured but never run", func(t *testing.T) {
		t.Setenv("CAPE_RESULTS_DIR", t.TempDir())
		s := loadCapeStatus()
		if !s.Configured || !s.Stale {
			t.Errorf("missing status.json should be Configured+Stale, got %+v", s)
		}
	})

	t.Run("fresh status", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CAPE_RESULTS_DIR", dir)
		raw := `{"version":1,"queued":2,"running":1,"failed":0,"done":5}`
		if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		s := loadCapeStatus()
		if s.Queued != 2 || s.Running != 1 || s.Done != 5 {
			t.Errorf("counts not parsed: %+v", s)
		}
		if s.Stale {
			t.Error("a just-written status.json should not be stale")
		}
	})

	t.Run("stale status, no request dir configured", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CAPE_RESULTS_DIR", dir)
		t.Setenv("CAPE_REQUEST_DIR", "")
		path := filepath.Join(dir, "status.json")
		if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * capeStatusStaleAfter)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		if s := loadCapeStatus(); !s.Stale {
			t.Error("an old status.json with no request dir to re-check should fall back to stale")
		}
	})

	// Same #204 reasoning loadGhidraStatus's own test asserts: an idle
	// honeypot with nothing submitted for 30+ minutes is routine, not proof
	// the worker died -- the path unit only rewrites status.json when it
	// fires. Staleness must follow the live spool, not the stale counts.
	t.Run("stale status.json but empty live spool is not stale", func(t *testing.T) {
		resultsDir, requestDir := t.TempDir(), t.TempDir()
		t.Setenv("CAPE_RESULTS_DIR", resultsDir)
		t.Setenv("CAPE_REQUEST_DIR", requestDir)
		path := filepath.Join(resultsDir, "status.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"queued":3,"running":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * capeStatusStaleAfter)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		if s := loadCapeStatus(); s.Stale {
			t.Errorf("empty live spool should not be stale even with stale status.json counts: %+v", s)
		}
	})

	t.Run("stale status.json with a non-empty live spool is stale", func(t *testing.T) {
		resultsDir, requestDir := t.TempDir(), t.TempDir()
		t.Setenv("CAPE_RESULTS_DIR", resultsDir)
		t.Setenv("CAPE_REQUEST_DIR", requestDir)
		path := filepath.Join(resultsDir, "status.json")
		if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * capeStatusStaleAfter)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(requestDir, shaA+".request"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		s := loadCapeStatus()
		if !s.Stale || s.Queued != 1 {
			t.Errorf("a queued request behind a stale status.json should report stale+queued=1, got %+v", s)
		}
	})
}

func capeAlertMessages(t *testing.T, dir string) []string {
	t.Helper()
	t.Setenv("CAPE_RESULTS_DIR", dir)
	var messages []string
	capeAlerts(&store{}, &messages, false)
	return messages
}

// TestCapeAlertsSilentWhenUnconfigured (#319 follow-up): matches
// TestGhidraAlertsSilentWhenUnconfigured -- alerting about a subsystem
// nobody deployed on this host is pure noise.
func TestCapeAlertsSilentWhenUnconfigured(t *testing.T) {
	t.Setenv("CAPE_RESULTS_DIR", "")
	var messages []string
	capeAlerts(&store{}, &messages, false)
	if len(messages) != 0 {
		t.Fatalf("unconfigured host produced alerts: %v", messages)
	}
}

func TestCapeAlertsOnStaleWorker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"queued":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * capeStatusStaleAfter)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	messages := capeAlertMessages(t, dir)
	if !hasAlert(messages, "not draining") {
		t.Fatalf("no stale-worker alert: %v", messages)
	}
	if !hasAlert(messages, "3 queued") {
		t.Errorf("stale alert omits the queue depth: %v", messages)
	}
}

func TestCapeAlertsOnFailedRequest(t *testing.T) {
	dir := t.TempDir()
	raw := `{"version":1,"failed":2}`
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	messages := capeAlertMessages(t, dir)
	if !hasAlert(messages, "2 failed request") {
		t.Fatalf("no failed-request alert: %v", messages)
	}
}

func TestCapeAlertsDedupeAcrossKeys(t *testing.T) {
	// Both alert keys ("cape:worker", "cape:failed") must be distinct from
	// ghidra's/github-analysis's own keys, or store.observe would dedupe
	// across unrelated subsystems. hasAlert's substring check above already
	// exercises the message text; this just confirms both fire together
	// without stepping on one another.
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	raw := `{"version":1,"queued":1,"failed":1}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * capeStatusStaleAfter)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	messages := capeAlertMessages(t, dir)
	if !hasAlert(messages, "not draining") || !hasAlert(messages, "1 failed request") {
		t.Fatalf("expected both a stale-worker and a failed-request alert, got: %v", messages)
	}
}
