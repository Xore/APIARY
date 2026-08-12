package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeGhidraResult(t *testing.T, dir, sha string, row map[string]any) {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sha+"_ghidra.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// esGhidraResult points esResultsClient (#1103: loadGhidraResults' only
// source now) at a stub serving rows -- each row is a ghidraResult's raw
// JSON fields, wrapped under "ghidra" per searchNamespace's field-name
// contract (see ghidra.go's own searchNamespace call).
func esGhidraResult(t *testing.T, rows ...map[string]any) {
	t.Helper()
	docs := make([]map[string]any, len(rows))
	for i, row := range rows {
		docs[i] = map[string]any{"ghidra": row}
	}
	esResultsClientFor(t, map[string][]map[string]any{"ghidra-analysis-v1": docs})
}

const shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// seedGhidraCache populates s.ghidraCache directly, bypassing
// refreshGhidraCacheAsync's background Elasticsearch round trip -- mirrors
// github_analysis_test.go's own seedGitHubAnalysisCache for the same reason:
// ghidraData's list branch reads only the cache (#1156-follow-up), so
// that's what a test needs to seed, not the ES stub.
func seedGhidraCache(s *store, rows ...ghidraResult) {
	s.ghidraCache = rows
	s.ghidraCacheAt = time.Now()
}

// A return path that leaves the dashboard must never be honored. "//evil" is
// the case a bare strings.HasPrefix(raw, "/") check lets through, which is
// exactly why safeReturnPath exists and is shared with sandbox submission.
func TestGhidraReturnURLRejectsOffsiteRedirects(t *testing.T) {
	for _, raw := range []string{
		"//evil.example/path",
		"https://evil.example/",
		"http://evil.example/payloads",
		"/etc/passwd",
		"/admin",
		"javascript:alert(1)",
		"",
		"   ",
	} {
		got := ghidraReturnURL(raw, shaA)
		if !strings.HasPrefix(got, "/payloads?") {
			t.Errorf("ghidraReturnURL(%q) = %q, want the /payloads fallback", raw, got)
		}
		if strings.Contains(got, "evil.example") {
			t.Errorf("ghidraReturnURL(%q) leaked an offsite host: %q", raw, got)
		}
	}
}

func TestGhidraReturnURLKeepsAllowedPaths(t *testing.T) {
	got := ghidraReturnURL("/ghidra/"+shaA, shaA)
	if !strings.HasPrefix(got, "/ghidra/"+shaA) {
		t.Fatalf("allowed path was not preserved: %q", got)
	}
	for _, want := range []string{"analysis=queued", "hash=" + shaA, "target=ghidra"} {
		if !strings.Contains(got, want) {
			t.Errorf("return URL %q is missing %q", got, want)
		}
	}
}

// The same guard backs sandbox submission; assert it directly so a future
// change to one caller cannot quietly weaken the other.
func TestSafeReturnPathAllowlist(t *testing.T) {
	if _, ok := safeReturnPath("/payloads", []string{"/payloads"}); !ok {
		t.Error("allowlisted prefix was rejected")
	}
	if _, ok := safeReturnPath("/payloads", []string{"/sandbox/"}); ok {
		t.Error("path outside the allowlist was accepted")
	}
	if _, ok := safeReturnPath("//evil.example", []string{"/"}); ok {
		t.Error("protocol-relative URL was accepted")
	}
}

func TestLoadGhidraResults(t *testing.T) {
	esGhidraResult(t,
		map[string]any{
			"sha256": shaA, "version": 1, "exit_status": "ok", "completed_at": "2026-07-31T10:00:00+00:00",
			"imports": []string{"kernel32.dll!CreateProcessA"},
		},
		map[string]any{
			"sha256": shaB, "version": 1, "exit_status": "error", "error": "boom",
			"completed_at": "2026-07-31T12:00:00+00:00",
		},
	)

	rows := loadGhidraResults()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	// Newest first.
	if rows[0].SHA256 != shaB {
		t.Errorf("rows are not newest-first: got %s first", rows[0].SHA256[:8])
	}
	// A failed analysis is still a visible result, with its reason.
	if rows[0].ExitStatus != "error" || rows[0].Error != "boom" {
		t.Errorf("failed result lost its status/reason: %+v", rows[0])
	}
}

// TestLoadGhidraResultsLocalSkipsMalformedAndNonResultFiles covers
// loadGhidraResultsLocal directly (not loadGhidraResults, #1103's ES-only
// wrapper) -- workbench_orchestrator.go's reconcileWorkbenchRun still calls
// it for job-completion freshness (see ghidra.go's own doc comment), so its
// directory-scanning behavior remains real, live code.
func TestLoadGhidraResultsLocalSkipsMalformedAndNonResultFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)

	writeGhidraResult(t, dir, shaA, map[string]any{"version": 1, "exit_status": "ok"})
	// Malformed JSON must not hide the valid result alongside it.
	if err := os.WriteFile(filepath.Join(dir, "c"+strings.Repeat("c", 63)+"_ghidra.json"),
		[]byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A non-result file in the same directory must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	rows := loadGhidraResultsLocal()
	if len(rows) != 1 || rows[0].SHA256 != shaA {
		t.Fatalf("got %+v, want exactly one row for %s", rows, shaA)
	}
}

// TestLoadGhidraResultsDecodesRevDeckCitations guards against a real
// production bug found live (2026-08-06): Rev·Deck's own "citations" SSE
// event (relayed verbatim by ghidra-worker.py's _revdeck_chat()) carries
// rich objects ({"kind":"import","raw":"[import:CreateFileA]",
// "valid":false,"value":"CreateFileA"}), not plain strings -- confirmed
// against a real production ghidra-analysis-v1 document. The previous
// []string typing on ghidraRevDeckCitations made json.Unmarshal fail
// outright for any result with a real citation in either list, which
// silently vanished the *entire document* from loadGhidraResultsES (it
// skips a row on any unmarshal error) -- both of this host's real
// documents were affected at the time, so /ghidra showed a completely
// empty table despite two successful analyses existing in Elasticsearch.
func TestLoadGhidraResultsDecodesRevDeckCitations(t *testing.T) {
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "version": 1, "exit_status": "ok", "completed_at": "2026-08-06T00:00:00+00:00",
		"revdeck": map[string]any{
			"workflow": "program_triage", "status": "complete", "answer": "ok",
			"citations": map[string]any{
				"valid": []map[string]any{
					{"kind": "import", "raw": "[import:WriteFile]", "value": "WriteFile", "valid": true},
				},
				"invalid": []map[string]any{
					{"kind": "import", "raw": "[import:CreateFileA]", "value": "CreateFileA", "valid": false},
				},
			},
		},
	})

	rows := loadGhidraResults()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 -- a citations decode failure must not vanish the whole document", len(rows))
	}
	citations := rows[0].RevDeck.Citations
	if len(citations.Valid) != 1 || citations.Valid[0].Raw != "[import:WriteFile]" || !citations.Valid[0].Valid {
		t.Errorf("valid citation not decoded correctly: %+v", citations.Valid)
	}
	if len(citations.Invalid) != 1 || citations.Invalid[0].Raw != "[import:CreateFileA]" || citations.Invalid[0].Valid {
		t.Errorf("invalid citation not decoded correctly: %+v", citations.Invalid)
	}
}

// The worker's statictools/server.py omits format-specific lief keys
// entirely rather than emitting them as null (is_dll/compile_timestamp do
// not exist for an ELF binary) — this decodes that real shape, not a
// convenient stand-in, and checks the omitted keys land as nil pointers
// rather than zero-valued false/0, which the template depends on to tell
// "not applicable to this format" from "computed as false/zero" (#138).
func TestLoadGhidraResultsDecodesFuzzyHashesAndLief(t *testing.T) {
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "version": 2, "exit_status": "ok", "completed_at": "2026-08-01T10:00:00+00:00",
		"fuzzy_hashes": map[string]any{
			"ssdeep": "3:AXGBicFlIT:AXGHFF", "ssdeep_error": nil,
			"tlsh": "T1STUB", "tlsh_error": nil,
		},
		"lief": map[string]any{
			"format": "ELF", "architecture": "X86_64", "entrypoint": "0x6760",
			"is_pie": true, "section_count": 1, "sections_truncated": false,
			"sections":  []map[string]any{{"name": ".text", "size": 100, "entropy": 6.234}},
			"libraries": []string{"libc.so.6"}, "stripped": false,
		},
	})

	rows := loadGhidraResults()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]

	if row.FuzzyHashes == nil || row.FuzzyHashes.SSDeep != "3:AXGBicFlIT:AXGHFF" {
		t.Fatalf("fuzzy_hashes did not decode: %+v", row.FuzzyHashes)
	}
	if row.Lief == nil || row.Lief.Format != "ELF" || row.Lief.Architecture != "X86_64" {
		t.Fatalf("lief did not decode: %+v", row.Lief)
	}
	if len(row.Lief.Sections) != 1 || row.Lief.Sections[0].Entropy == nil ||
		*row.Lief.Sections[0].Entropy != 6.234 {
		t.Fatalf("lief sections did not decode: %+v", row.Lief.Sections)
	}
	// stripped: false was SENT (present in the JSON), so it must decode as a
	// non-nil pointer to false — not be confused with the omitted case below.
	if row.Lief.Stripped == nil || *row.Lief.Stripped != false {
		t.Fatalf("lief.stripped should be a non-nil pointer to false, got %+v", row.Lief.Stripped)
	}
	// is_dll and compile_timestamp were never sent (ELF has no such concept) —
	// this is the case the pointer fields exist for.
	if row.Lief.IsDLL != nil {
		t.Fatalf("lief.is_dll should be nil when the worker never sent it, got %v", *row.Lief.IsDLL)
	}
	if row.Lief.CompileTimestamp != nil {
		t.Fatalf("lief.compile_timestamp should be nil when the worker never sent it, got %v",
			*row.Lief.CompileTimestamp)
	}
}

// The worker's capa_scan() forwards the sidecar's summary verbatim, and
// _statictools_post() already collapses both "sidecar down" and the 422
// "unsupported architecture/format/OS" case to a bare absent field — so on
// the decode side there is only one shape to check: present, full summary
// (#78).
func TestLoadGhidraResultsDecodesCapa(t *testing.T) {
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "version": 3, "exit_status": "ok", "completed_at": "2026-08-01T10:00:00+00:00",
		"capa": map[string]any{
			"arch": "amd64", "os": "linux", "format": "elf",
			"capabilities": []map[string]any{
				{"name": "create TCP socket", "namespace": "communication/socket/tcp", "matches": 2},
			},
			"capabilities_truncated": false,
			"attack": []map[string]any{
				{"id": "T1071.001", "tactic": "COMMAND_AND_CONTROL", "technique": "Application Layer Protocol", "subtechnique": "Web Protocols"},
			},
			"mbc": []map[string]any{
				{"id": "C0001", "objective": "Communication", "behavior": "Socket Communication", "method": "Send Data"},
			},
		},
	})

	rows := loadGhidraResults()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]

	if row.Capa == nil || row.Capa.Arch != "amd64" || row.Capa.OS != "linux" || row.Capa.Format != "elf" {
		t.Fatalf("capa did not decode: %+v", row.Capa)
	}
	if len(row.Capa.Capabilities) != 1 || row.Capa.Capabilities[0].Name != "create TCP socket" ||
		row.Capa.Capabilities[0].Matches != 2 {
		t.Fatalf("capa capabilities did not decode: %+v", row.Capa.Capabilities)
	}
	if len(row.Capa.Attack) != 1 || row.Capa.Attack[0].ID != "T1071.001" {
		t.Fatalf("capa attack did not decode: %+v", row.Capa.Attack)
	}
	if len(row.Capa.MBC) != 1 || row.Capa.MBC[0].ID != "C0001" {
		t.Fatalf("capa mbc did not decode: %+v", row.Capa.MBC)
	}
}

// capa's own architecture/format/OS decline is a distinct signal from
// "sidecar unavailable" as of #195 — the worker's capa_scan() now forwards
// {"unsupported": reason} instead of collapsing it to the same nil a down
// sidecar produces (TestLoadGhidraResultsCapaAbsentIsNil below).
func TestLoadGhidraResultsDecodesCapaUnsupported(t *testing.T) {
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "exit_status": "ok",
		"capa": map[string]any{
			"unsupported": "unsupported architecture -- capa's default backend covers only x86/amd64/arm64",
		},
	})

	rows := loadGhidraResults()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	capa := rows[0].Capa
	if capa == nil || capa.Unsupported == "" {
		t.Fatalf("capa.Unsupported should decode: %+v", capa)
	}
	if capa.Arch != "" || len(capa.Capabilities) != 0 {
		t.Fatalf("an unsupported result should carry no capability data: %+v", capa)
	}
}

// Absent (nil *ghidraCapa entirely) means the sidecar was unreachable, or
// capa is switched off on this host — decoding a result with no "capa" key
// at all must not panic or synthesize a zero-valued struct (#78). Distinct
// from the Unsupported case above since #195.
func TestLoadGhidraResultsCapaAbsentIsNil(t *testing.T) {
	esGhidraResult(t, map[string]any{"sha256": shaA, "exit_status": "ok"})

	rows := loadGhidraResults()
	if len(rows) != 1 || rows[0].Capa != nil {
		t.Fatalf("capa should be nil when the worker omitted it: %+v", rows)
	}
}

func TestLoadGhidraResultsDecodesFloss(t *testing.T) {
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "exit_status": "ok",
		"floss": map[string]any{
			"static_strings": []string{"/lib/ld-linux.so"}, "static_strings_total": 1,
			"stack_strings": []string{"stub-stack-string"}, "stack_strings_total": 1,
			"tight_strings": []string{}, "tight_strings_total": 0,
			"decoded_strings": []string{"stub-decoded-c2.example"}, "decoded_strings_total": 1,
			"truncated": false,
		},
	})

	rows := loadGhidraResults()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	floss := rows[0].Floss
	if floss == nil || floss.Unsupported != "" {
		t.Fatalf("floss did not decode: %+v", floss)
	}
	if len(floss.StaticStrings) != 1 || floss.StaticStrings[0] != "/lib/ld-linux.so" ||
		floss.StaticStringsTotal != 1 {
		t.Fatalf("floss static_strings did not decode: %+v", floss)
	}
	if len(floss.DecodedStrings) != 1 || floss.DecodedStrings[0] != "stub-decoded-c2.example" {
		t.Fatalf("floss decoded_strings did not decode: %+v", floss)
	}
}

// floss's own PE/shellcode-only decline is a distinct signal from "sidecar
// unavailable", the same three-state shape capa's own #195 established —
// the worker's floss_scan() forwards {"unsupported": reason} instead of
// collapsing it to the same nil a down sidecar produces
// (TestLoadGhidraResultsFlossAbsentIsNil below) (#207).
func TestLoadGhidraResultsDecodesFlossUnsupported(t *testing.T) {
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "exit_status": "ok",
		"floss": map[string]any{
			"unsupported": "unsupported format for string decoding -- floss's decoding/stack-string analysis covers PE and raw shellcode only",
		},
	})

	rows := loadGhidraResults()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	floss := rows[0].Floss
	if floss == nil || floss.Unsupported == "" {
		t.Fatalf("floss.Unsupported should decode: %+v", floss)
	}
	if floss.StaticStringsTotal != 0 || len(floss.StaticStrings) != 0 {
		t.Fatalf("an unsupported result should carry no string data: %+v", floss)
	}
}

// Absent (nil *ghidraFloss entirely) means the sidecar was unreachable, or
// floss is switched off on this host — decoding a result with no "floss" key
// at all must not panic or synthesize a zero-valued struct, mirroring
// TestLoadGhidraResultsCapaAbsentIsNil (#207).
func TestLoadGhidraResultsFlossAbsentIsNil(t *testing.T) {
	esGhidraResult(t, map[string]any{"sha256": shaA, "exit_status": "ok"})

	rows := loadGhidraResults()
	if len(rows) != 1 || rows[0].Floss != nil {
		t.Fatalf("floss should be nil when the worker omitted it: %+v", rows)
	}
}

// _revdeck_chat() in ghidra-worker.py forwards this shape verbatim, including
// a "max_turns" status kept as a deliberate partial answer rather than
// discarded (#78). Steps is checked as a pointer dereference the same way
// Lief's CompileTimestamp is, since the field exists to tell "absent" from
// "zero" apart on the template side.
func TestLoadGhidraResultsDecodesRevDeck(t *testing.T) {
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "version": 4, "exit_status": "ok", "completed_at": "2026-08-01T10:00:00+00:00",
		"revdeck": map[string]any{
			"workflow": "program_triage", "status": "max_turns",
			"answer": "This binary looks benign.", "steps": 4, "tool_calls": 3,
			"citations": map[string]any{
				"valid":   []map[string]any{{"kind": "function", "raw": "[function:0x401000]", "value": "0x401000", "valid": true}},
				"invalid": []map[string]any{{"kind": "function", "raw": "[function:0xdead]", "value": "0xdead", "valid": false}},
			},
			"warnings": []string{"capped tool budget"},
		},
	})

	rows := loadGhidraResults()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]

	if row.RevDeck == nil || row.RevDeck.Workflow != "program_triage" ||
		row.RevDeck.Status != "max_turns" || row.RevDeck.Answer != "This binary looks benign." {
		t.Fatalf("revdeck did not decode: %+v", row.RevDeck)
	}
	if row.RevDeck.Steps == nil || *row.RevDeck.Steps != 4 {
		t.Fatalf("revdeck steps did not decode: %+v", row.RevDeck.Steps)
	}
	if row.RevDeck.ToolCalls != 3 {
		t.Fatalf("revdeck tool_calls did not decode: %+v", row.RevDeck.ToolCalls)
	}
	if row.RevDeck.Citations == nil || len(row.RevDeck.Citations.Valid) != 1 ||
		row.RevDeck.Citations.Valid[0].Raw != "[function:0x401000]" || !row.RevDeck.Citations.Valid[0].Valid ||
		len(row.RevDeck.Citations.Invalid) != 1 {
		t.Fatalf("revdeck citations did not decode: %+v", row.RevDeck.Citations)
	}
	if len(row.RevDeck.Warnings) != 1 || row.RevDeck.Warnings[0] != "capped tool budget" {
		t.Fatalf("revdeck warnings did not decode: %+v", row.RevDeck.Warnings)
	}
}

// Absent covers every reason revdeck_triage() returns None in the worker
// (REVDECK_API_BASE unset, non-local, unreachable, or no usable answer) --
// all collapse to the same nil field before this ever reaches the dashboard,
// so decoding a result with no "revdeck" key at all must not panic or
// synthesize a zero-valued struct (#78).
func TestLoadGhidraResultsRevDeckAbsentIsNil(t *testing.T) {
	esGhidraResult(t, map[string]any{"sha256": shaA, "exit_status": "ok"})

	rows := loadGhidraResults()
	if len(rows) != 1 || rows[0].RevDeck != nil {
		t.Fatalf("revdeck should be nil when the worker omitted it: %+v", rows)
	}
}

// Identity comes from the filename, which the worker derived from a
// validated request — not from the document body, which could disagree
// with it. This is loadGhidraResultsLocal-specific (the ES path has no
// filename to trust; it trusts the document's own sha256 field, checked
// only against hashName -- see loadGhidraResultsES), and
// loadGhidraResultsLocal remains real, live code: workbench_orchestrator.go
// still calls it directly (#1103).
func TestLoadGhidraResultsTrustsFilenameOverBody(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	writeGhidraResult(t, dir, shaA, map[string]any{"sha256": shaB, "exit_status": "ok"})

	rows := loadGhidraResultsLocal()
	if len(rows) != 1 || rows[0].SHA256 != shaA {
		t.Fatalf("body sha256 overrode the filename: %+v", rows)
	}
}

func TestLoadGhidraStatus(t *testing.T) {
	t.Run("unconfigured", func(t *testing.T) {
		t.Setenv("GHIDRA_RESULTS_DIR", "")
		if s := loadGhidraStatus(); s.Configured {
			t.Error("unset results dir should report Configured=false")
		}
	})

	t.Run("configured but never run", func(t *testing.T) {
		t.Setenv("GHIDRA_RESULTS_DIR", t.TempDir())
		s := loadGhidraStatus()
		// "Nothing queued" and "nothing is running" look identical without
		// this, and they mean very different things.
		if !s.Configured || !s.Stale {
			t.Errorf("missing status.json should be Configured+Stale, got %+v", s)
		}
	})

	t.Run("fresh status", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GHIDRA_RESULTS_DIR", dir)
		raw := `{"version":1,"queued":2,"running":1,"failed":0,"done":5}`
		if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		s := loadGhidraStatus()
		if s.Queued != 2 || s.Running != 1 || s.Done != 5 {
			t.Errorf("counts not parsed: %+v", s)
		}
		if s.Stale {
			t.Error("a just-written status.json should not be stale")
		}
	})

	t.Run("stale status, no request dir configured", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("GHIDRA_RESULTS_DIR", dir)
		t.Setenv("GHIDRA_REQUEST_DIR", "")
		path := filepath.Join(dir, "status.json")
		if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * ghidraStatusStaleAfter)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		if s := loadGhidraStatus(); !s.Stale {
			t.Error("an old status.json with no request dir to re-check should fall back to stale")
		}
	})

	// #204: an idle honeypot with zero Ghidra submissions for 30+ minutes is
	// routine, not a broken worker -- the systemd path unit that drains the
	// spool (and rewrites status.json) only fires on a new request, so its
	// timestamp naturally goes cold when there is nothing to do. Staleness
	// must be judged against what is actually sitting in the request spool
	// right now, not status.json's own (also stale) queued/running counts.
	t.Run("stale status.json but empty live spool is not stale", func(t *testing.T) {
		resultsDir, requestDir := t.TempDir(), t.TempDir()
		t.Setenv("GHIDRA_RESULTS_DIR", resultsDir)
		t.Setenv("GHIDRA_REQUEST_DIR", requestDir)
		path := filepath.Join(resultsDir, "status.json")
		// The stale counts themselves claim work is pending -- proving the
		// live spool check, not these stale numbers, is what decides.
		if err := os.WriteFile(path, []byte(`{"version":1,"queued":3,"running":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * ghidraStatusStaleAfter)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		s := loadGhidraStatus()
		if s.Stale {
			t.Errorf("a cold status.json over an empty request spool must not be stale, got %+v", s)
		}
	})

	t.Run("stale status.json with pending live spool is stale, with live counts", func(t *testing.T) {
		resultsDir, requestDir := t.TempDir(), t.TempDir()
		t.Setenv("GHIDRA_RESULTS_DIR", resultsDir)
		t.Setenv("GHIDRA_REQUEST_DIR", requestDir)
		path := filepath.Join(resultsDir, "status.json")
		// Stale counts say "nothing pending"; the live spool disagrees --
		// e.g. a request arrived after the worker's last (also stuck) drain.
		if err := os.WriteFile(path, []byte(`{"version":1,"queued":0,"running":0}`), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-2 * ghidraStatusStaleAfter)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
		const shaC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		for _, name := range []string{shaA + ".request", shaB + ".request", shaC + ".request.running"} {
			if err := os.WriteFile(filepath.Join(requestDir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		s := loadGhidraStatus()
		if !s.Stale {
			t.Fatalf("a cold status.json over a non-empty request spool must be stale, got %+v", s)
		}
		if s.Queued != 2 || s.Running != 1 {
			t.Errorf("Stale should report the live spool counts, not status.json's stale ones: got queued=%d running=%d", s.Queued, s.Running)
		}
	})
}

// #763: attachGhidraDownload no longer builds a filesystem path out of
// worker-supplied strings at all (the artifact key is "<sha256>:report",
// and SHA256 is already hash-validated) -- so the traversal class this test
// used to guard against no longer applies. Its replacement,
// TestAttachGhidraDownloadGatesOnArtifactSet (ghidra_artifacts_es_test.go),
// covers the analogous "fail closed" property for the new design: no link
// unless the artifact is actually confirmed present in
// ghidra-report-artifacts-v1.

func TestServeGhidraExportRejectsBadHash(t *testing.T) {
	t.Setenv("GHIDRA_RESULTS_DIR", t.TempDir())
	for _, path := range []string{
		"/export/ghidra/../../etc/passwd",
		"/export/ghidra/not-a-hash",
		"/export/ghidra/",
	} {
		w := httptest.NewRecorder()
		serveGhidraExport(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, w.Code)
		}
	}
}

// Until phase 5 generates PDFs there is nothing to export; that must be a
// clear 404, not a zero-byte download.
func TestServeGhidraExportWithoutReport(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	writeGhidraResult(t, dir, shaA, map[string]any{"exit_status": "ok"})

	w := httptest.NewRecorder()
	serveGhidraExport(w, httptest.NewRequest(http.MethodGet, "/export/ghidra/"+shaA, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}

func TestServeGhidraAPI(t *testing.T) {
	// loadGhidraStatus's "status" subtest below still reads GHIDRA_RESULTS_DIR
	// directly (unrelated to #1103 -- queue status polling was never part of
	// the local-fallback pattern); the actual result data comes from ES.
	t.Setenv("GHIDRA_RESULTS_DIR", t.TempDir())
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "exit_status": "ok", "imports": []string{"ws2_32.dll!connect"},
	})
	s := &store{}
	// "list" reads s.ghidraCache (#1156-follow-up), not ES directly -- seeded
	// here rather than relying on refreshGhidraCacheAsync's background
	// goroutine racing this synchronous request.
	seedGhidraCache(s, ghidraResult{SHA256: shaA, ExitStatus: "ok", Imports: []string{"ws2_32.dll!connect"}})

	t.Run("list", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra", nil))
		var rows []ghidraResult
		if err := json.NewDecoder(w.Body).Decode(&rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].SHA256 != shaA {
			t.Fatalf("unexpected list payload: %+v", rows)
		}
	})

	t.Run("detail", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra/"+shaA, nil))
		var row ghidraResult
		if err := json.NewDecoder(w.Body).Decode(&row); err != nil {
			t.Fatal(err)
		}
		if row.SHA256 != shaA {
			t.Fatalf("unexpected detail payload: %+v", row)
		}
	})

	// #876: stored SHA256 values are always lowercase (worker output), but
	// nothing upstream of ghidraData enforced that a request's own hash was
	// lowercase too -- an upper/mixed-case request for a hash that genuinely
	// has a completed analysis used to 404.
	t.Run("detail with uppercase hash still resolves", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra/"+strings.ToUpper(shaA), nil))
		var row ghidraResult
		if err := json.NewDecoder(w.Body).Decode(&row); err != nil {
			t.Fatal(err)
		}
		if row.SHA256 != shaA {
			t.Fatalf("uppercase-hash lookup did not resolve: %+v", row)
		}
	})

	t.Run("unknown hash is 404", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra/"+shaB, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("got %d, want 404", w.Code)
		}
	})

	t.Run("malformed hash is 404, not a directory read", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra/../../etc", nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("got %d, want 404", w.Code)
		}
	})

	t.Run("status", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.serveGhidraAPI(w, httptest.NewRequest(http.MethodGet, "/api/ghidra/status", nil))
		var status ghidraQueueStatus
		if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
			t.Fatal(err)
		}
		if !status.Configured {
			t.Error("status should report Configured with a results dir set")
		}
	})
}

// Search must not match on the string table: nearly every binary contains
// nearly every short substring, which would make the filter useless.
func TestGhidraDataQueryIgnoresStrings(t *testing.T) {
	s := &store{}
	seedGhidraCache(s, ghidraResult{
		SHA256: shaA, ExitStatus: "ok",
		Strings: []string{"needle"},
		Imports: []string{"ws2_32.dll!connect"},
	})

	data, err := s.ghidraData("", "needle")
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 0 {
		t.Errorf("query matched the string table: %+v", data.Rows)
	}

	data, err = s.ghidraData("", "ws2_32")
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 1 {
		t.Errorf("query did not match imports: %+v", data.Rows)
	}
}

// TestGhidraDataListLoadingBeforeFirstRefresh covers #1156-follow-up: a
// request that reaches ghidraData's list branch before
// refreshGhidraCacheAsync's first cycle ever completes must report
// Loading=true with no rows, not an empty result -- ui/ghidra.html's
// ghidraresultspanel uses exactly this to choose a skeleton over "No Ghidra
// analyses match this view."
func TestGhidraDataListLoadingBeforeFirstRefresh(t *testing.T) {
	s := &store{}
	// Simulates the moment a request reaches ghidraData while
	// refreshGhidraCacheAsync's background goroutine is still running its
	// very first cycle -- set directly rather than racing the real
	// (near-instant, in-process) ES stub round trip a live esGhidraResult(t,
	// ...) call would complete before this goroutine-free assertion could
	// ever observe the in-flight state.
	s.ghidraRefreshing = true

	data, err := s.ghidraData("", "")
	if err != nil {
		t.Fatal(err)
	}
	if !data.Loading {
		t.Fatal("Loading must be true while the cache has never been populated and a refresh is in flight")
	}
	if len(data.Rows) != 0 {
		t.Fatalf("expected no rows before the first refresh completes, got %+v", data.Rows)
	}
}

// TestGhidraDataListNeverMasksRealDataRegardlessOfLoading pairs with
// skeleton_placeholders_test.go's own TestListingPagesNeverMaskRealDataRegardlessOfReady
// -- a warm cache with real rows must render them even if a background
// refresh happens to be in flight (Loading only means "never populated", not
// "currently refreshing").
func TestGhidraDataListNeverMasksRealDataRegardlessOfLoading(t *testing.T) {
	s := &store{}
	seedGhidraCache(s, ghidraResult{SHA256: shaA, ExitStatus: "ok"})
	s.ghidraRefreshing = true

	data, err := s.ghidraData("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 1 || data.Rows[0].SHA256 != shaA {
		t.Fatalf("real cached data must render even mid-refresh: %+v", data.Rows)
	}
	if data.Loading {
		t.Fatal("Loading must be false once the cache has been populated at least once, even mid-refresh")
	}
}

// TestRefreshGhidraCacheAsyncNoopWithoutES mirrors
// TestRefreshGithubAnalysisCacheAsyncNoopWithoutES: with no esResultsClient
// configured, the cache must stay unpopulated -- there is no local-file
// fallback for the listing cache, matching loadGhidraResults' own ES-only
// gate.
func TestRefreshGhidraCacheAsyncNoopWithoutES(t *testing.T) {
	s := &store{}
	s.refreshGhidraCacheAsync()
	if !s.ghidraCacheAt.IsZero() {
		t.Fatal("refreshGhidraCacheAsync populated the cache without a configured esResultsClient")
	}
}

// TestRefreshGhidraCacheAsyncPopulatesFromES proves the background refresh
// actually fills the cache from the (bounded, #1156-follow-up) Elasticsearch
// fetch -- runs in a goroutine, so poll briefly rather than asserting
// synchronously, the same pattern
// TestRefreshGithubAnalysisCacheAsyncPopulatesFromES uses.
func TestRefreshGhidraCacheAsyncPopulatesFromES(t *testing.T) {
	esGhidraResult(t, map[string]any{"sha256": shaA, "exit_status": "ok"})
	s := &store{}
	s.refreshGhidraCacheAsync()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.ghidraMu.Lock()
		ready := !s.ghidraCacheAt.IsZero()
		s.ghidraMu.Unlock()
		if ready {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.ghidraMu.Lock()
	cache := append([]ghidraResult(nil), s.ghidraCache...)
	s.ghidraMu.Unlock()
	if len(cache) != 1 || cache[0].SHA256 != shaA {
		t.Fatalf("expected the ES-seeded result to reach the cache: %+v", cache)
	}
}

// TestRefreshGhidraCacheAsyncSkipsWhileWarm proves the TTL/in-flight guard
// actually prevents a redundant Elasticsearch round trip, mirroring
// TestRefreshGithubAnalysisCacheAsyncSkipsWhileWarm.
func TestRefreshGhidraCacheAsyncSkipsWhileWarm(t *testing.T) {
	var requests int
	es := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"hits":{"hits":[]}}`))
	}))
	defer es.Close()
	prev := esResultsClient
	esResultsClient = newESClient(es.URL, "")
	t.Cleanup(func() { esResultsClient = prev })

	s := &store{}
	s.ghidraCacheAt = time.Now() // already warm
	s.refreshGhidraCacheAsync()
	// No goroutine should even be spawned -- the TTL guard returns
	// synchronously -- but give any accidental one a moment to prove it
	// wrong before asserting.
	time.Sleep(50 * time.Millisecond)
	if requests != 0 {
		t.Fatalf("expected no Elasticsearch request while the cache is still within TTL, got %d", requests)
	}
}

func ghidraAlertMessages(t *testing.T, dir string) []string {
	t.Helper()
	t.Setenv("GHIDRA_RESULTS_DIR", dir)
	var messages []string
	// s.alerts nil means "no dedupe sink configured", which makes every check
	// emit — exactly what a unit test wants.
	ghidraAlerts(&store{}, &messages, false)
	return messages
}

func hasAlert(messages []string, substr string) bool {
	for _, m := range messages {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

// An unconfigured host has not opted into Ghidra at all; alerting about a
// subsystem nobody deployed is pure noise.
func TestGhidraAlertsSilentWhenUnconfigured(t *testing.T) {
	t.Setenv("GHIDRA_RESULTS_DIR", "")
	var messages []string
	ghidraAlerts(&store{}, &messages, false)
	if len(messages) != 0 {
		t.Fatalf("unconfigured host produced alerts: %v", messages)
	}
}

func TestGhidraAlertsOnStaleWorker(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"queued":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * ghidraStatusStaleAfter)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	messages := ghidraAlertMessages(t, dir)
	if !hasAlert(messages, "not draining") {
		t.Fatalf("no stale-worker alert: %v", messages)
	}
	// The queue depth belongs in the message; "the worker is stuck" without it
	// does not tell the reader whether anything is actually waiting.
	if !hasAlert(messages, "3 queued") {
		t.Errorf("stale alert omits the queue depth: %v", messages)
	}
}

func TestGhidraAlertsOnFailedResult(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "status.json"),
		[]byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "exit_status": "error", "error": "analysis exceeded 4200s",
	})
	messages := ghidraAlertMessages(t, dir)
	if !hasAlert(messages, "analysis failed") || !hasAlert(messages, "exceeded 4200s") {
		t.Fatalf("failed result did not alert with its reason: %v", messages)
	}
}

// Crypto constants alone must not page: a stock AES table is in a great deal
// of benign software, and an alert people learn to ignore is worse than none.
func TestGhidraCryptoAloneDoesNotAlertByDefault(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "status.json"),
		[]byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "exit_status": "ok",
		"findcrypt": []map[string]string{{"address": "0x1", "constant": "AES Te0", "algorithm": "AES"}},
	})

	if messages := ghidraAlertMessages(t, dir); hasAlert(messages, "flagged") {
		t.Fatalf("crypto alone alerted with the default config: %v", messages)
	}

	t.Setenv("GHIDRA_ALERT_ON_CRYPTO", "true")
	if messages := ghidraAlertMessages(t, dir); !hasAlert(messages, "flagged") {
		t.Fatalf("opting in did not enable the crypto alert: %v", messages)
	}
}

func TestGhidraAlertsOnHighAIRisk(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "status.json"),
		[]byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	esGhidraResult(t, map[string]any{
		"sha256": shaA, "exit_status": "ok",
		"ai_triage": map[string]any{"risk_level": "high", "model": "qwen3:8b"},
	})
	messages := ghidraAlertMessages(t, dir)
	if !hasAlert(messages, "flagged") {
		t.Fatalf("high AI risk did not alert: %v", messages)
	}
	// The reader must be told this is a model's guess, in the alert itself —
	// the detail page's disclaimer is not visible from a webhook.
	if !hasAlert(messages, "UNVERIFIED") {
		t.Errorf("AI-risk alert does not mark itself unverified: %v", messages)
	}

	// A level outside the configured set stays quiet.
	t.Setenv("GHIDRA_ALERT_RISK_LEVELS", "critical")
	if messages := ghidraAlertMessages(t, dir); hasAlert(messages, "flagged") {
		t.Errorf("risk level outside the configured set alerted: %v", messages)
	}
}

// #763: attachGhidraCallGraph/serveGhidraCallGraph no longer read
// GHIDRA_RESULTS_DIR or build a filesystem path from a worker-supplied
// filename at all -- see ghidra_artifacts_es_test.go for this behavior's
// replacements: TestAttachGhidraDownloadGatesOnArtifactSet (fail-closed
// gating), TestServeGhidraCallGraphServesStoredSVG (serves from ES with
// the CSP/nosniff headers preserved), and
// TestServeGhidraExportRejectsBadHashStillWorksWithoutES (bad-hash/missing
// still 404).

// The Ghidra results list renders as a .project-grid/.project-card grid
// (#213 phase 4), not the old <table>. Each card links to the Ghidra
// detail page (not /payload-analysis/ -- that shortcut lived on the old
// hash cell and is still one click away from the detail page itself),
// and carries an exit-status badge plus a family-guess badge when triage
// offered one.
func TestGhidraResultsPageRendersAsCardGrid(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))

	data := ghidraPageData{
		Generated: time.Now(),
		Status:    ghidraQueueStatus{Configured: true},
		Rows: []ghidraResult{
			{
				SHA256: shaA, CompletedAt: "2026-08-01T10:00:00Z", ExitStatus: "success",
				Functions: []ghidraFunction{{Name: "main"}}, Imports: []string{"malloc", "connect"},
				AITriage: &ghidraTriage{FamilyGuess: "mirai"},
			},
			{
				SHA256: shaB, CompletedAt: "2026-08-01T09:00:00Z", ExitStatus: "error",
			},
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "ghidra", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if strings.Contains(body, `id="ghidra-results"><p`) && strings.Contains(body, "<table") {
		t.Fatalf("ghidra results still render as a table, want a card grid")
	}
	if !strings.Contains(body, "project-grid") || !strings.Contains(body, "project-card") {
		t.Fatalf("results list is missing the .project-grid/.project-card markup")
	}
	if !strings.Contains(body, `href="/ghidra/`+shaA+`"`) {
		t.Fatalf("card for %s does not link to its Ghidra detail page", shaA)
	}
	if !strings.Contains(body, ">mirai<") {
		t.Fatalf("family-guess badge for %s is missing", shaA)
	}
	if !strings.Contains(body, ">error<") {
		t.Fatalf("exit-status badge for %s is missing", shaB)
	}
	if strings.Count(body, "project-card__icon") != len(data.Rows) {
		t.Fatalf("expected one leading icon per row")
	}
}

// #1167: the deep-dive tab (types/globals/annotations) and the Functions
// evidence modal (pseudocode/callers/callees) actually render real content,
// not just "doesn't panic on nil" -- every other test touching ghidraResult
// leaves these fields zero-valued.
func TestGhidraDetailPageRendersDeepDiveData(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))

	data := ghidraPageData{
		Generated: time.Now(),
		Status:    ghidraQueueStatus{Configured: true},
		Detail: &ghidraResult{
			SHA256: shaA, CompletedAt: "2026-08-01T10:00:00Z", ExitStatus: "success",
			Functions: []ghidraFunction{{
				Address: "0x401000", Name: "main", Signature: "int main()",
				Pseudocode: "int main(void)\n\n{\n  return 0;\n}\n",
				Callers:    []ghidraXref{},
				Callees:    []ghidraXref{{Addr: "0x401050", Name: "sub_401050"}},
			}},
			FunctionsDeepened:          1,
			FunctionsDeepenedTruncated: true,
			Types: []ghidraType{{
				Name: "POINT", Kind: "struct", Size: 8,
				Fields: []ghidraTypeField{{Name: "x", Type: "int", Offset: 0, Size: 4}},
			}},
			Globals: []ghidraGlobal{{Addr: "0x403000", Name: "g_counter", Type: "int", Size: 4}},
			Annotations: &ghidraAnnotations{
				Revision: 3,
				Entries: map[string]ghidraAnnotation{
					"0x401000": {DisplayName: "real_main", Comment: "entry point, not CRT startup", Tags: []string{"reviewed"}},
				},
			},
			MemoryMap: []ghidraMemoryBlock{{
				Name: ".text", Start: "0x401000", End: "0x40100f", Size: 16,
				Preview: &ghidraHexdumpPreview{Hex: "90909090", ASCII: "...."},
			}},
			RevDeckChatThreads: &ghidraChatThreads{
				Threads: []ghidraChatThread{{ThreadID: "main", Title: "Main", MessageCount: 2}},
				ActiveThreadMessages: []ghidraChatMessage{
					{Role: "user", Content: json.RawMessage(`"List every function related to process creation."`)},
					{Role: "assistant", Content: json.RawMessage(`"No process-creation functions were found."`)},
				},
			},
			RevDeckRecovery: &ghidraRecovery{
				Index:   json.RawMessage(`{"metadata":{"function_count":12}}`),
				Symbols: json.RawMessage(`{"summary":{"renamed":1},"symbols":[{"renamed":"handle_request"}]}`),
			},
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "ghidra-detail-body", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	for _, want := range []string{
		"Deep dive",                                     // new tab
		"1 struct/union/enum/typedef",                   // types card summary
		"1 non-string global data",                      // globals card summary
		"1 analyst-authored annotation",                 // annotations card summary
		"deep-dive budget did not cover the whole list", // truncation note
		"sub_401050",                                    // callee name, in the functions evidence body
		"real_main",                                     // annotation display name, in the annotations evidence body
		"entry point, not CRT startup",                  // annotation comment
		"1 initialized memory block",                    // memory map card summary
		"0x401000-0x40100f",                             // block range, in the memory map evidence body
		"90909090",                                      // hexdump preview hex, in the memory map evidence body
		"1 thread, 2 messages",                          // chat threads card summary
		"No process-creation functions were found.",     // active thread message, in the chat threads evidence body
		"handle_request",                                // recovery symbol, in the recovery evidence body
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
}

// TestGhidraDetailPageIsolatesPseudocodeForSyntaxHighlighting covers #1288:
// each function's decompiled pseudocode must render inside its own
// pre.language-c, separate from the plain-text address/name/signature/
// callers/callees lines that used to share one giant pre with it -- Prism
// tokenizing that mixed content would have mangled the non-code lines.
// Functions with no pseudocode (never deepened) must not get an empty
// pre.language-c at all. The page must also load prism.js/prism.css so the
// class actually does something client-side.
func TestGhidraDetailPageIsolatesPseudocodeForSyntaxHighlighting(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))

	data := ghidraPageData{
		Generated: time.Now(),
		Status:    ghidraQueueStatus{Configured: true},
		Detail: &ghidraResult{
			SHA256: shaA, CompletedAt: "2026-08-01T10:00:00Z", ExitStatus: "success",
			Functions: []ghidraFunction{
				{
					Address: "0x401000", Name: "main", Signature: "int main()",
					Pseudocode: "int main(void)\n\n{\n  return 0;\n}\n",
					Callers:    []ghidraXref{},
					Callees:    []ghidraXref{{Addr: "0x401050", Name: "sub_401050"}},
				},
				{
					// Not deepened: no pseudocode, no callers/callees.
					Address: "0x401100", Name: "sub_401100", Signature: "void sub_401100()",
				},
			},
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "ghidra-detail-body", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if !strings.Contains(body, `<pre class="code language-c">int main(void)`) {
		t.Errorf("pseudocode should render in its own pre.language-c, got: %s", body)
	}
	if strings.Contains(body, "  return 0;\n}\ncallers:") || strings.Contains(body, "return 0;\n}\n  callers:") {
		t.Error("pseudocode and the callers/callees line must not share one pre any more")
	}
	if got := strings.Count(body, `class="code language-c"`); got != 1 {
		t.Errorf("expected exactly 1 pre.language-c (only the deepened function has pseudocode), got %d", got)
	}
	if !strings.Contains(body, `<pre class="code">0x401100  sub_401100  void sub_401100()`) {
		t.Errorf("un-deepened function should still render its header line in a plain pre, got: %s", body)
	}

	// The Prism script/stylesheet tags live in the page shell (loaded
	// unconditionally once .Detail is non-nil, real data or not -- #1288's
	// shell+hydrate conversion moved everything ES-derived into
	// "ghidra-detail-body" above, but these two tags never depended on ES
	// data in the first place).
	var shellBuf strings.Builder
	if err := tmpl.ExecuteTemplate(&shellBuf, "ghidra", &data); err != nil {
		t.Fatalf("render shell: %v", err)
	}
	shell := shellBuf.String()
	if !strings.Contains(shell, `/static/prism.js`) {
		t.Error("detail page shell should load the vendored Prism bundle")
	}
	if !strings.Contains(shell, `/static/prism.css`) {
		t.Error("detail page shell should load the Prism token theme")
	}
}

// TestChatMessageText covers #1286's unwrap of a chat message's Content:
// a plain user/assistant message is a bare JSON string, which should come
// back exactly as written (no surrounding quotes); a tool message's
// content shape isn't fixed (ghidraChatMessage's own comment explains
// why), so anything else should fall back to a readable indented dump
// rather than an empty string.
func TestChatMessageText(t *testing.T) {
	if got := chatMessageText(json.RawMessage(`"List every function related to process creation."`)); got != "List every function related to process creation." {
		t.Errorf("plain string content: got %q", got)
	}
	if got := chatMessageText(json.RawMessage(`{"ok":true,"count":3}`)); !strings.Contains(got, `"ok": true`) {
		t.Errorf("non-string content should fall back to an indented dump, got %q", got)
	}
}

// TestGhidraDetailPageRendersAIReportAndCitations covers #1285: the
// RevDeck Answer must render inside a data-markdown node (so
// hp-ghidra-markdown.js can find and parse it -- covered client-side, not
// here) instead of a bare <p>, and valid/invalid citations must render in
// visually distinct groups rather than two identical plain bullet lists.
func TestGhidraDetailPageRendersAIReportAndCitations(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))

	data := ghidraPageData{
		Generated: time.Now(),
		Status:    ghidraQueueStatus{Configured: true},
		Detail: &ghidraResult{
			SHA256: shaA, CompletedAt: "2026-08-01T10:00:00Z", ExitStatus: "success",
			RevDeck: &ghidraRevDeck{
				Workflow: "triage", Status: "completed", Answer: "### Summary\n\nThis binary connects to a C2 server.",
				Citations: &ghidraRevDeckCitations{
					Valid:   []ghidraRevDeckCitation{{Kind: "function", Raw: "sub_401000@0x401000", Valid: true}},
					Invalid: []ghidraRevDeckCitation{{Kind: "function", Raw: "sub_999999@0x999999", Valid: false}},
				},
			},
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "ghidra-detail-body", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if !strings.Contains(body, `<div class="hp-ai-report__body" data-markdown>### Summary`) {
		t.Errorf("Answer should render inside a data-markdown node for client-side rendering, got: %s", body)
	}
	if !strings.Contains(body, `hp-ai-citations__item--valid`) || !strings.Contains(body, "sub_401000@0x401000") {
		t.Error("valid citation missing its own styled group")
	}
	if !strings.Contains(body, `hp-ai-citations__item--invalid`) || !strings.Contains(body, "sub_999999@0x999999") {
		t.Error("invalid citation missing its own styled group")
	}

	// marked.js/DOMPurify/hp-ghidra-markdown.js load from the shell, same
	// reasoning as prism.js/prism.css above.
	var shellBuf strings.Builder
	if err := tmpl.ExecuteTemplate(&shellBuf, "ghidra", &data); err != nil {
		t.Fatalf("render shell: %v", err)
	}
	shell := shellBuf.String()
	if !strings.Contains(shell, `/static/marked.js`) || !strings.Contains(shell, `/static/dompurify.min.js`) || !strings.Contains(shell, `/static/hp-ghidra-markdown.js`) {
		t.Error("detail page shell should load marked.js, DOMPurify, and hp-ghidra-markdown.js")
	}
}

// TestGhidraDetailPageRendersChatBubblesByRole covers #1286: each message
// in the mirrored RevDeck chat transcript must render as its own
// role-tagged bubble (not one flat pre dump), with the assistant's text
// content inside a data-markdown node and any tool_calls behind a
// collapsible <details>.
func TestGhidraDetailPageRendersChatBubblesByRole(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))

	data := ghidraPageData{
		Generated: time.Now(),
		Status:    ghidraQueueStatus{Configured: true},
		Detail: &ghidraResult{
			SHA256: shaA, CompletedAt: "2026-08-01T10:00:00Z", ExitStatus: "success",
			RevDeckChatThreads: &ghidraChatThreads{
				Threads: []ghidraChatThread{{ThreadID: "main", Title: "Main", MessageCount: 2}},
				ActiveThreadMessages: []ghidraChatMessage{
					{Role: "user", Content: json.RawMessage(`"Run the standard triage workflow."`)},
					{
						Role: "assistant", Content: json.RawMessage(`"Calling get_function to inspect main."`),
						ToolCalls: json.RawMessage(`[{"name":"get_function","arguments":{"address":"0x401000"}}]`),
					},
				},
			},
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "ghidra-detail-body", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if !strings.Contains(body, `hp-chat-msg--user`) {
		t.Error("user message should get its own role-tagged bubble")
	}
	if !strings.Contains(body, `hp-chat-msg--assistant`) {
		t.Error("assistant message should get its own role-tagged bubble")
	}
	if !strings.Contains(body, `<div class="hp-chat-msg__content" data-markdown>Run the standard triage workflow.</div>`) {
		t.Errorf("user message content should be unwrapped from its JSON string and marked for client-side rendering, got: %s", body)
	}
	if !strings.Contains(body, `<details class="hp-chat-msg__toolcalls">`) || !strings.Contains(body, "get_function") {
		t.Error("tool_calls should render in a collapsible detail, not be silently dropped")
	}
}

// #1167: viewing the generated report inline (a modal + iframe, same shape
// as the Reports Studio viewer) needs the trigger button carrying the
// report URL, the modal markup itself, and its own script tag -- all three
// only when a report actually exists for this analysis.
func TestGhidraDetailPageRendersReportViewer(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))

	data := ghidraPageData{
		Generated: time.Now(),
		Status:    ghidraQueueStatus{Configured: true},
		Detail: &ghidraResult{
			SHA256: shaA, CompletedAt: "2026-08-01T10:00:00Z", ExitStatus: "success",
			ExportURL: "/export/ghidra/" + shaA,
		},
	}

	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "ghidra-detail-body", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()

	if !strings.Contains(body, `data-hp-gh-report-url="/export/ghidra/`+shaA+`"`) {
		t.Error("report-view trigger button is missing its report URL")
	}

	// The modal shell and its script tag live outside "ghidra-detail-body"
	// (unconditional page chrome, not derived from .Detail's ES fields).
	var shellBuf strings.Builder
	if err := tmpl.ExecuteTemplate(&shellBuf, "ghidra", &data); err != nil {
		t.Fatalf("render shell: %v", err)
	}
	shell := shellBuf.String()
	if !strings.Contains(shell, `id="hp-gh-viewer"`) || !strings.Contains(shell, `id="hp-gh-viewer-frame"`) {
		t.Error("report viewer modal markup is missing")
	}
	if !strings.Contains(shell, `/static/hp-ghidra-report.js`) {
		t.Error("hp-ghidra-report.js is not loaded on the detail page")
	}
}

// A query that matches nothing keeps the plain empty state, not an empty grid.
func TestGhidraResultsPageEmptyStateHasNoCardGrid(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))

	data := ghidraPageData{Generated: time.Now(), Status: ghidraQueueStatus{Configured: true}}
	var buf strings.Builder
	if err := tmpl.ExecuteTemplate(&buf, "ghidra", &data); err != nil {
		t.Fatalf("render: %v", err)
	}
	body := buf.String()
	if strings.Contains(body, "project-grid") {
		t.Fatalf("empty result set should not render a .project-grid")
	}
	if !strings.Contains(body, "No Ghidra analyses match this view.") {
		t.Fatalf("missing the empty-state message")
	}
}
