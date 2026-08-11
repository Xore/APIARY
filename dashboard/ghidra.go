package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The shapes here mirror what analysis/ghidra/worker/ghidra-worker.py writes.
// That worker is the only producer; the dashboard never writes a result and
// never calls the Ghidra REST service.

// ghidraXref is one entry of a function's callers/callees (#1167), matching
// export_json.py's own xrefs.json shape (addr+name, nothing else -- getting
// the full signature back out means a second lookup into Functions by
// address, which the template does rather than duplicating it here per edge).
type ghidraXref struct {
	Addr string `json:"addr"`
	Name string `json:"name"`
}

type ghidraFunction struct {
	Address   string `json:"address"`
	Name      string `json:"name"`
	Signature string `json:"signature"`
	Size      int    `json:"size"`

	// Pseudocode/Callers/Callees (#1167) are set only for the largest
	// functions the worker's deep-dive budget covered (see
	// GHIDRA_DEEPDIVE_MAX_FUNCTIONS in ghidra-worker.py) -- empty on every
	// other function in the list, not an error, the same three-state
	// convention FunctionsDeepenedTruncated below documents at the result
	// level.
	Pseudocode string       `json:"pseudocode,omitempty"`
	Callers    []ghidraXref `json:"callers,omitempty"`
	Callees    []ghidraXref `json:"callees,omitempty"`
}

type ghidraCrypto struct {
	Address   string `json:"address"`
	Constant  string `json:"constant"`
	Algorithm string `json:"algorithm"`
}

type ghidraFuzzyHashes struct {
	SSDeep      string `json:"ssdeep"`
	SSDeepError string `json:"ssdeep_error"`
	TLSH        string `json:"tlsh"`
	TLSHError   string `json:"tlsh_error"`
}

type ghidraSection struct {
	Name    string   `json:"name"`
	Size    int      `json:"size"`
	Entropy *float64 `json:"entropy"`
}

// ghidraLief mirrors what analysis/ghidra/statictools/server.py's
// lief_parse() returns, forwarded verbatim by the worker (#85, #138).
// Libraries and Stripped are format-specific (ELF/PE/Mach-O) and are absent
// -- zero value, not an error -- on a format that does not have the concept.
type ghidraLief struct {
	Format            string          `json:"format"`
	Architecture      string          `json:"architecture"`
	Entrypoint        string          `json:"entrypoint"`
	IsPIE             bool            `json:"is_pie"`
	SectionCount      int             `json:"section_count"`
	SectionsTruncated bool            `json:"sections_truncated"`
	Sections          []ghidraSection `json:"sections"`
	Libraries         []string        `json:"libraries"`
	// Stripped, IsDLL and CompileTimestamp are ELF/PE-specific and absent on
	// a format that has no such concept (e.g. Mach-O). Pointers so the
	// template can tell "absent" from "false"/"zero" rather than rendering a
	// claim the sidecar never made.
	Stripped         *bool  `json:"stripped"`
	IsDLL            *bool  `json:"is_dll"`
	CompileTimestamp *int64 `json:"compile_timestamp"`
}

type ghidraCapability struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Matches   int    `json:"matches"`
}

type ghidraAttack struct {
	ID           string `json:"id"`
	Tactic       string `json:"tactic"`
	Technique    string `json:"technique"`
	Subtechnique string `json:"subtechnique"`
}

type ghidraMBC struct {
	ID        string `json:"id"`
	Objective string `json:"objective"`
	Behavior  string `json:"behavior"`
	Method    string `json:"method"`
}

// ghidraCapa mirrors what analysis/ghidra/statictools/server.py's
// capa_scan() returns, forwarded through the worker's own capa_scan() (#78).
// nil *ghidraCapa means the sidecar was unreachable or capa isn't configured
// on this host. Unsupported set (everything else empty) means the opposite:
// the sidecar answered and capa itself declined the sample — its default
// backend covers x86/amd64/arm64 only, so MIPS/ARM32 (common in this
// honeypot's IoT catch) lands here on every run. Collapsing both to the same
// "no capa data" was the original behavior; #195 asked for the distinction
// to survive at least this far, since an operator reading "not observed" on
// a MIPS sample shouldn't have to wonder whether the sidecar was even up.
type ghidraCapa struct {
	Arch                  string             `json:"arch"`
	OS                    string             `json:"os"`
	Format                string             `json:"format"`
	Capabilities          []ghidraCapability `json:"capabilities"`
	CapabilitiesTruncated bool               `json:"capabilities_truncated"`
	Attack                []ghidraAttack     `json:"attack"`
	MBC                   []ghidraMBC        `json:"mbc"`
	Unsupported           string             `json:"unsupported,omitempty"`
}

// ghidraFloss mirrors what analysis/ghidra/statictools/server.py's
// floss_scan() returns, forwarded through the worker's own floss_scan()
// (#207). nil *ghidraFloss means the sidecar was unreachable or floss isn't
// configured on this host. Unsupported set (everything else empty) means
// the opposite: the sidecar answered and floss itself declined the sample —
// its decoding/stack-string analysis covers PE and raw shellcode only, so
// the ELF samples common in this honeypot's catch land here on every run.
// Same nil/unsupported/data three-state shape as ghidraCapa above (#195),
// for the same reason: an operator reading "not observed" on an ELF sample
// shouldn't have to wonder whether the sidecar was even up.
type ghidraFloss struct {
	StaticStrings       []string `json:"static_strings"`
	StaticStringsTotal  int      `json:"static_strings_total"`
	StackStrings        []string `json:"stack_strings"`
	StackStringsTotal   int      `json:"stack_strings_total"`
	TightStrings        []string `json:"tight_strings"`
	TightStringsTotal   int      `json:"tight_strings_total"`
	DecodedStrings      []string `json:"decoded_strings"`
	DecodedStringsTotal int      `json:"decoded_strings_total"`
	Truncated           bool     `json:"truncated"`
	Unsupported         string   `json:"unsupported,omitempty"`
}

// ghidraRevDeckCitation is one entry of Rev·Deck's own "citations" SSE
// event, relayed verbatim by ghidra-worker.py's _revdeck_chat(). Confirmed
// live (2026-08-06) against a real production document: this is a rich
// object ({"kind":"import","raw":"[import:CreateFileA]","valid":false,
// "value":"CreateFileA"}), not a plain string -- the previous []string
// typing made json.Unmarshal fail outright for any document with a real
// citation in either list, which silently vanished the whole document from
// the ES-backed /ghidra list (loadGhidraResultsES skips a row on any
// unmarshal error). Both of this host's real ghidra-analysis-v1 documents
// were affected, so /ghidra showed a completely empty table.
type ghidraRevDeckCitation struct {
	Kind  string `json:"kind"`
	Raw   string `json:"raw"`
	Value string `json:"value"`
	Valid bool   `json:"valid"`
}

// ghidraRevDeckCitations mirrors the "citations" object _revdeck_chat() in
// ghidra-worker.py builds from Rev·Deck's own "citations" SSE event.
type ghidraRevDeckCitations struct {
	Valid   []ghidraRevDeckCitation `json:"valid"`
	Invalid []ghidraRevDeckCitation `json:"invalid"`
}

// ghidraRevDeck mirrors the dict _revdeck_chat() in ghidra-worker.py returns
// (#78): the result of Rev·Deck's own bounded autonomous tool-calling loop
// against the Ghidra REST service, a second and independent AI aid alongside
// AITriage above rather than a replacement for it. Nil when REVDECK_API_BASE
// is unset, the endpoint was refused as non-local or unreachable, or the run
// produced no usable answer. Steps is a pointer for the same reason Lief's
// pointer fields are above: the template needs to tell "absent" from "zero".
//
// Status "max_turns" is not a failure — it is Rev·Deck's own forced
// best-effort synthesis after its step budget ran out, and _revdeck_chat()
// deliberately keeps that answer rather than discarding it, the same way
// triage() above keeps a half-assessment when only one workflow answers.
type ghidraRevDeck struct {
	Workflow  string                  `json:"workflow"`
	Status    string                  `json:"status"`
	Answer    string                  `json:"answer"`
	Steps     *int                    `json:"steps"`
	ToolCalls int                     `json:"tool_calls"`
	Citations *ghidraRevDeckCitations `json:"citations"`
	Warnings  []string                `json:"warnings"`
}

type ghidraTriage struct {
	Workflow    string   `json:"workflow"`
	FamilyGuess string   `json:"family_guess"`
	RiskLevel   string   `json:"risk_level"`
	Behaviors   []string `json:"behaviors"`
	Model       string   `json:"model"`
	// EvidenceShown says how much of the binary the model actually saw —
	// "150/312 imports, 200/11482 strings (longest first...)". A real sample
	// overflows any context window, so the assessment is formed from a subset,
	// and the size of that subset is the single most useful thing for deciding
	// how much weight it deserves. Empty on results written before #103.
	EvidenceShown string `json:"evidence_shown"`
}

// ghidraTypeField is one struct/union member (#1167), mirroring
// export_json.py's types.json writer.
type ghidraTypeField struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset int    `json:"offset"`
	Size   int    `json:"size"`
}

// ghidraType mirrors one entry of types.json (#1167) -- a recovered struct,
// union, enum or typedef from the program's own DataTypeManager. Kind
// selects which of Fields/Values/BaseType is populated; the other two stay
// zero-value for that entry, same "kind tells you which fields are live"
// convention ghidraLief's format-specific pointers use, but as plain values
// here since every type in the list has some kind, unlike Lief's
// format-conditional absence.
type ghidraType struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"` // "struct" | "union" | "enum" | "typedef"
	Size     int               `json:"size"`
	Fields   []ghidraTypeField `json:"fields,omitempty"`    // struct/union
	Values   map[string]int64  `json:"values,omitempty"`    // enum
	BaseType string            `json:"base_type,omitempty"` // typedef
}

// ghidraGlobal mirrors one entry of globals.json (#1167): a non-string
// defined-data symbol export_json.py found while walking the program's
// memory, distinct from the free-text Strings list above.
type ghidraGlobal struct {
	Addr string `json:"addr"`
	Name string `json:"name"`
	Type string `json:"type"`
	Size int    `json:"size"`
}

// ghidraAnnotation is one analyst-authored entry (#1167) -- display
// name/comment/tags/confidence on a function or address, written through
// RevDeck's own annotation UI (PUT /v1/jobs/{job}/annotations/{addr}) and
// mirrored here read-only. Confidence is left as json.RawMessage rather
// than a fixed type: server.py copies whatever the client PUT verbatim
// (_ENTRY_FIELDS) with no type coercion, so this must not fail to decode a
// numeric confidence just because a different analyst UI sent a string.
type ghidraAnnotation struct {
	DisplayName string          `json:"display_name,omitempty"`
	Comment     string          `json:"comment,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Confidence  json.RawMessage `json:"confidence,omitempty"`
}

// ghidraAnnotations mirrors GET /v1/jobs/{job}/annotations's whole-document
// shape (#1167): a revision counter (optimistic-concurrency, not meaningful
// once mirrored read-only here) plus entries keyed by the same canonical
// hex address ghidraFunction.Address and ghidraXref.Addr use.
type ghidraAnnotations struct {
	Revision int                         `json:"revision"`
	Entries  map[string]ghidraAnnotation `json:"entries"`
}

// ghidraHexdumpPreview is a small, bounded snapshot of a memory block's
// opening bytes (#1167) -- GHIDRA_DEEPDIVE_HEXDUMP_PREVIEW_BYTES in
// ghidra-worker.py, 256 by default. The full block's bytes never leave the
// Ghidra service (see server.py's own comment on _v1_list_memory); this is
// the only hexdump data that ever reaches ES, matching the standing rule
// that this dashboard reads from ES only, never a live analysis backend.
type ghidraHexdumpPreview struct {
	Hex   string `json:"hex"`
	ASCII string `json:"ascii"`
}

// ghidraMemoryBlock mirrors one entry of GET /v1/results/{job}/memory
// (#1167): one of the program's initialized memory sections (.text, .data,
// ...), with a bounded hexdump preview of its opening bytes.
type ghidraMemoryBlock struct {
	Name    string                `json:"name"`
	Start   string                `json:"start"`
	End     string                `json:"end"`
	Size    int                   `json:"size"`
	Preview *ghidraHexdumpPreview `json:"hexdump_preview,omitempty"`
}

type ghidraResult struct {
	Version     int    `json:"version"`
	SHA256      string `json:"sha256"`
	RequestedAt string `json:"requested_at"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
	ExitStatus  string `json:"exit_status"`
	// Error is set only when ExitStatus is "error". The worker records a
	// result for failures too, so a job that went wrong is visible with its
	// reason rather than silently missing from the list.
	Error string `json:"error,omitempty"`

	Functions []ghidraFunction `json:"functions"`
	Strings   []string         `json:"strings"`
	Imports   []string         `json:"imports"`
	FindCrypt []ghidraCrypto   `json:"findcrypt"`

	// FunctionsDeepened/FunctionsDeepenedTruncated (#1167) say how many of
	// Functions above actually got the Pseudocode/Callers/Callees
	// treatment, and whether the deep-dive budget (GHIDRA_DEEPDIVE_MAX_FUNCTIONS
	// in ghidra-worker.py) cut off before covering every function -- a
	// result showing zero of either must not be read as "this binary has
	// no functions worth decompiling."
	FunctionsDeepened          int  `json:"functions_deepened"`
	FunctionsDeepenedTruncated bool `json:"functions_deepened_truncated"`

	Types       []ghidraType        `json:"types"`
	Globals     []ghidraGlobal      `json:"globals"`
	Annotations *ghidraAnnotations  `json:"annotations"`
	MemoryMap   []ghidraMemoryBlock `json:"memory_map"`

	CallGraphSVG string             `json:"call_graph_svg"`
	AITriage     *ghidraTriage      `json:"ai_triage"`
	FuzzyHashes  *ghidraFuzzyHashes `json:"fuzzy_hashes"`
	Lief         *ghidraLief        `json:"lief"`
	Capa         *ghidraCapa        `json:"capa"`
	Floss        *ghidraFloss       `json:"floss"`
	RevDeck      *ghidraRevDeck     `json:"revdeck"`
	ReportPDF    string             `json:"report_pdf"`

	// Set by the dashboard, not the worker: download routes, present only when
	// the file actually exists.
	ExportURL    string `json:"export_url,omitempty"`
	CallGraphURL string `json:"call_graph_url,omitempty"`

	// IOCCorrelation (#680) cross-references Floss above against any
	// Windows-sandbox run of the same SHA-256 -- set by the dashboard at
	// read time in ghidraData(), nil when no sandbox run exists for this
	// sample at all.
	IOCCorrelation *iocCorrelation `json:"ioc_correlation,omitempty"`
}

// ghidraQueueStatus matches the status.json the worker writes. Flat, unlike
// sandboxQueueStatus's nested Counts, because the producer is a small script
// and one shape written in one place is worth more than symmetry with a
// struct nothing shares with it.
type ghidraQueueStatus struct {
	Version   int    `json:"version"`
	UpdatedAt string `json:"updated_at"`
	Queued    int    `json:"queued"`
	Running   int    `json:"running"`
	Failed    int    `json:"failed"`
	Done      int    `json:"done"`
	// Stale reports that status.json has not been rewritten recently. The
	// worker touches it on every drain, so a cold timestamp means the path
	// unit or the service is not firing — which otherwise looks exactly like
	// an empty queue.
	Stale bool `json:"stale"`
	// Configured is false when GHIDRA_RESULTS_DIR is unset, i.e. the host-side
	// worker was never deployed. The page uses it to explain the absence
	// rather than showing a permanently empty queue.
	Configured bool `json:"configured"`
}

type ghidraPageData struct {
	pageMeta
	Generated time.Time
	Rows      []ghidraResult
	Detail    *ghidraResult
	Status    ghidraQueueStatus
	Query     string
	Analysis  string
	// GPUQueue is the shared GPU job queue (#637 follow-up): jobs deferred
	// by insufficient GPU headroom, not this page's own file-spool queue
	// above (Status/ghidraLiveSpoolCounts). Ghidra's AI triage is the only
	// consumer today; the field lives here rather than on its own page
	// because there's nowhere else on the dashboard an operator would look
	// for it yet.
	GPUQueue []gpuQueueJob
}

func ghidraResultsDir() string { return getenv("GHIDRA_RESULTS_DIR", "") }

// ghidraStatusStaleAfter is how long status.json may go untouched before the
// queue is reported stale. The worker rewrites it on every drain and on every
// no-op run, so anything much older than a path-unit trigger means nothing is
// consuming the spool.
const ghidraStatusStaleAfter = 30 * time.Minute

// esResultsClient is nil unless ELASTICSEARCH_URL is configured (main.go).
// See its doc comment there for why this is a package-level var rather than
// a parameter threaded through loadGhidraResults' many call sites.
var esResultsClient *esClient

// loadGhidraResults reads #383's ghidra-analysis-v1 ES mirror (#384)
// exclusively (#1103) -- an unconfigured or failed ES query means "no
// results this cycle," not a reason to fall back to the local JSON files.
// workbench_orchestrator.go's reconcileWorkbenchRun deliberately calls
// loadGhidraResultsLocal directly instead of this: it polls for job
// completion to flip run state, and the ES mirror's import interval (5
// minutes by default) would delay or miss that transition (#1103 Category
// 3 tracks giving that path its own low-latency completion signal instead).
func loadGhidraResults() []ghidraResult {
	if esResultsClient == nil {
		return nil
	}
	rows, _ := loadGhidraResultsES(esResultsClient)
	return rows
}

func loadGhidraResultsES(es *esClient) ([]ghidraResult, bool) {
	raws, err := es.searchNamespace("ghidra-analysis-v1", "ghidra")
	if err != nil {
		return nil, false
	}
	artifacts := ghidraArtifactSet(es)
	rows := make([]ghidraResult, 0, len(raws))
	for _, raw := range raws {
		var row ghidraResult
		if json.Unmarshal(raw, &row) != nil || !hashName.MatchString(row.SHA256) {
			continue
		}
		attachGhidraDownload(&row, artifacts)
		rows = append(rows, row)
	}
	sortGhidraResults(rows)
	return rows, true
}

// loadGhidraResultByHash answers "the one Ghidra result for this hash", the
// single-result case ghidraData's detail view actually needs, scoped
// server-side via searchNamespaceByHash instead of loadGhidraResults'
// whole-index fetch (up to 10000 documents) filtered down to one match in
// Go -- see that function's own doc comment. ghidra-analysis-v1 documents
// are overwritten by deterministic _id on reanalysis (analysis/
// es-results-importer's own doc_id()), so there is at most one to find;
// this still handles more than one defensively rather than assuming that
// invariant always held for every document that ever landed in the index.
func loadGhidraResultByHash(es *esClient, sha256 string) (ghidraResult, bool) {
	if es == nil {
		return ghidraResult{}, false
	}
	raws, err := es.searchNamespaceByHash("ghidra-analysis-v1", "ghidra", sha256, 5)
	if err != nil {
		return ghidraResult{}, false
	}
	// Verified here, not trusted from the query alone: the server-side
	// term filter is what makes this cheap, but a caller that gets back a
	// document for the wrong hash (a test stub that does not actually
	// filter, same as every other loader in this package already guards
	// against with its own EqualFold/== check) must never be trusted
	// silently.
	for _, raw := range raws {
		var row ghidraResult
		if json.Unmarshal(raw, &row) != nil || !strings.EqualFold(row.SHA256, sha256) {
			continue
		}
		attachGhidraDownload(&row, ghidraArtifactSet(es))
		return row, true
	}
	return ghidraResult{}, false
}

func sortGhidraResults(rows []ghidraResult) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CompletedAt != rows[j].CompletedAt {
			return rows[i].CompletedAt > rows[j].CompletedAt
		}
		return rows[i].SHA256 < rows[j].SHA256
	})
}

func loadGhidraResultsLocal() []ghidraResult {
	dir := ghidraResultsDir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	// Metadata falls back to disk here (pre-dates and is outside #638's own
	// scope: that issue is specifically about the dashboard's binary-
	// artifact *serving* routes, not this existing ES-preferred/local-
	// fallback pattern for JSON result listings, used the same way by
	// loadSandboxResults() and others). The two binary artifacts
	// themselves never fall back to disk regardless of which path
	// produced this row -- ghidraArtifactSet still only ever asks ES,
	// same as loadGhidraResultsES's own call, and correctly yields no
	// links at all when esResultsClient is nil or unreachable rather than
	// reading GHIDRA_RESULTS_DIR for them.
	artifacts := ghidraArtifactSet(esResultsClient)
	var rows []ghidraResult
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_ghidra.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var row ghidraResult
		if err := json.Unmarshal(raw, &row); err != nil {
			// A malformed result is skipped rather than failing the page. The
			// worker writes atomically, so this means hand-editing or disk
			// damage, and one bad file should not hide the other results.
			continue
		}
		// Trust the filename over the document for identity: the filename is
		// what the worker derived from the validated request, and it is what
		// every route below looks up by.
		row.SHA256 = strings.TrimSuffix(entry.Name(), "_ghidra.json")
		if !hashName.MatchString(row.SHA256) {
			continue
		}
		attachGhidraDownload(&row, artifacts)
		rows = append(rows, row)
	}
	// Newest first. CompletedAt is an RFC3339 string from the worker, which
	// sorts correctly as text for a fixed offset; fall back to the hash so the
	// order is stable rather than map-random when timestamps tie or are empty.
	sortGhidraResults(rows)
	return rows
}

func loadGhidraStatus() ghidraQueueStatus {
	dir := ghidraResultsDir()
	status := ghidraQueueStatus{Configured: dir != ""}
	if dir == "" {
		return status
	}
	path := filepath.Join(dir, "status.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		// No status.json yet is the normal state before the worker's first
		// run. Report it as stale so the page says "not running" rather than
		// "nothing queued", which are very different things to an operator.
		status.Stale = true
		return status
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		status.Configured = true
		status.Stale = true
		return status
	}
	status.Configured = true
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) > ghidraStatusStaleAfter {
		// A cold status.json alone does not mean the worker is dead: it is a
		// systemd *path* unit (honeypot-ghidra-worker.path), triggered only
		// when a request lands in the spool, and it only rewrites status.json
		// from inside that run. Zero submissions for 30+ minutes -- routine
		// for a quiet honeypot -- leaves status.json stale with the worker
		// completely healthy (#204). Only call it stale when the *live* spool
		// (not the counts status.json itself last recorded, which predate
		// whatever made it go stale) actually has something queued or
		// running that isn't being drained; an old timestamp over an empty
		// spool is just "nothing to do". Live counts also replace the
		// stale/misleading ones from status.json so ghidraAlerts' message
		// reports what is really sitting in the spool right now.
		if queued, running, ok := ghidraLiveSpoolCounts(); ok {
			status.Stale = queued+running > 0
			if status.Stale {
				status.Queued, status.Running = queued, running
			}
		} else {
			// No request spool configured/readable to re-check against, but
			// GHIDRA_RESULTS_DIR is set: an unusual split configuration, or a
			// permissions problem. Fall back to the original, more
			// conservative "cold file means stale" behavior rather than
			// guessing that everything is fine.
			status.Stale = true
		}
	}
	return status
}

// ghidraLiveSpoolCounts re-checks the request spool directly rather than
// trusting status.json's Queued/Running fields, which are exactly the values
// that went stale -- a request that arrived after the worker's last drain
// would not be reflected in them at all. ok is false when the spool isn't
// configured or isn't readable, distinct from a genuinely empty spool.
func ghidraLiveSpoolCounts() (queued, running int, ok bool) {
	dir := ghidraRequestDir()
	if dir == "" {
		return 0, 0, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch name := entry.Name(); {
		case strings.HasSuffix(name, ".request.running"):
			running++
		case strings.HasSuffix(name, ".request"):
			queued++
		}
	}
	return queued, running, true
}

// attachGhidraDownload exposes a download route only for an artifact that
// actually exists in ghidra-report-artifacts-v1 -- no link is offered for
// one that is not there. `artifacts` is the set ghidraArtifactSet() built
// once for the whole page load (see #638/#763, dashboard/ghidra_artifacts_es.go);
// nil means "could not confirm anything exists" (ES unreachable/unconfigured),
// which is deliberately treated the same as "nothing exists" rather than
// falling back to a disk read -- the dashboard's own serving route must
// never read GHIDRA_RESULTS_DIR directly, only the disk-reading worker and
// its ES-mirroring importer may.
//
// Before #763 this validated ReportPDF/CallGraphSVG as bare filenames and
// os.Stat'd them under GHIDRA_RESULTS_DIR -- no longer needed now that the
// artifact key is derived purely from the already-hash-validated SHA256,
// never from a worker-supplied string.
func attachGhidraDownload(row *ghidraResult, artifacts map[string]bool) {
	if row == nil {
		return
	}
	attachGhidraCallGraph(row, artifacts)
	if row.ReportPDF == "" || !artifacts[row.SHA256+":report"] {
		return
	}
	row.ExportURL = "/export/ghidra/" + row.SHA256
}

// attachGhidraCallGraph exposes the rendered call graph, if one exists. The
// worker writes a callgraph SVG only when graphviz is installed on the host
// (row.CallGraphSVG != "" reflects that), and separately the importer must
// have actually mirrored it into ES yet (artifacts[...]) -- both need to be
// true, or a host without graphviz / a mirror that hasn't caught up yet
// would otherwise offer a broken link.
func attachGhidraCallGraph(row *ghidraResult, artifacts map[string]bool) {
	if row.CallGraphSVG == "" || !artifacts[row.SHA256+":callgraph"] {
		return
	}
	row.CallGraphURL = "/export/ghidra/" + row.SHA256 + "/callgraph.svg"
}

func ghidraData(sha256, query string) (ghidraPageData, error) {
	// #1142: the single-hash detail view (below) never needs the whole
	// listing -- ghidra.html's own {{if .Detail}} branch reads only
	// .Detail, never .Rows, so loading every result just to linear-scan
	// for the one that matches (loadGhidraResults' own doc comment) was
	// pure waste on this path. Resolved directly via
	// loadGhidraResultByHash instead, scoped server-side.
	if sha256 != "" {
		row, ok := loadGhidraResultByHash(esResultsClient, sha256)
		if !ok {
			return ghidraPageData{}, errors.New("ghidra result not found")
		}
		row.IOCCorrelation = correlateFlossSandboxIOCs(row.Floss, matchingSandboxRuns(sha256))
		return ghidraPageData{Generated: time.Now(), Detail: &row}, nil
	}
	data := ghidraPageData{
		Generated: time.Now(),
		Rows:      loadGhidraResults(),
		Status:    loadGhidraStatus(),
		Query:     strings.TrimSpace(query),
		GPUQueue:  loadGPUQueue(),
	}
	if data.Query != "" {
		needle := strings.ToLower(data.Query)
		filtered := data.Rows[:0]
		for _, row := range data.Rows {
			// Imports and the AI family guess are the two fields an analyst
			// actually hunts by; strings are deliberately excluded because a
			// binary's string table would match nearly every query.
			haystack := strings.ToLower(strings.Join(append([]string{
				row.SHA256, row.ExitStatus, triageFamily(row),
			}, row.Imports...), " "))
			if strings.Contains(haystack, needle) {
				filtered = append(filtered, row)
			}
		}
		data.Rows = filtered
	}
	return data, nil
}

func triageFamily(row ghidraResult) string {
	if row.AITriage == nil {
		return ""
	}
	return row.AITriage.FamilyGuess
}

func serveGhidraAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/ghidra/status" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loadGhidraStatus())
		return
	}
	sha := ""
	if r.URL.Path != "/api/ghidra" {
		sha = strings.TrimPrefix(r.URL.Path, "/api/ghidra/")
	}
	if sha != "" && !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	// #876: stored SHA256 values are always lowercase (worker output); a
	// request for an upper/mixed-case hash must still resolve, matching
	// serveGitHubAnalysisAPI's strings.ToLower(sha) convention.
	data, err := ghidraData(strings.ToLower(sha), r.URL.Query().Get("q"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if data.Detail != nil {
		json.NewEncoder(w).Encode(data.Detail)
		return
	}
	json.NewEncoder(w).Encode(data.Rows)
}

// serveGhidraExport streams the analysis report for one result, from
// ghidra-report-artifacts-v1 (#638/#763) -- never from GHIDRA_RESULTS_DIR.
//
// The plan also describes falling back to a zip of raw artifacts. That is not
// built here because the artifacts it would bundle — the call-graph SVG and
// the Ghidra project export — are produced by IMPLEMENTATION_PLAN.md phases
// 3-5, which do not exist yet. A zip containing one JSON file would be a
// worse download than the JSON the API already serves.
func serveGhidraExport(w http.ResponseWriter, r *http.Request) {
	// #876: stored artifacts are keyed by the lowercase SHA256 the worker
	// wrote them under; an upper/mixed-case request must still resolve.
	sha := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/export/ghidra/"))
	if rest, ok := strings.CutSuffix(sha, "/callgraph.svg"); ok {
		serveGhidraCallGraph(w, r, rest)
		return
	}
	if !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	doc, data, err := fetchGhidraArtifact(esResultsClient, sha, "report")
	if err != nil {
		http.Error(w, "no report has been generated for this analysis yet", http.StatusNotFound)
		return
	}
	// #763: this is genuinely an HTML report (build_report()'s own docstring
	// says so -- ghidra-worker.py's automatic call never passes --pdf, so a
	// real PDF is never produced despite the ReportPDF/report_pdf field
	// naming throughout this file). Serving it as "application/pdf" with a
	// .pdf filename -- what this handler did before -- handed the browser a
	// file that fails to open in any real PDF viewer. Content-Type/filename
	// now come from what the stored artifact actually is.
	//
	// Content-Disposition defaults to inline (ghidra.html's own "view
	// report" button, which points an <iframe> straight at this URL);
	// unconditional attachment here -- what this handler did before --
	// forced a download even for that iframe, so "view report" only ever
	// downloaded the file instead of rendering it. ?download=1 switches to
	// attachment, mirroring serveGitHubAnalysisPDFProxy's own identical
	// one-endpoint-two-dispositions shape; ghidra.html's own "full report
	// ↓" link sets it.
	disposition := "inline"
	if r.URL.Query().Get("download") == "1" {
		disposition = "attachment"
	}
	w.Header().Set("Content-Type", doc.ContentType)
	w.Header().Set("Content-Disposition", disposition+`; filename="`+doc.Filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(data)
}

// ghidraAlerts appends Ghidra queue and finding alerts, riding the same
// s.alerts sink as the sandbox and Suricata checks. No new transport.
//
// The plan sketched this against fields that do not exist here — HandoffOld,
// WorkerState, AITriage.Interesting, and a numeric GHIDRA_ALERT_RISK_SCORE.
// The worker reports a flat queue and a *string* risk level, so the checks
// below are written against what is actually produced rather than against the
// struct the sketch imagined.
func ghidraAlerts(s *store, messages *[]string, markOnly bool) {
	status := loadGhidraStatus()
	if !status.Configured {
		// The worker was never deployed on this host. Alerting about a
		// subsystem the operator has not opted into is pure noise.
		return
	}

	emit := func(key, message string) {
		if s.alerts == nil || s.alerts.observe(key, message, "", markOnly) {
			if !markOnly {
				*messages = append(*messages, message)
			}
		}
	}

	// One alert for "not draining", carrying the queue depth, rather than
	// separate stalled-handoff and unhealthy-worker alerts: both describe the
	// same fault and would page twice for one cause.
	if status.Stale {
		emit("ghidra:worker", fmt.Sprintf(
			"ghidra worker not draining: queue file is stale, %d queued, %d running (check honeypot-ghidra-worker.path)",
			status.Queued, status.Running))
	}
	if status.Failed > 0 {
		emit("ghidra:failed", fmt.Sprintf("ghidra queue has %d failed request(s)", status.Failed))
	}

	// Alert-worthy findings. Two things are deliberately NOT here:
	//
	// Crypto constants alone. A stock AES table appears in a great deal of
	// benign software, and the page already says their presence does not show
	// malicious use. Paging on it would train the reader to ignore the alert.
	// GHIDRA_ALERT_ON_CRYPTO=true opts in for an operator who wants it.
	//
	// A numeric risk threshold. There is no score to threshold — the worker
	// records a string level from the AI triage, so the levels that alert are
	// named instead.
	alertLevels := map[string]bool{}
	for _, level := range strings.Split(getenv("GHIDRA_ALERT_RISK_LEVELS", "high,critical"), ",") {
		if level = strings.ToLower(strings.TrimSpace(level)); level != "" {
			alertLevels[level] = true
		}
	}
	alertOnCrypto := strings.EqualFold(getenv("GHIDRA_ALERT_ON_CRYPTO", "false"), "true")

	for _, result := range loadGhidraResults() {
		if result.ExitStatus == "error" {
			emit("ghidra:error:"+result.SHA256, fmt.Sprintf(
				"ghidra analysis failed: sha256=%s reason=%s", result.SHA256, result.Error))
			continue
		}
		risky := result.AITriage != nil &&
			alertLevels[strings.ToLower(strings.TrimSpace(result.AITriage.RiskLevel))]
		crypto := alertOnCrypto && len(result.FindCrypt) > 0
		if !risky && !crypto {
			continue
		}
		// The AI level is an unverified model guess — the detail page says so,
		// and an alert that hides that would be worse than one that does not
		// fire. Say it in the message, where the reader actually sees it.
		detail := "crypto constants only"
		if risky {
			detail = fmt.Sprintf("AI-guessed risk=%s (UNVERIFIED, %s)",
				result.AITriage.RiskLevel, result.AITriage.Model)
		}
		emit("ghidra:flagged:"+result.SHA256, fmt.Sprintf(
			"ghidra flagged sample: sha256=%s crypto_hits=%d imports=%d %s",
			result.SHA256, len(result.FindCrypt), len(result.Imports), detail))
	}
}

// serveGhidraCallGraph streams the rendered call graph.
//
// The node labels are function names recovered from the sample, so this SVG is
// attacker-influenced content. An <img> tag cannot execute script in an SVG,
// but a browser navigating directly to this URL renders it as a document,
// where it can. Hence the headers: a default-src 'none' CSP leaves nothing for
// embedded script or remote references to reach, and nosniff keeps the
// declared type authoritative. The page embeds it with <img> regardless.
func serveGhidraCallGraph(w http.ResponseWriter, r *http.Request, sha string) {
	if !hashName.MatchString(sha) {
		http.NotFound(w, r)
		return
	}
	// #638/#763: from ghidra-report-artifacts-v1, never GHIDRA_RESULTS_DIR.
	_, data, err := fetchGhidraArtifact(esResultsClient, sha, "callgraph")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(data)
}
