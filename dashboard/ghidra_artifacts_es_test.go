package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ghidraArtifactStub answers both requests this package ever makes against
// ghidra-report-artifacts-v1: docListIDs' POST .../_search (used by
// ghidraArtifactSet for the cheap per-row existence check) and docGet's
// GET .../_doc/<id> (used by fetchGhidraArtifact to retrieve one artifact's
// actual bytes).
func ghidraArtifactStub(t *testing.T, docs map[string]ghidraArtifactDoc) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_search"):
			type hit struct {
				ID string `json:"_id"`
			}
			hits := make([]hit, 0, len(docs))
			for id := range docs {
				hits = append(hits, hit{ID: id})
			}
			json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/_doc/"):
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/_doc/")+len("/_doc/"):]
			doc, ok := docs[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"_id": id, "_source": doc})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestGhidraArtifactSetReflectsWhatIsStored(t *testing.T) {
	srv := httptest.NewServer(ghidraArtifactStub(t, map[string]ghidraArtifactDoc{
		shaA + ":report":    {SHA256: shaA, Kind: "report"},
		shaA + ":callgraph": {SHA256: shaA, Kind: "callgraph"},
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	set := ghidraArtifactSet(esResultsClient)
	if !set[shaA+":report"] || !set[shaA+":callgraph"] {
		t.Fatalf("expected both artifact keys present, got %v", set)
	}
	if set[shaB+":report"] {
		t.Errorf("unrelated sha should not appear in the set")
	}
}

func TestGhidraArtifactSetNilWhenESUnavailable(t *testing.T) {
	if set := ghidraArtifactSet(nil); set != nil {
		t.Fatalf("expected nil for a nil client, got %v", set)
	}
}

// attachGhidraDownload/attachGhidraCallGraph must only ever offer a link
// when the artifact genuinely exists in the set built for this page load --
// this is the #763 replacement for the old os.Stat-on-disk check, and (like
// that check) must fail closed: a row whose worker-reported filename fields
// are set but whose bytes never made it into ES offers nothing rather than
// a dead link.
func TestAttachGhidraDownloadGatesOnArtifactSet(t *testing.T) {
	present := map[string]bool{shaA + ":report": true, shaA + ":callgraph": true}

	row := ghidraResult{SHA256: shaA, ReportPDF: "whatever-the-worker-said.html", CallGraphSVG: "whatever.svg"}
	attachGhidraDownload(&row, present)
	if row.ExportURL == "" || row.CallGraphURL == "" {
		t.Fatalf("expected both URLs set when the artifact set has both keys, got %+v", row)
	}

	rowMissing := ghidraResult{SHA256: shaB, ReportPDF: "x.html", CallGraphSVG: "x.svg"}
	attachGhidraDownload(&rowMissing, present)
	if rowMissing.ExportURL != "" || rowMissing.CallGraphURL != "" {
		t.Fatalf("expected no URLs for a sha256 absent from the artifact set, got %+v", rowMissing)
	}

	rowNoFields := ghidraResult{SHA256: shaA}
	attachGhidraDownload(&rowNoFields, present)
	if rowNoFields.ExportURL != "" || rowNoFields.CallGraphURL != "" {
		t.Fatalf("worker never reporting a filename must still mean no link, even if the artifact set has the key: %+v", rowNoFields)
	}

	rowNilSet := ghidraResult{SHA256: shaA, ReportPDF: "x.html", CallGraphSVG: "x.svg"}
	attachGhidraDownload(&rowNilSet, nil)
	if rowNilSet.ExportURL != "" || rowNilSet.CallGraphURL != "" {
		t.Fatalf("a nil artifact set (ES unreachable) must not offer any link: %+v", rowNilSet)
	}
}

func TestServeGhidraExportServesStoredArtifactWithCorrectedContentType(t *testing.T) {
	srv := httptest.NewServer(ghidraArtifactStub(t, map[string]ghidraArtifactDoc{
		shaA + ":report": {
			SHA256: shaA, Kind: "report", Filename: shaA + "_ghidra_report.html",
			ContentType: "text/html", DataBase64: base64.StdEncoding.EncodeToString([]byte("<h1>hi</h1>")),
		},
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	w := httptest.NewRecorder()
	serveGhidraExport(w, httptest.NewRequest(http.MethodGet, "/export/ghidra/"+shaA, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", w.Code, w.Body.String())
	}
	// #763: this used to be hardcoded to application/pdf regardless of what
	// the file actually was -- the real content this handler ever served
	// (an HTML report) was mislabeled. It must now reflect the stored
	// artifact's own recorded content type.
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("Content-Type = %q, want text/html (not application/pdf)", ct)
	}
	if !strings.Contains(w.Header().Get("Content-Disposition"), shaA+"_ghidra_report.html") {
		t.Errorf("Content-Disposition missing the real filename: %q", w.Header().Get("Content-Disposition"))
	}
	if w.Body.String() != "<h1>hi</h1>" {
		t.Errorf("body = %q, want decoded artifact bytes", w.Body.String())
	}
}

func TestServeGhidraExportNotFoundWhenNoArtifactStored(t *testing.T) {
	srv := httptest.NewServer(ghidraArtifactStub(t, map[string]ghidraArtifactDoc{}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	w := httptest.NewRecorder()
	serveGhidraExport(w, httptest.NewRequest(http.MethodGet, "/export/ghidra/"+shaA, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}

func TestServeGhidraCallGraphServesStoredSVG(t *testing.T) {
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><text>f</text></svg>`
	srv := httptest.NewServer(ghidraArtifactStub(t, map[string]ghidraArtifactDoc{
		shaA + ":callgraph": {
			SHA256: shaA, Kind: "callgraph", Filename: shaA + "_callgraph.svg",
			ContentType: "image/svg+xml", DataBase64: base64.StdEncoding.EncodeToString([]byte(svg)),
		},
	}))
	defer srv.Close()
	withESResultsClient(t, srv.URL)

	w := httptest.NewRecorder()
	serveGhidraExport(w, httptest.NewRequest(http.MethodGet, "/export/ghidra/"+shaA+"/callgraph.svg", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != svg {
		t.Errorf("body = %q, want the decoded SVG", w.Body.String())
	}
	// The XSS-hardening headers (attacker-influenced content, see
	// serveGhidraCallGraph's own doc comment) must survive the ES move.
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing Content-Security-Policy header")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}
}

func TestServeGhidraExportRejectsBadHashStillWorksWithoutES(t *testing.T) {
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
