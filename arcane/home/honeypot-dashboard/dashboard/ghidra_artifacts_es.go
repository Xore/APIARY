package main

// ghidra_artifacts_es.go — #638/#763: the two binary artifacts
// dashboard/ghidra.go used to serve straight off GHIDRA_RESULTS_DIR (the
// per-sample analysis report, and the rendered call-graph SVG) now come
// from ghidra-report-artifacts-v1 instead. That index is written by
// analysis/es-results-importer (importer.py's own "binary" source
// handling, generalized here for #763 -- see its module docstring), not
// by this dashboard process: it already has GHIDRA_RESULTS_DIR mounted
// and already mirrors the JSON half of these results into
// ghidra-analysis-v1, so it is the natural writer for the binary half
// too, keeping the dashboard itself a pure ES reader for this artifact
// type, per #638's own "the dashboard must never read any file directly"
// direction.
//
// One index holds both artifact kinds (not two indices) -- document _id
// is "<sha256>:report" or "<sha256>:callgraph", so the two kinds for the
// same sample never collide.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const ghidraArtifactIndex = "ghidra-report-artifacts-v1"

var errGhidraArtifactStorageUnavailable = errors.New("ghidra artifact storage unavailable")

// ghidraArtifactDoc mirrors the document shape importer.py writes.
type ghidraArtifactDoc struct {
	SHA256      string `json:"sha256"`
	Kind        string `json:"kind"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
	DataBase64  string `json:"data_base64"`
}

// ghidraArtifactSet reports which "<sha256>:<kind>" artifacts currently
// exist, for attachGhidraDownload/attachGhidraCallGraph's per-row "is
// there really something to link to" check -- built once per page load
// via docListIDs (no artifact bytes fetched, see that method's own
// comment on why this matters here specifically: no retention cap bounds
// how many multi-hundred-KB base64 documents this index accumulates).
// nil (not an error) when es is nil or the query fails: the caller's
// existing philosophy already treats "can't confirm this exists" the
// same as "does not exist" -- no link is worse UX than a dead one, but
// neither may crash the page.
func ghidraArtifactSet(es *esClient) map[string]bool {
	if es == nil {
		return nil
	}
	ids, err := es.docListIDs(ghidraArtifactIndex, 20000)
	if err != nil {
		return nil
	}
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

// fetchGhidraArtifact retrieves one artifact's bytes by sha256+kind
// ("report" or "callgraph"). Only called from the two serving handlers
// (one document, one request) -- never from the list/row-attachment path
// above, which only needs the cheap existence check.
func fetchGhidraArtifact(es *esClient, sha256, kind string) (ghidraArtifactDoc, []byte, error) {
	if es == nil {
		return ghidraArtifactDoc{}, nil, errGhidraArtifactStorageUnavailable
	}
	hit, found, err := es.docGet(ghidraArtifactIndex, sha256+":"+kind)
	if err != nil {
		return ghidraArtifactDoc{}, nil, err
	}
	if !found {
		return ghidraArtifactDoc{}, nil, fmt.Errorf("%w: no %s artifact stored for this sample", errUnknownRecord, kind)
	}
	var doc ghidraArtifactDoc
	if err := json.Unmarshal(hit.Source, &doc); err != nil {
		return ghidraArtifactDoc{}, nil, err
	}
	data, err := base64.StdEncoding.DecodeString(doc.DataBase64)
	if err != nil {
		return ghidraArtifactDoc{}, nil, fmt.Errorf("decode stored %s artifact: %w", kind, err)
	}
	return doc, data, nil
}
