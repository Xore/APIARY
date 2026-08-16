package main

// sandbox_artifacts_es.go — #638/#764: the three binary artifacts
// dashboard/sandbox.go used to serve straight off sandboxResultsDirs()
// (guest PCAP, host PCAP, diagnostics ZIP) now come from
// sandbox-export-artifacts-v1 instead. Unlike the Ghidra artifacts (#763,
// ghidra_artifacts_es.go) and the cowrie TTY recordings (#638/#612)
// before them, these are too large for a single Elasticsearch document
// even base64-encoded -- a 64MB guest PCAP is ~85MB base64'd, well past
// what a normal ES document should hold (docIndexMaxBytes's own comment
// on this in elastic.go). So each artifact is chunked across multiple
// documents instead of raising a cap: analysis/es-results-importer/
// importer.py's own "chunked" source handling splits a file into
// SANDBOX_ARTIFACT_CHUNK_BYTES pieces, one document per chunk, doc _id
// "<job>:<kind>:<chunk_index>". Chunk 0 doubles as the artifact's own
// manifest -- it carries filename/content_type/total_chunks/size_bytes
// alongside its data, so a caller that only needs to know "does this
// exist, how big is it" (attachSandboxDownloads) never has to fetch more
// than one document, and a caller that needs the real bytes
// (serveSandboxExport) already has chunk 0's data in hand before
// fetching the rest.
//
// kind is one of "host_pcap", "guest_pcap", "diagnostics" -- matching
// importer.py's own artifact_kind values for these three sources.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

const sandboxArtifactIndex = "sandbox-export-artifacts-v1"

var errSandboxArtifactStorageUnavailable = errors.New("sandbox artifact storage unavailable")

// sandboxArtifactChunkDoc mirrors one chunk document's shape, as written
// by importer.py's chunked binary-source handling.
type sandboxArtifactChunkDoc struct {
	Job         string `json:"job"`
	Kind        string `json:"kind"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	ChunkIndex  int    `json:"chunk_index"`
	TotalChunks int    `json:"total_chunks"`
	SizeBytes   int64  `json:"size_bytes"`
	DataBase64  string `json:"data_base64"`
}

func sandboxArtifactChunkID(job, kind string, index int) string {
	return fmt.Sprintf("%s:%s:%d", job, kind, index)
}

// sandboxArtifactManifest fetches chunk 0 of job's `kind` artifact --
// enough to know it exists and to attach a download link/size, without
// pulling any of the remaining chunks. false (not an error) covers every
// "nothing to offer" case alike: es nil, the artifact was never stored,
// or the fetch/decode failed -- attachSandboxDownloads' own philosophy is
// already "no link is worse than a dead link, but neither may crash the
// page", same posture ghidraArtifactSet/attachGhidraDownload established
// for #763.
func sandboxArtifactManifest(es *esClient, job, kind string) (sandboxArtifactChunkDoc, bool) {
	if es == nil {
		return sandboxArtifactChunkDoc{}, false
	}
	hit, found, err := es.docGet(sandboxArtifactIndex, sandboxArtifactChunkID(job, kind, 0))
	if err != nil || !found {
		return sandboxArtifactChunkDoc{}, false
	}
	var doc sandboxArtifactChunkDoc
	if json.Unmarshal(hit.Source, &doc) != nil || doc.TotalChunks <= 0 {
		return sandboxArtifactChunkDoc{}, false
	}
	return doc, true
}

// serveSandboxArtifact streams job's `kind` artifact to w chunk by chunk,
// decoding and writing each one as it's fetched rather than assembling
// the whole (up to tens-of-MB) artifact in memory first. Headers are set
// from the manifest (chunk 0) before any byte is written, so a caller
// that gets an error back before this point can still respond with a
// clean 404/500 -- once writeChunk below has run once, the response is
// committed and a later chunk failure can only truncate the download,
// not signal a clean error (an inherent limitation of streaming once
// headers are sent, the same one http.ServeContent has for a local file
// that vanishes mid-read).
func serveSandboxArtifact(w http.ResponseWriter, es *esClient, job, kind string) error {
	manifest, ok := sandboxArtifactManifest(es, job, kind)
	if !ok {
		return errSandboxArtifactStorageUnavailable
	}
	w.Header().Set("Content-Type", manifest.ContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="`+manifest.Filename+`"`)

	writeChunk := func(doc sandboxArtifactChunkDoc) error {
		data, err := base64.StdEncoding.DecodeString(doc.DataBase64)
		if err != nil {
			return fmt.Errorf("decode chunk %d/%d: %w", doc.ChunkIndex, doc.TotalChunks, err)
		}
		_, err = w.Write(data)
		return err
	}
	if err := writeChunk(manifest); err != nil {
		return err
	}
	for i := 1; i < manifest.TotalChunks; i++ {
		hit, found, err := es.docGet(sandboxArtifactIndex, sandboxArtifactChunkID(job, kind, i))
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("%w: chunk %d/%d missing for %s:%s", errUnknownRecord, i, manifest.TotalChunks, job, kind)
		}
		var doc sandboxArtifactChunkDoc
		if err := json.Unmarshal(hit.Source, &doc); err != nil {
			return fmt.Errorf("decode chunk %d metadata: %w", i, err)
		}
		if err := writeChunk(doc); err != nil {
			return err
		}
	}
	return nil
}
