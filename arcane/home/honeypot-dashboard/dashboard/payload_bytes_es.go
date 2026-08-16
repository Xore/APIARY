package main

// payload_bytes_es.go -- #762: captured payload bytes mirrored into
// Elasticsearch, base64-encoded, keyed by hash, so the dashboard's download
// route (servePayload) never reads the host disk directly -- the last
// disk-backed *read* path this stack had, following the same #475/#483
// pattern already used for generated PDF reports and payload inventory
// metadata. The write-side detonation/analysis tooling (Payload Workbench,
// sandbox submission, Ghidra worker) stays disk-based by design -- this is
// about the dashboard's own serving route only, per the issue's own scope
// note.
//
// #1201/#1202 moved the periodic disk-walk-and-batch-mirror this file used
// to piggyback on (scanPayloads/refreshPayloadCacheAsync) into
// payload-inventory-worker, which owns bytes-mirroring for every payload it
// scans (#1221's own mirrorPayloadBytes, a separate function in a separate
// Go module -- not this file's). What's left here is on-demand only:
// mirrorOnePayloadBytes, called from payloadBytesForAnalysis when static
// analysis needs a hash this instance hasn't seen mirrored yet (or whose
// mirrored copy's fingerprint is stale), so static analysis never blocks on
// the worker's own next scan cycle.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// payloadBytesIndex holds one document per captured payload, keyed by the
// same hash payloadInventoryIndex uses. A document with TooLarge=true and
// no DataBase64 means the payload exceeded payloadBytesRawCap and was
// deliberately not mirrored -- recorded so a repeat scan doesn't re-read
// the file every cycle, and so the download route can show a clear message
// instead of a bare 404.
const payloadBytesIndex = "dashboard-payload-bytes-v1"

// payloadBytesRawCap bounds the raw (pre-base64) size mirrored into
// Elasticsearch. Matches payload_analysis.go's analysisReadCap reasoning:
// captured samples run from KB scripts to tens-of-MB binaries; double
// analysisReadCap (16MB) comfortably covers the large end of what this
// stack actually captures without letting one outsized sample blow out the
// index.
const payloadBytesRawCap = 32 << 20 // 32MB

// payloadBytesMaxBytes is the ES document size cap: raw bytes + base64
// overhead (~33%) + JSON envelope, comfortably above payloadBytesRawCap's
// base64'd size (~43MB).
const payloadBytesMaxBytes = 48 << 20 // 48MB

var errPayloadStorageUnavailable = errors.New("payload storage unavailable")

type storedPayloadBytes struct {
	Hash       string `json:"hash"`
	SizeBytes  int64  `json:"size_bytes"`
	TooLarge   bool   `json:"too_large,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
	// Fingerprint is fileFingerprint's size+mtime string at mirror time.
	// staticAnalysisFor (#1103 hybrid item) compares this against the
	// current local file before trusting this mirrored copy as the
	// analysis source -- this index is otherwise "immutable once written"
	// by design (#762, the download route never revisits a hash once
	// mirrored), which is fine for a capture that never changes after being
	// written, but not sufficient on its own for a source that must detect
	// a hash-named file whose content changed underneath it.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// mirrorOnePayloadBytes mirrors one payload's bytes into payloadBytesIndex
// on demand -- #1223: its only remaining caller is
// payloadBytesForAnalysis's self-heal path (a previously mirrored copy's
// fingerprint no longer matches the local file, or nothing's mirrored
// yet), which always needs the write to go through whether or not a
// (stale) document already exists. docIndex's non-create mode is a
// conditional overwrite (if_seq_no/if_primary_term), not a plain PUT --
// passing 0/0 blind (as this function did before this fix) only succeeds
// by coincidence for a document whose real seq_no genuinely is 0, and
// fails outright for the common "never mirrored before" case, exactly the
// case this on-demand path exists for. A docGet first tells this whether
// to create (found=false) or overwrite with the document's real seq_no/
// primary_term (found=true) -- one extra read, but this is an on-demand,
// per-cache-miss path already paying a disk read and a write, not a hot
// loop.
func (s *store) mirrorOnePayloadBytes(hash string, size int64) {
	hit, found, err := s.es.docGet(payloadBytesIndex, hash)
	if err != nil {
		return
	}
	create, seqNo, primaryTerm := !found, hit.SeqNo, hit.PrimaryTerm
	if size > payloadBytesRawCap {
		marker, err := json.Marshal(storedPayloadBytes{Hash: hash, SizeBytes: size, TooLarge: true})
		if err != nil {
			return
		}
		_ = s.es.docIndex(payloadBytesIndex, hash, marker, create, seqNo, primaryTerm)
		return
	}
	path, err := s.payloadPath(hash)
	if err != nil {
		return
	}
	data, fingerprint, err := readPayloadBytesCapped(path, payloadBytesRawCap)
	if err != nil {
		return
	}
	doc := storedPayloadBytes{Hash: hash, SizeBytes: int64(len(data)), DataBase64: base64.StdEncoding.EncodeToString(data), Fingerprint: fingerprint}
	body, err := json.Marshal(doc)
	if err != nil {
		return
	}
	_ = s.es.docIndexSized(payloadBytesIndex, hash, body, payloadBytesMaxBytes, create, seqNo, primaryTerm)
}

// readPayloadBytesCapped re-stats the file (its size may have changed since
// the scan that produced the capturedFile.Size this was called with) before
// reading, so a cap-exceeding file never gets read into memory in full.
func readPayloadBytesCapped(path string, cap int64) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if fi.Size() > cap {
		return nil, "", errors.New("payload exceeds mirror size cap")
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, "", err
	}
	return data, fileFingerprint(fi), nil
}

// fetchPayloadBytes retrieves one payload's raw bytes from
// payloadBytesIndex. found=false means never mirrored (not yet scanned, or
// genuinely doesn't exist); tooLarge=true means it was scanned and
// deliberately excluded (see payloadBytesRawCap) -- distinct from
// found=false so the download route can tell "doesn't exist" from "exists
// but too large to serve this way" apart. fingerprint is the size+mtime
// string recorded at mirror time (empty for documents mirrored before this
// field existed, or when tooLarge) -- staticAnalysisFor uses it to detect a
// local file that changed since it was mirrored; the download route has no
// use for it and can ignore it.
func (s *store) fetchPayloadBytes(hash string) (data []byte, tooLarge bool, found bool, fingerprint string, err error) {
	if s.es == nil {
		return nil, false, false, "", errPayloadStorageUnavailable
	}
	hit, found, err := s.es.docGet(payloadBytesIndex, hash)
	if err != nil {
		return nil, false, false, "", err
	}
	if !found {
		return nil, false, false, "", nil
	}
	var stored storedPayloadBytes
	if err := json.Unmarshal(hit.Source, &stored); err != nil {
		return nil, false, false, "", err
	}
	if stored.TooLarge {
		return nil, true, true, "", nil
	}
	data, err = base64.StdEncoding.DecodeString(stored.DataBase64)
	if err != nil {
		return nil, false, false, "", err
	}
	return data, false, true, stored.Fingerprint, nil
}
