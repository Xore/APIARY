package main

// payload_bytes_es.go -- #762: captured payload bytes mirrored into
// Elasticsearch, base64-encoded, keyed by hash, so the dashboard's download
// route (servePayload) never reads the host disk directly -- the last
// disk-backed *read* path this stack had, following the same #475/#483
// pattern already used for generated PDF reports and payload inventory
// metadata. The write-side detonation/analysis tooling (Payload Workbench,
// sandbox submission, Ghidra worker, and scanPayloads' own disk walk for
// metadata) stays disk-based by design -- this is about the dashboard's own
// serving route only, per the issue's own scope note.
//
// Mirroring piggybacks on the existing periodic payload-inventory scan
// (refreshPayloadCacheAsync) rather than a separate one-off backfill
// script or a lazy mirror-on-first-download: that scan already walks every
// captured file's disk path on every tick, so extending it to also mirror
// bytes backfills every existing payload within the first couple of scan
// cycles, and covers every new capture the same way going forward, with no
// separate migration step to run or forget to run.

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
}

// mirrorPayloadBytes upserts the raw bytes for every scanned file into
// payloadBytesIndex, skipping any hash already recorded (found -- whether
// successfully mirrored or previously marked too-large) so a repeat scan of
// an unchanged capture directory costs one docGet per file, not a disk
// read. Best effort throughout, same posture as indexPayloadInventory: a
// failed mirror this cycle is retried next cycle, not treated as fatal.
func (s *store) mirrorPayloadBytes(files []capturedFile) {
	if s.es == nil {
		return
	}
	for _, file := range files {
		_, found, err := s.es.docGet(payloadBytesIndex, file.Hash)
		if err != nil || found {
			continue
		}
		if file.Size > payloadBytesRawCap {
			marker, err := json.Marshal(storedPayloadBytes{Hash: file.Hash, SizeBytes: file.Size, TooLarge: true})
			if err != nil {
				continue
			}
			_ = s.es.docIndex(payloadBytesIndex, file.Hash, marker, true, 0, 0)
			continue
		}
		path, err := s.payloadPath(file.Hash)
		if err != nil {
			continue
		}
		data, err := readPayloadBytesCapped(path, payloadBytesRawCap)
		if err != nil {
			continue
		}
		doc := storedPayloadBytes{Hash: file.Hash, SizeBytes: int64(len(data)), DataBase64: base64.StdEncoding.EncodeToString(data)}
		body, err := json.Marshal(doc)
		if err != nil {
			continue
		}
		_ = s.es.docIndexSized(payloadBytesIndex, file.Hash, body, payloadBytesMaxBytes, true, 0, 0)
	}
}

// readPayloadBytesCapped re-stats the file (its size may have changed since
// the scan that produced the capturedFile.Size this was called with) before
// reading, so a cap-exceeding file never gets read into memory in full.
func readPayloadBytesCapped(path string, cap int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > cap {
		return nil, errors.New("payload exceeds mirror size cap")
	}
	return io.ReadAll(f)
}

// fetchPayloadBytes retrieves one payload's raw bytes from
// payloadBytesIndex. found=false means never mirrored (not yet scanned, or
// genuinely doesn't exist); tooLarge=true means it was scanned and
// deliberately excluded (see payloadBytesRawCap) -- distinct from
// found=false so the download route can tell "doesn't exist" from "exists
// but too large to serve this way" apart.
func (s *store) fetchPayloadBytes(hash string) (data []byte, tooLarge bool, found bool, err error) {
	if s.es == nil {
		return nil, false, false, errPayloadStorageUnavailable
	}
	hit, found, err := s.es.docGet(payloadBytesIndex, hash)
	if err != nil {
		return nil, false, false, err
	}
	if !found {
		return nil, false, false, nil
	}
	var stored storedPayloadBytes
	if err := json.Unmarshal(hit.Source, &stored); err != nil {
		return nil, false, false, err
	}
	if stored.TooLarge {
		return nil, true, true, nil
	}
	data, err = base64.StdEncoding.DecodeString(stored.DataBase64)
	if err != nil {
		return nil, false, false, err
	}
	return data, false, true, nil
}
