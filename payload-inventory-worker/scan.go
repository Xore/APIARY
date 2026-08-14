package main

// scan.go -- #1201: the write half of the payload inventory, moved off
// dashboard/payloads_data.go's scanPayloads (a per-dashboard-instance disk
// walk gated on that instance having a PAYLOAD_DIRS mount) into this
// single standalone worker. Reads the same capture directories, classifies
// each file with the same payload_kind.go logic, and writes to the exact
// same Elasticsearch indices (dashboard-payload-inventory-v1,
// dashboard-payload-bytes-v1) dashboard/payloads_data.go's readPayloadInventory
// and servePayload already read from -- the read side doesn't change at
// all. Whether dashboard's own scanPayloads is removed (redundant, not
// wrong: both writers converge on the same hash-keyed documents) is #1202.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var errPayloadTooLarge = errors.New("payload exceeds mirror size cap")

// hashName matches a captured file named by its own hash -- ported from
// dashboard/util.go's constant of the same name.
var hashName = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)

const payloadPreviewCap = 512

const payloadInventoryIndex = "dashboard-payload-inventory-v1"
const payloadBytesIndex = "dashboard-payload-bytes-v1"

// payloadBytesRawCap/payloadBytesMaxBytes match dashboard/payload_bytes_es.go's
// own constants exactly -- same store, same caps, so a file mirrored by
// this worker looks identical to one mirrored by a dashboard instance's own
// (soon to be removed, #1202) mirrorPayloadBytes.
const payloadBytesRawCap = 32 << 20 // 32MB
const payloadBytesMaxBytes = 48 << 20

// capturedFile mirrors dashboard/payloads_data.go's struct field-for-field
// (including JSON tags via default Go encoding, which dashboard's own
// json.Marshal(file) also relies on with no custom tags) so a document
// written here round-trips through dashboard's readPayloadInventory
// unchanged.
type capturedFile struct {
	Hash             string
	Size             int64
	SizeH            string
	Mtime            string
	MtimeUTC         string
	MIME             string
	Kind             string
	KindCode         string
	Platform         string
	AnalysisPath     string
	Dynamic          bool
	Sources          []string
	Copies           int
	Preview          string
	PreviewTruncated bool
}

type storedPayloadBytes struct {
	Hash       string `json:"hash"`
	SizeBytes  int64  `json:"size_bytes"`
	TooLarge   bool   `json:"too_large,omitempty"`
	DataBase64 string `json:"data_base64,omitempty"`
}

// payloadSourceName classifies a capture directory into a display source
// name -- ported verbatim from dashboard/payloads_data.go.
func payloadSourceName(dir string) string {
	lower := strings.ToLower(filepath.ToSlash(dir))
	switch {
	case strings.Contains(lower, "dionaea"):
		return "dionaea"
	case strings.Contains(lower, "cowrie"):
		return "cowrie"
	case strings.Contains(lower, "script"):
		return "scripts"
	default:
		name := strings.TrimSpace(filepath.Base(filepath.Clean(dir)))
		if name == "" || name == "." || name == string(filepath.Separator) {
			return "payloads"
		}
		return name
	}
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// scanDirs walks every capture directory and returns the merged inventory
// plus a hash -> first-seen-path map (mirrorPayloadBytes needs a real path
// to read from; dashboard's own capturedFile carries no path field, since
// dashboard re-derives it on demand via payloadPath's disk search --
// unnecessary here, since this worker already has the path in hand while
// walking). Same two-pass shape as dashboard/payloads_data.go's
// scanPayloads (collect per-file info, then merge sources/copies across
// directories sharing a hash), split into its own function so the walk
// itself is testable without a real Elasticsearch.
func scanDirs(dirs []string) ([]capturedFile, map[string]string) {
	files := map[string]*capturedFile{}
	paths := map[string]string{}
	sourceSets := map[string]map[string]bool{}
	sourceCounts := map[string]int{}

	for _, dir := range dirs {
		source := payloadSourceName(dir)
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() || !hashName.MatchString(d.Name()) {
				return nil
			}
			fi, err := d.Info()
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
			hash := strings.ToLower(d.Name())
			if sourceSets[hash] == nil {
				sourceSets[hash] = map[string]bool{}
			}
			if !sourceSets[hash][source] {
				sourceSets[hash][source] = true
				sourceCounts[source]++
			}
			if existing := files[hash]; existing != nil {
				existing.Copies++
				if modified := fi.ModTime().Format("2006-01-02 15:04"); modified > existing.Mtime {
					existing.Mtime, existing.MtimeUTC = modified, utcOrEmpty(fi.ModTime())
				}
				return nil
			}
			mime := "application/octet-stream"
			classification := classifyPayload(nil)
			var preview string
			if f, err := os.Open(path); err == nil {
				head := make([]byte, 64<<10)
				n, _ := f.Read(head)
				f.Close()
				head = head[:n]
				mime = http.DetectContentType(head)
				classification = classifyPayload(head)
				previewBytes := head
				if len(previewBytes) > payloadPreviewCap {
					previewBytes = previewBytes[:payloadPreviewCap]
				}
				preview = hex.Dump(previewBytes)
			}
			files[hash] = &capturedFile{
				Hash: hash, Size: fi.Size(), SizeH: humanBytes(fi.Size()),
				Mtime: fi.ModTime().Format("2006-01-02 15:04"), MtimeUTC: utcOrEmpty(fi.ModTime()), MIME: mime,
				Kind: classification.Label, KindCode: classification.Code,
				Platform: classification.Platform, AnalysisPath: classification.AnalysisPath,
				Dynamic: classification.Dynamic, Copies: 1,
				Preview: preview, PreviewTruncated: fi.Size() > payloadPreviewCap,
			}
			paths[hash] = path
			return nil
		})
	}

	var out []capturedFile
	for hash, file := range files {
		for source := range sourceSets[hash] {
			file.Sources = append(file.Sources, source)
		}
		sort.Strings(file.Sources)
		out = append(out, *file)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mtime > out[j].Mtime })
	return out, paths
}

func utcOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// indexPayloadInventory upserts every freshly-scanned file, skipping any
// file whose stored document already matches -- ported from
// dashboard/payloads_data.go's own function of the same name, minus the
// optimistic-concurrency CAS (see es.go's docIndex doc comment for why an
// unconditioned overwrite is fine here).
func indexPayloadInventory(es *esClient, files []capturedFile) (failures int) {
	for _, file := range files {
		fresh, err := json.Marshal(file)
		if err != nil {
			continue
		}
		var freshFields map[string]json.RawMessage
		if json.Unmarshal(fresh, &freshFields) != nil {
			continue
		}

		hit, found, err := es.docGet(payloadInventoryIndex, file.Hash)
		if err != nil {
			log.Printf("payload-inventory-worker: docGet %s/%s: %v", payloadInventoryIndex, file.Hash, err)
			failures++
			continue
		}

		var stored map[string]json.RawMessage
		if found {
			if json.Unmarshal(hit.Source, &stored) != nil {
				stored = nil // treat an unparseable existing doc as absent
			}
		}
		// Compare only the fields this worker owns (freshFields) against
		// their stored values -- an extra key the stored doc carries that
		// freshFields doesn't (e.g. GitHubAnalysisURL, see the merge below)
		// must never make this look "changed" and trigger a needless
		// rewrite every single scan cycle.
		if found && fieldsUnchanged(stored, freshFields) {
			continue
		}

		body := fresh
		if stored != nil {
			// Merge onto the existing document rather than a blind
			// overwrite: dashboard writes extra fields on this same
			// document this worker's capturedFile struct doesn't know
			// about (GitHubAnalysisURL/GitHubAnalysisLabel, populated by
			// attachGitHubAnalysisVerdicts after a GitHub-analysis
			// submission) -- a plain PUT of this worker's own field set
			// would silently delete them on the next scan that finds this
			// hash's classification changed for an unrelated reason (e.g.
			// a new copy showing up in a second source directory).
			for k, v := range freshFields {
				stored[k] = v
			}
			if merged, err := json.Marshal(stored); err == nil {
				body = merged
			}
		}
		if err := es.docIndex(payloadInventoryIndex, file.Hash, body, !found); err != nil {
			log.Printf("payload-inventory-worker: docIndex %s/%s: %v", payloadInventoryIndex, file.Hash, err)
			failures++
		}
	}
	return failures
}

// fieldsUnchanged reports whether every key in want has an identical raw
// JSON value in got -- extra keys got has that want doesn't are ignored,
// so an existing document carrying dashboard-only enrichment fields still
// compares equal when this worker's own fields haven't changed.
func fieldsUnchanged(got, want map[string]json.RawMessage) bool {
	for k, v := range want {
		if string(got[k]) != string(v) {
			return false
		}
	}
	return true
}

// mirrorPayloadBytes upserts the raw bytes for every scanned file --
// ported from dashboard/payload_bytes_es.go's own function of the same
// name. path is resolved by the caller (scanDirs already knows each
// file's real path; re-deriving dashboard's own payloadPath disk-search
// fallback isn't needed here). The existence check is a HEAD (docExists),
// not a full docGet -- #1221, see docExists' own doc comment for why that
// mattered live.
// mirrorPayloadBytes returns a non-nil error only for a failed Elasticsearch
// call (docExists/docIndex), so runScan can distinguish an ES-side failure
// from the benign case of a file that vanished or grew between the scan and
// the mirror attempt.
func mirrorPayloadBytes(es *esClient, hash, path string, size int64) error {
	exists, err := es.docExists(payloadBytesIndex, hash)
	if err != nil {
		log.Printf("payload-inventory-worker: docExists %s/%s: %v", payloadBytesIndex, hash, err)
		return err
	}
	if exists {
		return nil
	}
	if size > payloadBytesRawCap {
		marker, err := json.Marshal(storedPayloadBytes{Hash: hash, SizeBytes: size, TooLarge: true})
		if err != nil {
			return nil
		}
		if err := es.docIndex(payloadBytesIndex, hash, marker, true); err != nil {
			log.Printf("payload-inventory-worker: docIndex %s/%s: %v", payloadBytesIndex, hash, err)
			return err
		}
		return nil
	}
	data, err := readPayloadBytesCapped(path, payloadBytesRawCap)
	if err != nil {
		return nil
	}
	doc := storedPayloadBytes{Hash: hash, SizeBytes: int64(len(data)), DataBase64: base64.StdEncoding.EncodeToString(data)}
	body, err := json.Marshal(doc)
	if err != nil || len(body) > payloadBytesMaxBytes {
		return nil
	}
	if err := es.docIndex(payloadBytesIndex, hash, body, true); err != nil {
		log.Printf("payload-inventory-worker: docIndex %s/%s: %v", payloadBytesIndex, hash, err)
		return err
	}
	return nil
}

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
		return nil, errPayloadTooLarge
	}
	return os.ReadFile(path)
}
