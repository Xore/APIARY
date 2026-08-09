package main

// reports_es.go — #475: generated PDF reports (metadata + bytes) live in
// Elasticsearch, not local disk, in this file's own index
// (dashboard-generated-reports-v1). Definitions (reports_store.go) are also
// Elasticsearch-backed since #787, but in a separate singleton-document
// index (dashboard-reports-definitions-v1, via settings_store_es.go) --
// this file only covers the *generated* history, per #475's own scope ("the
// generated files... stored/indexed via Elasticsearch"). No local-file
// fallback: errReportsStorageUnavailable when es is nil, the same "ES is
// mandatory infrastructure" posture #494/#483 already established.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

var errReportsStorageUnavailable = errors.New("reports storage unavailable")

// generatedReportIndex holds one document per produced PDF: generatedReport's
// own metadata fields plus the base64-encoded bytes. Every dashboard instance
// reads and writes the same index, so a report is servable regardless of
// which instance originally generated it.
const generatedReportIndex = "dashboard-generated-reports-v1"

// generatedReportMaxBytes is deliberately larger than docIndexMaxBytes's 2MB
// default: unlike bookkeeping/cache records, a generated PDF is a real,
// legitimately-stored artifact. report_pdf.go's writer is a hand-rolled,
// text-only emitter (no embedded images), so even a "Full security report"
// with a large event appendix stays well under this; a report that somehow
// exceeds it needs a smaller scope/appendix limit, not a bigger cap here.
const generatedReportMaxBytes = 24 << 20 // 24MB (comfortably covers a base64'd PDF up to ~18MB raw)

// storedGeneratedReport is the Elasticsearch document shape: generatedReport
// promotes its own fields into the same JSON object (Go embedding), plus the
// PDF payload alongside it.
type storedGeneratedReport struct {
	generatedReport
	PDFBase64 string `json:"pdf_base64"`
}

// addGenerated renders-then-stores in one step: assigns a server-side id,
// stamps CreatedAt/Origin, writes the metadata+PDF as one Elasticsearch
// document (op_type=create -- generated ids are random, so a collision is
// not a real scenario to design retry logic around), and prunes the oldest
// records past the retention cap.
func (rs *reportStore) addGenerated(meta generatedReport, pdf []byte) (generatedReport, string, error) {
	if rs.es == nil {
		return generatedReport{}, "", errReportsStorageUnavailable
	}
	if len(pdf) == 0 {
		return generatedReport{}, "", errors.New("refusing to record an empty report PDF")
	}
	meta.ID = newReportID("gen_")
	meta.SizeBytes = int64(len(pdf))
	meta.CreatedAt = time.Now().UTC()
	if meta.Origin == "" {
		meta.Origin = "manual"
	}
	doc := storedGeneratedReport{generatedReport: meta, PDFBase64: base64.StdEncoding.EncodeToString(pdf)}
	body, err := json.Marshal(doc)
	if err != nil {
		return generatedReport{}, "", err
	}
	if err := rs.es.docIndexSized(generatedReportIndex, meta.ID, body, generatedReportMaxBytes, true, 0, 0); err != nil {
		return generatedReport{}, "", fmt.Errorf("persist report PDF: %w", err)
	}
	rs.pruneGenerated()
	return meta, "", nil
}

// pruneGenerated deletes the oldest generated reports past rs.maxGenerated.
// Best effort: a failed delete just means that record survives to the next
// prune pass rather than aborting the whole cycle -- this is retention
// hygiene, not correctness-critical state.
func (rs *reportStore) pruneGenerated() {
	all, err := rs.listGenerated()
	if err != nil || len(all) <= rs.maxGenerated {
		return
	}
	for _, meta := range all[:len(all)-rs.maxGenerated] {
		_ = rs.es.docDelete(generatedReportIndex, meta.ID)
	}
}

// listGenerated returns every generated report's metadata (never the PDF
// bytes -- callers that need those call generatedPDF for one record at a
// time), oldest first.
func (rs *reportStore) listGenerated() ([]generatedReport, error) {
	if rs.es == nil {
		return nil, errReportsStorageUnavailable
	}
	hits, err := rs.es.docSearchAll(generatedReportIndex, 10000)
	if err != nil {
		return nil, err
	}
	out := make([]generatedReport, 0, len(hits))
	for _, hit := range hits {
		var stored storedGeneratedReport
		if json.Unmarshal(hit.Source, &stored) != nil {
			continue
		}
		out = append(out, stored.generatedReport)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// generated fetches one generated report's metadata only.
func (rs *reportStore) generated(id string) (generatedReport, bool) {
	if rs.es == nil {
		return generatedReport{}, false
	}
	hit, found, err := rs.es.docGet(generatedReportIndex, id)
	if err != nil || !found {
		return generatedReport{}, false
	}
	var stored storedGeneratedReport
	if json.Unmarshal(hit.Source, &stored) != nil {
		return generatedReport{}, false
	}
	return stored.generatedReport, true
}

// generatedPDF fetches one generated report's metadata and decoded PDF
// bytes together -- the one place PDFBase64 actually gets decoded, so a page
// that only needs the history list (listGenerated) never pays for it.
func (rs *reportStore) generatedPDF(id string) (generatedReport, []byte, error) {
	if rs.es == nil {
		return generatedReport{}, nil, errReportsStorageUnavailable
	}
	hit, found, err := rs.es.docGet(generatedReportIndex, id)
	if err != nil {
		return generatedReport{}, nil, err
	}
	if !found {
		return generatedReport{}, nil, fmt.Errorf("%w: no generated report with this id", errUnknownRecord)
	}
	var stored storedGeneratedReport
	if err := json.Unmarshal(hit.Source, &stored); err != nil {
		return generatedReport{}, nil, err
	}
	pdf, err := base64.StdEncoding.DecodeString(stored.PDFBase64)
	if err != nil {
		return generatedReport{}, nil, fmt.Errorf("decode stored report PDF: %w", err)
	}
	return stored.generatedReport, pdf, nil
}

func (rs *reportStore) deleteGenerated(id string) error {
	if rs.es == nil {
		return errReportsStorageUnavailable
	}
	if _, found, err := rs.es.docGet(generatedReportIndex, id); err != nil {
		return err
	} else if !found {
		return fmt.Errorf("%w: no generated report with this id", errUnknownRecord)
	}
	return rs.es.docDelete(generatedReportIndex, id)
}
