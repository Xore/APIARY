package main

import (
	"fmt"
	"strings"
)

// hashCorrelation is #354's "ask the backend if this hash is known" answer
// for a captured payload -- advisory only, by explicit decision: it never
// blocks a new analysis submission, it just tells the operator what already
// exists so they can decide whether one is worth queueing. Checked across
// every source that can independently confirm a hash was already analyzed:
// Ghidra (previously not surfaced on /payload-analysis at all), sandbox,
// GitHub-analysis, and raw sensor event history in Elasticsearch (source
// detection, not analysis -- "have we captured this before", not "has it
// been analyzed").
//
// Workbench's own run records are deliberately NOT queried here: they are
// owner-scoped bookkeeping (who clicked "run"), not a second copy of
// results -- the three native result stores above are already visible
// across every owner, so there is nothing extra to learn from workbench's
// own run history that would justify crossing its owner-isolation boundary.
type hashCorrelation struct {
	Known   bool
	Ghidra  *ghidraResult
	Sandbox []sandboxResult
	GitHub  *githubAnalysisResult

	// Elasticsearch sighting summary: how many raw sensor events carried
	// this hash, and which sensors/when. Advisory and best-effort -- always
	// zero-value when Elasticsearch is unconfigured or the query fails,
	// never blocks anything that depends on the rest of this struct.
	ESAvailable bool
	ESSightings int
	ESSensors   []kv
	ESFirstSeen string
	ESLastSeen  string
	// ESTruncated is true when ESSightings exceeds the number of records
	// actually fetched (see correlate's cap below) -- ESFirstSeen is then
	// only the oldest record within that capped, newest-first page, not the
	// hash's true first sighting, which may be considerably earlier (#887).
	ESTruncated bool
}

// correlateHash answers #354's "is this hash known" question by checking
// every source that can confirm it independently.
//
// primary must be the payload's true content SHA-256 -- what Ghidra,
// sandbox, and GitHub-analysis always key their own results by, since each
// computes it from the captured bytes rather than trusting whatever a
// sensor originally logged. altID is an additional identifier worth
// checking in Elasticsearch too when it differs from primary: a Dionaea
// capture's on-disk identity is its MD5 (dionaea's own convention, #364),
// not a SHA-256, and that is genuinely what file.hash.md5 in Elasticsearch
// carries for it -- searching only primary would silently miss every
// Dionaea sighting. altID may be empty (a caller with no cheaper way to
// know it, e.g. the workbench page, which deliberately avoids a full-file
// read) -- local-store matching then only ever uses primary, since those
// three sources have no MD5-keyed records to find regardless.
//
// Both identifiers are validated before use -- a malformed value must
// never reach an Elasticsearch query string or a case-insensitive scan of
// untrusted-shaped input.
func (s *store) correlateHash(primary, altID string) hashCorrelation {
	primary = strings.ToLower(strings.TrimSpace(primary))
	altID = strings.ToLower(strings.TrimSpace(altID))
	if !hashName.MatchString(primary) {
		return hashCorrelation{}
	}
	result := hashCorrelation{}
	for _, r := range loadGhidraResults() {
		if strings.EqualFold(r.SHA256, primary) {
			row := r
			result.Ghidra = &row
			result.Known = true
			break
		}
	}
	for _, r := range loadSandboxResults() {
		if strings.EqualFold(r.SHA256, primary) {
			result.Sandbox = append(result.Sandbox, r)
			result.Known = true
		}
	}
	for _, r := range loadGitHubAnalysisResults() {
		if strings.EqualFold(r.SHA256, primary) {
			row := r
			result.GitHub = &row
			result.Known = true
			break
		}
	}
	if s.es != nil {
		ids := []string{primary}
		if altID != "" && altID != primary && hashName.MatchString(altID) {
			ids = append(ids, altID)
		}
		if records, total, err := s.es.correlate(hashQuery(ids...), 200); err == nil {
			result.ESAvailable = true
			result.ESSightings = total
			// #887: records is sorted newest-first (esClient.correlate's own
			// doc comment) and capped at 200 -- for a hash with more than
			// 200 sightings, the oldest record in this page is NOT the
			// hash's true first sighting, just the oldest one that fit.
			// ESTruncated flags that so callers don't present it as fact.
			result.ESTruncated = total > len(records)
			sensors := map[string]int{}
			for i, record := range records {
				sensors[record.Sensor]++
				if i == 0 {
					result.ESLastSeen = record.Time.Format("2006-01-02 15:04:05")
				}
				result.ESFirstSeen = record.Time.Format("2006-01-02 15:04:05")
			}
			result.ESSensors = topN(sensors, 10)
			if total > 0 {
				result.Known = true
			}
		}
	}
	return result
}

// hashQuery matches either hash field the geoip-honeypot pipeline populates
// -- cowrie's genuine SHA-256 (file.hash.sha256) or Dionaea's MD5 (#354's
// file.hash.md5) -- for every identifier a caller has for this payload.
func hashQuery(hashes ...string) string {
	clauses := make([]string, 0, len(hashes)*2)
	for _, h := range hashes {
		clauses = append(clauses, fmt.Sprintf(`file.hash.sha256:"%s"`, h), fmt.Sprintf(`file.hash.md5:"%s"`, h))
	}
	return strings.Join(clauses, " OR ")
}
