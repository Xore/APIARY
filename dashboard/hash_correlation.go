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
}

// correlateHash answers #354's "is this hash known" question by checking
// every source that can confirm it independently. hash is validated before
// any lookup -- a malformed value must never reach an Elasticsearch query
// string or a case-insensitive scan of untrusted-shaped input.
func (s *store) correlateHash(hash string) hashCorrelation {
	hash = strings.ToLower(strings.TrimSpace(hash))
	if !hashName.MatchString(hash) {
		return hashCorrelation{}
	}
	result := hashCorrelation{}
	for _, r := range loadGhidraResults() {
		if strings.EqualFold(r.SHA256, hash) {
			row := r
			result.Ghidra = &row
			result.Known = true
			break
		}
	}
	for _, r := range loadSandboxResults() {
		if strings.EqualFold(r.SHA256, hash) {
			result.Sandbox = append(result.Sandbox, r)
			result.Known = true
		}
	}
	for _, r := range loadGitHubAnalysisResults() {
		if strings.EqualFold(r.SHA256, hash) {
			row := r
			result.GitHub = &row
			result.Known = true
			break
		}
	}
	if s.es != nil {
		if records, total, err := s.es.correlate(hashQuery(hash), 200); err == nil {
			result.ESAvailable = true
			result.ESSightings = total
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
// -- cowrie's genuine SHA-256 (file.hash.sha256) or dionaea's MD5 (#354's
// file.hash.md5) -- since a caller here only has "the identity hash this
// payload is addressed by locally", not which algorithm produced it.
func hashQuery(hash string) string {
	return fmt.Sprintf(`file.hash.sha256:"%s" OR file.hash.md5:"%s"`, hash, hash)
}
