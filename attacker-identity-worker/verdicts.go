package main

// verdicts.go -- #1200's "joined against payload/analysis verdicts" half:
// for each entity's payload hash set, look up ghidra-analysis-v1 (already
// a flat, worker-written index per #1204's own gap analysis) and attach
// any malware-family guess found.
//
// Scope: ghidra-analysis-v1 only. sandbox-analysis-v1 and
// github-analysis-v1 aren't keyed by hash in their document ID (sandbox's
// is "sandbox:<job-id>", confirmed live), so joining against them needs a
// search query per hash rather than a direct docGet -- more expensive per
// entity, and github-analysis-v1 has zero documents in this deployment
// today, so there's nothing to verify that join against yet. Both are
// explicit follow-ups, not attempted here. revdeck-analysis-v1 similarly
// skipped: the one live document sampled during this worker's development
// was itself an error record ("REVDECK_API_BASE is not configured"), not
// real analysis data, on this deployment.

import "encoding/json"

const ghidraAnalysisIndex = "ghidra-analysis-v1"

// ghidraVerdict pulls out only the field this worker surfaces --
// ghidra.ai_triage.family_guess -- from a much larger document (behaviors,
// evidence_shown, etc., see dashboard/ghidra.go for the full shape this
// worker deliberately doesn't need to know about).
func ghidraVerdict(es *esClient, sha256 string) (familyGuess string, found bool) {
	source, found, err := es.docGet(ghidraAnalysisIndex, "ghidra:"+sha256)
	if err != nil || !found {
		return "", false
	}
	var v struct {
		Ghidra struct {
			AITriage struct {
				FamilyGuess string `json:"family_guess"`
			} `json:"ai_triage"`
		} `json:"ghidra"`
	}
	if json.Unmarshal(source, &v) != nil {
		return "", false
	}
	if v.Ghidra.AITriage.FamilyGuess == "" {
		return "", false
	}
	return v.Ghidra.AITriage.FamilyGuess, true
}

// attachVerdicts looks up every payload hash on e and records any
// non-empty family guess found, deduplicated and sorted for stable output.
func attachVerdicts(es *esClient, e *entity) {
	seen := map[string]bool{}
	var verdicts []string
	for _, hash := range e.Payloads {
		if family, ok := ghidraVerdict(es, hash); ok {
			label := hash[:min(12, len(hash))] + ": " + family
			if !seen[label] {
				seen[label] = true
				verdicts = append(verdicts, label)
			}
		}
	}
	e.Verdicts = verdicts
}
