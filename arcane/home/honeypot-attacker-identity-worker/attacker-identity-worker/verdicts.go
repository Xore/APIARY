package main

// verdicts.go -- #1200's "joined against payload/analysis verdicts" half:
// for each entity's payload hash set, look up every analysis index that
// might have a verdict for that hash and attach whatever it found.
//
// ghidra-analysis-v1 and revdeck-analysis-v1 are both keyed by a direct
// "<label>:<sha256>" document ID (confirmed live for revdeck-analysis-v1,
// 2026-08-12 -- its one live document on this deployment is
// "revdeck:25b7e641...", matching ghidra's own "ghidra:<sha256>"
// convention exactly), so both use a cheap docGet. github-analysis-v1
// uses the same "<label>:<sample-id>" scheme (analysis/es-results-
// importer/importer.py's own doc_id() -- sample-id is the sha256 in the
// common case, its own fallback logic assumes as much), but this
// deployment has zero documents in that index today (#1220's own finding,
// reconfirmed live) so the join can't be verified against real data yet;
// ported directly from the writer's own indexing convention rather than
// left undone.
//
// sandbox-analysis-v1 is different: its document ID is "sandbox:<job-id>",
// not hash-keyed (confirmed live), so it needs a search query per hash
// (term match on sandbox.sha256) rather than a direct docGet -- more
// expensive per entity, same reason ghidra's own dashboard reader
// (dashboard/elastic.go's searchNamespaceByHash) already treats sandbox
// as the one namespace that can't use its generic by-hash search either.

import "encoding/json"

const (
	ghidraAnalysisIndex  = "ghidra-analysis-v1"
	sandboxAnalysisIndex = "sandbox-analysis-v1"
	githubAnalysisIndex  = "github-analysis-v1"
	revdeckAnalysisIndex = "revdeck-analysis-v1"
)

// sandboxRiskWorthReporting mirrors sandbox/export-result.py's own
// risk_level thresholds (critical >=75, high >=50, medium >=25, else low/
// unrated) -- only medium-and-up is worth surfacing as an entity verdict;
// "low"/"unrated" is the common case for benign traffic and would just be
// noise in the badge list (see attackers.html), the same signal-only
// posture ghidraVerdict already has by only ever attaching a non-empty
// family guess.
func sandboxRiskWorthReporting(level string) bool {
	switch level {
	case "medium", "high", "critical":
		return true
	default:
		return false
	}
}

// ghidraVerdict pulls out only the field this worker surfaces --
// ghidra.ai_triage.family_guess -- from a much larger document (behaviors,
// evidence_shown, etc., see dashboard/ghidra.go for the full shape this
// worker deliberately doesn't need to know about).
func ghidraVerdict(es *esClient, sha256 string) (label string, found bool) {
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
	if json.Unmarshal(source, &v) != nil || v.Ghidra.AITriage.FamilyGuess == "" {
		return "", false
	}
	return v.Ghidra.AITriage.FamilyGuess, true
}

// sandboxVerdict term-searches sandbox-analysis-v1 on sandbox.sha256 (its
// document ID isn't hash-keyed, see this file's header) and surfaces the
// highest risk_level found across every run of this hash, when it clears
// sandboxRiskWorthReporting.
func sandboxVerdict(es *esClient, sha256 string) (label string, found bool) {
	body, err := json.Marshal(map[string]any{
		"size":  5,
		"query": map[string]any{"term": map[string]any{"sandbox.sha256": sha256}},
	})
	if err != nil {
		return "", false
	}
	b, err := es.searchBody("/"+sandboxAnalysisIndex+"/_search", body)
	if err != nil {
		return "", false
	}
	var v struct {
		Hits struct {
			Hits []struct {
				Source struct {
					Sandbox struct {
						RiskLevel string `json:"risk_level"`
					} `json:"sandbox"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if json.Unmarshal(b, &v) != nil {
		return "", false
	}
	rank := map[string]int{"medium": 1, "high": 2, "critical": 3}
	best := ""
	for _, hit := range v.Hits.Hits {
		level := hit.Source.Sandbox.RiskLevel
		if !sandboxRiskWorthReporting(level) {
			continue
		}
		if best == "" || rank[level] > rank[best] {
			best = level
		}
	}
	if best == "" {
		return "", false
	}
	return "sandbox: " + best + " risk", true
}

// githubVerdict mirrors ghidraVerdict's direct docGet, against
// github-analysis-v1's own family field (dashboard/github_analysis.go's
// githubAnalysisResult.Family -- the same "malware family guess" concept
// ghidra's own ai_triage.family_guess is, just from GitHub's scanner
// consensus instead of Ghidra's own AI triage).
func githubVerdict(es *esClient, sha256 string) (label string, found bool) {
	source, found, err := es.docGet(githubAnalysisIndex, "github_analysis:"+sha256)
	if err != nil || !found {
		return "", false
	}
	var v struct {
		GithubAnalysis struct {
			Family string `json:"family"`
		} `json:"github_analysis"`
	}
	if json.Unmarshal(source, &v) != nil || v.GithubAnalysis.Family == "" {
		return "", false
	}
	return v.GithubAnalysis.Family, true
}

// revdeckAnswerLimit truncates RevDeck's free-text Answer field to a
// length that still reads as a badge (attackers.html renders every
// verdict inside a `.badge`, not a paragraph) rather than the multi-
// sentence answer RevDeck's own agentic workflow can produce.
const revdeckAnswerLimit = 80

// revdeckVerdict mirrors ghidraVerdict's direct docGet. Unlike ghidra/
// github-analysis, RevDeck is a Q&A-style agentic reverse-engineering
// tool (dashboard/ghidra.go's ghidraRevDeck: Workflow/Status/Answer/
// ToolCalls/Citations), not a classifier -- it has no single "family"
// field, so this surfaces its own free-text Answer (truncated) once the
// workflow reports Status "completed", the closest equivalent to a
// verdict this shape has. Unverified against a real completed RevDeck
// document (the one live document on this deployment during #1220's own
// development was itself an error record, see this file's header) --
// ported from dashboard/ghidra.go's own struct definition, not observed
// live; worth re-checking once a real completed run exists.
func revdeckVerdict(es *esClient, sha256 string) (label string, found bool) {
	source, found, err := es.docGet(revdeckAnalysisIndex, "revdeck:"+sha256)
	if err != nil || !found {
		return "", false
	}
	var v struct {
		Revdeck struct {
			Revdeck struct {
				Status string `json:"status"`
				Answer string `json:"answer"`
			} `json:"revdeck"`
		} `json:"revdeck"`
	}
	if json.Unmarshal(source, &v) != nil {
		return "", false
	}
	answer := v.Revdeck.Revdeck.Answer
	if v.Revdeck.Revdeck.Status != "completed" || answer == "" {
		return "", false
	}
	if len(answer) > revdeckAnswerLimit {
		answer = answer[:revdeckAnswerLimit] + "…"
	}
	return "revdeck: " + answer, true
}

// attachVerdicts looks up every payload hash on e against every analysis
// index above and records any non-empty verdict found, deduplicated and
// sorted for stable output.
func attachVerdicts(es *esClient, e *entity) {
	seen := map[string]bool{}
	var verdicts []string
	add := func(label string) {
		if !seen[label] {
			seen[label] = true
			verdicts = append(verdicts, label)
		}
	}
	for _, hash := range e.Payloads {
		short := hash[:min(12, len(hash))]
		if family, ok := ghidraVerdict(es, hash); ok {
			add(short + ": " + family)
		}
		if verdict, ok := sandboxVerdict(es, hash); ok {
			add(short + ": " + verdict)
		}
		if family, ok := githubVerdict(es, hash); ok {
			add(short + ": " + family)
		}
		if verdict, ok := revdeckVerdict(es, hash); ok {
			add(short + ": " + verdict)
		}
	}
	e.Verdicts = verdicts
}
