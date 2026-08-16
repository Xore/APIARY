package main

import "strings"

// promoteAttckTechniqueFields (#1260) writes canonical_attck_techniques, a
// keyword array of MITRE ATT&CK technique IDs, after promoteCanonicalFields
// (canonical.go) has already set canonical_command/canonical_user/
// canonical_pass/canonical_fingerprint/canonical_shasum for this event --
// ported from dashboard/kill_chain.go's techniquesForEvent, but only the
// subset genuinely derivable from fields this worker already promotes.
//
// NOT ported here, deliberately: techniquesForEvent's T1190 (needs a
// request path + alert, neither promoted by any persona in this worker)
// and its two ICS techniques T0886/T1692.001 (need Sensor/Proto/Asset/
// Alert/Detail for conpot/modbus/s7/iec104/dnp3/enip traffic -- conpot is
// watched here for IP resolution only; canonical.go's own doc comment
// already states classify.go sets none of these fields for it. Suricata,
// the actual IDS-alert source, isn't watched by this worker at all -- it
// ships to its own suricata-v2-* index family, see dashboard/
// es_aggregate.go's own comment on that split). Porting those two would
// mean either widening this worker's scope to sensors/fields it
// deliberately doesn't touch, or a second, approximate implementation
// silently drifting from techniquesForEvent -- left to the dashboard's own
// heuristic for those, not attempted here. See #1260.
//
// Also narrower than techniquesForEvent for T1110: that check is
// `e.IsLogin || e.HasCredential`, which also fires on an EMPTY-credential
// login attempt (IsLogin alone). This worker has no persona-agnostic way
// to know "this event IS a login event" without per-persona eventid
// checks canonical.go doesn't do either -- so this only fires when a
// non-empty credential pair was actually promoted, matching setCreds'
// own validCredentialPair gate. A real, if narrow, gap versus the
// dashboard's own heuristic.
//
// Must run after promoteCanonicalFields, not instead of it -- reads its
// output rather than re-deriving anything from raw per-sensor fields, so
// this one function is sensor-agnostic instead of needing its own persona
// switch.
func promoteAttckTechniqueFields(e map[string]any) bool {
	var ids []string

	hasCreds := str(e["canonical_user"]) != "" || str(e["canonical_pass"]) != ""
	if hasCreds {
		ids = append(ids, "T1110")
	}

	command := str(e["canonical_command"])
	if command != "" {
		ids = append(ids, attckCommandTechnique(command))
	}

	lowerCommand := strings.ToLower(command)
	if str(e["canonical_shasum"]) != "" || strings.Contains(lowerCommand, "wget") || strings.Contains(lowerCommand, "curl") ||
		strings.Contains(lowerCommand, "invoke-webrequest") || strings.Contains(lowerCommand, "downloadstring") {
		ids = append(ids, "T1105")
	}

	if str(e["canonical_fingerprint"]) != "" && command == "" && !hasCreds {
		ids = append(ids, "T1595")
	}

	if len(ids) == 0 {
		return false
	}
	e["canonical_attck_techniques"] = uniqueAttckIDs(ids)
	return true
}

// attckCommandTechnique mirrors techniquesForEvent's own command
// sub-classification exactly (dashboard/kill_chain.go).
func attckCommandTechnique(command string) string {
	text := strings.ToLower(command)
	switch {
	case strings.Contains(text, "powershell") || strings.Contains(text, "pwsh"):
		return "T1059.001"
	case strings.Contains(text, "cmd.exe") || strings.Contains(text, "cmd /c"):
		return "T1059.003"
	case strings.Contains(text, "/bin/sh") || strings.Contains(text, "bash") || strings.Contains(text, "wget") || strings.Contains(text, "curl"):
		return "T1059.004"
	default:
		return "T1059"
	}
}

func uniqueAttckIDs(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
