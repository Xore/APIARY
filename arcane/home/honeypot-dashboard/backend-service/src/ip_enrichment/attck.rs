//! Ported from ip-enrichment-worker/attck.go: writes canonical_attck_techniques
//! after canonical-field promotion has already set canonical_command/
//! canonical_user/canonical_pass/canonical_fingerprint/canonical_shasum for
//! this event — the subset of dashboard/kill_chain.go's techniquesForEvent
//! genuinely derivable from fields this worker already promotes. NOT
//! ported: T1190 (needs a request path + alert, neither promoted here) and
//! the two ICS techniques T0886/T1692.001 (need fields no persona here
//! promotes) — left to the dashboard's own heuristic for those.

use serde_json::Value;

fn str(e: &Value, key: &str) -> String {
    e.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Must run after canonical-field promotion — reads its output rather than
/// re-deriving anything from raw per-sensor fields.
pub fn promote_attck_technique_fields(e: &mut Value) -> bool {
    let mut ids: Vec<String> = Vec::new();

    let user = str(e, "canonical_user");
    let pass = str(e, "canonical_pass");
    let has_creds = !user.is_empty() || !pass.is_empty();
    if has_creds {
        ids.push("T1110".to_string());
    }

    let command = str(e, "canonical_command");
    if !command.is_empty() {
        ids.push(attck_command_technique(&command).to_string());
    }

    let lower_command = command.to_lowercase();
    let shasum = str(e, "canonical_shasum");
    if !shasum.is_empty()
        || lower_command.contains("wget")
        || lower_command.contains("curl")
        || lower_command.contains("invoke-webrequest")
        || lower_command.contains("downloadstring")
    {
        ids.push("T1105".to_string());
    }

    let fingerprint = str(e, "canonical_fingerprint");
    if !fingerprint.is_empty() && command.is_empty() && !has_creds {
        ids.push("T1595".to_string());
    }

    if ids.is_empty() {
        return false;
    }
    e["canonical_attck_techniques"] = Value::from(unique_attck_ids(ids));
    true
}

/// Mirrors techniquesForEvent's own command sub-classification exactly.
fn attck_command_technique(command: &str) -> &'static str {
    let text = command.to_lowercase();
    if text.contains("powershell") || text.contains("pwsh") {
        "T1059.001"
    } else if text.contains("cmd.exe") || text.contains("cmd /c") {
        "T1059.003"
    } else if text.contains("/bin/sh") || text.contains("bash") || text.contains("wget") || text.contains("curl") {
        "T1059.004"
    } else {
        "T1059"
    }
}

fn unique_attck_ids(ids: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    ids.into_iter().filter(|id| seen.insert(id.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn credentials_promote_t1110() {
        let mut e = json!({"canonical_user": "root", "canonical_pass": "toor"});
        assert!(promote_attck_technique_fields(&mut e));
        assert_eq!(e["canonical_attck_techniques"], json!(["T1110"]));
    }

    #[test]
    fn powershell_command_promotes_t1059_001_and_t1105_via_downloadstring() {
        let mut e = json!({"canonical_command": "powershell -c IEX (New-Object Net.WebClient).DownloadString(...)"});
        assert!(promote_attck_technique_fields(&mut e));
        let ids = e["canonical_attck_techniques"].as_array().unwrap();
        assert!(ids.iter().any(|v| v == "T1059.001"));
        assert!(ids.iter().any(|v| v == "T1105"));
    }

    #[test]
    fn bare_fingerprint_with_no_command_or_creds_promotes_t1595() {
        let mut e = json!({"canonical_fingerprint": "aa:bb"});
        assert!(promote_attck_technique_fields(&mut e));
        assert_eq!(e["canonical_attck_techniques"], json!(["T1595"]));
    }

    #[test]
    fn nothing_promoted_is_not_a_change() {
        let mut e = json!({});
        assert!(!promote_attck_technique_fields(&mut e));
    }
}
