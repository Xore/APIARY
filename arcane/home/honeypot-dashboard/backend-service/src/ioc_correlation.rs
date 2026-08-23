//! Floss / Windows-sandbox IOC correlation, ported from the Go dashboard's
//! `ioc_correlation.go` (#680, restored by #1735).
//!
//! Cross-references a sample's floss-decoded strings against the same
//! sample's sandbox run(s), keyed by SHA-256. A sample analysed by both
//! pipelines has two independent views of its indicators with nothing
//! joining them: floss can decode a string the binary never stores in the
//! clear, and the sandbox can observe a connection the binary never spells
//! out. Agreement between them is a materially stronger signal than either
//! alone, which is the whole point of the card this feeds.
//!
//! Computed on read rather than stored, matching the Go tier: both inputs
//! already live in Elasticsearch, either side can gain a new result
//! independently (a sample can be re-detonated long after its Ghidra run),
//! and a stored correlation would go stale silently. There is no migration
//! and existing analyses light up immediately.
//!
//! The patterns are a direct port of the Go file's, which were themselves a
//! port of `sandbox/windows/orchestrate/extract_iocs.py`'s RE_IP/RE_URL/
//! RE_DOMAIN/RE_UNC/PRIVATE — kept identical so a floss-decoded string and a
//! sandbox static string spelling the same indicator are recognised as one
//! value rather than two near-misses. Rust's `regex` crate is RE2-family
//! like Go's, so `\b` and the character classes behave the same; the one
//! difference is that `regex` rejects backreferences and lookaround, and
//! none of these patterns use them.
//!
//! Three buckets per indicator kind:
//!   - `floss_only`: floss decoded it and no sandbox run saw it, statically
//!     or at runtime. Visible only because floss emulates the decoding — a
//!     plain printable-strings scan cannot reach it.
//!   - `sandbox_static_only`: the sandbox's own binary scan found it and
//!     floss never surfaced it.
//!   - `confirmed_at_runtime`: floss decoded it *and* a sandbox run actually
//!     observed it happening. The strongest signal this correlation
//!     produces.
use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::AppState;

static RE_IP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("static ip pattern"));
static RE_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"https?://[^\s'"<>)\]]+"#).expect("static url pattern"));
static RE_DOMAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b").expect("static domain pattern"));
static RE_UNC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\\\\[a-zA-Z0-9_.-]+\\[^\s\\"'<>|*?]+(?:\\[^\s\\"'<>|*?]+)*"#).expect("static unc pattern")
});
static RE_PRIVATE_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255)").expect("static private pattern")
});

/// One indicator kind's three-way split. `confirmed_at_runtime` is always
/// empty for UNC paths: the sandbox's dynamic parsers (Sysmon / PowerShell /
/// FakeNet-NG) have no SMB observation path, only its static binary scan
/// does — so a UNC path can never be "confirmed at runtime" here, and an
/// empty bucket there means "not observable", not "not observed".
#[derive(Serialize, Default, Debug, PartialEq)]
pub struct IocKindCorrelation {
    pub floss_only: Vec<String>,
    pub sandbox_static_only: Vec<String>,
    pub confirmed_at_runtime: Vec<String>,
}

impl IocKindCorrelation {
    pub fn is_empty(&self) -> bool {
        self.floss_only.is_empty() && self.sandbox_static_only.is_empty() && self.confirmed_at_runtime.is_empty()
    }
}

/// The card's whole state. The two booleans are what let the frontend tell
/// three different "nothing here" situations apart, which is most of the
/// card's diagnostic value:
///   - no sandbox run for this sample at all -> nothing to correlate against
///   - a run exists but floss produced nothing usable (declined the sample,
///     or the sidecar was unavailable)
///   - both sides have data but share no indicator
#[derive(Serialize, Default, Debug)]
pub struct IocCorrelation {
    pub has_sandbox_run: bool,
    pub has_floss_data: bool,
    /// True when both sides had data but share no indicator at all — the
    /// third of the card's three distinct "nothing to show" states, and the
    /// one the other two flags cannot express. Sent rather than recomputed
    /// in the frontend, which would mean checking twelve arrays to answer a
    /// question this side already knows (the Go template's `.Empty`).
    pub is_empty: bool,
    pub ips: IocKindCorrelation,
    pub domains: IocKindCorrelation,
    pub urls: IocKindCorrelation,
    pub unc_paths: IocKindCorrelation,
}

/// Indicators found in a set of strings. Private and loopback addresses are
/// dropped: a sample referencing 127.0.0.1 or 192.168.x.x says nothing about
/// where it calls home, and leaving them in buries the real indicators.
fn extract_ioc_patterns(strings: &[String]) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let (mut ips, mut domains, mut urls, mut uncs) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for text in strings {
        for m in RE_IP.find_iter(text) {
            if !RE_PRIVATE_IP.is_match(m.as_str()) {
                ips.insert(m.as_str().to_string());
            }
        }
        for m in RE_URL.find_iter(text) {
            urls.insert(m.as_str().to_string());
        }
        for m in RE_DOMAIN.find_iter(text) {
            domains.insert(m.as_str().to_string());
        }
        for m in RE_UNC.find_iter(text) {
            uncs.insert(m.as_str().to_string());
        }
    }
    (ips, domains, urls, uncs)
}

/// The three-way split for one indicator kind. Order matters: a value the
/// sandbox observed at runtime is reported as confirmed even if its static
/// scan also found it — runtime observation is the stronger claim and must
/// not be masked by the weaker one.
fn correlate_set(floss: &BTreeSet<String>, sandbox_static: &BTreeSet<String>, sandbox_dynamic: &BTreeSet<String>) -> IocKindCorrelation {
    let mut out = IocKindCorrelation::default();
    for value in floss {
        if sandbox_dynamic.contains(value) {
            out.confirmed_at_runtime.push(value.clone());
        } else if !sandbox_static.contains(value) {
            out.floss_only.push(value.clone());
        }
    }
    for value in sandbox_static {
        if !floss.contains(value) {
            out.sandbox_static_only.push(value.clone());
        }
    }
    // BTreeSet iteration is already sorted, so the vectors come out sorted.
    out
}

/// Every string in a `_source` array field, skipping non-strings rather than
/// failing — these documents are worker output and a malformed entry should
/// cost one value, not the whole card.
fn string_list(node: &Value) -> Vec<String> {
    node.as_array()
        .map(|values| values.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

fn insert_strings(set: &mut BTreeSet<String>, node: &Value) {
    for value in string_list(node) {
        set.insert(value);
    }
}

/// Correlate one Ghidra document against every sandbox run for the same
/// sample. `ghidra_source` is the `_source` the detail endpoint already
/// fetched, so this costs exactly one extra Elasticsearch query per page
/// view rather than re-reading the Ghidra document.
pub async fn correlate(state: &AppState, sha256: &str, ghidra_source: &Value) -> IocCorrelation {
    // A sample can be detonated more than once; the Go tier unioned every
    // run's indicators, so a value observed in any run counts as observed.
    let runs = state
        .es
        .search_index(
            &["sandbox-analysis-v1"],
            serde_json::json!({
                "size": 50,
                "query": {"bool": {"should": [
                    {"term": {"file.hash.sha256": sha256}},
                    {"term": {"sandbox.sha256": sha256}}
                ], "minimum_should_match": 1}}
            }),
        )
        .await;

    let Ok(runs) = runs else { return IocCorrelation::default() };
    let hits = runs["hits"]["hits"].as_array().cloned().unwrap_or_default();
    if hits.is_empty() {
        // No run at all — distinct from "a run exists but shares nothing".
        return IocCorrelation::default();
    }

    let mut out = IocCorrelation { has_sandbox_run: true, ..Default::default() };

    // floss declining the sample (`unsupported`) is not the same as floss
    // having run and found nothing, and neither is the sidecar being
    // unavailable. All three land here as "no floss data" and the frontend
    // says so rather than implying the two sets disagreed.
    let floss = &ghidra_source["ghidra"]["floss"];
    let unsupported = floss["unsupported"].as_str().unwrap_or("");
    if floss.is_null() || !unsupported.is_empty() {
        return out;
    }
    out.has_floss_data = true;

    let mut all_strings = Vec::new();
    for key in ["decoded_strings", "static_strings", "stack_strings", "tight_strings"] {
        all_strings.extend(string_list(&floss[key]));
    }
    let (floss_ips, floss_domains, floss_urls, floss_uncs) = extract_ioc_patterns(&all_strings);

    let (mut static_ips, mut static_domains, mut static_urls, mut static_uncs) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    let (mut dynamic_ips, mut dynamic_domains, mut dynamic_urls) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());

    for hit in &hits {
        // es_importer wraps the exporter payload under "sandbox"; a few
        // older documents carry it flat. Read whichever is present rather
        // than silently correlating against nothing.
        let source = &hit["_source"];
        let run = if source["sandbox"].is_object() { &source["sandbox"] } else { source };
        let iocs = &run["iocs"];
        insert_strings(&mut static_ips, &iocs["static_remote_ips"]);
        insert_strings(&mut static_domains, &iocs["static_dns_domains"]);
        insert_strings(&mut static_urls, &iocs["static_download_urls"]);
        insert_strings(&mut static_uncs, &iocs["static_unc_paths"]);
        insert_strings(&mut dynamic_ips, &run["network_summary"]["remote_ips"]);
        insert_strings(&mut dynamic_domains, &run["network_summary"]["dns_queries"]);
        insert_strings(&mut dynamic_urls, &iocs["download_urls"]);
    }

    let empty = BTreeSet::new();
    out.ips = correlate_set(&floss_ips, &static_ips, &dynamic_ips);
    out.domains = correlate_set(&floss_domains, &static_domains, &dynamic_domains);
    out.urls = correlate_set(&floss_urls, &static_urls, &dynamic_urls);
    // No dynamic set for UNC paths — see IocKindCorrelation's doc comment.
    out.unc_paths = correlate_set(&floss_uncs, &static_uncs, &empty);
    out.is_empty = out.ips.is_empty() && out.domains.is_empty() && out.urls.is_empty() && out.unc_paths.is_empty();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn extracts_each_indicator_kind() {
        let strings = vec![
            "connect to 203.0.113.7 now".to_string(),
            "fetch https://evil.example.com/payload.bin".to_string(),
            r"copy \\fileserver\share\tool.exe".to_string(),
        ];
        let (ips, domains, urls, uncs) = extract_ioc_patterns(&strings);
        assert!(ips.contains("203.0.113.7"));
        assert!(urls.contains("https://evil.example.com/payload.bin"));
        assert!(domains.contains("evil.example.com"));
        assert!(uncs.contains(r"\\fileserver\share\tool.exe"));
    }

    #[test]
    fn drops_private_and_loopback_addresses() {
        let strings = vec!["10.0.0.5 192.168.1.1 172.16.4.4 127.0.0.1 8.8.8.8".to_string()];
        let (ips, ..) = extract_ioc_patterns(&strings);
        assert_eq!(ips, set(&["8.8.8.8"]));
    }

    #[test]
    fn runtime_observation_outranks_a_static_match() {
        // Present in floss, the sandbox's static scan AND its runtime
        // observation: must report as confirmed, not as static-only.
        let out = correlate_set(&set(&["1.2.3.4"]), &set(&["1.2.3.4"]), &set(&["1.2.3.4"]));
        assert_eq!(out.confirmed_at_runtime, vec!["1.2.3.4".to_string()]);
        assert!(out.floss_only.is_empty());
        assert!(out.sandbox_static_only.is_empty());
    }

    #[test]
    fn splits_the_three_buckets() {
        let out = correlate_set(
            &set(&["a.example", "b.example", "c.example"]),
            &set(&["b.example", "d.example"]),
            &set(&["c.example"]),
        );
        // a: floss only. b: both static, so neither floss-only nor
        // static-only. c: confirmed. d: sandbox static only.
        assert_eq!(out.floss_only, vec!["a.example".to_string()]);
        assert_eq!(out.confirmed_at_runtime, vec!["c.example".to_string()]);
        assert_eq!(out.sandbox_static_only, vec!["d.example".to_string()]);
    }

    #[test]
    fn empty_everywhere_is_empty() {
        let out = correlate_set(&set(&[]), &set(&[]), &set(&[]));
        assert!(out.is_empty());
    }

    #[test]
    fn default_reports_no_run_and_no_floss() {
        // What the frontend sees when there is no sandbox run at all: the
        // two flags are what separate that from "a run exists but shares
        // nothing", so they must not both default to something ambiguous.
        let out = IocCorrelation::default();
        assert!(!out.has_sandbox_run);
        assert!(!out.has_floss_data);
    }
}
