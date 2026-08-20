//! attacker-identity-worker port (#1610 worker migration): the missing
//! piece #1204's gap analysis called out -- campaigns/clusters
//! (correlator-worker) are CIDR/fingerprint-bucket scoped and recomputed
//! from scratch every cycle; neither produces a durable attacker *entity*.
//! This does: it merges IPs into persistent `attackers-v1` entities when
//! they share >=2 of three strong signal categories (fingerprint, payload
//! sha256, credential pair) -- a single shared signal never merges two IPs
//! alone (the epic's own "decided up front" tunable). Entities are durable:
//! once created they're never deleted for going quiet, and membership only
//! grows -- the one exception is two previously-separate entities turning
//! out to share a member, which folds one into the other.
//!
//! Ported from honeypot-attacker-identity-worker/attacker-identity-worker/
//! (main.go/fetch.go/identity.go/verdicts.go/es.go). Pure ES, no host
//! mounts, no local state -- runs as the `attacker-identity` WORKER_LOOPS
//! entry on the existing (stateless-by-design) backend-worker service.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crate::AppState;

const ATTACKERS_INDEX: &str = "attackers-v1";
const MAX_EXISTING_LOAD: u32 = 20_000;
const TUNNEL_PEER_IP: &str = "10.8.0.1";
const MERGE_THRESHOLD: usize = 2;
const EVENT_PAGE_SIZE: u64 = 10_000;
const EVENT_MAX_PAGES: u32 = 50;

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn env_duration(name: &str, default: Duration) -> Duration {
    let raw = std::env::var(name).unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return default;
    }
    let (digits, unit) = raw.split_at(raw.len().saturating_sub(1));
    match (digits.parse::<u64>(), unit) {
        (Ok(n), "h") => Duration::from_secs(n * 3600),
        (Ok(n), "m") => Duration::from_secs(n * 60),
        (Ok(n), "s") => Duration::from_secs(n),
        _ => default,
    }
}

// --------------------------------------------------------------------
// fetch.go
// --------------------------------------------------------------------

struct CorrEvent {
    when: Option<chrono::DateTime<chrono::Utc>>,
    src_ip: String,
    sensor: String,
    user: String,
    pass: String,
    shasum: String,
    fingerprint: String,
    techniques: Vec<String>,
}

/// Ported verbatim from dashboard/links.go via fetch.go's own copy -- gates
/// which canonical_user/canonical_pass pairs count as a real credential
/// signal for entity merging.
fn valid_credential_pair(user: &str, pass: &str) -> bool {
    if (user.is_empty() && pass.is_empty()) || user.len() > 128 || pass.len() > 512 {
        return false;
    }
    for value in [user, pass] {
        let lower = value.to_lowercase();
        if value.contains(['\0', '\r', '\n']) || lower.contains("\\x00") || lower.contains("\\u0000") {
            return false;
        }
    }
    if user.contains([' ', '\t', '/', ';', '|', '&', '<', '>']) {
        return false;
    }
    let lower_pass = pass.trim().to_lowercase();
    for marker in ["/bin/", "busybox", "linuxshell", "powershell", "cmd.exe"] {
        if lower_pass.contains(marker) {
            return false;
        }
    }
    true
}

async fn fetch_recent_events(
    state: &AppState,
    since: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<Vec<CorrEvent>> {
    let since_str = since.to_rfc3339();
    let hits = state
        .es
        .search_paginated(
            "honeypot-v2-*",
            |search_after| {
                let mut body = json!({
                    "sort": [{"@timestamp": "asc"}, {"_shard_doc": "asc"}],
                    "query": {"bool": {"filter": [
                        {"range": {"@timestamp": {"gte": since_str}}},
                        {"exists": {"field": "source.ip"}}
                    ]}},
                    "_source": [
                        "@timestamp", "source.ip", "event.sensor",
                        "honeypot.canonical_user", "honeypot.canonical_pass", "honeypot.canonical_shasum",
                        "honeypot.canonical_fingerprint", "honeypot.canonical_attck_techniques"
                    ]
                });
                if let Some(sa) = search_after {
                    body["search_after"] = sa.clone();
                }
                body
            },
            EVENT_PAGE_SIZE,
            EVENT_MAX_PAGES,
        )
        .await?;

    let mut out = Vec::with_capacity(hits.len());
    for hit in hits {
        let src = &hit["_source"];
        let ip = src["source"]["ip"].as_str().unwrap_or("").to_string();
        if ip.is_empty() || ip == TUNNEL_PEER_IP {
            continue;
        }
        let when = src["@timestamp"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        let techniques = src["honeypot"]["canonical_attck_techniques"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        out.push(CorrEvent {
            when,
            src_ip: ip,
            sensor: src["event"]["sensor"].as_str().unwrap_or("").to_string(),
            user: src["honeypot"]["canonical_user"].as_str().unwrap_or("").to_string(),
            pass: src["honeypot"]["canonical_pass"].as_str().unwrap_or("").to_string(),
            shasum: src["honeypot"]["canonical_shasum"].as_str().unwrap_or("").to_string(),
            fingerprint: src["honeypot"]["canonical_fingerprint"].as_str().unwrap_or("").to_string(),
            techniques,
        });
    }
    Ok(out)
}

// --------------------------------------------------------------------
// identity.go
// --------------------------------------------------------------------

#[derive(Default, Clone)]
struct SignalSet {
    fingerprints: HashSet<String>,
    payloads: HashSet<String>,
    creds: HashSet<String>,
}

impl SignalSet {
    fn merge(&mut self, other: &SignalSet) {
        self.fingerprints.extend(other.fingerprints.iter().cloned());
        self.payloads.extend(other.payloads.iter().cloned());
        self.creds.extend(other.creds.iter().cloned());
    }
}

fn intersects(a: &HashSet<String>, b: &HashSet<String>) -> bool {
    let (small, big) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    small.iter().any(|k| big.contains(k))
}

/// How many of the three signal categories (fingerprint/payload/cred) have
/// at least one value in common between a and b. >=2 is a merge; 0 or 1 is
/// not, regardless of how many individual values overlap within one
/// category.
fn shared_signal_count(a: &SignalSet, b: &SignalSet) -> usize {
    let mut n = 0;
    if intersects(&a.fingerprints, &b.fingerprints) {
        n += 1;
    }
    if intersects(&a.payloads, &b.payloads) {
        n += 1;
    }
    if intersects(&a.creds, &b.creds) {
        n += 1;
    }
    n
}

struct IpObservation {
    ip: String,
    signals: SignalSet,
    sensors: HashSet<String>,
    techniques: HashSet<String>,
    first: Option<chrono::DateTime<chrono::Utc>>,
    last: Option<chrono::DateTime<chrono::Utc>>,
    events: i64,
}

fn build_ip_observations(events: &[CorrEvent]) -> HashMap<String, IpObservation> {
    let mut out: HashMap<String, IpObservation> = HashMap::new();
    for e in events {
        let o = out.entry(e.src_ip.clone()).or_insert_with(|| IpObservation {
            ip: e.src_ip.clone(),
            signals: SignalSet::default(),
            sensors: HashSet::new(),
            techniques: HashSet::new(),
            first: None,
            last: None,
            events: 0,
        });
        o.events += 1;
        if !e.sensor.is_empty() {
            o.sensors.insert(e.sensor.clone());
        }
        for t in &e.techniques {
            if !t.is_empty() {
                o.techniques.insert(t.clone());
            }
        }
        if !e.fingerprint.is_empty() {
            o.signals.fingerprints.insert(e.fingerprint.clone());
        }
        if !e.shasum.is_empty() {
            o.signals.payloads.insert(e.shasum.clone());
        }
        if valid_credential_pair(&e.user, &e.pass) {
            o.signals.creds.insert(format!("{} / {}", e.user, e.pass));
        }
        if let Some(when) = e.when {
            if o.first.is_none_or(|f| when < f) {
                o.first = Some(when);
            }
            if o.last.is_none_or(|l| when > l) {
                o.last = Some(when);
            }
        }
    }
    out
}

/// `attackers-v1`'s own persisted document shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Entity {
    id: String,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    fingerprints: Vec<String>,
    #[serde(default)]
    payloads: Vec<String>,
    #[serde(default)]
    credentials: Vec<String>,
    #[serde(default)]
    sensors: Vec<String>,
    #[serde(default)]
    events: i64,
    #[serde(default)]
    first: String,
    #[serde(default)]
    last: String,
    #[serde(default)]
    updated: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    verdicts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    techniques: Vec<String>,
}

/// The in-memory working form `resolve_identities` merges into --
/// unexported set-based fields that `Entity`'s slice fields are flattened
/// into on load and flattened back out of on finalize, same shape as Go's
/// entity struct's own lazily-built unexported fields (entitySignals/
/// entityIPSet/entitySensorSet/entityTechniqueSet), just built eagerly here
/// instead of lazily -- Rust's ownership makes lazy memoization on a shared
/// struct awkward for no real benefit at this data size (existing entities
/// cap at 20,000).
struct Working {
    id: String,
    ip_set: HashSet<String>,
    signals: SignalSet,
    sensor_set: HashSet<String>,
    technique_set: HashSet<String>,
    events: i64,
    // Formatted RFC3339 (whole-second, "Z"-suffixed) strings, compared
    // lexicographically -- matches Go's own absorb/mergeEntityInto, which
    // compares e.First/e.Last as strings (time.RFC3339, always whole-
    // second precision) rather than re-parsing them back into time.Time.
    // Lexicographic order over this exact fixed-width format is
    // chronological order, the same trick Go relies on.
    first: String,
    last: String,
    verdicts: Vec<String>,
}

fn working_from_entity(e: &Entity) -> Working {
    Working {
        id: e.id.clone(),
        ip_set: e.ips.iter().cloned().collect(),
        signals: SignalSet {
            fingerprints: e.fingerprints.iter().cloned().collect(),
            payloads: e.payloads.iter().cloned().collect(),
            creds: e.credentials.iter().cloned().collect(),
        },
        sensor_set: e.sensors.iter().cloned().collect(),
        technique_set: e.techniques.iter().cloned().collect(),
        events: e.events,
        first: e.first.clone(),
        last: e.last.clone(),
        verdicts: e.verdicts.clone(),
    }
}

fn new_working(id: String) -> Working {
    Working {
        id,
        ip_set: HashSet::new(),
        signals: SignalSet::default(),
        sensor_set: HashSet::new(),
        technique_set: HashSet::new(),
        events: 0,
        first: String::new(),
        last: String::new(),
        verdicts: Vec::new(),
    }
}

fn fmt_rfc3339_whole_seconds(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Folds one IP observation's signals/sensors/techniques/events/time-range
/// into `e` in place.
fn absorb(e: &mut Working, o: &IpObservation) {
    e.ip_set.insert(o.ip.clone());
    e.signals.merge(&o.signals);
    e.sensor_set.extend(o.sensors.iter().cloned());
    e.technique_set.extend(o.techniques.iter().cloned());
    e.events += o.events;
    if let Some(first) = o.first {
        let first_str = fmt_rfc3339_whole_seconds(first);
        if e.first.is_empty() || first_str < e.first {
            e.first = first_str;
        }
    }
    if let Some(last) = o.last {
        let last_str = fmt_rfc3339_whole_seconds(last);
        if last_str > e.last {
            e.last = last_str;
        }
    }
}

/// Folds `b`'s members/signals into `a` in place -- `a` survives, `b` is
/// discarded by the caller (the absorbed-id list).
fn merge_entity_into(a: &mut Working, b: &Working) {
    a.ip_set.extend(b.ip_set.iter().cloned());
    a.signals.merge(&b.signals);
    a.sensor_set.extend(b.sensor_set.iter().cloned());
    a.technique_set.extend(b.technique_set.iter().cloned());
    a.events += b.events;
    if !b.first.is_empty() && (a.first.is_empty() || b.first < a.first) {
        a.first = b.first.clone();
    }
    if b.last > a.last {
        a.last = b.last.clone();
    }
}

/// KNOWN GAP (found during #1628's worker-retirement research, not yet
/// IP-derived only, deliberately not timestamp-seeded (fixed post-#1628
/// worker-retirement research — see git history for the original
/// timestamp-seeded version and the race it had). This function is only
/// ever called once per IP for the lifetime of this index: resolve_identities
/// looks the IP up in `ip_to_index` (populated from every existing entity's
/// `ip_set`, loaded fresh from attackers-v1 each cycle) before ever reaching
/// here, so a previously-seen IP — by this worker or, since both read/write
/// the same shared index, by a prior run or even a differently-seeded past
/// version of this same function — never re-derives a new id. That
/// invariant is exactly what makes a pure function of the seed IP correct
/// and actually useful: two Rust instances (concurrent replicas, or the
/// same worker racing itself across a restart) that independently mint an
/// entity for the same never-before-seen IP in the same cycle now converge
/// on the identical id, so their concurrent writes land on one document
/// instead of two — the same "safe idempotent upsert on a deterministic
/// key" property agent-intrusion-worker's campaign_id already has.
///
/// This does NOT by itself make a Go+Rust dual-write bake period safe: the
/// old Go worker's own newEntityID still seeds on a timestamp and was
/// deliberately left alone (no reason to invest further in code slated for
/// deletion) — Go and Rust computing different ids for the same
/// simultaneously-first-seen IP remains possible for as long as both are
/// writing attackers-v1 at once. The safe retirement path for this
/// specific worker is still: stop the old worker, then start this one —
/// not an extended side-by-side bake period the way agent-intrusion-worker
/// (whose campaign_id has always been a pure function of event content) can
/// safely do.
fn new_entity_id(seed_ip: &str) -> String {
    let digest = Sha256::digest(format!("attacker:{seed_ip}").as_bytes());
    to_hex(&digest[..16])
}

/// Merges this cycle's per-IP observations into `existing`, returning the
/// full set of entities that changed this cycle (new or updated -- callers
/// upsert these) and the IDs of any entity absorbed into another and
/// therefore now stale (callers delete these). Entities that didn't change
/// this cycle are neither returned nor touched -- durable identity means
/// "leave it alone until there's new evidence", not "recompute and rewrite
/// everything every cycle".
fn resolve_identities(
    existing: Vec<Entity>,
    observations: &HashMap<String, IpObservation>,
) -> (Vec<Entity>, Vec<String>) {
    let mut candidates: Vec<Working> = existing.iter().map(working_from_entity).collect();
    let mut ip_to_index: HashMap<String, usize> = HashMap::new();
    for (i, e) in candidates.iter().enumerate() {
        for ip in &e.ip_set {
            ip_to_index.insert(ip.clone(), i);
        }
    }

    // Deterministic iteration order so a run over the same input always
    // merges the same way -- HashMap iteration order is randomized, and
    // two runs (or a test) over identical data would otherwise see
    // different entity groupings.
    let mut ips: Vec<&String> = observations.keys().collect();
    ips.sort();

    let mut touched: Vec<usize> = Vec::new();
    let mut touched_set: HashSet<usize> = HashSet::new();
    let mut absorbed_indices: HashSet<usize> = HashSet::new();
    // Real ids of absorbed entities, captured at the moment of absorption
    // -- candidates[extra] is overwritten with an empty placeholder right
    // below (to satisfy the borrow checker while merging it into
    // candidates[first]), so its `.id` can never be read back out
    // afterward the way the index-only bookkeeping might suggest.
    let mut absorbed_ids: Vec<String> = Vec::new();

    for ip in ips {
        let o = &observations[ip];
        let mut target_index = ip_to_index.get(ip).copied();

        if target_index.is_none() {
            // Not yet a member of anything -- look for a candidate entity
            // (pre-existing, or created earlier this same cycle) this IP's
            // signals now qualify it to join. Qualifying for more than one
            // means those entities merge together too (they were always
            // the same actor, this observation is just the first evidence
            // that reveals it).
            let matches: Vec<usize> = candidates
                .iter()
                .enumerate()
                .filter(|(i, e)| {
                    !absorbed_indices.contains(i) && shared_signal_count(&o.signals, &e.signals) >= MERGE_THRESHOLD
                })
                .map(|(i, _)| i)
                .collect();

            if let Some((&first, rest)) = matches.split_first() {
                target_index = Some(first);
                for &extra in rest {
                    let extra_ips: Vec<String> = candidates[extra].ip_set.iter().cloned().collect();
                    let extra_working = std::mem::replace(&mut candidates[extra], new_working(String::new()));
                    absorbed_ids.push(extra_working.id.clone());
                    merge_entity_into(&mut candidates[first], &extra_working);
                    absorbed_indices.insert(extra);
                    touched_set.remove(&extra);
                    touched.retain(|&t| t != extra);
                    for eip in extra_ips {
                        ip_to_index.insert(eip, first);
                    }
                }
            } else {
                let new_id = new_entity_id(ip);
                candidates.push(new_working(new_id));
                target_index = Some(candidates.len() - 1);
            }
            ip_to_index.insert(ip.clone(), target_index.unwrap());
        }

        let idx = target_index.unwrap();
        absorb(&mut candidates[idx], o);
        if touched_set.insert(idx) {
            touched.push(idx);
        }
    }

    let mut changed: Vec<Entity> = touched
        .into_iter()
        .map(|i| finalize_entity(&candidates[i]))
        .collect();
    changed.sort_by(|a, b| a.id.cmp(&b.id));

    let _ = absorbed_indices; // only used above to gate re-matching against an already-absorbed candidate
    let mut absorbed = absorbed_ids;
    absorbed.sort();

    (changed, absorbed)
}

/// Flattens a working entity's sets back into its persisted slice fields,
/// sorted for stable JSON output.
fn finalize_entity(e: &Working) -> Entity {
    let sorted = |s: &HashSet<String>| -> Vec<String> {
        let mut v: Vec<String> = s.iter().filter(|k| !k.trim().is_empty()).cloned().collect();
        v.sort();
        v
    };
    Entity {
        id: e.id.clone(),
        ips: sorted(&e.ip_set),
        fingerprints: sorted(&e.signals.fingerprints),
        payloads: sorted(&e.signals.payloads),
        credentials: sorted(&e.signals.creds),
        sensors: sorted(&e.sensor_set),
        events: e.events,
        first: e.first.clone(),
        last: e.last.clone(),
        updated: String::new(),
        verdicts: e.verdicts.clone(),
        techniques: sorted(&e.technique_set),
    }
}

// --------------------------------------------------------------------
// verdicts.go
// --------------------------------------------------------------------

fn sandbox_risk_worth_reporting(level: &str) -> bool {
    matches!(level, "medium" | "high" | "critical")
}

async fn ghidra_verdict(state: &AppState, sha256: &str) -> Option<String> {
    let doc = state.es.get_doc("ghidra-analysis-v1", &format!("ghidra:{sha256}")).await.ok()??;
    let family = doc["ghidra"]["ai_triage"]["family_guess"].as_str()?;
    if family.is_empty() {
        return None;
    }
    Some(family.to_string())
}

async fn sandbox_verdict(state: &AppState, sha256: &str) -> Option<String> {
    let body = json!({"size": 5, "query": {"term": {"sandbox.sha256": sha256}}});
    let result = state.es.search_index(&["sandbox-analysis-v1"], body).await.ok()?;
    let rank = |level: &str| match level {
        "medium" => 1,
        "high" => 2,
        "critical" => 3,
        _ => 0,
    };
    let mut best = "";
    for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
        let level = hit["_source"]["sandbox"]["risk_level"].as_str().unwrap_or("");
        if !sandbox_risk_worth_reporting(level) {
            continue;
        }
        if best.is_empty() || rank(level) > rank(best) {
            best = level;
        }
    }
    if best.is_empty() {
        None
    } else {
        Some(format!("sandbox: {best} risk"))
    }
}

async fn github_verdict(state: &AppState, sha256: &str) -> Option<String> {
    let doc = state.es.get_doc("github-analysis-v1", &format!("github_analysis:{sha256}")).await.ok()??;
    let family = doc["github_analysis"]["family"].as_str()?;
    if family.is_empty() {
        return None;
    }
    Some(family.to_string())
}

const REVDECK_ANSWER_LIMIT: usize = 80;

async fn revdeck_verdict(state: &AppState, sha256: &str) -> Option<String> {
    let doc = state.es.get_doc("revdeck-analysis-v1", &format!("revdeck:{sha256}")).await.ok()??;
    let inner = &doc["revdeck"]["revdeck"];
    let status = inner["status"].as_str().unwrap_or("");
    let answer = inner["answer"].as_str().unwrap_or("");
    if status != "completed" || answer.is_empty() {
        return None;
    }
    let truncated: String = if answer.chars().count() > REVDECK_ANSWER_LIMIT {
        format!("{}…", answer.chars().take(REVDECK_ANSWER_LIMIT).collect::<String>())
    } else {
        answer.to_string()
    };
    Some(format!("revdeck: {truncated}"))
}

/// Looks up every payload hash on `e` against every analysis index and
/// records any non-empty verdict found, deduplicated and sorted.
async fn attach_verdicts(state: &AppState, e: &mut Entity) {
    let mut seen: HashSet<String> = HashSet::new();
    let mut verdicts: Vec<String> = Vec::new();
    let add = |label: String, seen: &mut HashSet<String>, verdicts: &mut Vec<String>| {
        if seen.insert(label.clone()) {
            verdicts.push(label);
        }
    };
    for hash in &e.payloads {
        let short = &hash[..hash.len().min(12)];
        if let Some(family) = ghidra_verdict(state, hash).await {
            add(format!("{short}: {family}"), &mut seen, &mut verdicts);
        }
        if let Some(verdict) = sandbox_verdict(state, hash).await {
            add(format!("{short}: {verdict}"), &mut seen, &mut verdicts);
        }
        if let Some(family) = github_verdict(state, hash).await {
            add(format!("{short}: {family}"), &mut seen, &mut verdicts);
        }
        if let Some(verdict) = revdeck_verdict(state, hash).await {
            add(format!("{short}: {verdict}"), &mut seen, &mut verdicts);
        }
    }
    e.verdicts = verdicts;
}

// --------------------------------------------------------------------
// main.go
// --------------------------------------------------------------------

async fn load_existing_entities(state: &AppState) -> anyhow::Result<Vec<Entity>> {
    let hits = state
        .es
        .search_paginated(
            ATTACKERS_INDEX,
            |search_after| {
                let mut body = json!({"sort": [{"_shard_doc": "asc"}], "query": {"match_all": {}}});
                if let Some(sa) = search_after {
                    body["search_after"] = sa.clone();
                }
                body
            },
            10_000,
            (MAX_EXISTING_LOAD / 10_000).max(1),
        )
        .await?;
    let mut out = Vec::with_capacity(hits.len());
    for hit in hits {
        if let Ok(e) = serde_json::from_value::<Entity>(hit["_source"].clone()) {
            out.push(e);
        }
    }
    Ok(out)
}

async fn run_cycle(state: &AppState, window: Duration) {
    let start = chrono::Utc::now();
    let since = start - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::hours(6));

    let events = match fetch_recent_events(state, since).await {
        Ok(events) => events,
        Err(error) => {
            tracing::warn!(%error, "attacker-identity: fetching recent events failed, skipping this cycle");
            return;
        }
    };
    let observations = build_ip_observations(&events);

    let existing = match load_existing_entities(state).await {
        Ok(existing) => existing,
        Err(error) => {
            tracing::warn!(%error, "attacker-identity: loading existing entities failed, skipping this cycle");
            return;
        }
    };
    let existing_count = existing.len();
    if existing_count as u32 >= MAX_EXISTING_LOAD {
        tracing::warn!(
            "attacker-identity: existing entity population hit the {MAX_EXISTING_LOAD}-doc load cap -- merge candidates beyond this cap won't be considered this cycle"
        );
    }

    let (mut changed, absorbed) = resolve_identities(existing, &observations);

    for e in &mut changed {
        e.updated = start.to_rfc3339();
        attach_verdicts(state, e).await;
        let Ok(body) = serde_json::to_value(&*e) else { continue };
        if let Err(error) = state.es.index_doc(ATTACKERS_INDEX, &e.id, body).await {
            tracing::warn!(%error, id = %e.id, "attacker-identity: index entity failed");
        }
    }
    for id in &absorbed {
        if let Err(error) = state.es.delete_doc(ATTACKERS_INDEX, id).await {
            tracing::warn!(%error, id = %id, "attacker-identity: delete absorbed entity failed");
        }
    }

    tracing::info!(
        events = events.len(),
        ips_observed = observations.len(),
        changed = changed.len(),
        absorbed = absorbed.len(),
        existing_loaded = existing_count,
        duration_ms = (chrono::Utc::now() - start).num_milliseconds(),
        "attacker-identity: cycle complete"
    );
}

pub async fn attacker_identity_loop(state: AppState) {
    let window = env_duration("EVIDENCE_WINDOW", Duration::from_secs(6 * 3600));
    let interval = env_duration("ATTACKER_IDENTITY_RUN_INTERVAL", Duration::from_secs(15 * 60));
    loop {
        run_cycle(&state, window).await;
        tokio::time::sleep(interval).await;
    }
}

// --------------------------------------------------------------------
// tests -- ported from identity_test.go
// --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(ip: &str, fp: &str, payload: &str, cred: &str) -> IpObservation {
        let mut signals = SignalSet::default();
        if !fp.is_empty() {
            signals.fingerprints.insert(fp.to_string());
        }
        if !payload.is_empty() {
            signals.payloads.insert(payload.to_string());
        }
        if !cred.is_empty() {
            signals.creds.insert(cred.to_string());
        }
        IpObservation {
            ip: ip.to_string(),
            signals,
            sensors: HashSet::new(),
            techniques: HashSet::new(),
            first: Some(chrono::Utc::now()),
            last: Some(chrono::Utc::now()),
            events: 1,
        }
    }

    #[test]
    fn new_entity_id_is_a_pure_function_of_the_seed_ip() {
        assert_eq!(new_entity_id("203.0.113.5"), new_entity_id("203.0.113.5"));
        assert_ne!(new_entity_id("203.0.113.5"), new_entity_id("203.0.113.6"));
    }

    #[test]
    fn two_independent_first_sightings_of_the_same_ip_converge_on_one_entity_id() {
        // Simulates two uncoordinated writers (concurrent replicas, or the
        // same worker racing itself across a restart) each observing the
        // same never-before-seen IP with no existing entity yet -- the
        // scenario that used to mint two different, colliding entity ids
        // before new_entity_id dropped its timestamp seed.
        let mut observations = HashMap::new();
        observations.insert("203.0.113.9".to_string(), obs("203.0.113.9", "fp-x", "sha-x", ""));
        let (run_a, _) = resolve_identities(Vec::new(), &observations);
        let (run_b, _) = resolve_identities(Vec::new(), &observations);
        assert_eq!(run_a.len(), 1);
        assert_eq!(run_b.len(), 1);
        assert_eq!(run_a[0].id, run_b[0].id, "two independent first-sighting runs must mint the identical entity id");
    }

    #[test]
    fn single_shared_signal_never_merges() {
        let mut observations = HashMap::new();
        observations.insert("1.1.1.1".to_string(), obs("1.1.1.1", "fp-a", "", ""));
        observations.insert("2.2.2.2".to_string(), obs("2.2.2.2", "fp-a", "", ""));
        let (changed, absorbed) = resolve_identities(Vec::new(), &observations);
        assert!(absorbed.is_empty());
        assert_eq!(changed.len(), 2, "one shared signal category must create two separate entities, not merge");
    }

    #[test]
    fn two_shared_signals_merge_into_one_entity() {
        let mut observations = HashMap::new();
        observations.insert("1.1.1.1".to_string(), obs("1.1.1.1", "fp-a", "sha-a", ""));
        observations.insert("2.2.2.2".to_string(), obs("2.2.2.2", "fp-a", "sha-a", ""));
        let (changed, absorbed) = resolve_identities(Vec::new(), &observations);
        assert!(absorbed.is_empty());
        assert_eq!(changed.len(), 1, "two shared signal categories must merge into one entity");
        assert_eq!(changed[0].ips, vec!["1.1.1.1", "2.2.2.2"]);
    }

    #[test]
    fn transitive_merge_in_one_cycle_folds_all_three() {
        // A<->B share fingerprint+payload; B<->C share fingerprint+cred.
        // Processed in IP-sorted order (deterministic), C's own match
        // against the entity A+B already formed this same cycle must still
        // fold C in, not create a separate entity.
        let mut observations = HashMap::new();
        observations.insert("1.1.1.1".to_string(), obs("1.1.1.1", "fp-shared", "sha-ab", ""));
        observations.insert("2.2.2.2".to_string(), obs("2.2.2.2", "fp-shared", "sha-ab", "user / pass"));
        observations.insert("3.3.3.3".to_string(), obs("3.3.3.3", "fp-shared", "", "user / pass"));
        let (changed, absorbed) = resolve_identities(Vec::new(), &observations);
        assert!(absorbed.is_empty(), "no pre-existing entities to absorb in a single-cycle transitive merge");
        assert_eq!(changed.len(), 1, "all three IPs must resolve to one entity");
        assert_eq!(changed[0].ips, vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
    }

    #[test]
    fn merging_two_existing_entities_absorbs_one() {
        let existing = vec![
            Entity { id: "entity-a".into(), ips: vec!["1.1.1.1".into()], fingerprints: vec!["fp-a".into()], payloads: vec!["sha-a".into()], first: "2026-01-01T00:00:00Z".into(), last: "2026-01-01T00:00:00Z".into(), ..Default::default() },
            Entity { id: "entity-b".into(), ips: vec!["2.2.2.2".into()], fingerprints: vec!["fp-a".into()], payloads: vec!["sha-a".into()], first: "2026-01-02T00:00:00Z".into(), last: "2026-01-02T00:00:00Z".into(), ..Default::default() },
        ];
        let mut observations = HashMap::new();
        observations.insert("3.3.3.3".to_string(), obs("3.3.3.3", "fp-a", "sha-a", ""));
        let (changed, absorbed) = resolve_identities(existing, &observations);
        assert_eq!(absorbed, vec!["entity-b".to_string()]);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].id, "entity-a", "the first-encountered matching entity survives, later matches are absorbed into it");
        assert_eq!(changed[0].ips, vec!["1.1.1.1", "2.2.2.2", "3.3.3.3"]);
    }

    #[test]
    fn untouched_existing_entities_are_not_returned() {
        let existing = vec![Entity {
            id: "entity-quiet".into(),
            ips: vec!["9.9.9.9".into()],
            ..Default::default()
        }];
        let observations = HashMap::new();
        let (changed, absorbed) = resolve_identities(existing, &observations);
        assert!(changed.is_empty(), "an entity with no new evidence this cycle must not be rewritten");
        assert!(absorbed.is_empty());
    }

    #[test]
    fn valid_credential_pair_rejects_shell_markers() {
        assert!(!valid_credential_pair("root", "/bin/sh"));
        assert!(!valid_credential_pair("root", "powershell -enc AAAA"));
        assert!(valid_credential_pair("admin", "hunter2"));
        assert!(!valid_credential_pair("", ""));
    }

    #[test]
    fn shared_signal_count_requires_real_intersection() {
        let mut a = SignalSet::default();
        a.fingerprints.insert("fp-1".into());
        a.payloads.insert("sha-1".into());
        let mut b = SignalSet::default();
        b.fingerprints.insert("fp-1".into());
        b.payloads.insert("sha-2".into());
        assert_eq!(shared_signal_count(&a, &b), 1, "only fingerprints overlap");
    }
}
