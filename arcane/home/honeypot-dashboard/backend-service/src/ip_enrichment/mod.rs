//! ip-enrichment-worker (#1610, discovered beyond #1610's originally-named
//! inventory while surveying the codebase): moves the portbridge via_port
//! -> real attacker IP join from dashboard read-time to ingest time. Unlike
//! every other worker ported under #1610, this one never touches
//! Elasticsearch at all — it tails each affected sensor's raw JSON log
//! file, rewrites any line whose src_ip is still the WireGuard tunnel peer
//! address to the real attacker IP (joined against portbridge's own
//! connection log by source port), and promotes a set of cross-sensor
//! "canonical_*" fields. The rewritten stream is written to its own file
//! under OUT_DIR, which Filebeat tails *instead of* the raw file for these
//! sensors — this module doesn't touch Filebeat's own config, it only has
//! to keep producing the same enriched-file format at the same path.
//!
//! Runs in its own compose service (`backend-worker-enrichment`,
//! `network_mode: none`) rather than on the ES-reaching `backend-worker` —
//! see compose.yml's own comment on that service for why.

mod attck;
mod canonical;
mod pending;
mod rotate;
mod sensors;
mod tail;
mod tftp;
mod viamap;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use pending::{EnrichFn, PendingQueue};
use rotate::OutputWriter;
use sensors::{
    enrich_beelzebub_line, enrich_dionaea_incident_line, enrich_galah_line, enrich_hellpot_line, enrich_line,
    enrich_sentrypeer_line, enrich_wordpot_line, TUNNEL_PEER_IP,
};
use viamap::{ViaMap, ViaMapBuilder};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

fn env_duration(name: &str, default: Duration) -> Duration {
    let raw = env_or(name, "");
    if raw.is_empty() {
        return default;
    }
    parse_go_duration(&raw).unwrap_or(default)
}

/// Parses a Go-style "2s"/"5m"/"1h" duration string (the only shapes this
/// worker's own env vars ever use).
fn parse_go_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (digits, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: u64 = digits.parse().ok()?;
    match unit {
        "s" => Some(Duration::from_secs(n)),
        "m" => Some(Duration::from_secs(n * 60)),
        "h" => Some(Duration::from_secs(n * 3600)),
        _ => None,
    }
}

fn env_i64(name: &str, default: i64) -> i64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Debug (#1206) per-source resolution counters, logged periodically and
/// reset each interval — a snapshot of "what happened in the last N
/// seconds", the signal a live miss-rate regression would show up in.
#[derive(Default)]
struct SourceStats {
    attempted: AtomicI64,
    resolved_first: AtomicI64,
    resolved_retry: AtomicI64,
    timed_out: AtomicI64,
}

struct Source {
    name: String,
    input: PathBuf,
    output: PathBuf,
    state_path: PathBuf,
    enrich: EnrichFn,
    stats: Arc<SourceStats>,
}

/// Finds every input file this worker is responsible for — mirrors
/// discoverSources exactly, including conpot's glob-by-persona-subdirectory
/// discovery.
fn discover_sources(logs_dir: &Path, out_dir: &Path, state_dir: &Path) -> Vec<Source> {
    let mut sources = Vec::new();
    let mut add = |name: &str, input: PathBuf, enrich: EnrichFn| {
        sources.push(Source {
            name: name.to_string(),
            input,
            output: out_dir.join(format!("{name}.json")),
            state_path: state_dir.join(format!("{name}.offset")),
            enrich,
            stats: Arc::new(SourceStats::default()),
        });
    };

    add("cowrie", logs_dir.join("cowrie").join("cowrie.json"), enrich_line);
    add("dionaea", logs_dir.join("dionaea").join("dionaea.json"), enrich_line);
    add("dns-honeypot", logs_dir.join("dns-honeypot").join("dns-honeypot.json"), enrich_line);
    add("cisco-asa-honeypot", logs_dir.join("cisco-asa-honeypot").join("cisco-asa-honeypot.json"), enrich_line);
    // #623: no top-level src_ip at all — needs its own enrich function.
    add("dionaea-incident", logs_dir.join("dionaea").join("dionaea_incident.json"), enrich_dionaea_incident_line);
    add("beelzebub", logs_dir.join("beelzebub").join("beelzebub.json"), enrich_beelzebub_line);
    add("hellpot", logs_dir.join("hellpot").join("HellPot.log"), enrich_hellpot_line);
    // elasticpot's native log shape already matches enrichLine's exactly
    // (flat top-level src_ip/src_port, stable "sensor" literal via its own
    // config) — no bespoke enrich function, no canonical.go promotion case
    // either (it captures no credentials).
    add("elasticpot", logs_dir.join("elasticpot").join("elasticpot.json"), enrich_line);
    add("galah", logs_dir.join("galah").join("event_log.json"), enrich_galah_line);
    add("sentrypeer", logs_dir.join("sentrypeer").join("sentrypeer.json"), enrich_sentrypeer_line);
    add("wordpot", logs_dir.join("wordpot").join("wordpot.log"), enrich_wordpot_line);
    // mailoney's own log shape already matches enrichLine's exactly.
    add("mailoney", logs_dir.join("mailoney").join("mailoney.json"), enrich_line);

    // #1217: field-normalization-only sources — already carry the real
    // attacker IP via PROXY protocol, watched solely so canonical.go's
    // per-sensor promotion runs on their lines too.
    add("multipot", logs_dir.join("multipot").join("multipot.json"), enrich_line);
    add("tanner", logs_dir.join("tanner").join("tanner_report.json"), enrich_line);
    add("http-honeypot", logs_dir.join("http-honeypot").join("http.json"), enrich_line);
    add("citrix-honeypot", logs_dir.join("citrix-honeypot").join("citrix-honeypot.json"), enrich_line);
    add("rdp-honeypot", logs_dir.join("rdp-honeypot").join("rdp-honeypot.json"), enrich_line);

    if let Ok(entries) = std::fs::read_dir(logs_dir) {
        let mut personas: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| name.starts_with("conpot") && logs_dir.join(name).join("conpot.json").is_file())
            .collect();
        personas.sort(); // deterministic discovery order
        for persona in personas {
            let input = logs_dir.join(&persona).join("conpot.json");
            add(&persona, input, enrich_line);
        }
    }

    sources
}

async fn run_source(
    mut source: Source,
    vm: Arc<RwLock<ViaMap>>,
    tftp_vm: Arc<RwLock<ViaMap>>,
    refresh: Duration,
    pending_timeout: Duration,
) {
    let mut writer = match OutputWriter::open(source.output.clone(), env_i64("OUTPUT_MAX_BYTES", 67_108_864) as u64) {
        Ok(w) => w,
        Err(error) => {
            tracing::warn!(source = %source.name, path = %source.output.display(), %error, "ip-enrichment: open output failed");
            return;
        }
    };

    let mut offset = tail::load_offset(&source.state_path).unwrap_or(0);
    let mut queue = PendingQueue::default();
    let mut ticker = tokio::time::interval(refresh);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let snapshot_vm = vm.read().await.clone();
        let snapshot_tftp = tftp_vm.read().await.clone();
        offset = process_source_tick(&mut source, &mut writer, &mut queue, &snapshot_vm, &snapshot_tftp, pending_timeout, offset);
    }
}

/// One read/enrich/write cycle. Returns the offset to use next tick:
/// the new offset on success, or the offset passed in, unchanged, on
/// either a write or an offset-persist failure — so the same input range
/// is retried next tick instead of being silently skipped or re-written.
#[allow(clippy::too_many_arguments)]
fn process_source_tick(
    source: &mut Source,
    writer: &mut OutputWriter,
    queue: &mut PendingQueue,
    vm: &ViaMap,
    tftp_vm: &ViaMap,
    pending_timeout: Duration,
    offset: i64,
) -> i64 {
    let (lines, new_offset) = match tail::read_new_lines(&source.input, offset) {
        Ok(v) => v,
        Err(_) => return offset, // sensor container restarting, file briefly absent, etc. — retry next tick
    };

    let now = Instant::now();
    let tunnel_peer_marker = format!("\"src_ip\":\"{TUNNEL_PEER_IP}\"");
    let mut ready = Vec::new();
    for line in lines {
        let is_tunnel_peer = String::from_utf8_lossy(&line).contains(&tunnel_peer_marker); // #1206 debug stat only
        let (enriched, resolved) = (source.enrich)(&line, vm, tftp_vm, &source.name);
        if resolved {
            if is_tunnel_peer {
                source.stats.resolved_first.fetch_add(1, Ordering::Relaxed);
            }
            ready.push(enriched);
        } else {
            source.stats.attempted.fetch_add(1, Ordering::Relaxed);
            queue.add(line, pending_timeout, now);
        }
    }
    let drained = queue.drain(vm, tftp_vm, now, &source.name, source.enrich);
    for out in &drained {
        if String::from_utf8_lossy(out).contains(&tunnel_peer_marker) {
            source.stats.timed_out.fetch_add(1, Ordering::Relaxed);
        } else {
            source.stats.resolved_retry.fetch_add(1, Ordering::Relaxed);
        }
    }
    ready.extend(drained);

    if !writer.write_lines(&ready) {
        return offset; // don't advance/persist the offset over a batch that failed to write
    }
    if new_offset == offset {
        return offset;
    }
    if let Err(error) = tail::save_offset(&source.state_path, new_offset) {
        tracing::warn!(source = %source.name, %error, "ip-enrichment: save offset failed");
        return offset;
    }
    new_offset
}

async fn log_stats(sources: &[Arc<SourceStats>], names: &[String], interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        for (stats, name) in sources.iter().zip(names) {
            let attempted = stats.attempted.swap(0, Ordering::Relaxed);
            let first = stats.resolved_first.swap(0, Ordering::Relaxed);
            let retry = stats.resolved_retry.swap(0, Ordering::Relaxed);
            let timed_out = stats.timed_out.swap(0, Ordering::Relaxed);
            if attempted == 0 && first == 0 {
                continue; // nothing seen for this source this interval
            }
            tracing::info!(
                source = %name,
                attempted,
                resolved_first = first,
                resolved_retry = retry,
                timed_out,
                "ip-enrichment: tunnel-peer join stats"
            );
        }
    }
}

pub async fn ip_enrichment_loop(_state: crate::AppState) {
    let logs_dir = PathBuf::from(env_or("LOGS_DIR", "/logs"));
    let out_dir = PathBuf::from(env_or("OUT_DIR", "/logs/enriched"));
    let state_dir = PathBuf::from(env_or("STATE_DIR", "/state/ip-enrichment-worker"));
    let refresh = env_duration("REFRESH_INTERVAL", Duration::from_secs(2));
    let pending_timeout = env_duration("PENDING_TIMEOUT", Duration::from_secs(5));

    if let Err(error) = std::fs::create_dir_all(&out_dir) {
        tracing::error!(path = %out_dir.display(), %error, "ip-enrichment: create OUT_DIR failed");
        return;
    }
    if let Err(error) = std::fs::create_dir_all(&state_dir) {
        tracing::error!(path = %state_dir.display(), %error, "ip-enrichment: create STATE_DIR failed");
        return;
    }

    let sources = discover_sources(&logs_dir, &out_dir, &state_dir);
    if sources.is_empty() {
        tracing::error!(path = %logs_dir.display(), "ip-enrichment: no input sources found under LOGS_DIR");
        return;
    }
    for source in &sources {
        tracing::info!(source = %source.name, input = %source.input.display(), output = %source.output.display(), "ip-enrichment: watching");
        // First run for this source: start at EOF rather than walking its
        // full history — an operator restarting this worker doesn't want
        // years of already-shipped raw log re-enriched and re-appended.
        if tail::load_offset(&source.state_path).is_none() {
            if let Ok(meta) = std::fs::metadata(&source.input) {
                let _ = tail::save_offset(&source.state_path, meta.len() as i64);
            }
        }
    }

    let portbridge_dir = logs_dir.join("portbridge");
    let mut via_builder = ViaMapBuilder::new(portbridge_dir);
    let vm = Arc::new(RwLock::new(via_builder.refresh()));
    let tftp_vm = Arc::new(RwLock::new(tftp::build_tftp_session_map(&logs_dir)));

    {
        let vm = vm.clone();
        let tftp_vm = tftp_vm.clone();
        let logs_dir = logs_dir.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(refresh);
            loop {
                ticker.tick().await;
                let refreshed = via_builder.refresh();
                *vm.write().await = refreshed;
                let refreshed_tftp = tftp::build_tftp_session_map(&logs_dir);
                *tftp_vm.write().await = refreshed_tftp;
            }
        });
    }

    let stats: Vec<Arc<SourceStats>> = sources.iter().map(|s| s.stats.clone()).collect();
    let names: Vec<String> = sources.iter().map(|s| s.name.clone()).collect();
    tokio::spawn(async move { log_stats(&stats, &names, Duration::from_secs(30)).await });

    let mut handles = Vec::new();
    for source in sources {
        let vm = vm.clone();
        let tftp_vm = tftp_vm.clone();
        handles.push(tokio::spawn(async move { run_source(source, vm, tftp_vm, refresh, pending_timeout).await }));
    }
    // Runs forever; process supervision (docker restart policy) handles
    // crashes, same posture as the original.
    futures::future::join_all(handles).await;
}
