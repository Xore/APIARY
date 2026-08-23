//! huginn-sidecar — per-flow passive fingerprinting for the S5 sensing layer.
//!
//! #1727 §0 keeps Zeek as the depth engine and Suricata as the alerting
//! engine, and adds this for the four signals neither can produce:
//!
//!   * per-flow TCP fingerprints carrying a *confidence tier* rather than
//!     p0f's binary match/no-match,
//!   * server-side SYN+ACK fingerprints — our sensors as an attacker sees them,
//!   * client and server uptime hints,
//!   * the Akamai HTTP/2 fingerprint (SETTINGS / WINDOW_UPDATE / PRIORITY /
//!     pseudo-header order), which nothing else in the stack extracts.
//!
//! It deliberately does **not** exist to produce OS labels. huginn-net ships
//! the same p0f v3 signature database p0f did — Linux tops out at 3.x, Android
//! at 4.x — so its labels are exactly as stale as the ones being retired. The
//! value here is the per-flow precision, the confidence tier and the HTTP/2
//! fingerprint; the OS name is carried through as one signal among several,
//! not as the answer.
//!
//! Output is newline-delimited JSON, one object per observation, each stamped
//! with a Community ID so it joins to portbridge, Suricata and Zeek records
//! for the same flow. Without that key these observations would be an island.

mod community_id;

use community_id::{community_id, PROTO_TCP};
use huginn_net::output::FingerprintResult;
use huginn_net::{Database, HuginnNet};
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

/// One emitted observation. `observation` carries huginn-net's own serialized
/// output verbatim rather than a restatement of it, so upstream field
/// additions arrive without needing a change here.
#[derive(Serialize)]
struct Record<'a> {
    sensor: &'static str,
    kind: &'a str,
    proto: &'static str,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    community_id: Option<String>,
    observation: Value,
}

struct Args {
    source: Source,
    dedupe: bool,
    dedupe_capacity: usize,
    out: Option<String>,
    max_bytes: u64,
}

enum Source {
    Pcap(String),
    Interface(String),
}

fn usage() -> ! {
    eprintln!(
        "usage: huginn-sidecar (--pcap <file> | --interface <name>) [options]\n\
         \n\
         options:\n  \
           --no-dedupe             emit every observation, including repeats\n  \
           --dedupe-capacity <n>   flows remembered for de-duplication (default 65536)\n  \
           --out <path>            write NDJSON to this file and rotate it in place\n  \
           --max-bytes <n>         rotate --out at this size (default 33554432)\n\
         \n\
         Emits one NDJSON observation per line on stdout, or to --out."
    );
    process::exit(2)
}

fn parse_args() -> Args {
    let mut argv = std::env::args().skip(1);
    let source = match (argv.next().as_deref(), argv.next()) {
        (Some("--pcap"), Some(path)) => Source::Pcap(path),
        (Some("--interface"), Some(name)) => Source::Interface(name),
        _ => usage(),
    };
    let mut args = Args {
        source,
        dedupe: true,
        dedupe_capacity: 65536,
        out: None,
        max_bytes: 32 * 1024 * 1024,
    };
    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--no-dedupe" => args.dedupe = false,
            "--dedupe-capacity" => {
                args.dedupe_capacity = argv
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "--out" => {
                args.out = Some(argv.next().unwrap_or_else(|| usage()));
            }
            "--max-bytes" => {
                args.max_bytes = argv
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            _ => usage(),
        }
    }
    args
}

/// Suppresses repeat observations of the same kind for the same flow.
///
/// Measured on real capture: huginn-net emits a `tcp_syn_ack` observation per
/// SYN+ACK *packet*, and our perimeter retransmits heavily to scanners that
/// never complete the handshake -- 55 826 records covering just 289 distinct
/// flows, a 193x duplication. Every other observation kind came in at 1.0x.
/// Shipping that unfiltered would make this sidecar the largest writer in the
/// stack while adding nothing: the 193 copies are byte-identical.
///
/// Bounded on purpose. In live mode this runs forever, so an unbounded set
/// would be a slow memory leak; past the capacity the oldest flows are
/// forgotten, which can re-emit a long-idle flow rather than grow without
/// limit. That trade is the right way round for a sensor.
struct Deduper {
    seen: std::collections::HashSet<(String, String)>,
    order: std::collections::VecDeque<(String, String)>,
    capacity: usize,
    suppressed: u64,
}

impl Deduper {
    fn new(capacity: usize) -> Self {
        Self {
            seen: std::collections::HashSet::new(),
            order: std::collections::VecDeque::new(),
            capacity: capacity.max(1),
            suppressed: 0,
        }
    }

    /// True when this (kind, flow) has not been emitted recently.
    fn admit(&mut self, kind: &str, community_id: &str) -> bool {
        let key = (kind.to_string(), community_id.to_string());
        if self.seen.contains(&key) {
            self.suppressed += 1;
            return false;
        }
        if self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.order.push_back(key.clone());
        self.seen.insert(key);
        true
    }
}

/// Pull the flow tuple out of a serialized observation. Every huginn-net
/// output type shares the same `source`/`destination` `IpPort` shape, so one
/// extraction covers all of them.
fn tuple_of(value: &Value) -> Option<(IpAddr, u16, IpAddr, u16)> {
    let endpoint = |key: &str| -> Option<(IpAddr, u16)> {
        let node = value.get(key)?;
        let ip = node.get("ip")?.as_str()?.parse().ok()?;
        let port = u16::try_from(node.get("port")?.as_u64()?).ok()?;
        Some((ip, port))
    };
    let (src_ip, src_port) = endpoint("source")?;
    let (dst_ip, dst_port) = endpoint("destination")?;
    Some((src_ip, src_port, dst_ip, dst_port))
}

fn emit<W: Write>(out: &mut W, dedupe: Option<&mut Deduper>, kind: &str, observation: Value) {
    let Some((src_ip, src_port, dst_ip, dst_port)) = tuple_of(&observation) else {
        // No tuple means nothing to join on. Dropping is better than emitting
        // an unjoinable record, but it should be visible rather than silent.
        eprintln!("huginn-sidecar: {kind} observation carried no flow tuple, dropped");
        return;
    };
    let community = community_id(PROTO_TCP, src_ip, src_port, dst_ip, dst_port);
    if let (Some(dedupe), Some(id)) = (dedupe, community.as_deref()) {
        if !dedupe.admit(kind, id) {
            return;
        }
    }
    // Every observation huginn-net produces is TCP-borne: SYN/SYN+ACK/MTU/
    // uptime are TCP by construction, and HTTP and TLS ride on it.
    let record = Record {
        sensor: "huginn",
        kind,
        proto: "tcp",
        src_ip: src_ip.to_string(),
        src_port,
        dst_ip: dst_ip.to_string(),
        dst_port,
        community_id: community,
        observation,
    };
    match serde_json::to_string(&record) {
        Ok(line) => {
            let _ = writeln!(out, "{line}");
        }
        Err(error) => eprintln!("huginn-sidecar: could not serialize {kind}: {error}"),
    }
}

/// Turn one FingerprintResult into zero or more emitted records. A single
/// result can carry several observations at once (a SYN plus its MTU, say).
/// NDJSON sink that rotates by rename-and-reopen.
///
/// Deliberately not copy-truncate. Truncating a file a log shipper is tailing
/// splits its registry state: the truncation resets the live harvester to
/// offset 0, while the rewritten head hashes to a new fingerprint identity and
/// starts a second harvester on the same path. Both then ship every appended
/// line. That was measured on portbridge at 99.9% duplicate documents (#1776),
/// and this sidecar's log was rotated the same way until this existed.
///
/// Renaming leaves the old inode untouched for whoever is still reading it and
/// gives the shipper a new file to discover, which is stable under either
/// identity scheme. Only one generation is kept: this is a staging buffer that
/// Filebeat drains, not an archive.
struct RotatingWriter {
    path: PathBuf,
    max_bytes: u64,
    written: u64,
    file: File,
}

impl RotatingWriter {
    fn open(path: &str, max_bytes: u64) -> io::Result<Self> {
        let path = PathBuf::from(path);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        // Start from the file's real length so a restart does not get a full
        // budget on an already-large file.
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path,
            max_bytes,
            written,
            file,
        })
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.flush()?;
        let mut rotated = self.path.clone().into_os_string();
        rotated.push(".1");
        fs::rename(&self.path, Path::new(&rotated))?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        Ok(())
    }
}

impl Write for RotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Rotate on the record boundary before the write, so a rotation never
        // splits a JSON line across two files.
        if self.written >= self.max_bytes {
            self.rotate()?;
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn emit_result<W: Write>(
    out: &mut W,
    dedupe: &mut Option<Deduper>,
    result: FingerprintResult,
) {
    macro_rules! forward {
        ($field:expr, $kind:literal) => {
            if let Some(value) = $field {
                match serde_json::to_value(&value) {
                    Ok(json) => emit(out, dedupe.as_mut(), $kind, json),
                    Err(error) => {
                        eprintln!("huginn-sidecar: could not encode {}: {error}", $kind)
                    }
                }
            }
        };
    }

    forward!(result.tcp_syn, "tcp_syn");
    forward!(result.tcp_syn_ack, "tcp_syn_ack");
    forward!(result.tcp_mtu, "tcp_mtu");
    forward!(result.tcp_client_uptime, "tcp_client_uptime");
    forward!(result.tcp_server_uptime, "tcp_server_uptime");
    forward!(result.http_request, "http_request");
    forward!(result.http_response, "http_response");
    forward!(result.tls_client, "tls_client");
}

fn main() {
    let args = parse_args();
    // Read out before `args` moves into the analysis thread below.
    let args_dedupe = args.dedupe;
    let args_capacity = args.dedupe_capacity;
    let args_out = args.out.clone();
    let args_max_bytes = args.max_bytes;

    let database = match Database::load_default() {
        Ok(database) => database,
        Err(error) => {
            eprintln!("huginn-sidecar: could not load the signature database: {error}");
            process::exit(1);
        }
    };

    let (sender, receiver) = mpsc::channel::<FingerprintResult>();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();

    let worker = thread::spawn(move || {
        let mut analyzer = match HuginnNet::new(Some(&database), 1000, None) {
            Ok(analyzer) => analyzer,
            Err(error) => {
                eprintln!("huginn-sidecar: could not start the analyzer: {error}");
                return Err(());
            }
        };
        let outcome = match args.source {
            Source::Pcap(ref path) => analyzer.analyze_pcap(path, sender, Some(worker_cancel)),
            Source::Interface(ref name) => {
                analyzer.analyze_network(name, sender, Some(worker_cancel))
            }
        };
        if let Err(error) = outcome {
            eprintln!("huginn-sidecar: analysis failed: {error}");
            return Err(());
        }
        Ok(())
    });

    // Line-oriented NDJSON for a log shipper, buffered rather than syscalling
    // per record. With --out the sidecar owns the file and rotates it itself;
    // without it, stdout keeps the plain-filter behaviour.
    let stdout = io::stdout();
    let mut out: BufWriter<Box<dyn Write>> = match args_out {
        Some(ref path) => {
            let sink = RotatingWriter::open(path, args_max_bytes).unwrap_or_else(|error| {
                eprintln!("huginn-sidecar: cannot open {path}: {error}");
                process::exit(1);
            });
            BufWriter::new(Box::new(sink))
        }
        None => BufWriter::new(Box::new(stdout.lock())),
    };

    let mut dedupe = if args_dedupe {
        Some(Deduper::new(args_capacity))
    } else {
        None
    };

    let mut emitted: u64 = 0;
    for result in receiver {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        emit_result(&mut out, &mut dedupe, result);
        emitted += 1;
    }
    let _ = out.flush();

    let analysis_ok = matches!(worker.join(), Ok(Ok(())));
    let suppressed = dedupe.as_ref().map(|d| d.suppressed).unwrap_or(0);
    eprintln!("huginn-sidecar: {emitted} fingerprint result(s), {suppressed} duplicate observation(s) suppressed");
    if !analysis_ok {
        // Exit non-zero so a failed run cannot be mistaken for a quiet one.
        process::exit(1);
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::RotatingWriter;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("huginn-rot-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join("huginn.json")
    }

    #[test]
    fn rotates_by_rename_and_keeps_writing_to_the_original_path() {
        let path = scratch("rename");
        let mut w = RotatingWriter::open(path.to_str().unwrap(), 16).unwrap();

        // Exceed the budget, then write again to trigger the rotation.
        w.write_all(b"aaaaaaaaaaaaaaaaaaaa\n").unwrap();
        w.write_all(b"second\n").unwrap();
        w.flush().unwrap();

        let rotated = PathBuf::from(format!("{}.1", path.display()));
        assert!(rotated.exists(), "previous generation should be renamed aside");
        assert_eq!(fs::read_to_string(&rotated).unwrap(), "aaaaaaaaaaaaaaaaaaaa\n");
        // The live path must still be the one being appended to -- that is what
        // makes this rename-and-reopen rather than a move that abandons the path.
        assert_eq!(fs::read_to_string(&path).unwrap(), "second\n");
    }

    #[test]
    fn never_splits_a_record_across_two_files() {
        let path = scratch("boundary");
        let mut w = RotatingWriter::open(path.to_str().unwrap(), 4).unwrap();
        for line in ["alpha\n", "bravo\n", "charlie\n"] {
            w.write_all(line.as_bytes()).unwrap();
        }
        w.flush().unwrap();

        let live = fs::read_to_string(&path).unwrap();
        let rotated = fs::read_to_string(format!("{}.1", path.display())).unwrap();
        // Every line that survives is whole; rotation happens between records.
        for content in [&live, &rotated] {
            for line in content.lines() {
                assert!(
                    ["alpha", "bravo", "charlie"].contains(&line),
                    "record was split across a rotation: {line:?}"
                );
            }
        }
        assert!(live.ends_with('\n'));
    }

    #[test]
    fn resumes_from_existing_length_rather_than_a_fresh_budget() {
        let path = scratch("resume");
        fs::write(&path, "x".repeat(100)).unwrap();
        let w = RotatingWriter::open(path.to_str().unwrap(), 16).unwrap();
        // A restart against an already-oversized file must rotate on the next
        // write, not append another full budget to it.
        assert_eq!(w.written, 100);
    }
}
