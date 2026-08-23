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
use std::io::{self, BufWriter, Write};
use std::net::IpAddr;
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
}

enum Source {
    Pcap(String),
    Interface(String),
}

fn usage() -> ! {
    eprintln!(
        "usage: huginn-sidecar (--pcap <file> | --interface <name>)\n\
         \n\
         Emits one NDJSON observation per line on stdout."
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
    Args { source }
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

fn emit<W: Write>(out: &mut W, kind: &str, observation: Value) {
    let Some((src_ip, src_port, dst_ip, dst_port)) = tuple_of(&observation) else {
        // No tuple means nothing to join on. Dropping is better than emitting
        // an unjoinable record, but it should be visible rather than silent.
        eprintln!("huginn-sidecar: {kind} observation carried no flow tuple, dropped");
        return;
    };
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
        community_id: community_id(PROTO_TCP, src_ip, src_port, dst_ip, dst_port),
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
fn emit_result<W: Write>(out: &mut W, result: FingerprintResult) {
    macro_rules! forward {
        ($field:expr, $kind:literal) => {
            if let Some(value) = $field {
                match serde_json::to_value(&value) {
                    Ok(json) => emit(out, $kind, json),
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

    // stdout is line-oriented NDJSON for a log shipper, so it is buffered here
    // and flushed once at the end rather than syscalling per record.
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let mut emitted: u64 = 0;
    for result in receiver {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        emit_result(&mut out, result);
        emitted += 1;
    }
    let _ = out.flush();

    let analysis_ok = matches!(worker.join(), Ok(Ok(())));
    eprintln!("huginn-sidecar: {emitted} fingerprint result(s)");
    if !analysis_ok {
        // Exit non-zero so a failed run cannot be mistaken for a quiet one.
        process::exit(1);
    }
}
