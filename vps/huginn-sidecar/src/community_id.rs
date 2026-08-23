//! Community ID v1 (#1728), so this sidecar's observations join to everything
//! else in the stack.
//!
//! This is the third implementation of the same hash in APIARY -- portbridge
//! computes it in Go, Suricata and Zeek each compute their own. That is the
//! point: a fingerprint nobody can join to the flow it came from is close to
//! useless, and the only way to be sure they agree is to check them against
//! each other. The tests here reuse the exact fixtures from
//! vps/portbridge/community_id_test.go, which were themselves taken from live
//! Suricata and Zeek output.
//!
//! Spec: https://github.com/corelight/community-id-spec

use base64::Engine;
use sha1::{Digest, Sha1};
use std::net::IpAddr;

/// Must match Suricata's `community-id-seed: 0` and Zeek's default. A
/// different seed still produces well-formed IDs that silently never match.
const SEED: u16 = 0;

pub const PROTO_TCP: u8 = 6;
/// Every observation huginn-net emits is TCP-borne, so nothing in this binary
/// hashes a UDP tuple today. Kept because the hash is protocol-generic and the
/// UDP fixtures below (taken from Zeek) are what prove that -- dropping it
/// would mean dropping the only UDP coverage this implementation has.
#[cfg_attr(not(test), allow(dead_code))]
pub const PROTO_UDP: u8 = 17;

/// Community ID for one 5-tuple, or None when the tuple cannot be hashed
/// correctly.
///
/// Returning None rather than a best-effort value is deliberate, for the same
/// reason as the Go side: an ID derived from a wildcard or placeholder address
/// looks joinable in Elasticsearch and matches nothing, which is worse than an
/// absent field.
pub fn community_id(
    proto: u8,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
) -> Option<String> {
    if src_ip.is_unspecified() || dst_ip.is_unspecified() {
        return None;
    }
    let (src_bytes, dst_bytes) = match (src_ip, dst_ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (a.octets().to_vec(), b.octets().to_vec()),
        (IpAddr::V6(a), IpAddr::V6(b)) => (a.octets().to_vec(), b.octets().to_vec()),
        // Mixed address families cannot describe one flow.
        _ => return None,
    };

    let (src_bytes, src_port, dst_bytes, dst_port) =
        if is_ordered(&src_bytes, src_port, &dst_bytes, dst_port) {
            (src_bytes, src_port, dst_bytes, dst_port)
        } else {
            (dst_bytes, dst_port, src_bytes, src_port)
        };

    let mut buf = Vec::with_capacity(2 + src_bytes.len() + dst_bytes.len() + 6);
    buf.extend_from_slice(&SEED.to_be_bytes());
    buf.extend_from_slice(&src_bytes);
    buf.extend_from_slice(&dst_bytes);
    buf.push(proto);
    buf.push(0); // pads the protocol byte to two
    buf.extend_from_slice(&src_port.to_be_bytes());
    buf.extend_from_slice(&dst_port.to_be_bytes());

    let digest = Sha1::digest(&buf);
    Some(format!(
        "1:{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    ))
}

/// Lower address first, ties broken by the lower port, so both directions of
/// one flow hash identically.
fn is_ordered(src: &[u8], src_port: u16, dst: &[u8], dst_port: u16) -> bool {
    match src.cmp(dst) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => src_port < dst_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Identical fixtures to vps/portbridge/community_id_test.go, so a
    /// divergence between the Go and Rust implementations fails here rather
    /// than silently producing two sets of records that cannot be joined.
    ///
    /// Originally captured from the live stack; the responder address is now
    /// RFC 5737 documentation space because this repository is public, and the
    /// expected hashes were recomputed with Zeek's own community_id_v1()
    /// rather than with either implementation under test.
    const VECTORS: &[(u8, &str, u16, &str, u16, &str)] = &[
        // --- Suricata, TCP ---
        (PROTO_TCP, "198.51.100.20", 23, "123.188.73.228", 42451, "1:IIqFM6s6T7Q3qpPtQlcLozWAsqc="),
        (PROTO_TCP, "123.188.73.228", 42482, "198.51.100.20", 23, "1:YCy2phL1VvHw/ee7ABoEJYPCcRk="),
        (PROTO_TCP, "94.131.219.245", 57806, "198.51.100.20", 23, "1:b0iDcD8ZThtLhSFx7oYoSQE0l58="),
        (PROTO_TCP, "124.222.229.150", 53260, "198.51.100.20", 5900, "1:sQ1WP/gQDETidlyH4iAwiUGYyFI="),
        (PROTO_TCP, "85.217.140.16", 60747, "198.51.100.20", 46289, "1:UNE6fvrvzraqUf0OLOq3jTVbauI="),
        (PROTO_TCP, "198.74.50.114", 47150, "198.51.100.20", 5003, "1:YDXfCSDYgtLn7PkRgKQywAQMYf0="),
        // --- Zeek, UDP ---
        (PROTO_UDP, "107.174.188.218", 1032, "198.51.100.20", 5060, "1:dTygMYvbdFFKpWRBgjgdXy82+ec="),
        (PROTO_UDP, "167.172.89.195", 1434, "198.51.100.20", 1900, "1:UvV/ad2me9OyoAKUSWKX9jUX/+I="),
        (PROTO_UDP, "46.105.160.250", 54723, "198.51.100.20", 5060, "1:OuGHk+tSDv+eV114znY+Qo5Jqfo="),
        (PROTO_UDP, "138.117.127.7", 34528, "198.51.100.20", 38698, "1:2B8cMkAxqDpzI6juGBf82Y1oDoo="),
        (PROTO_UDP, "217.160.124.58", 62466, "198.51.100.20", 5060, "1:V9NkjK4Y3HdeT0B6kWu/+1JeUF0="),
    ];

    #[test]
    fn matches_suricata_and_zeek() {
        for &(proto, s, sp, d, dp, want) in VECTORS {
            let got = community_id(proto, s.parse().unwrap(), sp, d.parse().unwrap(), dp);
            assert_eq!(
                got.as_deref(),
                Some(want),
                "tuple {s}:{sp} -> {d}:{dp} proto {proto}"
            );
        }
    }

    #[test]
    fn is_direction_agnostic() {
        for &(proto, s, sp, d, dp, _) in VECTORS {
            let fwd = community_id(proto, s.parse().unwrap(), sp, d.parse().unwrap(), dp);
            let rev = community_id(proto, d.parse().unwrap(), dp, s.parse().unwrap(), sp);
            assert_eq!(fwd, rev, "direction changed the hash for {s}:{sp} <-> {d}:{dp}");
        }
    }

    #[test]
    fn refuses_tuples_it_cannot_hash() {
        let real: IpAddr = "203.0.113.5".parse().unwrap();
        let wildcard4: IpAddr = "0.0.0.0".parse().unwrap();
        let wildcard6: IpAddr = "::".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();

        assert_eq!(community_id(PROTO_UDP, real, 1234, wildcard4, 53), None);
        assert_eq!(community_id(PROTO_UDP, wildcard6, 1234, v6, 53), None);
        assert_eq!(community_id(PROTO_TCP, real, 1234, v6, 80), None, "mixed families");
    }
}
