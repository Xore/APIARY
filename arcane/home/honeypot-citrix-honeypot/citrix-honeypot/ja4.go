package main

// JA4 TLS ClientHello fingerprinting (#759, split from #609 -- see ja3.go's
// own header for why JA4 was deliberately left out of that fix). Builds on
// parseClientHello/peekClientHelloBody, adding the two fields JA3 doesn't
// need: the first ALPN protocol name and the signature_algorithms list.
//
// Verified against FoxIO's own reference implementation
// (github.com/FoxIO-LLC/ja4, python/ja4.py + python/common.py's to_ja4/
// get_hex_sorted/sha_encode), not just the prose spec -- both test vectors
// in ja4_test.go were computed by re-deriving that exact algorithm in a
// standalone Python script (sha256/hex-sort/comma-join, byte for byte) and
// are independent of this Go implementation, the same verification
// standard ja3.go's own known-vector test already set.
//
// Format: ptype + tls_version + sni + cipher_count(2) + ext_count(2) +
// alpn(2) + "_" + cipher_hash(12) + "_" + extension_hash(12).
//
//   - ptype: "t" always here -- citrix-honeypot only terminates TLS over
//     TCP, never QUIC.
//   - tls_version/sni/cipher_count: same GREASE-filtering and #002b
//     supported_versions override as JA3, via the shared helpers in ja3.go.
//     cipher_count is the wire-order (unsorted) cipher list length.
//   - ext_count: wire-order extension list length (GREASE filtered) --
//     unlike the hash below, this INCLUDES SNI (0x0000) and ALPN (0x0010),
//     per FoxIO's own spec and confirmed in to_ja4() (the count is taken
//     before get_hex_sorted's SNI/ALPN removal step runs).
//   - alpn: first ALPN protocol name's first+last character (e.g.
//     "http/1.1" -> "h1", "h2" -> "h2"), "00" if no ALPN extension.
//   - cipher_hash: SHA256, first 12 hex chars, of the GREASE-filtered
//     cipher list as 4-digit lowercase hex, SORTED, comma-joined.
//     "000000000000" if no ciphers survive filtering.
//   - extension_hash: same construction over the extension list, but with
//     SNI/ALPN excluded (not just left out of the count -- excluded from
//     this list entirely), and if a signature_algorithms extension (0x000d)
//     is present, its GREASE-filtered values (hex, wire order, NOT sorted)
//     are appended after a literal "_" before hashing.

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	extALPN                = 0x0010
	extSignatureAlgorithms = 0x000d
)

// peekJA4 parses a TLS record + Handshake ClientHello from r without
// consuming it and returns the JA4 fingerprint for logging, or "" if the
// prefix isn't a well-formed ClientHello.
func peekJA4(r *bufio.Reader) string {
	body, ok := peekClientHelloBody(r)
	if !ok {
		return ""
	}

	ver, ciphers, exts, _, _, ok := parseClientHello(body)
	if !ok {
		return ""
	}
	ver = negotiatedVersion(ver, body)

	sni := "i"
	for _, e := range exts {
		if e == 0x0000 {
			sni = "d"
			break
		}
	}

	alpn := "00"
	if data, present := extData(body, extALPN); present {
		if name := parseALPNFirst(data); name != "" {
			if len(name) > 2 {
				alpn = string([]byte{name[0], name[len(name)-1]})
			} else {
				alpn = name
			}
		}
	}

	var sigAlgs []uint16
	if data, present := extData(body, extSignatureAlgorithms); present {
		sigAlgs = parseSignatureAlgorithms(data)
	}

	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s",
		ja4TLSVersion(ver), sni,
		min99(len(ciphers)), min99(len(exts)), alpn,
		ja4CipherHash(ciphers), ja4ExtensionHash(exts, sigAlgs))
}

// parseALPNFirst extracts the first protocol name from an ALPN extension's
// data (2-byte protocol_name_list length, then a list of 1-byte-length-
// prefixed names).
func parseALPNFirst(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	pos := 2
	if pos >= len(data) {
		return ""
	}
	n := int(data[pos])
	pos++
	if n <= 0 || pos+n > len(data) {
		return ""
	}
	return string(data[pos : pos+n])
}

// parseSignatureAlgorithms extracts a signature_algorithms extension's
// values (2-byte list length, then 2-byte entries) in wire order,
// GREASE-filtered -- JA4's extension hash appends these unsorted, unlike
// every other list it hashes.
func parseSignatureAlgorithms(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	pos := 2
	end := pos + listLen
	if end > len(data) {
		end = len(data)
	}
	var out []uint16
	for pos+1 < end {
		if v := binary.BigEndian.Uint16(data[pos : pos+2]); !isGREASE(v) {
			out = append(out, v)
		}
		pos += 2
	}
	return out
}

// ja4TLSVersion maps a negotiated TLS version to JA4's version token.
// Unmapped values (any DTLS/QUIC-only version, or a value this honeypot's
// TCP-only listener should never actually see) fall back to "00", the same
// default the reference implementation uses for an unrecognized version.
func ja4TLSVersion(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	default:
		return "00"
	}
}

func min99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

// sortedHexJoin renders each value as 4-digit lowercase hex, sorts the
// resulting strings (lexicographic sort on fixed-width lowercase hex is the
// same ordering as a numeric sort), and comma-joins them.
func sortedHexJoin(vs []uint16) string {
	hexes := make([]string, len(vs))
	for i, v := range vs {
		hexes[i] = fmt.Sprintf("%04x", v)
	}
	sort.Strings(hexes)
	return strings.Join(hexes, ",")
}

// wireHexJoin is sortedHexJoin without the sort -- JA4's signature_algorithms
// suffix is hashed in the order the client sent it, not sorted.
func wireHexJoin(vs []uint16) string {
	hexes := make([]string, len(vs))
	for i, v := range vs {
		hexes[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(hexes, ",")
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func ja4CipherHash(ciphers []uint16) string {
	if len(ciphers) == 0 {
		return "000000000000"
	}
	return sha12(sortedHexJoin(ciphers))
}

// ja4ExtensionHash hashes the extension list (SNI/ALPN excluded, GREASE
// already filtered by parseClientHello, sorted) with the wire-order
// signature_algorithms list appended after a literal "_" when present --
// matching the reference implementation's plain string concatenation
// exactly, including the (practically unreachable, since a
// signature_algorithms extension's own type 0x000d always survives the
// SNI/ALPN-only exclusion above) edge case of a leading "_" if the
// extension list were ever empty while signature_algorithms were not.
func ja4ExtensionHash(exts, sigAlgs []uint16) string {
	filtered := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e == 0x0000 || e == extALPN {
			continue
		}
		filtered = append(filtered, e)
	}
	s := sortedHexJoin(filtered)
	if len(sigAlgs) > 0 {
		s = s + "_" + wireHexJoin(sigAlgs)
	}
	if s == "" {
		return "000000000000"
	}
	return sha12(s)
}
