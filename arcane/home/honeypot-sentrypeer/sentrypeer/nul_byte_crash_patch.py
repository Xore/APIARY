#!/usr/bin/env python3
"""Build-time patch for SentryPeer's sentrypeer_rust/src/sip.rs (#1424).

sentrypeer_rust::sip::log_sip_packet() builds a CString directly from raw
received packet bytes and calls .unwrap() on the Result -- CString::new()
fails whenever the input contains an embedded NUL (0x00) byte anywhere
before the end. Confirmed live: a single 0x00 byte sent to the SIP
listener (even our own healthcheck's `nc -z -u` probe) crashes the
tls_tokio_runtime thread with a NulError panic. This is a trivial DoS for
a sensor whose entire job is sitting on the open internet accepting
arbitrary garbage -- real attacker traffic, not just malformed input, will
contain stray NUL bytes often enough to make this a routine crash.

Same exact-match-replace + idempotency-marker shape as
dionaea/log_rotation_patch.py and hellpot/router_patch.py: escape any
embedded NUL byte to a visible "\\x00" before constructing the CString,
instead of dropping or crashing on it -- preserves full packet content
for evidence/artifact purposes (this repo's own #1415 epic requirement),
just makes it representable as a C string.
"""
import sys

PATH = "sentrypeer_rust/src/sip.rs"
MARKER = "// #1424 nul_byte_crash_patch: sanitized before CString::new"

ORIGINAL = """    let packet_ptr = CString::new(String::from_utf8_lossy(&buf[..bytes_read]).to_string())
        .unwrap()
        .into_raw();"""

PATCHED = """    // #1424 nul_byte_crash_patch: sanitized before CString::new
    let sanitized_packet =
        String::from_utf8_lossy(&buf[..bytes_read]).replace('\\0', "\\\\x00");
    let packet_ptr = CString::new(sanitized_packet)
        .expect("sanitized_packet must not contain an embedded NUL after replacement")
        .into_raw();"""

with open(PATH) as f:
    text = f.read()

if MARKER in text:
    print(f"{PATH}: already patched, skipping")
    sys.exit(0)

count = text.count(ORIGINAL)
if count != 1:
    print(f"{PATH}: expected exactly 1 match for the target block, found {count}", file=sys.stderr)
    sys.exit(1)

with open(PATH, "w") as f:
    f.write(text.replace(ORIGINAL, PATCHED))

print(f"{PATH}: patched (nul-byte CString crash)")
