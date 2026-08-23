#!/usr/bin/env python3
"""Build a tiny pcap containing one HTTP download of a binary payload.

Exists because the file-extraction policy (vps/zeek/extract.zeek, #1738) is
easy to verify negatively and hard to verify positively: real capture samples
are dominated by text/html and text/plain, which the policy deliberately
skips, so "nothing was extracted" is the expected result almost everywhere and
is indistinguishable from a broken script.

This produces the case that *must* extract -- an HTTP response carrying
application/octet-stream -- so the policy can be regression-tested without
waiting for a real payload delivery to show up in a sample.

Checksums are left zero; Zeek is run with -C in this lab, which is also how it
runs against the VPS's offload-enabled capture.
"""

import struct
import sys

ATTACKER = bytes([203, 0, 113, 9])       # RFC 5737 documentation ranges, so
DECOY = bytes([198, 51, 100, 20])        # the fixture can never look like real
ATTACKER_PORT = 51544                    # captured traffic.
DECOY_PORT = 80

PAYLOAD = bytes(range(256)) * 8          # 2048 bytes, no recognisable magic


def ipv4(payload, src, dst, proto=6):
    total = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0x1234, 0x4000, 64, proto, 0, src, dst,
    )
    return header + payload


def tcp(payload, sport, dport, seq, ack, flags):
    # data offset 5 (20 bytes), no options
    header = struct.pack(
        "!HHIIBBHHH",
        sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0,
    )
    return header + payload


def ethernet(payload):
    return (bytes.fromhex("020000000002") + bytes.fromhex("020000000001")
            + struct.pack("!H", 0x0800) + payload)


def frame(src, dst, sport, dport, seq, ack, flags, payload=b""):
    return ethernet(ipv4(tcp(payload, sport, dport, seq, ack, flags), src, dst))


FIN, SYN, ACK, PSH = 0x01, 0x02, 0x10, 0x08


def build():
    packets = []
    cseq, sseq = 1000, 5000

    # Handshake.
    packets.append(frame(ATTACKER, DECOY, ATTACKER_PORT, DECOY_PORT, cseq, 0, SYN))
    packets.append(frame(DECOY, ATTACKER, DECOY_PORT, ATTACKER_PORT, sseq, cseq + 1, SYN | ACK))
    cseq += 1
    sseq += 1
    packets.append(frame(ATTACKER, DECOY, ATTACKER_PORT, DECOY_PORT, cseq, sseq, ACK))

    request = (b"GET /update.bin HTTP/1.1\r\n"
               b"Host: news.honeypot.example\r\n"
               b"User-Agent: curl/8.5.0\r\n"
               b"Accept: */*\r\n\r\n")
    packets.append(frame(ATTACKER, DECOY, ATTACKER_PORT, DECOY_PORT, cseq, sseq, PSH | ACK, request))
    cseq += len(request)

    response = (b"HTTP/1.1 200 OK\r\n"
                b"Server: nginx\r\n"
                b"Content-Type: application/octet-stream\r\n"
                + b"Content-Length: " + str(len(PAYLOAD)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n") + PAYLOAD
    packets.append(frame(DECOY, ATTACKER, DECOY_PORT, ATTACKER_PORT, sseq, cseq, PSH | ACK, response))
    sseq += len(response)

    packets.append(frame(DECOY, ATTACKER, DECOY_PORT, ATTACKER_PORT, sseq, cseq, FIN | ACK))
    packets.append(frame(ATTACKER, DECOY, ATTACKER_PORT, DECOY_PORT, cseq, sseq + 1, FIN | ACK))
    return packets


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "extract-fixture.pcap"
    with open(out, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for i, packet in enumerate(build()):
            # Monotonic, deterministic timestamps -- a fixture that changes
            # between runs is not a fixture.
            fh.write(struct.pack("<IIII", 1787500000 + i, 0, len(packet), len(packet)))
            fh.write(packet)
    print(f"wrote {out}: {len(build())} packets, {len(PAYLOAD)}-byte octet-stream body")


if __name__ == "__main__":
    main()
