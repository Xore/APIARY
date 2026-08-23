#!/usr/bin/env python3
"""Filter pcap files down to packets touching a set of TCP/UDP ports.

Runs on the capture host so that only matching packets ever cross the
network: scanning gigabytes there costs a few megabytes here.

Why not tcpdump: the VPS has AppArmor enabled, and its tcpdump profile
refuses to read the capture directory even as root -- `head` on the same
file succeeds while `tcpdump -r` returns "Permission denied". Rather than
loosen a security profile on the host, this parses the pcap format
directly. It needs nothing but the standard library.

Deliberately reports counts on stderr rather than failing silently. The
first version of this scan used tcpdump with stderr redirected to
/dev/null and reported "no ICS traffic found" when in fact every single
read had been denied -- an answer indistinguishable from the truth.

Handles Ethernet II with optional 802.1Q/QinQ VLAN tags, IPv4 and IPv6,
TCP and UDP. Anything else is skipped rather than guessed at.
"""

import struct
import sys

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D
PCAP_MAGIC_NS_BE = 0x4DC3B2A1

LINKTYPE_ETHERNET = 1

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)

IPPROTO_TCP = 6
IPPROTO_UDP = 17


def packet_ports(data):
    """Return (sport, dport) for an Ethernet frame, or None if not TCP/UDP."""
    if len(data) < 14:
        return None
    offset = 12
    ethertype = struct.unpack_from("!H", data, offset)[0]
    offset += 2
    # Walk any stack of VLAN tags.
    while ethertype in VLAN_TPIDS:
        if len(data) < offset + 4:
            return None
        ethertype = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4

    if ethertype == ETH_P_IP:
        if len(data) < offset + 20:
            return None
        ver_ihl = data[offset]
        if ver_ihl >> 4 != 4:
            return None
        ihl = (ver_ihl & 0x0F) * 4
        proto = data[offset + 9]
        # Fragments after the first carry no transport header.
        frag = struct.unpack_from("!H", data, offset + 6)[0]
        if frag & 0x1FFF:
            return None
        transport = offset + ihl
    elif ethertype == ETH_P_IPV6:
        if len(data) < offset + 40:
            return None
        proto = data[offset + 6]
        transport = offset + 40
    else:
        return None

    if proto not in (IPPROTO_TCP, IPPROTO_UDP):
        return None
    if len(data) < transport + 4:
        return None
    return struct.unpack_from("!HH", data, transport)


def read_pcap(path):
    """Yield (record_header_bytes, packet_bytes) and expose the link type."""
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            return
        magic = struct.unpack("<I", header[:4])[0]
        if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
            endian = "<"
        elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
            endian = ">"
        else:
            return
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype != LINKTYPE_ETHERNET:
            return
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            ts_sec, ts_usec, incl, orig = struct.unpack(endian + "IIII", rec)
            if incl > 0x00FFFFFF:  # refuse an implausible length rather than allocate it
                return
            data = fh.read(incl)
            if len(data) < incl:
                return
            yield (ts_sec, ts_usec, incl, orig), data


def main():
    if len(sys.argv) < 3:
        print("usage: pcap-port-filter.py <out.pcap> <ports-csv> <in.pcap>...",
              file=sys.stderr)
        return 2

    out_path = sys.argv[1]
    ports = {int(p) for p in sys.argv[2].split(",") if p.strip()}
    inputs = sys.argv[3:]

    scanned = matched = files_with_hits = unreadable = 0

    with open(out_path, "wb") as out:
        # One global header for the merged output: little-endian, microsecond,
        # Ethernet, no snaplen limit.
        out.write(struct.pack("<IHHiIII", PCAP_MAGIC_LE, 2, 4, 0, 0, 262144,
                              LINKTYPE_ETHERNET))
        for path in inputs:
            hits = 0
            try:
                for (ts_sec, ts_usec, incl, orig), data in read_pcap(path):
                    scanned += 1
                    p = packet_ports(data)
                    if p and (p[0] in ports or p[1] in ports):
                        out.write(struct.pack("<IIII", ts_sec, ts_usec, incl, orig))
                        out.write(data)
                        hits += 1
            except (OSError, PermissionError) as exc:
                unreadable += 1
                print(f"unreadable: {path}: {exc}", file=sys.stderr)
                continue
            if hits:
                files_with_hits += 1
                matched += hits

    print(f"scanned_packets={scanned} matched_packets={matched} "
          f"files_with_hits={files_with_hits} files_unreadable={unreadable} "
          f"files_total={len(inputs)}", file=sys.stderr)

    # A run where nothing could be read is a failure, not an empty result.
    if unreadable == len(inputs) and inputs:
        print("every input was unreadable — this is a failure, not 'no traffic'",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
