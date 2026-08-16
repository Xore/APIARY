#!/usr/bin/env python3
"""Protocol-level liveness probe for conpot's gevent reactor.

A TCP connect (Docker's built-in "is the port open" check, or `nc -z`) is not
enough: conpot's gevent event loop can wedge in a single-threaded busy state
that still completes the three-way handshake -- the kernel backlog does that
without any help from the process -- while never servicing a single byte.
That is the exact failure observed in #111: 101% CPU, the listen socket still
accepting connections, zero log output for 51 minutes. Each probe below sends
a real, well-formed request for the one protocol this container's
CONPOT_TEMPLATE speaks and requires a real response within a short timeout,
which only a live reactor can produce.

Every request/response shape here was verified against the actual image
(dtagdevsec/conpot:24.04 plus this repo's patches) rather than assumed from
protocol docs -- see the commit that added this file.

Usage: healthcheck.py <modbus|iec104|guardian_ast|kamstrup> [port]
"""
import socket
import struct
import sys

TIMEOUT = 4.0


def _recv(sock, minimum=1):
    sock.settimeout(TIMEOUT)
    data = sock.recv(256)
    if len(data) < minimum:
        raise ValueError(f"short response: {data!r}")
    return data


def probe_modbus(port):
    # MBAP header (arbitrary transaction id, protocol id 0, length 6, unit 2)
    # + function 0x03 (Read Holding Registers), address 40001, quantity 1.
    #
    # #725: unit 1 (this stack's s7_200/s7_1200/s7_1500 templates all define
    # the same layout) has no HOLDING_REGISTERS block at all, so a read
    # there always came back as Modbus exception 0x02 (illegal data
    # address) -- a well-formed, correctly-answered request, but conpot's
    # own slave.py logs every such exception at ERROR, indistinguishable
    # from a real attacker probing an invalid address. Unit 2, address
    # 40001 is the one block these templates actually populate (confirmed
    # live against hp-conpot/-s7-1200/-s7-1500), so this probe now gets a
    # real 0x03 success reply and produces zero exception-path log noise.
    req = struct.pack(">HHHB", 0x4842, 0x0000, 6, 0x02) + bytes(
        [0x03, 0x9C, 0x41, 0x00, 0x01]
    )
    with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as s:
        s.sendall(req)
        resp = _recv(s, minimum=8)
    if resp[7] != 0x03:
        raise ValueError(f"unexpected modbus response: {resp!r}")


def probe_iec104(port):
    # U-format STARTDT act; a live server always answers with STARTDT con.
    req = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
    with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as s:
        s.sendall(req)
        resp = _recv(s, minimum=6)
    if resp[:3] != bytes([0x68, 0x04, 0x0B]):
        raise ValueError(f"unexpected IEC104 response: {resp!r}")


def probe_guardian_ast(port):
    req = b"\x01I20100\r\n"
    with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as s:
        s.sendall(req)
        _recv(s, minimum=2)
        # #333: unlike this file's other single-exchange protocols,
        # guardian_ast_server.py's handle() keeps the session open in its
        # own while-True loop, expecting a next command over the same
        # connection. Exiting the `with` block right after the minimum read
        # above can abandon still-arriving response bytes (the full I20100
        # report is longer than the 2-byte minimum), which makes the kernel
        # send a TCP RST on close instead of a clean FIN -- confirmed live:
        # the server's next sock.recv() on that same session then raised
        # ConnectionResetError every single healthcheck cycle (60s),
        # logged as an ERROR-level traceback for a completely benign,
        # expected disconnect. Half-closing the write side first tells the
        # server plainly "no more commands coming" -- its own
        # `if not request: break` already handles that cleanly -- and
        # draining until it closes its end avoids the RST entirely.
        s.shutdown(socket.SHUT_WR)
        while s.recv(4096):
            pass


def probe_kamstrup(port):
    # GetRegisters(register 13), CRC16/XMODEM-framed and byte-stuffed per the
    # protocol's own escaping rule. Register 13 is one of the four numeric
    # registers this stack's persona sets in conpot/persona_patch.py; an
    # unpatched default register can hit an upstream template bug where a
    # float register value crashes the response serializer (found while
    # building this probe -- see the commit that fixed persona_patch.py's
    # guardian_ast vol1-4 for the same class of bug).
    from binascii import crc_hqx  # CRC-16/XMODEM, verified against crc16pure

    comm_addr, command_byte, register = 0x3F, 0x10, 13
    body = bytes([comm_addr, command_byte, 0x01, 0x00, register])
    crc = crc_hqx(body, 0)
    full = body + bytes([(crc >> 8) & 0xFF, crc & 0xFF])
    need_escape = {0x06, 0x0D, 0x1B, 0x40, 0x80}
    stuffed = bytearray()
    for b in full:
        if b in need_escape:
            stuffed += bytes([0x1B, b ^ 0xFF])
        else:
            stuffed.append(b)
    req = bytes([0x80]) + bytes(stuffed) + bytes([0x0D])
    with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as s:
        s.sendall(req)
        resp = _recv(s, minimum=2)
    if resp[0] != 0x40:
        raise ValueError(f"unexpected kamstrup response: {resp!r}")


PROBES = {
    "modbus": (probe_modbus, 502),
    "iec104": (probe_iec104, 2404),
    "guardian_ast": (probe_guardian_ast, 10001),
    "kamstrup": (probe_kamstrup, 1025),
}


def main(argv):
    if len(argv) < 2 or argv[1] not in PROBES:
        print(f"usage: {argv[0]} <{'|'.join(PROBES)}> [port]", file=sys.stderr)
        return 2
    probe, default_port = PROBES[argv[1]]
    port = int(argv[2]) if len(argv) > 2 else default_port
    try:
        probe(port)
    except Exception as e:
        print(f"unhealthy: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
