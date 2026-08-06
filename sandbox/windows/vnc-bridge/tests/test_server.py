#!/usr/bin/env python3
"""Exercises the read-only enforcement in server.py's negotiate_and_filter
(#805) -- the one piece of this bridge that must be provably correct: every
KeyEvent/PointerEvent/ClientCutText byte the "client" sends must be
consumed (to stay in sync with the stream) but never reach the "VM" socket,
while the handshake and the three read-only message types must reach it
byte-exact.

Uses a pair of real socket.socketpair()s to stand in for the browser
WebSocket connection and the real VNC TCP connection, so this exercises
the actual WebSocket frame decode + RFB message parsing, not a mock of
either.

Usage: sandbox/windows/vnc-bridge/tests/test_server.py
"""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import server  # noqa: E402

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


def masked_client_frame(payload: bytes) -> bytes:
    """Build one RFC 6455 client->server frame (masked, as every real
    browser produces) carrying payload as a single binary frame."""
    mask_key = bytes([0x11, 0x22, 0x33, 0x44])
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    length = len(payload)
    header = bytes([0x82])  # FIN + binary opcode
    if length < 126:
        header += bytes([0x80 | length])
    else:
        header += bytes([0x80 | 126]) + length.to_bytes(2, "big")
    return header + mask_key + masked


def test_ws_recv_frame_unmasks_correctly():
    client_sock, bridge_sock = socket.socketpair()
    try:
        payload = b"RFB 003.008\n"
        client_sock.sendall(masked_client_frame(payload))
        opcode, decoded = server.ws_recv_frame(bridge_sock)
        check(opcode == 0x2, "opcode decoded as binary")
        check(decoded == payload, f"payload unmasked correctly, got {decoded!r}")
    finally:
        client_sock.close()
        bridge_sock.close()


def test_ws_recv_frame_rejects_unmasked():
    client_sock, bridge_sock = socket.socketpair()
    try:
        # A server-shaped (unmasked) frame arriving on the client path is a
        # protocol violation and must raise, not be silently accepted.
        client_sock.sendall(server.ws_encode_frame(b"not masked"))
        raised = False
        try:
            server.ws_recv_frame(bridge_sock)
        except server.BridgeError:
            raised = True
        check(raised, "unmasked 'client' frame is rejected")
    finally:
        client_sock.close()
        bridge_sock.close()


def rfb_message(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + body


def test_negotiate_and_filter_forwards_allowed_drops_input():
    ws_client, ws_bridge = socket.socketpair()
    vm_bridge, vm_observer = socket.socketpair()

    client_version = b"RFB 003.008\n"
    security_choice = bytes([1])   # type 1: None
    client_init = bytes([1])       # shared

    set_pixel_format = rfb_message(0, b"\x00" * 19)
    key_event = rfb_message(4, b"\x00" * 7)             # must be dropped
    pointer_event = rfb_message(5, b"\x00" * 5)          # must be dropped
    fb_update_request = rfb_message(3, b"\x00" * 9)
    cut_text = rfb_message(6, (0).to_bytes(3, "big") + (5).to_bytes(4, "big") + b"hello")  # must be dropped

    stream = client_version + security_choice + client_init + \
        set_pixel_format + key_event + pointer_event + fb_update_request + cut_text
    ws_client.sendall(masked_client_frame(stream))

    client = server.ClientByteStream(ws_bridge)

    def run():
        try:
            server.negotiate_and_filter(client, vm_bridge, client_version)
        except (server.BridgeError, ConnectionError, OSError):
            pass  # expected once the test closes ws_client below

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    vm_observer.settimeout(5)
    expected = client_version + security_choice + client_init + set_pixel_format + fb_update_request
    received = b""
    try:
        while len(received) < len(expected):
            chunk = vm_observer.recv(4096)
            if not chunk:
                break
            received += chunk
    except socket.timeout:
        pass

    check(received == expected,
          f"only handshake + allowed message types reach the VM socket\n    expected: {expected!r}\n    got:      {received!r}")

    ws_client.close()
    thread.join(timeout=2)
    check(not thread.is_alive(), "filter thread exits when the client connection closes")
    ws_bridge.close()
    vm_bridge.close()
    vm_observer.close()


def test_unrecognised_message_type_closes():
    ws_client, ws_bridge = socket.socketpair()
    vm_bridge, vm_observer = socket.socketpair()

    client_version = b"RFB 003.008\n"
    stream = client_version + bytes([1]) + bytes([1]) + bytes([250])  # 250: no such message type
    ws_client.sendall(masked_client_frame(stream))

    client = server.ClientByteStream(ws_bridge)
    raised = []

    def run():
        try:
            server.negotiate_and_filter(client, vm_bridge, client_version)
        except server.BridgeError:
            raised.append(True)
        except (ConnectionError, OSError):
            pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=5)
    check(raised == [True], "an unrecognised RFB message type raises BridgeError (fail closed), not a guess")

    ws_client.close()
    ws_bridge.close()
    vm_bridge.close()
    vm_observer.close()


def test_non_none_security_type_is_rejected():
    ws_client, ws_bridge = socket.socketpair()
    vm_bridge, _vm_observer = socket.socketpair()

    client_version = b"RFB 003.008\n"
    stream = client_version + bytes([2])  # type 2: VNC auth -- not implemented
    ws_client.sendall(masked_client_frame(stream))

    client = server.ClientByteStream(ws_bridge)
    raised = []

    def run():
        try:
            server.negotiate_and_filter(client, vm_bridge, client_version)
        except server.SecurityHandshakeUnsupported:
            raised.append(True)
        except (ConnectionError, OSError):
            pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=5)
    check(raised == [True], "a non-None security type fails closed instead of falling back to unfiltered passthrough")

    ws_client.close()
    ws_bridge.close()
    vm_bridge.close()


if __name__ == "__main__":
    test_ws_recv_frame_unmasks_correctly()
    test_ws_recv_frame_rejects_unmasked()
    test_negotiate_and_filter_forwards_allowed_drops_input()
    test_unrecognised_message_type_closes()
    test_non_none_security_type_is_rejected()
    if fails:
        print(f"\n{len(fails)} check(s) failed: {fails}")
        sys.exit(1)
    print("\nall checks passed")
