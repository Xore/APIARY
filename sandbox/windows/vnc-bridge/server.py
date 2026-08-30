#!/usr/bin/env python3
"""Read-only VNC viewer bridge for the Windows sandbox's live detonation VM
(#805).

Runs on the sandbox host (needs `virsh`, which the dashboard container never
gets -- IMPLEMENTATION_PLAN.md's rule that the dashboard only ever writes a
spool file and never talks to libvirt/Docker directly applies here too).
Bridges a browser WebSocket to the guest's own VNC server (already enabled
in sandbox/windows/packer/win11-kvm.xml: `<graphics type='vnc' port='-1'
autoport='yes' listen='127.0.0.1'/>`) so an operator can *watch* a live
detonation the way the sandbox's own IMPLEMENTATION_PLAN.md always assumed
was possible, without ever being able to *drive* it.

Read-only is enforced here, at the byte level, not by trusting the browser
client: this module parses the RFB message stream in the client-to-server
direction and only ever forwards SetPixelFormat(0), SetEncodings(2), and
FramebufferUpdateRequest(3) -- the three messages a viewer needs to receive
updates at all. KeyEvent(4), PointerEvent(5), and ClientCutText(6) are
parsed (to stay byte-in-sync with the stream) and their bytes discarded
before ever reaching the VM. Server-to-client bytes (the actual screen
updates) are never filtered -- a VM's own display output cannot inject
input into itself.

Deliberately narrow: this deployment's VNC graphics element sets no
password ("the socket is not reachable" is its own stated security
boundary -- see the XML comment above), so RFB security type 1 (None) is
the only one implemented. Any other negotiated security type closes the
connection rather than silently falling back to unfiltered passthrough --
a fail-closed choice, not an oversight; see SecurityHandshakeUnsupported.

Protocol references: RFC 6143 (The Remote Framebuffer Protocol) and
RFC 6455 (The WebSocket Protocol). No third-party WebSocket or VNC library
-- stdlib only, matching this project's #103/#207/#498-established
convention wherever a script talks to something security-sensitive.

Usage: sandbox/windows/vnc-bridge/server.py
Env:
  VNC_BRIDGE_BIND      default 127.0.0.1 -- HP_BIND-style opt-in, see
                        docs/analysis/ghidra/revdeck/README.md's own
                        "reaching it remotely" section for the exact same
                        pattern applied to a different service.
  VNC_BRIDGE_PORT       default 6090
  VIRSH_PATH            default /usr/bin/virsh
  LIBVIRT_URI           default qemu:///system
  VM_DOMAIN             default win11-sandbox
"""
import base64
import hashlib
import http.server
import os
import re
import socket
import socketserver
import subprocess
import sys
import threading

BIND = os.environ.get("VNC_BRIDGE_BIND", "127.0.0.1")
PORT = int(os.environ.get("VNC_BRIDGE_PORT", "6090"))
VIRSH_PATH = os.environ.get("VIRSH_PATH", "/usr/bin/virsh")
LIBVIRT_URI = os.environ.get("LIBVIRT_URI", "qemu:///system")
VM_DOMAIN = os.environ.get("VM_DOMAIN", "win11-sandbox")

WS_MAGIC = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# RFB client-to-server message types (RFC 6143 §7.5) this bridge will ever
# forward to the real VM. Everything else in the message loop is either
# dropped (KEYEVENT/POINTEREVENT/CLIENTCUTTEXT, parsed to stay in sync) or
# an unrecognised type, which closes the connection.
MSG_SET_PIXEL_FORMAT = 0
MSG_SET_ENCODINGS = 2
MSG_FRAMEBUFFER_UPDATE_REQUEST = 3
MSG_KEY_EVENT = 4
MSG_POINTER_EVENT = 5
MSG_CLIENT_CUT_TEXT = 6
FORWARD_TYPES = {MSG_SET_PIXEL_FORMAT, MSG_SET_ENCODINGS, MSG_FRAMEBUFFER_UPDATE_REQUEST}
DROP_TYPES = {MSG_KEY_EVENT, MSG_POINTER_EVENT, MSG_CLIENT_CUT_TEXT}


class BridgeError(Exception):
    """A condition this bridge refuses to proceed past -- always fail
    closed (drop the connection) rather than guess."""


class SecurityHandshakeUnsupported(BridgeError):
    pass


def resolve_vnc_port() -> int:
    """`virsh vncdisplay <domain>` prints ":N" (or "host:N") for the
    running domain's VNC display; the real TCP port is 5900+N, the
    standard VNC display-to-port convention libvirt itself follows.
    Raises BridgeError if the domain has no live VNC display -- not
    running, or started without graphics."""
    try:
        out = subprocess.run(
            [VIRSH_PATH, "-c", LIBVIRT_URI, "vncdisplay", VM_DOMAIN],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise BridgeError(f"vncdisplay failed for {VM_DOMAIN}: {exc}") from None
    match = re.match(r"^(?:[^:]*:)?(\d+)$", out)
    if not match:
        raise BridgeError(f"unrecognised vncdisplay output: {out!r}")
    return 5900 + int(match.group(1))


# ---------------------------------------------------------------------------
# Minimal RFC 6455 WebSocket framing -- server-side accept handshake, and
# frame encode/decode. No subprotocol negotiation, no fragmentation
# handling beyond concatenating payloads in arrival order (correct for a
# raw byte relay: neither RFB nor this bridge cares about WS message
# boundaries, only about the underlying byte stream they carry).
# ---------------------------------------------------------------------------

def ws_accept_key(client_key: str) -> str:
    digest = hashlib.sha1((client_key.strip() + WS_MAGIC.decode()).encode()).digest()
    return base64.b64encode(digest).decode()


def ws_encode_frame(payload: bytes, opcode: int = 0x2) -> bytes:
    header = bytes([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([length])
    elif length < 65536:
        header += bytes([126]) + length.to_bytes(2, "big")
    else:
        header += bytes([127]) + length.to_bytes(8, "big")
    return header + payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        buf += chunk
    return bytes(buf)


def ws_recv_frame(sock: socket.socket):
    """Returns (opcode, payload) for one client frame, unmasked. Client
    frames are always masked (RFC 6455 §5.1); a client frame that is not
    masked is a protocol violation and raises."""
    head = _recv_exact(sock, 2)
    opcode = head[0] & 0x0F
    masked = head[1] & 0x80
    length = head[1] & 0x7F
    if not masked:
        raise BridgeError("client frame not masked (protocol violation)")
    if length == 126:
        length = int.from_bytes(_recv_exact(sock, 2), "big")
    elif length == 127:
        length = int.from_bytes(_recv_exact(sock, 8), "big")
    mask_key = _recv_exact(sock, 4)
    payload = bytearray(_recv_exact(sock, length))
    for i in range(len(payload)):
        payload[i] ^= mask_key[i % 4]
    return opcode, bytes(payload)


# ---------------------------------------------------------------------------
# RFB stream buffering + client-to-server message filtering.
# ---------------------------------------------------------------------------

class ClientByteStream:
    """Pull-based view over the browser's WebSocket frames as a single RFB
    byte stream. take(n) blocks (by pulling more WS frames) until n bytes
    are available, the same shape a protocol parser needs regardless of
    how the underlying transport happened to chunk the data."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf = bytearray()

    def take(self, n: int) -> bytes:
        while len(self._buf) < n:
            opcode, payload = ws_recv_frame(self._sock)
            if opcode == 0x8:  # close
                raise ConnectionError("client closed")
            if opcode == 0x9:  # ping -- pong the same payload back
                self._sock.sendall(ws_encode_frame(payload, opcode=0xA))
                continue
            if opcode == 0xA:  # pong
                continue
            self._buf += payload
        result = bytes(self._buf[:n])
        del self._buf[:n]
        return result


def negotiate_and_filter(client: ClientByteStream, vm: socket.socket, server_version: bytes) -> None:
    """Walks the RFB pre-message-loop handshake on the client-to-server
    side, forwarding every byte verbatim once it validates (none of it is
    an input event), then enters the message loop and filters per
    FORWARD_TYPES/DROP_TYPES.
    Runs in its own thread; the caller pairs it with an unfiltered
    vm-to-client relay thread.
    """
    client_version = client.take(12)

    # #2280: each handshake step is validated *before* the bytes it
    # validates are relayed on, so a handshake this bridge is going to
    # reject never puts a single byte in front of the VM's VNC server --
    # the VM only ever sees the connection go away. Shutting the VM
    # socket down afterwards is not enough on its own: shutdown() sets
    # EOF but does not retract bytes already queued to the peer.
    #
    # "RFB 003.008\n" -> (3, 8). RFB 3.3 has no client response to the
    # security-type step at all (the server unilaterally picks and sends
    # a 4-byte type, already relayed on the vm-to-client side); 3.7+ has
    # the client choose from a list with a single response byte.
    match = re.match(rb"RFB (\d{3})\.(\d{3})\n", client_version)
    if not match:
        raise BridgeError(f"unrecognised client RFB version: {client_version!r}")
    major, minor = int(match.group(1)), int(match.group(2))

    if (major, minor) < (3, 7):
        # #805: 3.3 never happens in practice against a current QEMU/
        # libvirt VNC server (it offers 3.8), kept only so an unexpected
        # older server fails closed here instead of hanging on a read
        # that will never come.
        raise SecurityHandshakeUnsupported(f"RFB {major}.{minor} (3.3) is not implemented")

    # Accepted: relay it now, not later -- the client is blocked waiting
    # on the security-types list the VM only sends once it has this.
    vm.sendall(client_version)

    chosen_type = client.take(1)
    security_type = chosen_type[0]
    if security_type != 1:
        # Type 2 (VNC auth) and anything else needs its own handshake
        # this bridge does not implement -- see the module docstring for
        # why that is a deliberate fail-closed choice, not a gap to fill
        # in later. This deployment's graphics element sets no password,
        # so type 1 (None) is what a correctly configured host presents.
        raise SecurityHandshakeUnsupported(f"security type {security_type} is not implemented")
    vm.sendall(chosen_type)

    # Type 1 (None): no challenge/response. Straight to ClientInit.
    client_init = client.take(1)
    vm.sendall(client_init)

    # ---- message loop -----------------------------------------------
    while True:
        msg_type = client.take(1)[0]
        if msg_type == MSG_SET_PIXEL_FORMAT:
            body = client.take(19)  # 3 padding + 16 pixel-format
            vm.sendall(bytes([msg_type]) + body)
        elif msg_type == MSG_SET_ENCODINGS:
            head = client.take(3)  # 1 padding + 2 count
            count = int.from_bytes(head[1:3], "big")
            encodings = client.take(4 * count)
            vm.sendall(bytes([msg_type]) + head + encodings)
        elif msg_type == MSG_FRAMEBUFFER_UPDATE_REQUEST:
            body = client.take(9)  # incremental + x + y + w + h
            vm.sendall(bytes([msg_type]) + body)
        elif msg_type == MSG_KEY_EVENT:
            client.take(7)  # down-flag + 2 padding + key -- discarded
        elif msg_type == MSG_POINTER_EVENT:
            client.take(5)  # button-mask + x + y -- discarded
        elif msg_type == MSG_CLIENT_CUT_TEXT:
            head = client.take(7)  # 3 padding + 4 length
            length = int.from_bytes(head[3:7], "big")
            client.take(length)  # text -- discarded
        else:
            raise BridgeError(f"unrecognised RFB client message type {msg_type} -- closing rather than guessing its length")


def run_negotiate_and_filter(client: ClientByteStream, vm: socket.socket, ws: socket.socket,
                              server_version: bytes, log) -> None:
    """Thread target wrapping negotiate_and_filter: it runs in its own
    daemon thread paired with the main thread's relay_vm_to_client, so an
    exception raised inside it (every fail-closed handshake rejection --
    bad protocol version, unsupported security type, unrecognised message
    type) would otherwise die as a bare thread-excepthook traceback while
    the main thread stays blocked forever in vm.recv(), and the browser's
    WebSocket never gets a close frame. shutdown() (not close()) is used
    here because it safely unblocks a recv() another thread is blocked in,
    without the fd-reuse race close() has across threads.
    """
    try:
        negotiate_and_filter(client, vm, server_version)
    except (BridgeError, ConnectionError, OSError) as exc:
        log("closing (handshake): %s", exc)
    finally:
        try:
            ws.sendall(ws_encode_frame((1008).to_bytes(2, "big"), opcode=0x8))
        except OSError:
            pass
        for sock in (vm, ws):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def relay_vm_to_client(vm: socket.socket, ws: socket.socket) -> None:
    """Server-to-client direction: framebuffer updates only. No filtering
    -- a VM's own display output cannot inject input into itself."""
    while True:
        chunk = vm.recv(65536)
        if not chunk:
            return
        ws.sendall(ws_encode_frame(chunk))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args) -> None:
        sys.stderr.write("vnc-bridge: " + (fmt % args) + "\n")

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/vnc":
            self.send_response(404)
            self.end_headers()
            return
        key = self.headers.get("Sec-WebSocket-Key")
        if self.headers.get("Upgrade", "").lower() != "websocket" or not key:
            self.send_response(400)
            self.end_headers()
            return

        try:
            port = resolve_vnc_port()
            vm = socket.create_connection(("127.0.0.1", port), timeout=10)
        except BridgeError as exc:
            self.log_message("%s", exc)
            self.send_response(503)
            self.end_headers()
            return

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", ws_accept_key(key))
        self.end_headers()

        ws = self.connection
        self.log_message("viewer connected -> %s (port %d)", VM_DOMAIN, port)
        try:
            server_version = vm.recv(12)
            ws.sendall(ws_encode_frame(server_version))
            client = ClientByteStream(ws)

            to_vm = threading.Thread(
                target=run_negotiate_and_filter,
                args=(client, vm, ws, server_version, self.log_message),
                daemon=True,
            )
            to_vm.start()
            relay_vm_to_client(vm, ws)
        except (BridgeError, ConnectionError, OSError) as exc:
            self.log_message("closing: %s", exc)
        finally:
            vm.close()
            self.log_message("viewer disconnected -> %s", VM_DOMAIN)


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main() -> None:
    server = ThreadingServer((BIND, PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
