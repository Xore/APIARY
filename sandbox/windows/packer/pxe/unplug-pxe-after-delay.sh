#!/usr/bin/env python3
"""unplug-pxe-after-delay.sh -- disables the PXE NIC's link a fixed delay
after the VM starts, so the next boot (Windows Setup's own guest-triggered
restart) can't reach PXE and falls through to the disk instead.

Why a fixed delay instead of reacting to the guest's first RESET event
(the previous approach, pxe/unplug-pxe-on-reset.sh): that approach's
device_del failed structurally, not from a naming bug -- confirmed live,
"Bus 'pcie.0' does not support hotplugging". q35's PCIe root complex does
not support hot-unplugging a device attached directly to it; only devices
on an explicit pcie-root-port bus with hotplug=on do, which the qemuargs
in win11-analysis.pkr.hcl don't set up. Rather than restructure the PCIe
topology just to make device_del work, this disables the NIC's *link*
instead (QMP `set_link`), which needs no hotplug support at all -- the
device stays present, but DHCP/PXE simply gets no carrier, so BdsDxe's PXE
attempt fails cleanly and falls through to the next boot option (the disk,
which by 120s in has had time to become the real bootable one).

120s is a fixed budget, not a detected event: confirmed live across
tonight's runs, the initial PXE boot (iPXE -> wimboot -> boot.wim -> WinPE
start) reliably completes well under a minute, so 120s is comfortable
headroom before Windows Setup's own first self-triggered restart, without
being so long that it risks still being mid-transfer if a run is slower
than usual.

Usage: unplug-pxe-after-delay.sh [qmp-socket-path] [delay-seconds]
Run this alongside (not instead of) the packer build; it just watches and
disables a link, it doesn't launch or manage the VM itself.
"""
import json
import socket
import sys
import time

sock_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/win11-analysis-qmp.sock"
delay = float(sys.argv[2]) if len(sys.argv) > 2 else 120


def send(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


def read_one(sock):
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("QMP socket closed")
        buf += chunk
    line, _ = buf.split(b"\n", 1)
    return json.loads(line)


def main():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)

    greeting = read_one(sock)
    print(f"connected: QEMU {greeting.get('QMP', {}).get('version', {}).get('qemu', {})}", flush=True)
    send(sock, {"execute": "qmp_capabilities"})
    ack = read_one(sock)
    if "error" in ack:
        print(f"qmp_capabilities failed: {ack}", file=sys.stderr)
        sys.exit(1)

    print(f"waiting {delay}s before disabling pxenet0's link...", flush=True)
    time.sleep(delay)

    send(sock, {"execute": "set_link", "arguments": {"name": "pxenet0", "up": False}})
    result = read_one(sock)
    print(f"set_link result: {result}", flush=True)
    if "error" in result:
        print("set_link failed -- pxenet0 may not exist under that name", file=sys.stderr)
        sys.exit(1)

    print("pxenet0 link disabled -- next boot will fail PXE and fall through to disk", flush=True)


if __name__ == "__main__":
    main()
