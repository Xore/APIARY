#!/usr/bin/env python3
"""unplug-pxe-on-reset.sh -- hot-unplugs the PXE NIC (pxenet0) the instant
the guest's first self-triggered restart happens.

Why this exists: Windows Setup restarts the guest itself several times
mid-install (ACPI reset within the same qemu process, not a new one).
bootindex=1 on pxenet0 is evaluated fresh on *every* boot including those,
so left alone it re-triggers PXE forever instead of ever continuing into
the disk-resident install already in progress -- confirmed live, an
infinite reinstall-from-scratch loop. `-boot once=n` (the obvious fix) is a
no-op on this OVMF build -- also confirmed live, the boot log showed the
plain default NVRAM order regardless. A static boot-order flag structurally
can't distinguish "first boot of this qemu process" from "the guest reset
itself" -- both look identical to the firmware. Removing the PXE-capable
device entirely once it's no longer needed sidesteps the question rather
than trying to answer it.

QMP's RESET event fires the instant the guest asks for a reset, before
firmware even starts re-enumerating boot options for that next boot -- so
device_del issued right then reliably lands before pxenet0 could be tried
again.

Usage: unplug-pxe-on-reset.sh [qmp-socket-path]
Run this alongside (not instead of) the packer build; it just watches and
unplugs, it doesn't launch or manage the VM itself.
"""
import json
import socket
import sys

sock_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/win11-analysis-qmp.sock"


def send(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


def read_objs(sock):
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            if line.strip():
                yield json.loads(line)


def main():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    objs = read_objs(sock)

    greeting = next(objs)
    print(f"connected: QEMU {greeting.get('QMP', {}).get('version', {}).get('qemu', {})}", flush=True)
    send(sock, {"execute": "qmp_capabilities"})
    ack = next(objs)
    if "error" in ack:
        print(f"qmp_capabilities failed: {ack}", file=sys.stderr)
        sys.exit(1)

    print("watching for guest RESET...", flush=True)
    for obj in objs:
        event = obj.get("event")
        if event is None:
            continue
        print(f"QMP event: {event}", flush=True)
        if event == "RESET":
            print("guest reset detected -- unplugging pxenet0dev", flush=True)
            # The *device* id, not the netdev backend id -- confirmed live,
            # device_del on the netdev id ("pxenet0") fails with
            # "Device 'pxenet0' not found" even though that name is real
            # (it's just the backend, not the qdev/PCI frontend). The
            # frontend needs its own explicit id= on the -device line
            # (win11-analysis.pkr.hcl sets id=pxenet0dev) since QEMU
            # otherwise auto-generates an anonymous one device_del can't
            # target by name at all.
            send(sock, {"execute": "device_del", "arguments": {"id": "pxenet0dev"}})
            result = next(objs)
            print(f"device_del result: {result}", flush=True)
            if "error" in result:
                # Already unplugged (e.g. a second RESET before qemu
                # finished the first device_del) is not a failure worth
                # retrying over.
                print("device_del error (may already be unplugged) -- exiting", flush=True)
            break

    print("done", flush=True)


if __name__ == "__main__":
    main()
