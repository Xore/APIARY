#!/usr/bin/env python3
"""unplug-pxe-after-delay.sh -- a fixed delay after the VM starts, both
disables the PXE NIC's link AND ejects the bootable Windows ISO, so the
next boot (Windows Setup's own guest-triggered restart) can only possibly
boot the disk.

Why both, not just the NIC: disabling only pxenet0's link stops PXE, but
the Windows install ISO is *also* still attached as a bootable CD-ROM
(packer attaches it as install-source media for Setup's file-copy phase --
removing it outright breaks the install, since that's where install.wim
actually comes from; boot.wim via PXE is WinPE only, not the full image).
Neither the disk nor that CD-ROM gets an explicit bootindex (packer
generates both drives itself; qemuargs can't safely inject a property into
a drive it also auto-adds without creating a duplicate attachment against
the same file), so which one firmware would try next is unspecified
default-enumeration order -- a real risk of booting the installer CD
again instead of the now-bootable disk, the same reinstall-from-scratch
failure mode via a different device. Ejecting the ISO's *media* (QMP
`eject`, not detaching the drive) sidesteps needing bootindex on it at
all: an empty optical drive just isn't a bootable option, so the disk is
the only one left standing.

The autounattend CD (ide2-cd0) is deliberately left alone: it was never
bootable El Torito media, only a data CD Setup reads once during the
specialize pass, so it carries none of the CD1's accidental-reboot risk.

Why a fixed delay instead of reacting to the guest's first RESET event
(the previous approach, pxe/unplug-pxe-on-reset.sh): that approach's
device_del failed structurally, not from a naming bug -- confirmed live,
"Bus 'pcie.0' does not support hotplugging". q35's PCIe root complex does
not support hot-unplugging a device attached directly to it; only devices
on an explicit pcie-root-port bus with hotplug=on do, which the qemuargs
in win11-analysis.pkr.hcl don't set up. set_link and eject both sidestep
that: neither needs hotplug support, since the device/drive stays
present -- only its link state or its media does not.

120s is a fixed budget, not a detected event: confirmed live across
tonight's runs, the initial PXE boot (iPXE -> wimboot -> boot.wim -> WinPE
start) reliably completes well under a minute, so 120s is comfortable
headroom before Windows Setup's own first self-triggered restart, without
being so long that it risks still being mid-transfer if a run is slower
than usual.

Usage: unplug-pxe-after-delay.sh [qmp-socket-path] [delay-seconds] [iso-block-device-id]
Run this alongside (not instead of) the packer build; it just watches and
disables/ejects, it doesn't launch or manage the VM itself. The block
device id defaults to ide1-cd0, confirmed live via `query-block` against a
running build (packer's own drive ordering: ide0-hd0 the disk, ide1-cd0
the Windows ISO, ide2-cd0 the autounattend CD) -- re-check with
`query-block` if win11-analysis.pkr.hcl's drive order ever changes, since
nothing enforces that ordering staying stable.
"""
import json
import socket
import sys
import time

sock_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/win11-analysis-qmp.sock"
delay = float(sys.argv[2]) if len(sys.argv) > 2 else 120
iso_device_id = sys.argv[3] if len(sys.argv) > 3 else "ide1-cd0"


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

    print(f"waiting {delay}s before disabling pxenet0's link and ejecting {iso_device_id}...", flush=True)
    time.sleep(delay)

    send(sock, {"execute": "set_link", "arguments": {"name": "pxenet0", "up": False}})
    result = read_one(sock)
    print(f"set_link result: {result}", flush=True)
    if "error" in result:
        print("set_link failed -- pxenet0 may not exist under that name", file=sys.stderr)

    send(sock, {"execute": "eject", "arguments": {"id": iso_device_id, "force": True}})
    result = read_one(sock)
    print(f"eject result: {result}", flush=True)
    if "error" in result:
        print(f"eject failed -- {iso_device_id} may not exist under that id (re-check with query-block)", file=sys.stderr)
        sys.exit(1)

    print("pxenet0 link disabled and Windows ISO ejected -- next boot can only reach the disk", flush=True)


if __name__ == "__main__":
    main()
