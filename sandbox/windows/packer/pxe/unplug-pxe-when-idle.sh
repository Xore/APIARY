#!/usr/bin/env python3
"""unplug-pxe-when-idle.sh -- ejects the Windows install ISO (ide1-cd0) once
Setup has genuinely finished reading from it, closing the same boot-order
gap unplug-pxe-on-reset.sh's own PXE-NIC removal leaves open.

Why this is needed on top of the PXE-NIC unplug: neither the disk
(ide0-hd0) nor the install ISO (ide1-cd0) gets an explicit bootindex --
packer generates both drives itself, and qemuargs can't safely inject a
property into a drive it also auto-adds without creating a duplicate
attachment against the same file. So once pxenet0 is gone, which of those
two firmware tries next on the guest's *next* self-triggered reset is
unspecified default-enumeration order -- confirmed live (#953, and
reproduced independently rebuilding win11-analysis.qcow2 for #1123): a
reset landed back on the install ISO instead of the now-bootable disk,
and Windows Setup -- booting fresh from the ISO and finding an existing
install on the target disk -- asked whether to reinstall from scratch.
Left alone, that would have wiped the entire in-progress build. An empty
optical drive just isn't a bootable option, so ejecting the ISO once it's
no longer needed removes the ambiguity entirely instead of needing a
bootindex packer's own drive-attachment model won't allow.

Why *poll for idle* instead of a fixed delay: a fixed delay
(pxe/unplug-pxe-after-delay.sh's approach, used by win11-cape's build for
a different reason -- see that script's own header) is a guess, and
guessing this specific delay already broke two live win11-analysis builds
during #953's own investigation: once because the delay fired before
Setup's WIM-apply had actually finished reading the ISO (ejecting
mid-read), and once because a retry attempt's fresh QMP socket needed the
watcher relaunched with the same guess re-applied under different timing.
Polling QMP `query-blockstats` on ide1-cd0's own `rd_bytes` instead reacts
to what Setup is actually doing: wait for read activity to start (so this
can't fire before Setup ever touches the ISO), then wait for it to hold
perfectly steady across several consecutive polls (so it can't fire while
a read is merely paused between files) before ejecting.

Usage: unplug-pxe-when-idle.sh [qmp-socket-path] [cdrom-device]
Run this alongside (not instead of) unplug-pxe-on-reset.sh and the packer
build itself; it just watches and ejects, it doesn't launch or manage the
VM. Like that script, this must be relaunched for every build-with-retry.sh
attempt -- a retry starts an entirely new VM with a fresh QMP socket, and
an old watcher does not carry over.
"""
import json
import socket
import sys
import time

sock_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/win11-analysis-qmp.sock"
cdrom_device = sys.argv[2] if len(sys.argv) > 2 else "ide1-cd0"

POLL_INTERVAL_SECS = 20
IDLE_POLLS_REQUIRED = 5


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


def read_reply(objs):
    # query-blockstats/eject replies interleave with unrelated async events
    # on the same connection (VNC_CONNECTED, RESET, ...) -- skip anything
    # without a "return"/"error" key rather than assuming the next line on
    # the wire is necessarily this command's own reply.
    for obj in objs:
        if "return" in obj or "error" in obj:
            return obj


def rd_bytes_for(objs, sock, device):
    send(sock, {"execute": "query-blockstats"})
    reply = read_reply(objs)
    if reply is None or "error" in reply:
        return None
    for entry in reply["return"]:
        if entry.get("device") == device:
            return entry["stats"]["rd_bytes"]
    return None


def main():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    objs = read_objs(sock)

    greeting = next(objs)
    print(f"connected: QEMU {greeting.get('QMP', {}).get('version', {}).get('qemu', {})}", flush=True)
    send(sock, {"execute": "qmp_capabilities"})
    ack = read_reply(objs)
    if ack is None or "error" in ack:
        print(f"qmp_capabilities failed: {ack}", file=sys.stderr)
        sys.exit(1)

    print(f"watching {cdrom_device} for read activity, then idle...", flush=True)

    last = rd_bytes_for(objs, sock, cdrom_device)
    started_reading = False
    idle_polls = 0
    while True:
        time.sleep(POLL_INTERVAL_SECS)
        current = rd_bytes_for(objs, sock, cdrom_device)
        if current is None:
            # Device already gone (e.g. ejected some other way, or the
            # attempt ended) -- nothing left to watch.
            print(f"{cdrom_device} no longer present -- exiting", flush=True)
            return

        if not started_reading:
            if current > (last or 0):
                started_reading = True
                print(f"{cdrom_device}: read activity detected (rd_bytes {last} -> {current})", flush=True)
            last = current
            continue

        if current == last:
            idle_polls += 1
            print(f"{cdrom_device}: idle poll {idle_polls}/{IDLE_POLLS_REQUIRED} (rd_bytes steady at {current})", flush=True)
            if idle_polls >= IDLE_POLLS_REQUIRED:
                break
        else:
            idle_polls = 0
        last = current

    print(f"{cdrom_device}: idle confirmed -- ejecting", flush=True)
    send(sock, {"execute": "eject", "arguments": {"device": cdrom_device, "force": True}})
    result = read_reply(objs)
    print(f"eject result: {result}", flush=True)
    if result is not None and "error" in result:
        print("eject error (may already be ejected) -- exiting", flush=True)

    print("done", flush=True)


if __name__ == "__main__":
    main()
