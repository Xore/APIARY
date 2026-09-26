#!/usr/bin/env python3
"""Test cowrie/service_request_log_patch.py (#3307).

The fixture is upstream's real ssh_KEXINIT and the start of
timeoutConnection at the pinned commit (ced855a). The behavioural tests exec
the *patched* methods in a stub transport, because what matters is what gets
dispatched: nothing for the normal ssh-userauth request, one event for any
other service, with the auth state and the KEXINIT count that together mark
the CVE-2026-67279 probe.

Usage: python arcane/home/honeypot-cowrie/cowrie/tests/test_service_request_log_patch.py
"""
import importlib.util
import struct
import tempfile
import textwrap
import unittest
from pathlib import Path

PATCH = Path(__file__).resolve().parents[1] / "service_request_log_patch.py"
_spec = importlib.util.spec_from_file_location("service_request_log_patch", PATCH)
patch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(patch)

# Verbatim from cowrie v3.0.12 (ced855a), src/cowrie/ssh/transport.py, :242-268.
UPSTREAM_FIXTURE = '''class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):
    def ssh_KEXINIT(self, packet: bytes) -> Any:
        k = getNS(packet[16:], 10)
        strings, _ = k[:-1], k[-1]
        (kexAlgs, keyAlgs, encCS, _, macCS, _, compCS, _, langCS, _) = (
            s.split(b",") for s in strings
        )

        hasshAlgorithms, hassh = hassh_client(kexAlgs, encCS, macCS, compCS)

        if self.events:
            self.events.dispatch(
                "cowrie.client.kex",
                "SSH client hassh fingerprint: %(hassh)s",
                hassh=hassh,
                hasshAlgorithms=hasshAlgorithms,
                kexAlgs=kexAlgs,
                keyAlgs=keyAlgs,
                encCS=encCS,
                macCS=macCS,
                compCS=compCS,
                langCS=langCS,
            )

        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def timeoutConnection(self) -> None:
        pass
'''

# Stand-ins for the names transport.py imports, and for Twisted's base class.
HARNESS = '''
from typing import Any

def NS(b):
    return struct.pack(">L", len(b)) + b

def getNS(data, count=1):
    out = []
    for _ in range(count):
        (n,) = struct.unpack(">L", data[:4])
        out.append(data[4:4 + n]); data = data[4 + n:]
    return tuple(out) + (data,)

def hassh_client(*a):
    return ("algs", "hassh")

class TimeoutMixin:
    pass

class _Base:
    def ssh_KEXINIT(self, packet):
        return "base-kexinit"
    def ssh_SERVICE_REQUEST(self, packet):
        self.base_calls.append(packet)
        return "base-service"

class transport:
    SSHServerTransport = _Base
'''


class Events:
    def __init__(self):
        self.sent = []

    def dispatch(self, eventid, fmt, **kw):
        self.sent.append((eventid, kw))


def kexinit_packet():
    lists = [b"curve25519-sha256", b"ssh-ed25519", b"aes128-ctr", b"aes128-ctr", b"hmac-sha2-256",
             b"hmac-sha2-256", b"none", b"none", b"", b""]
    ns = lambda b: struct.pack(">L", len(b)) + b  # noqa: E731
    return b"\x00" * 16 + b"".join(ns(x) for x in lists) + b"\x00" + b"\x00\x00\x00\x00"


class PatchTests(unittest.TestCase):
    def patched_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "transport.py"
            target.write_text(UPSTREAM_FIXTURE)
            self.assertIn("patched", patch.apply_patch(target))
            self.assertIn("already patched", patch.apply_patch(target))
            source = target.read_text()
        ns = {"struct": struct}
        exec(textwrap.dedent(HARNESS), ns)
        exec(source, ns)
        return ns["HoneyPotSSHTransport"]

    def transport(self, service=None):
        t = self.patched_class()()
        t.events, t.base_calls, t.service = Events(), [], service
        return t

    def request(self, t, name):
        return t.ssh_SERVICE_REQUEST(struct.pack(">L", len(name)) + name)

    def test_normal_userauth_request_is_not_logged(self):
        t = self.transport()
        t.ssh_KEXINIT(kexinit_packet())
        self.assertEqual(self.request(t, b"ssh-userauth"), "base-service")
        self.assertEqual([e for e, _ in t.events.sent], ["cowrie.client.kex"])

    def test_rekey_then_preauth_connection_request_is_the_probe_shape(self):
        t = self.transport()
        t.ssh_KEXINIT(kexinit_packet())
        t.ssh_KEXINIT(kexinit_packet())  # client-requested rekey, before any auth
        self.request(t, b"ssh-connection")
        eventid, fields = t.events.sent[-1]
        self.assertEqual(eventid, "cowrie.client.service_request")
        self.assertEqual(fields, {"service": "ssh-connection", "authenticated": False, "kex_count": 2})
        self.assertEqual(len(t.base_calls), 1, "Twisted still decides -- the refusal is unchanged")

    def test_authenticated_state_is_reported(self):
        class Conn:
            name = b"ssh-connection"
        t = self.transport(service=Conn())
        self.request(t, b"ssh-connection")
        self.assertTrue(t.events.sent[-1][1]["authenticated"])

    def test_service_name_is_bounded(self):
        t = self.transport()
        self.request(t, b"x" * 500)
        self.assertEqual(len(t.events.sent[-1][1]["service"]), 64)

    def test_drift_fails_the_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "transport.py"
            target.write_text(UPSTREAM_FIXTURE.replace("hassh_client(", "hassh_client_v2("))
            with self.assertRaises(SystemExit):
                patch.apply_patch(target)

    def test_fixture_matches_the_pinned_upstream_anchors(self):
        self.assertEqual(UPSTREAM_FIXTURE.count(patch.KEX_OLD), 1)
        self.assertEqual(UPSTREAM_FIXTURE.count(patch.METHOD_ANCHOR), 1)


if __name__ == "__main__":
    unittest.main()
