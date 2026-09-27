#!/usr/bin/env python3
"""Test cowrie/service_request_log_patch.py (#3307).

The fixture is upstream's real ssh_KEXINIT, dispatchMessage and the start of
timeoutConnection at the pinned commit (ced855a). The behavioural tests exec
the *patched* methods in a stub transport, because what matters is what gets
dispatched and what the decoy answers: nothing for the normal ssh-userauth
request, one event for any other service, a rekey before authentication
attempted recorded on its own, and a channel open before that attempt refused
rather than routed.

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

# Verbatim from cowrie v3.0.12 (ced855a), src/cowrie/ssh/transport.py, :242-268
# for ssh_KEXINIT, :166-192 for dispatchMessage.
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

    def dispatchMessage(self, messageNum: int, payload: bytes) -> None:
        try:
            transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)
        except struct.error:
            # A truncated or garbage message body underflows getNS()/struct
            # parsing inside a handler (any message type: service-request,
            # userauth, channel ops, ...). Real OpenSSH treats this as a fatal
            # protocol error, logging server-side and dropping the connection
            # without a SSH_MSG_DISCONNECT; match that (which also avoids a
            # cowrie-specific disconnect string), and record the probe -- these
            # malformed pre-auth packets are a common exploit/scanner signal.
            if self.events:
                self.events.dispatch(
                    "cowrie.client.malformed_packet",
                    "Malformed SSH packet (message %(messagenum)d, %(datalen)d bytes); disconnecting",
                    messagenum=messageNum,
                    datalen=len(payload),
                    data=payload[:256].hex(),
                )
            self.transport.loseConnection()
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
    def dispatchMessage(self, messageNum, payload):
        self.base_dispatch.append((messageNum, payload))
        return "base-dispatch"
    def sendDisconnect(self, reason, desc):
        self.disconnects.append((reason, desc))

class transport:
    SSHServerTransport = _Base
    DISCONNECT_PROTOCOL_ERROR = 2
'''


class Events:
    def __init__(self):
        self.sent = []

    def dispatch(self, eventid, fmt, **kw):
        self.sent.append((eventid, kw))


class Wire:
    def __init__(self):
        self.lost = 0

    def loseConnection(self):
        self.lost += 1


def kexinit_packet():
    lists = [b"curve25519-sha256", b"ssh-ed25519", b"aes128-ctr", b"aes128-ctr", b"hmac-sha2-256",
             b"hmac-sha2-256", b"none", b"none", b"", b""]
    ns = lambda b: struct.pack(">L", len(b)) + b  # noqa: E731
    return b"\x00" * 16 + b"".join(ns(x) for x in lists) + b"\x00" + b"\x00\x00\x00\x00"


# RFC 4253 section 6: "session", as a client would name the channel type.
CHANNEL_OPEN_SESSION = b"\x00\x00\x00\x0a\x07session\x00\x00\x00\x00\x00\x00\x00\x00"


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
        t.base_dispatch, t.disconnects, t.transport = [], [], Wire()
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
        self.assertEqual(UPSTREAM_FIXTURE.count(patch.CLASS_ANCHOR), 1)
        self.assertEqual(UPSTREAM_FIXTURE.count(patch.DISPATCH_ANCHOR), 1)

    # --- #3307: the auth-phase bypass the advisory describes ---------------
    #
    # The advisory's precondition is a client-requested rekey followed by the
    # connection protocol "even though user authentication was never
    # attempted". Two sessions in 30 days of captures were shaped exactly
    # `version > kex > kex > closed`, and the KEXINIT counter was only ever
    # read back out on a later service request -- so a rekey with no service
    # request produced no event at all.

    def test_rekey_before_any_auth_is_logged_with_no_service_request(self):
        t = self.transport()
        t.ssh_KEXINIT(kexinit_packet())
        self.assertEqual([e for e, _ in t.events.sent], ["cowrie.client.kex"])
        t.ssh_KEXINIT(kexinit_packet())
        # The rekey event is dispatched from the top of ssh_KEXINIT, where
        # the counter is incremented, so it lands between the two KEXINITs'
        # own hassh events. Both carry the session, so the pairing is not lost.
        self.assertEqual(
            [e for e, _ in t.events.sent],
            ["cowrie.client.kex", "cowrie.client.rekey_before_auth", "cowrie.client.kex"],
        )
        self.assertEqual(t.events.sent[1][1], {"kex_count": 2})

    def test_rekey_after_the_userauth_request_is_not_the_bypass_shape(self):
        # The false-positive guard. A client still inside a password guess has
        # attempted authentication, so its rekey is the weaker fact and is not
        # recorded as this probe -- refusing or alerting on it would hit every
        # ordinary session on the fleet.
        t = self.transport()
        t.ssh_KEXINIT(kexinit_packet())
        self.request(t, b"ssh-userauth")
        t.ssh_KEXINIT(kexinit_packet())
        self.assertEqual([e for e, _ in t.events.sent], ["cowrie.client.kex", "cowrie.client.kex"])

    def test_channel_open_before_authentication_is_refused(self):
        t = self.transport()
        t.ssh_KEXINIT(kexinit_packet())
        t.dispatchMessage(90, CHANNEL_OPEN_SESSION)
        self.assertEqual(t.base_dispatch, [], "the base router must never see it")
        self.assertEqual(t.disconnects, [(2, b"channel opened before authentication")])
        self.assertEqual(t.events.sent[-1][0], "cowrie.client.channel_before_auth")
        self.assertEqual(t.events.sent[-1][1], {"kex_count": 1})

    def test_channel_open_is_refused_with_no_event_log_bound(self):
        # The refusal is a property of the decoy, not of the logging. A gate
        # inside `if self.events:` would leave the decoy accepting the probe
        # whenever the event log is not bound.
        t = self.transport()
        t.events = None
        t.dispatchMessage(90, CHANNEL_OPEN_SESSION)
        self.assertEqual(t.base_dispatch, [])
        self.assertEqual(t.disconnects, [(2, b"channel opened before authentication")])

    def test_channel_open_after_the_userauth_request_reaches_the_base_router(self):
        t = self.transport()
        t.ssh_KEXINIT(kexinit_packet())
        self.request(t, b"ssh-userauth")
        t.dispatchMessage(90, CHANNEL_OPEN_SESSION)
        self.assertEqual([m for m, _ in t.base_dispatch], [90])
        self.assertEqual(t.disconnects, [])

    def test_other_messages_are_untouched_by_the_refusal(self):
        # 94 is MSG_CHANNEL_DATA and 50 is MSG_USERAUTH_REQUEST: neither is
        # the channel open, and the guard must not widen into a range.
        t = self.transport()
        t.dispatchMessage(50, b"\x00" * 4)
        t.dispatchMessage(94, b"\x00" * 4)
        self.assertEqual([m for m, _ in t.base_dispatch], [50, 94])
        self.assertEqual(t.disconnects, [])

    def test_authenticated_is_reported_for_a_service_that_names_nothing(self):
        # What the pinned twisted actually has: SSHService.name is None and
        # SSHConnection does not override it, so the old `name ==
        # b"ssh-connection"` test could never be true and the field could not
        # tell an authenticated session from an unauthenticated one.
        class Conn:
            name = None

        t = self.transport(service=Conn())
        self.request(t, b"ssh-connection")
        self.assertTrue(t.events.sent[-1][1]["authenticated"])

    def test_the_userauth_service_installed_is_not_yet_authenticated(self):
        class Auth:
            name = b"ssh-userauth"

        t = self.transport(service=Auth())
        self.request(t, b"ssh-connection")
        self.assertFalse(t.events.sent[-1][1]["authenticated"])

    def test_dispatch_anchor_drift_fails_the_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "transport.py"
            target.write_text(
                UPSTREAM_FIXTURE.replace(
                    "    def dispatchMessage(self, messageNum: int, payload: bytes) -> None:\n",
                    "    def dispatchMessage(self, messageNum, payload) -> None:\n",
                )
            )
            with self.assertRaises(SystemExit):
                patch.apply_patch(target)


if __name__ == "__main__":
    unittest.main()
