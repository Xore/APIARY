#!/usr/bin/env python3
"""Answer the CVE-2026-67279 auth-phase probe the way the decoy should (#3307).

CVE-2026-67279 (MikroTik RouterOS, KEV 2026-09-25): after a client-requested
rekey, RouterOS enters the connection protocol although the client never
attempted user authentication, and honours an `exec` on the resulting channel.
A probe for it rekeys, then asks for the connection protocol directly.

Cowrie cannot be exploited that way today, and that is not because Cowrie
checks. In the pinned stack (cowrie v3.0.12 / twisted 26.4.0, both pinned in
this repository's Dockerfile):

  * `CowrieSSHFactory.services` DOES contain
    `b"ssh-connection": CowrieSSHConnection` -- the connection service is in
    the offer map, not absent from it.
  * `SSHFactory.getService(transport, service)` returns that class when
    `service == b"ssh-userauth" or hasattr(transport, "avatar")`.
  * `SSHTransportBase.dispatchMessage` hands every message numbered >= 50 to
    `self.service.packetReceived(...)` -- whatever service is installed, with
    no auth check of its own. A channel open is message 90.
  * `transport.avatar` is written in exactly one place,
    `SSHUserAuthServer._cbFinishedAuth`, as a side effect of a successful
    login. It is a plain writable instance attribute.

So the entire pre-auth protection of the connection service is
`hasattr(transport, "avatar")`: nothing in this repository sets it and nothing
in this repository checks it. Touch it before authentication completes and a
pre-auth `SERVICE_REQUEST ssh-connection` is answered with MSG_SERVICE_ACCEPT,
`setService(CowrieSSHConnection())` installs the connection service, and the
client's next message 90 is routed straight into it. That is the advisory's
primitive, in the version this fleet pins, one attribute away from live.

This patch gives the decoy an auth fact of its own, read from bytes already on
the wire, and answers the three auth-phase requests the advisory names.

  1. `cowrie.client.service_request` -- a SERVICE_REQUEST for anything but
    `ssh-userauth`, with the auth state and the KEXINIT count. A conforming
    client never sends this: it reaches the connection service through the
    service-name field of USERAUTH_REQUEST instead.

  2. `cowrie.client.channel_before_auth` -- a MSG_CHANNEL_OPEN on a transport
     that has never sent `SERVICE_REQUEST ssh-userauth` is REFUSED. Before
     this, the base router answered it with MSG_UNIMPLEMENTED (when no
     service was installed) or passed it into the userauth service, which has
     no `ssh_CHANNEL_OPEN` handler and drops it -- and either way the
     connection stayed open and the probe was invisible. Now the decoy sends
     MSG_DISCONNECT / DISCONNECT_PROTOCOL_ERROR and ends it, the same
     teardown the neighbouring malformed-packet branch in this very method
     already uses. The refusal does NOT depend on `self.events`: a decoy that
     logged the probe only when an event log happened to be bound would be
     exploitable exactly when it was not.

  3. `cowrie.client.rekey_before_auth` -- a second SSH_MSG_KEXINIT before any
     authentication was attempted. This is the precondition the advisory
     names, and the shape 30 days of captures actually held: two sessions
     shaped `version > kex > kex > closed`, a rekey before auth and then a
     disconnect with no service request and no auth attempt. Those sessions
     produced no event at all before, because the KEXINIT count was only ever
     read back out on a later service request.

The auth fact is `_apiary_userauth`, set when `SERVICE_REQUEST ssh-userauth`
arrives and read everywhere else. It is deliberately the WEAKER of the two
available facts -- "authentication was never attempted", which is the
advisory's own wording -- and not "authentication never succeeded". The
transport cannot see MSG_USERAUTH_SUCCESS: userauth sends it, and it is never
routed back through the transport. A decoy that refused a rekey or a channel
open merely because a login had not landed yet would drop every session that
is still mid-password-guess, which is most of them. The cost is stated rather
than hidden: a client that requests userauth, completes it, and only then
opens a channel is inside its rights and is not refused.

`cowrie.client.service_request`'s `authenticated` field is corrected here too,
because the field cannot be left next to new auth-state work while meaning
nothing. It was read off `self.service.name == b"ssh-connection"`, but
`twisted.conch.ssh.service.SSHService.name` is `None` and
`twisted.conch.ssh.connection.SSHConnection` does not override it in 26.4.0
-- only `SSHUserAuthServer` sets a name, to `b"ssh-userauth"`. So the field
could only ever read False, authenticated or not, and the pre-auth/post-auth
distinction the advisory's Signal A is defined on could not be made from the
event at all. It is now read off the decoy's own fact: a service is installed
and it is not the userauth service. `factory.getService` can only ever return
one of the two keys in `factory.services`, so that is exact rather than a
heuristic. `None` (nothing installed) still reads False, and a service named
`ssh-connection` still reads True, so every existing assertion holds.

(The same drift makes cowrie's own `setService` override inert -- its
`if service.name == b"ssh-connection"` is never true, so the interactive
timeout and the zlib compression setup never run. That is a separate
upstream-version bug with a real effect on session behaviour, and is left
alone here on purpose.)

Detection is byte-pattern matching on the SSH message number and on the
service name. Nothing here deserialises a client-supplied value and nothing is
evaluated: `getNS` is the same length-prefixed reader upstream already calls
on this very packet, the only decode is `.decode("ascii", "replace")` on a
name truncated to 64 characters, and the only comparisons are against literals
in this file.

Applied at image build like txtcmds_priority_patch.py; fails the build if the
pinned upstream text drifts.
"""
from __future__ import annotations

from pathlib import Path

TARGET = Path("/cowrie/cowrie-git/src/cowrie/ssh/transport.py")
MARKER = "# APIARY #3307: auth-phase bypass"

# Verbatim from cowrie v3.0.12 (ced855a), src/cowrie/ssh/transport.py.
CLASS_ANCHOR = """class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):
"""
CLASS_NEW = """class HoneyPotSSHTransport(transport.SSHServerTransport, TimeoutMixin):
    # APIARY #3307: RFC 4253 section 6 MSG_CHANNEL_OPEN. Spelled as a class
    # constant rather than imported from twisted.conch.ssh.connection so the
    # patch adds no module-level import: the test execs this class against
    # stand-ins for every name transport.py imports, and a new import is the
    # one name it cannot stand in for.
    _apiary_msg_channel_open = 90
"""

KEX_OLD = """        hasshAlgorithms, hassh = hassh_client(kexAlgs, encCS, macCS, compCS)

        if self.events:
"""
KEX_NEW = """        hasshAlgorithms, hassh = hassh_client(kexAlgs, encCS, macCS, compCS)
        self._apiary_kex_count = getattr(self, "_apiary_kex_count", 0) + 1
        MARKER_PLACEHOLDER
        if (
            self._apiary_kex_count > 1
            and not getattr(self, "_apiary_userauth", False)
            and self.events
        ):
            self.events.dispatch(
                "cowrie.client.rekey_before_auth",
                "SSH client rekeyed before requesting authentication (kex=%(kex_count)s)",
                kex_count=self._apiary_kex_count,
            )

        if self.events:
""".replace("MARKER_PLACEHOLDER", MARKER)

# The router every message >= 50 reaches. Its own `except struct.error` branch
# already ends malformed pre-auth packets; the guard below is the same
# teardown for a well-formed one that must not be answered at all.
DISPATCH_ANCHOR = """    def dispatchMessage(self, messageNum: int, payload: bytes) -> None:
        try:
            transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)
        except struct.error:
"""
DISPATCH_NEW = """    def dispatchMessage(self, messageNum: int, payload: bytes) -> None:
        # APIARY #3307: the connection protocol is not reachable before
        # authentication has been attempted, by any route. Gating on the
        # decoy's own fact rather than on hasattr(self, "avatar") is the
        # point of the whole patch: the base router routes message 90 to
        # whatever service is installed, and the only thing that has so far
        # stopped an unauthenticated client reaching the connection service
        # is that one attribute, set by a successful login.
        #
        # Same teardown, and the same single one, as the malformed-packet
        # branch immediately below: sendDisconnect() ends the connection and
        # dispatchMessage() returns, and dataReceived()'s packet loop carries
        # on over whatever is left in the buffer exactly as it already does
        # after that branch. Nothing here adds a second way to end a session.
        if messageNum == self._apiary_msg_channel_open and not getattr(
            self, "_apiary_userauth", False
        ):
            if self.events:
                self.events.dispatch(
                    "cowrie.client.channel_before_auth",
                    "SSH channel opened before authentication was requested (kex=%(kex_count)s)",
                    kex_count=getattr(self, "_apiary_kex_count", 0),
                )
            self.sendDisconnect(
                transport.DISCONNECT_PROTOCOL_ERROR,
                b"channel opened before authentication",
            )
            return
        try:
            transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)
        except struct.error:
"""

METHOD_ANCHOR = """        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def timeoutConnection(self) -> None:
"""
METHOD_NEW = """        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def ssh_SERVICE_REQUEST(self, packet: bytes) -> Any:
        MARKER_PLACEHOLDER
        service = getNS(packet)[0]
        if service == b"ssh-userauth":
            # The decoy's own auth fact, and the only one the transport can
            # own: the advisory's "authentication was never attempted".
            self._apiary_userauth = True
        elif self.events:
            self.events.dispatch(
                "cowrie.client.service_request",
                "SSH service request %(service)s (authenticated=%(authenticated)s, kex=%(kex_count)s)",
                service=service.decode("ascii", "replace")[:64],
                authenticated=self._apiary_connection_service_installed(),
                kex_count=getattr(self, "_apiary_kex_count", 0),
            )
        return transport.SSHServerTransport.ssh_SERVICE_REQUEST(self, packet)

    def _apiary_connection_service_installed(self) -> bool:
        # APIARY #3307: a service is installed, and it is not the userauth
        # one. Deliberately not `name == b"ssh-connection"` -- in the pinned
        # twisted that is always False, because SSHService.name is None and
        # SSHConnection does not override it, so the field could not tell an
        # authenticated session from an unauthenticated one.
        active = getattr(self, "service", None)
        return active is not None and getattr(active, "name", None) != b"ssh-userauth"

    def timeoutConnection(self) -> None:
""".replace("MARKER_PLACEHOLDER", MARKER)


def apply_patch(target: Path) -> str:
    """Idempotently apply; returns a one-line status. Importable without side
    effects so tests/test_service_request_log_patch.py can run it."""
    text = target.read_text()
    if MARKER in text:
        return f"service_request_log_patch: {target} already patched, skipping"
    for name, old in (
        ("class header", CLASS_ANCHOR),
        ("ssh_KEXINIT hassh block", KEX_OLD),
        ("dispatchMessage router", DISPATCH_ANCHOR),
        ("ssh_KEXINIT return", METHOD_ANCHOR),
    ):
        count = text.count(old)
        if count != 1:
            raise SystemExit(f"service_request_log_patch: expected exactly 1 match for {name} in {target}, found {count}")
    text = (
        text.replace(CLASS_ANCHOR, CLASS_NEW, 1)
        .replace(KEX_OLD, KEX_NEW, 1)
        .replace(DISPATCH_ANCHOR, DISPATCH_NEW, 1)
        .replace(METHOD_ANCHOR, METHOD_NEW, 1)
    )
    target.write_text(text)
    return f"service_request_log_patch: patched {target}"


if __name__ == "__main__":
    print(apply_patch(TARGET))
