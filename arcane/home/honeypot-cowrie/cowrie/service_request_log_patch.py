#!/usr/bin/env python3
"""Log SSH service requests other than ssh-userauth, with auth state (#3307).

CVE-2026-67279 (MikroTik RouterOS, KEV 2026-09-25): after a client-requested
rekey, RouterOS enters the connection protocol although the client never
authenticated, and honours an `exec` on the resulting channel. A probe for it
rekeys before authenticating and then asks for the `ssh-connection` service
directly.

Cowrie cannot be exploited this way -- Twisted's SSHServerTransport only
offers ssh-userauth before authentication and disconnects on anything else
-- but it also logs nothing when it refuses, so the probe is invisible: 30
days of captures hold two sessions shaped `version > kex > kex > closed`
(a rekey before auth, then a disconnect without one auth attempt), and
nothing records what they asked for.

A legitimate client never sends SERVICE_REQUEST for ssh-connection: it gets
there through a USERAUTH_REQUEST naming that service. So any service request
other than ssh-userauth is a protocol violation worth one event. The normal
ssh-userauth request (every session, ~3,700/day) is deliberately not logged.

Event `cowrie.client.service_request`: service (ASCII, <=64 chars),
authenticated (whether an ssh-connection service is already active), and
kex_count (KEXINITs seen on this transport -- >= 2 means a rekey happened).
`service=ssh-connection, authenticated=false, kex_count>=2` is the
CVE-2026-67279 probe shape.

Applied at image build like txtcmds_priority_patch.py; fails the build if the
pinned upstream text drifts.
"""
from __future__ import annotations

from pathlib import Path

TARGET = Path("/cowrie/cowrie-git/src/cowrie/ssh/transport.py")
MARKER = "# APIARY #3307: service-request log"

# Verbatim from cowrie v3.0.12 (ced855a), src/cowrie/ssh/transport.py.
KEX_OLD = """        hasshAlgorithms, hassh = hassh_client(kexAlgs, encCS, macCS, compCS)

        if self.events:
"""
KEX_NEW = """        hasshAlgorithms, hassh = hassh_client(kexAlgs, encCS, macCS, compCS)
        self._apiary_kex_count = getattr(self, "_apiary_kex_count", 0) + 1

        if self.events:
"""
METHOD_ANCHOR = """        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def timeoutConnection(self) -> None:
"""
METHOD_NEW = """        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

    def ssh_SERVICE_REQUEST(self, packet: bytes) -> Any:
        MARKER_PLACEHOLDER
        service = getNS(packet)[0]
        if service != b"ssh-userauth" and self.events:
            active = getattr(self, "service", None)
            self.events.dispatch(
                "cowrie.client.service_request",
                "SSH service request %(service)s (authenticated=%(authenticated)s, kex=%(kex_count)s)",
                service=service.decode("ascii", "replace")[:64],
                authenticated=getattr(active, "name", None) == b"ssh-connection",
                kex_count=getattr(self, "_apiary_kex_count", 0),
            )
        return transport.SSHServerTransport.ssh_SERVICE_REQUEST(self, packet)

    def timeoutConnection(self) -> None:
""".replace("MARKER_PLACEHOLDER", MARKER)


def apply_patch(target: Path) -> str:
    """Idempotently apply; returns a one-line status. Importable without side
    effects so tests/test_service_request_log_patch.py can run it."""
    text = target.read_text()
    if MARKER in text:
        return f"service_request_log_patch: {target} already patched, skipping"
    for name, old in (("ssh_KEXINIT hassh block", KEX_OLD), ("ssh_KEXINIT return", METHOD_ANCHOR)):
        count = text.count(old)
        if count != 1:
            raise SystemExit(f"service_request_log_patch: expected exactly 1 match for {name} in {target}, found {count}")
    text = text.replace(KEX_OLD, KEX_NEW, 1).replace(METHOD_ANCHOR, METHOD_NEW, 1)
    target.write_text(text)
    return f"service_request_log_patch: patched {target}"


if __name__ == "__main__":
    print(apply_patch(TARGET))
