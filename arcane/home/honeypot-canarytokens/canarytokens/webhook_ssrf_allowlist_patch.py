"""Build-time patch: let this stack's own webhook adapter receive alerts.

canarytokens/channel_output_webhook.py's WEBHOOK_ADDR_VALIDATOR uses
advocate's default SSRF protection, which unconditionally rejects any
webhook_url resolving to an RFC1918 private address (see
advocate/addrvalidator.py's is_ip_allowed -- "if addr_ip.is_private: return
False", no whitelist override applied upstream). That protection exists to
stop an attacker-supplied webhook_url from reaching internal infrastructure.
It doesn't apply to our own deployment: every token this stack creates sets
its own webhook_url to our own adapter service, a fixed value we control,
never attacker input -- so there's nothing to protect against here, and the
unmodified validator would silently blackhole every alert since our adapter
only has a private Docker-network address (no public exposure planned for
it, see arcane/home/honeypot-canarytokens/compose.yml).

Confirmed live: an unpatched build's webhook send failed with "Disallowed
requests to <adapter-url>" for a real self-triggered token before this
patch; the same request succeeds afterward.

Exact-match replace + idempotency marker, same convention as
dionaea/log_rotation_patch.py and hellpot/router_patch.py.
"""

import pathlib
import sys

TARGET = pathlib.Path("/srv/canarytokens/channel_output_webhook.py")
MARKER = "# apiary-patch: RFC1918 webhook targets allowed (self-issued only)"

OLD = (
    "WEBHOOK_ADDR_VALIDATOR = advocate.AddrValidator(port_whitelist=set(range(0, 65535)))"
)
NEW = (
    f"{MARKER}\n"
    "import ipaddress as _ipaddress  # noqa: E402\n"
    "WEBHOOK_ADDR_VALIDATOR = advocate.AddrValidator(\n"
    "    port_whitelist=set(range(0, 65535)),\n"
    "    ip_whitelist={\n"
    "        _ipaddress.ip_network(\"10.0.0.0/8\"),\n"
    "        _ipaddress.ip_network(\"172.16.0.0/12\"),\n"
    "        _ipaddress.ip_network(\"192.168.0.0/16\"),\n"
    "    },\n"
    ")"
)

text = TARGET.read_text()

if MARKER in text:
    sys.exit(0)  # already patched, idempotent no-op

count = text.count(OLD)
if count != 1:
    sys.exit(
        f"webhook_ssrf_allowlist_patch: expected exactly 1 match for the "
        f"validator construction, found {count} in {TARGET}"
    )

TARGET.write_text(text.replace(OLD, NEW, 1))
