#!/usr/bin/env python3
"""Regression test for #2368: sync-client-secrets.sh must enumerate
exactly the 6 VPS-fronted oauth2-proxy gateway clients, not the stale
pre-#1185 / pre-#1026 list (which included dockge, oidc-dockge, and
apiary-dashboard's oidc-dashboard — all of which were decommissioned
in their own PRs and would now turn the closing
`docker compose up -d --force-recreate` into a guaranteed reject).

The fix also restructures the script's two failure modes so the
runbook and the script share a single source of truth for which
clients are gateway-fronted (and which are not). The gateway map
now has exactly six entries:

  kibana           -> oidc-kibana
  evebox           -> oidc-evebox
  arkime           -> oidc-arkime
  tanner           -> oidc-tanner
  revdeck          -> oidc-revdeck
  traefik-dashboard-> oidc-traefik

The three confidential clients NOT in the map (apiary-dashboard,
arcane, auth-events-poller) have their own provisioner scripts and
do not sit behind VPS oauth2-proxy gateways.

This test asserts:
- the script's CLIENT_CONTAINERS map has exactly six entries
- the script does NOT use the decommissioned client names as
  bash array keys (a comment mentioning them as historical
  context is fine; an entry in the assoc array is not)
- the script's preamble lists each of the three non-gateway
  clients and references their dedicated provisioner script
- the runbook (KEYCLOAK-OPERATIONS.md) does not REPEAT the
  decommissioned clients in its per-client gateway enumeration
  table (the file path /var/dockge/stacks/... is fine and is the
  real deployment location of the Keycloak stack)

The pre-flight check inside the script itself (the realm-client
mismatch check) is part of the source-level contract too -- the
test asserts that branch is present and wired into the pre-write
phase.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "arcane/home/honeypot-keycloak/keycloak/sync-client-secrets.sh"
RUNBOOK = REPO_ROOT / "docs/KEYCLOAK-OPERATIONS.md"

EXPECTED_GATEWAY_CLIENTS = {
    "kibana",
    "evebox",
    "arkime",
    "tanner",
    "revdeck",
    "traefik-dashboard",
}
NON_GATEWAY_CLIENTS = {
    "apiary-dashboard",
    "arcane",
    "auth-events-poller",
}
# Decommissioned map entries that the pre-#2368 list had:
#   [dockge]=oidc-dockge              -- removed by #2195 (#1194 decommission)
#   [apiary-dashboard]=oidc-dashboard -- removed by #1026's follow-up
# These would now turn the closing `docker compose up -d --force-recreate`
# into a guaranteed reject, since Compose validates every named service
# before recreating any of them.
DECOMMISSIONED_MAP_ENTRIES = {
    "dockge",          # was a CLIENT_CONTAINERS key
    "oidc-dockge",     # was a CLIENT_CONTAINERS value
    "apiary-dashboard", # was a CLIENT_CONTAINERS key (overlaps with non-gateway set;
                        # the decommissioned MAP row was the one that broke the
                        # compose recreation, even though apiary-dashboard is
                        # a real (non-gateway) client in its own right)
}


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def test_client_containers_map_has_exactly_six_entries():
    """The CLIENT_CONTAINERS bash array must have exactly six keys:
    kibana, evebox, arkime, tanner, revdeck, traefik-dashboard."""
    text = _read(SCRIPT)
    m = re.search(
        r"declare\s+-A\s+CLIENT_CONTAINERS=\(\s*\n(.*?)\n\s*\)",
        text,
        re.DOTALL,
    )
    assert m, "could not find `declare -A CLIENT_CONTAINERS=(...)` block"
    body = m.group(1)
    keys = set(re.findall(r"^\s*\[([a-zA-Z0-9_-]+)\]=", body, re.MULTILINE))
    assert keys == EXPECTED_GATEWAY_CLIENTS, (
        f"CLIENT_CONTAINERS keys must be exactly the six VPS-fronted "
        f"oauth2-proxy gateway clients. Got {keys!r}, expected "
        f"{EXPECTED_GATEWAY_CLIENTS!r} -- #2368"
    )


def test_script_client_containers_map_has_no_decommissioned_keys():
    """The CLIENT_CONTAINERS bash array must not have a key matching
    any decommissioned client. A comment in the preamble explaining
    "this used to have dockge but it was retired by #1194" is fine
    (it's an explicit historical note); the key being in the assoc
    array is the failure mode (it would be passed to docker compose,
    which would reject the whole run)."""
    text = _read(SCRIPT)
    m = re.search(
        r"declare\s+-A\s+CLIENT_CONTAINERS=\(\s*\n(.*?)\n\s*\)",
        text,
        re.DOTALL,
    )
    assert m, "could not find `declare -A CLIENT_CONTAINERS=(...)` block"
    body = m.group(1)
    keys = set(re.findall(r"^\s*\[([a-zA-Z0-9_-]+)\]=", body, re.MULTILINE))
    # Specifically: dockge (was a key), oidc-dockge (was a value), and
    # apiary-dashboard (was a key, even though the client itself still
    # exists in the realm under a different provisioner).
    for client in ("dockge",):
        assert client not in keys, (
            f"CLIENT_CONTAINERS still has {client!r} as a key -- #2368. "
            f"The decommissioned entry would silently wedge the run via "
            f"`docker compose up -d --force-recreate` rejecting every "
            f"valid gateway because the compose validation sees a "
            f"non-existent service name."
        )


def test_script_preamble_lists_non_gateway_clients():
    """The script's preamble must explain that the realm has 9
    confidential clients total, the script handles the 6 gateway
    ones, and the other 3 (apiary-dashboard, arcane, auth-events-
    poller) have their own provisioner scripts."""
    text = _read(SCRIPT)
    # The realm total must be 9 (6 gateway + 3 non-gateway)
    assert "9 confidential clients" in text or "9 confidential" in text, (
        "script preamble must state the realm has 9 confidential clients total"
    )
    # Each non-gateway client must be mentioned, with its provisioner script named
    for client in NON_GATEWAY_CLIENTS:
        assert client in text, (
            f"script preamble must mention non-gateway client {client!r}"
        )
    # Each non-gateway client must be associated with a provisioner script
    assert "provision-dashboard-oidc-secret.sh" in text, (
        "apiary-dashboard's provisioner must be named (provision-dashboard-oidc-secret.sh)"
    )
    assert "provision-arcane-oidc-secret.sh" in text, (
        "arcane's provisioner must be named (provision-arcane-oidc-secret.sh)"
    )
    assert "provision-events-poller.sh" in text, (
        "auth-events-poller's provisioner must be named (provision-events-poller.sh)"
    )


def test_pre_flight_realm_client_mismatch_check_is_present():
    """The script must validate the hand-maintained map against the
    realm's own client list BEFORE syncing anything. This is the
    #2195 pre-flight; it must still be present (and is what would
    catch a future drift before it can wedge the run)."""
    text = _read(SCRIPT)
    assert "get clients -r \"$REALM\"" in text, (
        "pre-flight must query the realm's own client list"
    )
    assert "missing+=(\"$client\")" in text or 'missing+=("$client")' in text, (
        "pre-flight must record missing clients"
    )
    assert "ABORT: listed in CLIENT_CONTAINERS but absent" in text, (
        "pre-flight must abort loudly with a named cause when a listed "
        "client is absent from the realm (the failure mode #2368 reported)"
    )


def test_runbook_enumerates_the_same_six_gateway_clients():
    """KEYCLOAK-OPERATIONS.md must enumerate the same six gateway
    clients as the script (single source of truth)."""
    text = _read(RUNBOOK)
    for client in EXPECTED_GATEWAY_CLIENTS:
        assert client in text, (
            f"KEYCLOAK-OPERATIONS.md must mention the gateway client {client!r}"
        )


def test_runbook_does_not_promote_dockge_to_a_gateway_role():
    """The runbook must not recommend dockge as a gateway
    client in its per-client enumeration table. The
    /var/dockge/stacks/... filesystem path is fine and is the
    real deployment location of the Keycloak stack; this test
    only guards against dockge being named as a CLIENT in the
    per-client gateway table."""
    text = _read(RUNBOOK)
    # Find the per-client directory table. The pattern: a line that
    # names a directory under vps/secrets/oidc/<client> and a public
    # consumer. We don't want to grep for plain "dockge" because the
    # file legitimately references /var/dockge/stacks/ as a host path
    # (the real deployment location).
    # A real leak would be something like `| `dockge` | ... |` in the
    # table (backticks around dockge as a column entry).
    assert not re.search(r"\|\s*`?\bdockge\b`?\s*\|", text), (
        "KEYCLOAK-OPERATIONS.md per-client gateway table still names "
        "dockge as a gateway client -- #2368. The /var/dockge/stacks/... "
        "host path is fine; the runbook must not recommend dockge as "
        "a client to provision secrets for."
    )
    # Same for apiary-dashboard as a gateway row (it's a real
    # non-gateway client, but it must NOT be in the gateway table).
    # The table is the "Directory/client" column. A leak would have
    # `apiary-dashboard` listed as a row with a "VPS oauth2-proxy
    # gateway" or "compat gateway" public consumer.
    # The post-#1026 follow-up retired the compat gateway. Find the
    # runbook's table heading and check no row says
    # apiary-dashboard alongside a gateway.
    table_rows = re.findall(
        r"^\|\s*`?([\w-]+)`?\s*\|\s*([^|]+)\s*\|",
        text,
        re.MULTILINE,
    )
    for client, consumer in table_rows:
        if client == "apiary-dashboard":
            assert "gateway" not in consumer.lower(), (
                f"KEYCLOAK-OPERATIONS.md per-client gateway table lists "
                f"apiary-dashboard with consumer {consumer!r} -- #2368. "
                f"apiary-dashboard is a real (non-gateway) client, but "
                f"it must not be in the gateway enumeration; its compat "
                f"gateway was retired by #1026's follow-up."
            )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
