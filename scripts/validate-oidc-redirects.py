#!/usr/bin/env python3
"""Ensure every VPS oauth2-proxy callback is allowlisted by its realm client."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REALM = ROOT / "keycloak/realm/apiary-realm.json"
COMPOSE = ROOT / "vps/docker-compose.yml"
VPS_ENV_EXAMPLE = ROOT / "vps/.env.example"
KEYCLOAK_ENV_EXAMPLE = ROOT / "keycloak.env.example"
PLACEHOLDER = "${OIDC_PUBLIC_DOMAIN:?set OIDC_PUBLIC_DOMAIN}"
REALM_TEMPLATE_DOMAIN = "example.invalid"


def read_env_value(path: Path, key: str) -> str:
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"{key} not found in {path}")


def main() -> None:
    # The two domains below are independently configured -- oauth2-proxy's
    # redirect_uri is built from OIDC_PUBLIC_DOMAIN (vps/.env.example), while
    # the realm template's own placeholder domain is rewritten at Keycloak
    # startup using KEYCLOAK_PUBLIC_DOMAIN (keycloak.env.example). If an
    # operator sets these to two different values, Keycloak registers
    # redirect_uris the gateways never actually send, and every login fails
    # with invalid_redirect_uri. This is exactly what #1018 found: the
    # checked-in example files disagreed with each other.
    oidc_public_domain = read_env_value(VPS_ENV_EXAMPLE, "OIDC_PUBLIC_DOMAIN")
    keycloak_public_domain = read_env_value(KEYCLOAK_ENV_EXAMPLE, "KEYCLOAK_PUBLIC_DOMAIN")
    if oidc_public_domain != keycloak_public_domain:
        raise SystemExit(
            "domain mismatch: vps/.env.example's OIDC_PUBLIC_DOMAIN="
            f"{oidc_public_domain!r} does not match keycloak.env.example's "
            f"KEYCLOAK_PUBLIC_DOMAIN={keycloak_public_domain!r} -- oauth2-proxy "
            "would send a redirect_uri the realm never registers."
        )

    realm_text = REALM.read_text()
    # Simulate the exact substitution docker-compose.keycloak.yml's startup
    # command performs (`sed s/example\.invalid/$KEYCLOAK_PUBLIC_DOMAIN/g`) so
    # the redirectUris checked below match what Keycloak will actually import.
    realm = json.loads(realm_text.replace(REALM_TEMPLATE_DOMAIN, keycloak_public_domain))
    allowed = {
        client["clientId"]: set(client.get("redirectUris", []))
        for client in realm.get("clients", [])
    }
    compose = COMPOSE.read_text()
    gateways = re.findall(
        r"OAUTH2_PROXY_CLIENT_ID:\s*([^\s#]+).*?"
        r"OAUTH2_PROXY_REDIRECT_URL:\s*([^\n#]+)",
        compose,
        flags=re.DOTALL,
    )
    if not gateways:
        raise SystemExit("no OIDC gateways found in VPS Compose")

    failures: list[str] = []
    seen: set[str] = set()
    for client_id, callback in gateways:
        if client_id in seen:
            failures.append(f"duplicate gateway client: {client_id}")
        seen.add(client_id)
        normalized = callback.strip().replace(PLACEHOLDER, oidc_public_domain)
        if client_id not in allowed:
            failures.append(f"gateway has no realm client: {client_id}")
        elif normalized not in allowed[client_id]:
            failures.append(
                f"{client_id} callback is not allowlisted: {normalized}"
            )

    if failures:
        raise SystemExit("\n".join(failures))
    print(f"OIDC redirect validation passed for {len(gateways)} gateways.")


if __name__ == "__main__":
    main()
