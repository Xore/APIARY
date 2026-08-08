#!/usr/bin/env python3
"""Ensure every VPS oauth2-proxy callback is allowlisted by its realm client."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REALM = ROOT / "keycloak/realm/apiary-realm.json"
COMPOSE = ROOT / "vps/docker-compose.yml"
PLACEHOLDER = "${OIDC_PUBLIC_DOMAIN:?set OIDC_PUBLIC_DOMAIN}"
PUBLIC_DOMAIN = "example.invalid"


def main() -> None:
    realm = json.loads(REALM.read_text())
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
        normalized = callback.strip().replace(PLACEHOLDER, PUBLIC_DOMAIN)
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
