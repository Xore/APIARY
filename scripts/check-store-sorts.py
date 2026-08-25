#!/usr/bin/env python3
"""Check every store list's sort field against the live Elasticsearch mapping.

A store list is paged with `sort: [{field: {..., unmapped_type: ...}}]`. That
`unmapped_type` exists so a deployment where the index has not been created
yet gets an empty list instead of an error -- but it also means a field the
documents do not actually have sorts every hit as null rather than failing.
The list then comes back in no order at all, and nothing anywhere says so.

Three shipped that way (#1566): ml-anomalies asked for `timestamp` where the
worker writes `@timestamp`, auth-events asked for `last_seen` where Keycloak
writes `@timestamp`, and static-analysis asked for `Analysis.GeneratedUTC`,
which its documents do not carry in any spelling.

CI cannot see Elasticsearch, so this is not a CI check -- run it against a
real cluster after a deploy, or when adding a store:

    ssh homeserver "docker exec hp-elasticsearch curl -s \\
        'http://localhost:9200/_mapping'" > mappings.json
    python scripts/check-store-sorts.py mappings.json

Exits non-zero if any store's sort field is missing from an index that
exists. An index that does not exist on this deployment is reported and
skipped -- that is the case `unmapped_type` is legitimately for.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORES_RS = ROOT / "arcane/home/honeypot-dashboard/backend-service/src/stores.rs"

# ("index", "sort field", "type", ...) in the generic store table, and the
# direct store_page(&state, &["index"], "field", "type", ...) callers.
TABLE_ENTRY = re.compile(
    r'=>\s*\(\s*"(?P<index>[^"]+)"\s*,\s*"(?P<field>[^"]+)"\s*,\s*"(?P<kind>[^"]+)"',
)
DIRECT_CALL = re.compile(
    r'store_page(?:_excluding)?\(\s*&state,\s*&\[\s*"(?P<index>[^"]+)"\s*\]\s*,'
    r'\s*"(?P<field>[^"]+)"\s*,\s*"(?P<kind>[^"]+)"',
)


def declared_sorts(source: str) -> list[tuple[str, str, str]]:
    seen: dict[tuple[str, str], str] = {}
    for pattern in (TABLE_ENTRY, DIRECT_CALL):
        for match in pattern.finditer(source):
            seen[(match["index"], match["field"])] = match["kind"]
    return sorted((index, field, kind) for (index, field), kind in seen.items())


def field_type(properties: dict, dotted: str) -> str | None:
    """Resolve a possibly-dotted field path through a mapping's properties."""
    cursor = properties
    parts = dotted.split(".")
    for depth, part in enumerate(parts):
        if part not in cursor:
            return None
        node = cursor[part]
        if depth == len(parts) - 1:
            return node.get("type", "object")
        cursor = node.get("properties", {})
    return None


def indices_matching(mappings: dict, name: str) -> list[tuple[str, dict]]:
    """Concrete indices behind a name, which may be an alias or a datastream."""
    exact = [(key, value) for key, value in mappings.items() if key == name]
    if exact:
        return exact
    # A datastream-backed name appears as .ds-<name>-<date>-<seq>.
    return [(key, value) for key, value in mappings.items() if key.startswith(f".ds-{name}-")]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    mappings = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

    problems: list[str] = []
    skipped: list[str] = []
    checked = 0

    for index, field, kind in declared_sorts(STORES_RS.read_text(encoding="utf-8")):
        concrete = indices_matching(mappings, index)
        if not concrete:
            skipped.append(f"{index}: not present on this deployment (sort={field})")
            continue
        for name, body in concrete:
            actual = field_type(body.get("mappings", {}).get("properties", {}), field)
            checked += 1
            if actual is None:
                problems.append(
                    f"{name}: sort field {field!r} is not in the mapping -- "
                    "every hit sorts as null and the list is unordered"
                )
            elif actual != kind and not (actual, kind) in {("float", "double"), ("integer", "long"), ("half_float", "double")}:
                problems.append(
                    f"{name}: sort field {field!r} is mapped as {actual!r} but "
                    f"declared as {kind!r} -- unmapped_type must match the real type"
                )

    for line in skipped:
        print(f"  skipped: {line}")
    if problems:
        print(f"\nStore sort check failed ({checked} checked):", file=sys.stderr)
        for problem in sorted(set(problems)):
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"\nStore sort check passed ({checked} sort fields verified against live mappings).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
