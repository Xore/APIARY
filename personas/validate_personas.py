#!/usr/bin/env python3
"""Fail when persona IDs collide, required metadata is missing, or Cowrie leaks its retired identity."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads((Path(__file__).parent / "personas.json").read_text(encoding="utf-8"))
personas = manifest["personas"]
required = {"organization", "site_id", "asset_id", "services"}
errors = []
seen_services = {}
for persona_id, persona in personas.items():
    missing = sorted(required - persona.keys())
    if missing:
        errors.append(f"{persona_id}: missing {', '.join(missing)}")
    for service in persona.get("services", []):
        if service in seen_services:
            errors.append(f"service {service} assigned to both {seen_services[service]} and {persona_id}")
        seen_services[service] = persona_id

# Cowrie is deliberately one coherent GPU-node story. These strings belonged
# to the retired web-server persona and must never reappear in attacker-facing files.
retired = (
    "web-03", "Meridian Retail", "meridian-portal", "meridian.internal",
    "meridian.example", "portal-noreply", "Debian 12",
)
for path in (ROOT / "cowrie").rglob("*"):
    if not path.is_file() or path.name == "README-fs.md":
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for marker in retired:
        if marker.lower() in text.lower():
            errors.append(f"{path.relative_to(ROOT)}: retired Cowrie marker {marker!r}")

# Every canonical ID must be wired into at least one emitter or enrichment
# surface, and SNARE must remain a deterministic repository-owned persona.
compose_path = ROOT / "docker-compose.yml"
if not compose_path.exists():  # Dockge deploys the repository file as compose.yml.
    compose_path = ROOT / "compose.yml"
surfaces = [
    compose_path, ROOT / "analysis/filebeat.yml",
    ROOT / "dashboard/main.go", ROOT / "multipot/main.go",
    ROOT / "http-honeypot/main.go", ROOT / "dnp3-honeypot/main.go",
]
wiring = "\n".join(path.read_text(encoding="utf-8") for path in surfaces)
for persona_id in personas:
    if persona_id not in wiring:
        errors.append(f"{persona_id}: not wired into an event/enrichment surface")
if "SNARE_TARGET" in compose_path.read_text(encoding="utf-8"):
    errors.append(f"{compose_path.name}: live-site SNARE_TARGET override is not allowed")
if "portal.meridian.example" not in (ROOT / "snare/Dockerfile").read_text(encoding="utf-8"):
    errors.append("snare/Dockerfile: canonical fictional portal is missing")

if errors:
    raise SystemExit("persona validation failed:\n- " + "\n- ".join(errors))
print(f"persona validation OK: {len(personas)} personas, {len(seen_services)} services")
