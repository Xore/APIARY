#!/usr/bin/env python3
"""Fail when portable APIARY tokens drift from the vendored Xore/theme."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
# #1502: dashboard/ moved under arcane/home/honeypot-dashboard/.
THEME = ROOT / "arcane" / "home" / "honeypot-dashboard" / "dashboard" / "static" / "theme.css"
TOKENS = ROOT / "branding" / "tokens.json"

MAPPING = {
    "background": "app-bg",
    "sidebar": "sidebar-bg",
    "surface": "surface-1",
    "surfaceRaised": "surface-raised",
    "text": "text-primary",
    "textSecondary": "text-secondary",
    "textMuted": "text-muted",
    "accent": "accent",
    "link": "text-link",
    "info": "info",
    "success": "success",
    "warning": "warning",
    "danger": "danger",
}


def block(css: str, marker: str) -> str:
    start = css.index(marker) + len(marker)
    end = css.index("\n}", start)
    return css[start:end]


def variables(css_block: str) -> dict[str, str]:
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})\s*;", css_block))


def main() -> None:
    css = THEME.read_text(encoding="utf-8")
    token_data = json.loads(TOKENS.read_text(encoding="utf-8"))
    theme_modes = {
        "dark": variables(block(css, ":root {")),
        "light": variables(block(css, '[data-theme="light"] {')),
    }

    failures: list[str] = []
    for mode, theme_values in theme_modes.items():
        branded = token_data["color"][mode]
        for token_name, theme_name in MAPPING.items():
            expected = theme_values[theme_name].lower()
            actual = branded[token_name]["$value"].lower()
            if actual != expected:
                failures.append(
                    f"color.{mode}.{token_name} is {actual}, "
                    f"but Xore/theme --{theme_name} is {expected}"
                )

    font_mapping = {"sans": "font-sans", "display": "font-display", "mono": "font-mono"}
    for token_name, theme_name in font_mapping.items():
        match = re.search(rf"--{theme_name}:\s*\"([^\"]+)\"", css)
        if not match:
            failures.append(f"Xore/theme --{theme_name} has no primary quoted family")
            continue
        actual = token_data["font"][token_name]["$value"]
        if actual != match.group(1):
            failures.append(
                f"font.{token_name} is {actual!r}, "
                f"but Xore/theme --{theme_name} starts with {match.group(1)!r}"
            )

    if failures:
        raise SystemExit("APIARY brand tokens have drifted from Xore/theme:\n- " + "\n- ".join(failures))
    print("APIARY brand tokens match the vendored Xore/theme contract")


if __name__ == "__main__":
    main()
