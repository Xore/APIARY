#!/usr/bin/env python3
"""Assemble the curated APIARY branding site for GitHub Pages."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BRAND = ROOT / "branding"
TEMPLATE = BRAND / "templates" / "web"


def safe_output(path: Path) -> Path:
    output = path.resolve()
    if output == ROOT or ROOT not in output.parents:
        raise ValueError(f"Output must be a dedicated directory inside {ROOT}: {output}")
    if output == BRAND or BRAND in output.parents:
        raise ValueError(f"Output must not overwrite branding source files: {output}")
    return output


def build(output: Path) -> None:
    output = safe_output(output)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    shutil.copytree(BRAND / "assets", output / "assets")
    (output / "downloads").mkdir()
    shutil.copy2(BRAND / "pdf" / "APIARY-brand-guide.pdf", output / "downloads" / "APIARY-brand-guide.pdf")

    html = (TEMPLATE / "index.html").read_text(encoding="utf-8")
    html = html.replace("../../assets/", "assets/")
    html = html.replace("../../README.md", "https://github.com/Xore/APIARY/tree/main/branding")
    html = html.replace("../../pdf/APIARY-brand-guide.pdf", "downloads/APIARY-brand-guide.pdf")
    html = html.replace("../../../docs/CGNAT-DEPLOYMENT.md", "https://github.com/Xore/APIARY/blob/main/docs/CGNAT-DEPLOYMENT.md")
    (output / "index.html").write_text(html, encoding="utf-8", newline="\n")

    css = (TEMPLATE / "apiary-theme.css").read_text(encoding="utf-8")
    css = css.replace("../../assets/", "assets/")
    (output / "apiary-theme.css").write_text(css, encoding="utf-8", newline="\n")

    (output / ".nojekyll").write_text("", encoding="utf-8")
    (output / "robots.txt").write_text("User-agent: *\nAllow: /\n", encoding="utf-8", newline="\n")
    (output / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        '  <url><loc>https://xore.github.io/APIARY/</loc></url>\n'
        '</urlset>\n',
        encoding="utf-8",
        newline="\n",
    )
    print(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "_site")
    args = parser.parse_args()
    build(args.output)


if __name__ == "__main__":
    main()
