#!/usr/bin/env python3
"""Build deterministic APIARY brand exports from the approved alpha masks."""

from __future__ import annotations

import json
import shutil
import zlib
from pathlib import Path

from PIL import Image, ImageDraw


ROOT = Path(__file__).resolve().parents[2]
BRAND = ROOT / "branding"
SOURCE = BRAND / "source"
LOGO = BRAND / "assets" / "logo"
FAVICON = BRAND / "assets" / "favicon"
SOCIAL = BRAND / "assets" / "social"
DASHBOARD_STATIC = ROOT / "dashboard" / "static"
PDF_ASSETS = ROOT / "dashboard" / "assets_pdf"

CHARCOAL = (32, 32, 31)
IVORY = (247, 246, 242)
COPPER_DARK_TOP = (225, 135, 104)
COPPER_DARK_BOTTOM = (201, 104, 75)
COPPER_LIGHT_TOP = (185, 88, 60)
COPPER_LIGHT_BOTTOM = (143, 63, 46)
COPPER_DARK = (217, 119, 87)
COPPER_LIGHT = (199, 101, 72)


def ensure_dirs() -> None:
    for path in (LOGO, FAVICON, SOCIAL):
        path.mkdir(parents=True, exist_ok=True)


def alpha_bbox(image: Image.Image, padding: int = 0) -> tuple[int, int, int, int]:
    bbox = image.getchannel("A").getbbox()
    if bbox is None:
        raise ValueError("Alpha mask contains no visible pixels")
    left, top, right, bottom = bbox
    return (
        max(0, left - padding),
        max(0, top - padding),
        min(image.width, right + padding),
        min(image.height, bottom + padding),
    )


def colorize(mask: Image.Image, top: tuple[int, int, int], bottom: tuple[int, int, int]) -> Image.Image:
    """Use only the approved alpha geometry; RGB chroma contamination is discarded."""
    mask = mask.convert("RGBA")
    alpha = mask.getchannel("A")
    gradient = Image.new("RGBA", mask.size)
    pixels = gradient.load()
    height = max(mask.height - 1, 1)
    for y in range(mask.height):
        t = y / height
        color = tuple(round(a + (b - a) * t) for a, b in zip(top, bottom))
        for x in range(mask.width):
            pixels[x, y] = (*color, 255)
    gradient.putalpha(alpha)
    return gradient


def crop_visible(image: Image.Image, padding: int) -> Image.Image:
    return image.crop(alpha_bbox(image, padding))


def contain(image: Image.Image, size: tuple[int, int], padding: int = 0) -> Image.Image:
    canvas = Image.new("RGBA", size, (0, 0, 0, 0))
    max_size = (size[0] - 2 * padding, size[1] - 2 * padding)
    item = image.copy()
    item.thumbnail(max_size, Image.Resampling.LANCZOS)
    x = (size[0] - item.width) // 2
    y = (size[1] - item.height) // 2
    canvas.alpha_composite(item, (x, y))
    return canvas


def on_background(image: Image.Image, size: tuple[int, int], rgb: tuple[int, int, int], padding: int) -> Image.Image:
    canvas = Image.new("RGBA", size, (*rgb, 255))
    placed = contain(image, size, padding)
    canvas.alpha_composite(placed)
    return canvas.convert("RGB")


def save_png(image: Image.Image, path: Path) -> None:
    image.save(path, "PNG", optimize=True)


def compact_mark(source: Image.Image, color: tuple[int, int, int], size: int = 64) -> Image.Image:
    """Recover the optically simplified favicon geometry on transparent copper."""
    source = source.convert("RGB")
    alpha = Image.new("L", source.size)
    alpha.putdata([
        min(255, max(0, pixel[0] - max(pixel[1], pixel[2]) - 14) * 12)
        for y in range(source.height)
        for x in range(source.width)
        for pixel in (source.getpixel((x, y)),)
    ])
    alpha = alpha.resize((size, size), Image.Resampling.LANCZOS)
    result = Image.new("RGBA", (size, size), (*color, 255))
    result.putalpha(alpha)
    return result


def export_pdf_header_mark(mark: Image.Image) -> None:
    """Write a compact 1-bit PDF stencil mask derived from the approved mark."""
    alpha = mark.getchannel("A")
    packed = bytearray()
    for y in range(alpha.height):
        for x0 in range(0, alpha.width, 8):
            value = 0
            for bit in range(8):
                x = x0 + bit
                if x < alpha.width and alpha.getpixel((x, y)) >= 64:
                    value |= 1 << (7 - bit)
            packed.append(value)
    PDF_ASSETS.mkdir(parents=True, exist_ok=True)
    (PDF_ASSETS / "apiary-header-mark.maskdata").write_bytes(zlib.compress(bytes(packed), level=9))


def export_logos() -> dict[str, Image.Image]:
    lockup_mask = Image.open(SOURCE / "apiary-lockup-alpha-mask.png").convert("RGBA")
    mark_mask = Image.open(SOURCE / "apiary-mark-alpha-mask.png").convert("RGBA")

    lockup_dark = crop_visible(colorize(lockup_mask, COPPER_DARK_TOP, COPPER_DARK_BOTTOM), 32)
    lockup_light = crop_visible(colorize(lockup_mask, COPPER_LIGHT_TOP, COPPER_LIGHT_BOTTOM), 32)
    mark_dark = crop_visible(colorize(mark_mask, COPPER_DARK_TOP, COPPER_DARK_BOTTOM), 44)
    mark_light = crop_visible(colorize(mark_mask, COPPER_LIGHT_TOP, COPPER_LIGHT_BOTTOM), 44)

    save_png(lockup_dark, LOGO / "apiary-lockup-for-dark.png")
    save_png(lockup_light, LOGO / "apiary-lockup-for-light.png")
    save_png(mark_dark, LOGO / "apiary-mark-for-dark.png")
    save_png(mark_light, LOGO / "apiary-mark-for-light.png")

    # The right-hand component is the wordmark plus tagline. Keep a little connector detail.
    split = round(lockup_dark.width * 0.37)
    wordmark_dark = crop_visible(lockup_dark.crop((split, 0, lockup_dark.width, lockup_dark.height)), 18)
    wordmark_light = crop_visible(lockup_light.crop((split, 0, lockup_light.width, lockup_light.height)), 18)
    save_png(wordmark_dark, LOGO / "apiary-wordmark-for-dark.png")
    save_png(wordmark_light, LOGO / "apiary-wordmark-for-light.png")

    save_png(
        on_background(lockup_dark, (1800, 600), CHARCOAL, 72),
        LOGO / "apiary-lockup-on-charcoal.png",
    )
    save_png(
        on_background(lockup_light, (1800, 600), IVORY, 72),
        LOGO / "apiary-lockup-on-ivory.png",
    )

    # Keep the historic README asset path clean for downstream references.
    save_png(lockup_dark, ROOT / "docs" / "assets" / "apiary-readme.png")

    return {
        "lockup_dark": lockup_dark,
        "lockup_light": lockup_light,
        "mark_dark": mark_dark,
        "mark_light": mark_light,
    }


def export_favicons() -> None:
    # The dashboard's existing small-size artwork is optically simplified and remains
    # more legible at 16-32 px than a mechanical downscale of the full emblem.
    mapping = {
        "favicon.ico": "favicon.ico",
        "favicon-16x16.png": "favicon-16x16.png",
        "favicon-32x32.png": "favicon-32x32.png",
        "apple-touch-icon.png": "apple-touch-icon.png",
        "icon-192.png": "icon-192.png",
        "icon-512.png": "icon-512.png",
    }
    for source_name, target_name in mapping.items():
        shutil.copy2(DASHBOARD_STATIC / source_name, FAVICON / target_name)

    favicon_48 = Image.open(DASHBOARD_STATIC / "brand-mark@2x.png").convert("RGBA")
    favicon_48 = favicon_48.resize((48, 48), Image.Resampling.LANCZOS)
    save_png(favicon_48, FAVICON / "favicon-48x48.png")

    manifest = {
        "name": "APIARY",
        "short_name": "APIARY",
        "description": "Automated Payload Intelligence & Attacker Response",
        "id": "/",
        "start_url": "/",
        "scope": "/",
        "icons": [
            {"src": "icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "icon-512.png", "sizes": "512x512", "type": "image/png"},
        ],
        "theme_color": "#20201f",
        "background_color": "#20201f",
        "display": "standalone",
    }
    manifest_text = json.dumps(manifest, indent=2) + "\n"
    (FAVICON / "site.webmanifest").write_text(manifest_text, encoding="utf-8")
    (DASHBOARD_STATIC / "site.webmanifest").write_text(manifest_text, encoding="utf-8")

    source = Image.open(DASHBOARD_STATIC / "favicon-32x32.png")
    compact_assets: dict[str, Image.Image] = {}
    for name, color in (
        ("apiary-compact-mark-for-dark.png", COPPER_DARK),
        ("apiary-compact-mark-for-light.png", COPPER_LIGHT),
    ):
        mark = compact_mark(source, color)
        compact_assets[name] = mark
        save_png(mark, LOGO / name)
        save_png(mark, DASHBOARD_STATIC / name)
    export_pdf_header_mark(compact_assets["apiary-compact-mark-for-dark.png"])


def export_social(assets: dict[str, Image.Image]) -> None:
    card = Image.new("RGBA", (1200, 630), (*CHARCOAL, 255))
    draw = ImageDraw.Draw(card)
    # Quiet honeycomb-inspired rails keep the social card recognizably APIARY.
    for x in range(0, 1200, 80):
        draw.line((x, 0, max(0, x - 160), 160), fill=(217, 119, 87, 18), width=1)
        draw.line((x, 630, min(1200, x + 160), 470), fill=(217, 119, 87, 14), width=1)
    logo = contain(assets["lockup_dark"], (1080, 430), 20)
    card.alpha_composite(logo, (60, 100))
    save_png(card.convert("RGB"), SOCIAL / "apiary-open-graph-1200x630.png")

    avatar = on_background(assets["mark_dark"], (1024, 1024), CHARCOAL, 104)
    save_png(avatar, SOCIAL / "apiary-avatar-1024.png")


def main() -> None:
    ensure_dirs()
    assets = export_logos()
    export_favicons()
    export_social(assets)
    print("Exported APIARY brand assets to", BRAND / "assets")


if __name__ == "__main__":
    main()
