#!/usr/bin/env python3
"""Generate the APIARY brand guide PDF with ReportLab."""

from __future__ import annotations

from pathlib import Path

from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parents[2]
BRAND = ROOT / "branding"
OUT = BRAND / "pdf" / "APIARY-brand-guide.pdf"
ASSETS = BRAND / "assets"
W, H = landscape(A4)

C = {
    "dark": HexColor("#20201f"),
    "sidebar": HexColor("#1e1e1c"),
    "surface": HexColor("#2c2c2a"),
    "raised": HexColor("#383835"),
    "ivory": HexColor("#f7f6f2"),
    "light_surface": HexColor("#f4f2ed"),
    "text_dark": HexColor("#2f2b27"),
    "text_light": HexColor("#e9e6df"),
    "muted_dark": HexColor("#66615b"),
    "muted_light": HexColor("#a5a9a6"),
    "copper": HexColor("#d97757"),
    "copper_print": HexColor("#c76548"),
    "blue": HexColor("#78a9d4"),
    "green": HexColor("#79c99e"),
    "amber": HexColor("#deb36a"),
    "red": HexColor("#dc7774"),
}


def image(path: Path) -> ImageReader:
    return ImageReader(str(path))


def fit_image(c: canvas.Canvas, path: Path, x: float, y: float, w: float, h: float, pad: float = 0) -> None:
    reader = image(path)
    iw, ih = reader.getSize()
    scale = min((w - pad * 2) / iw, (h - pad * 2) / ih)
    dw, dh = iw * scale, ih * scale
    c.drawImage(reader, x + (w - dw) / 2, y + (h - dh) / 2, dw, dh, mask="auto")


def cover_image(c: canvas.Canvas, path: Path) -> None:
    reader = image(path)
    iw, ih = reader.getSize()
    scale = max(W / iw, H / ih)
    dw, dh = iw * scale, ih * scale
    c.drawImage(reader, (W - dw) / 2, (H - dh) / 2, dw, dh)


def page_base(c: canvas.Canvas, page: int, title: str, eyebrow: str) -> None:
    c.setFillColor(C["ivory"])
    c.rect(0, 0, W, H, fill=1, stroke=0)
    c.setFillColor(C["copper_print"])
    c.setFont("Courier-Bold", 8)
    c.drawString(42, H - 38, eyebrow.upper())
    c.setFillColor(C["text_dark"])
    c.setFont("Helvetica-Bold", 25)
    c.drawString(42, H - 69, title)
    c.setStrokeColor(HexColor("#d2cec6"))
    c.setLineWidth(0.6)
    c.line(42, H - 82, W - 42, H - 82)
    c.setFillColor(C["muted_dark"])
    c.setFont("Courier", 7.5)
    c.drawString(42, 24, "APIARY BRAND SYSTEM / AUTOMATED PAYLOAD INTELLIGENCE & ATTACKER RESPONSE")
    c.drawRightString(W - 42, 24, f"{page:02d}")


def paragraph(c: canvas.Canvas, text: str, x: float, y: float, width: float, size: float = 10.5, leading: float = 15, color=None) -> float:
    color = color or C["text_dark"]
    words = text.split()
    lines: list[str] = []
    line = ""
    for word in words:
        trial = f"{line} {word}".strip()
        if stringWidth(trial, "Helvetica", size) <= width:
            line = trial
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    c.setFillColor(color)
    c.setFont("Helvetica", size)
    for item in lines:
        c.drawString(x, y, item)
        y -= leading
    return y


def label(c: canvas.Canvas, text: str, x: float, y: float, color=None) -> None:
    c.setFillColor(color or C["copper_print"])
    c.setFont("Courier-Bold", 8)
    c.drawString(x, y, text.upper())


def rounded_panel(c: canvas.Canvas, x: float, y: float, w: float, h: float, fill, stroke=HexColor("#dedad2"), radius: float = 10) -> None:
    c.setFillColor(fill)
    c.setStrokeColor(stroke)
    c.setLineWidth(0.7)
    c.roundRect(x, y, w, h, radius, fill=1, stroke=1)


def draw_cover(c: canvas.Canvas) -> None:
    cover_image(c, ASSETS / "backgrounds" / "apiary-hero-background.png")
    c.setFillColorRGB(0.05, 0.05, 0.05, alpha=0.30)
    c.rect(0, 0, W, H, fill=1, stroke=0)
    fit_image(c, ASSETS / "logo" / "apiary-lockup-for-dark.png", 64, 210, W - 128, 230)
    c.setFillColor(C["text_light"])
    c.setFont("Helvetica-Bold", 27)
    c.drawCentredString(W / 2, 154, "Brand system and implementation guide")
    c.setFillColor(C["muted_light"])
    c.setFont("Helvetica", 11)
    c.drawCentredString(W / 2, 133, "Logo, color, typography, digital components, social assets, and PDF standards")
    c.setStrokeColor(C["copper"])
    c.setLineWidth(1)
    c.line(W / 2 - 34, 110, W / 2 + 34, 110)
    c.setFillColor(C["muted_light"])
    c.setFont("Courier", 8)
    c.drawCentredString(W / 2, 72, "VERSION 1.0 / CANONICAL REPOSITORY ASSETS")
    c.showPage()


def draw_logo_page(c: canvas.Canvas) -> None:
    page_base(c, 2, "Logo system", "01 / Identity")
    paragraph(c, "The horizontal lockup is primary. The emblem is reserved for square or compact placements, and the wordmark is used when the full emblem would compete with interface content.", 42, H - 110, 700)

    x1, x2 = 42, W / 2 + 8
    panel_w, panel_h, panel_y = W / 2 - 58, 170, 270
    rounded_panel(c, x1, panel_y, panel_w, panel_h, C["dark"], C["dark"])
    fit_image(c, ASSETS / "logo" / "apiary-lockup-for-dark.png", x1 + 18, panel_y + 18, panel_w - 36, panel_h - 36)
    rounded_panel(c, x2, panel_y, panel_w, panel_h, HexColor("#ffffff"))
    fit_image(c, ASSETS / "logo" / "apiary-lockup-for-light.png", x2 + 18, panel_y + 18, panel_w - 36, panel_h - 36)
    label(c, "For dark surfaces", x1, panel_y - 18)
    label(c, "For light surfaces", x2, panel_y - 18)

    mark_y, mark_h = 78, 145
    rounded_panel(c, 42, mark_y, 170, mark_h, C["dark"], C["dark"])
    fit_image(c, ASSETS / "logo" / "apiary-mark-for-dark.png", 55, mark_y + 10, 144, 125)
    rounded_panel(c, 230, mark_y, 240, mark_h, HexColor("#ffffff"))
    fit_image(c, ASSETS / "logo" / "apiary-wordmark-for-light.png", 242, mark_y + 18, 216, 109)
    label(c, "Emblem / 64 px minimum", 42, mark_y - 18)
    label(c, "Wordmark / compact horizontal", 230, mark_y - 18)

    label(c, "Usage rules", 510, mark_y + 125)
    rules = [
        "Clear space: one A-stem on every side.",
        "Horizontal lockup: 420 px minimum.",
        "Emblem: 64 px minimum; use favicon below.",
        "Never stretch, rotate, glow, outline, or recolor.",
        "Never mix the dark and light surface variants.",
    ]
    y = mark_y + 103
    for rule in rules:
        c.setFillColor(C["copper_print"])
        c.circle(516, y + 3, 1.8, fill=1, stroke=0)
        c.setFillColor(C["text_dark"])
        c.setFont("Helvetica", 9.5)
        c.drawString(526, y, rule)
        y -= 19
    c.showPage()


def swatch(c: canvas.Canvas, x: float, y: float, w: float, name: str, value: str, fill, text_color) -> None:
    c.setFillColor(fill)
    c.roundRect(x, y, w, 54, 7, fill=1, stroke=0)
    c.setFillColor(text_color)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(x + 10, y + 31, name)
    c.setFont("Courier", 8)
    c.drawString(x + 10, y + 15, value)


def draw_color_page(c: canvas.Canvas) -> None:
    page_base(c, 3, "Color and contrast", "02 / Foundations")
    paragraph(c, "Warm neutral surfaces keep dense technical content quiet. Copper identifies APIARY and primary actions. Semantic colors are reserved for evidence state and must not become decoration.", 42, H - 110, 700)
    label(c, "Dark interface", 42, 425)
    darks = [("Background", "#20201f", C["dark"]), ("Sidebar", "#1e1e1c", C["sidebar"]), ("Surface", "#2c2c2a", C["surface"]), ("Raised", "#383835", C["raised"]), ("Copper", "#d97757", C["copper"])]
    for i, (name, value, fill) in enumerate(darks):
        swatch(c, 42 + i * 148, 352, 132, name, value, fill, C["text_light"] if i < 4 else C["text_dark"])

    label(c, "Light interface", 42, 320)
    lights = [("Background", "#f7f6f2", C["ivory"]), ("Surface", "#f4f2ed", C["light_surface"]), ("Primary", "#2f2b27", C["text_dark"]), ("Muted", "#66615b", C["muted_dark"]), ("Copper", "#c76548", C["copper_print"])]
    for i, (name, value, fill) in enumerate(lights):
        text = C["text_light"] if i >= 2 else C["text_dark"]
        swatch(c, 42 + i * 148, 247, 132, name, value, fill, text)

    label(c, "Evidence semantics", 42, 215)
    semantic = [("Information", "#78a9d4", C["blue"]), ("Clean / success", "#79c99e", C["green"]), ("Warning", "#deb36a", C["amber"]), ("Detected / high risk", "#dc7774", C["red"])]
    for i, (name, value, fill) in enumerate(semantic):
        swatch(c, 42 + i * 185, 142, 169, name, value, fill, C["text_dark"])
    paragraph(c, "Accessibility: verify foreground/background combinations at implementation time. Do not communicate severity by color alone; pair state color with text, iconography, or a status label.", 42, 105, 720, 9.5, 13, C["muted_dark"])
    c.showPage()


def draw_type_page(c: canvas.Canvas) -> None:
    page_base(c, 4, "Typography and interface voice", "03 / Digital")
    paragraph(c, "Space Grotesk carries display hierarchy, Fira Sans carries interface prose, and Fira Code identifies machine evidence, timestamps, hashes, protocols, and compact labels. Native fallbacks keep offline rendering predictable.", 42, H - 110, 720)
    rounded_panel(c, 42, 250, 350, 200, C["light_surface"])
    label(c, "Fira Sans / Space Grotesk", 62, 422)
    c.setFillColor(C["text_dark"])
    c.setFont("Helvetica-Bold", 36)
    c.drawString(62, 370, "Know the payload.")
    c.setFont("Helvetica-Bold", 20)
    c.drawString(62, 328, "Understand the attacker.")
    c.setFont("Helvetica", 10)
    c.setFillColor(C["muted_dark"])
    c.drawString(62, 295, "Fira Sans / 15 px body / 1.6 line height")
    c.drawString(62, 276, "Tight headings, calm prose, direct sentence case")

    rounded_panel(c, 414, 250, W - 456, 200, C["dark"], C["dark"])
    label(c, "Evidence mono", 434, 422, C["copper"])
    c.setFont("Courier-Bold", 9)
    c.setFillColor(C["green"])
    c.drawString(434, 378, "YARA.MATCH / MIRAI_DOWNLOADER")
    c.setFillColor(C["text_light"])
    c.setFont("Courier", 9)
    c.drawString(434, 346, "21:44:12  sha256:8f4a...  cowrie.ssh")
    c.setFillColor(C["muted_light"])
    c.drawString(434, 314, "CASE/AP-2481  ANALYSIS.QUEUED  CONTAINED")
    c.drawString(434, 282, "Fira Code / Cascadia Code / SFMono-Regular")

    label(c, "Voice principles", 42, 210)
    principles = [
        ("Specific", "Name the evidence, action, or system state."),
        ("Calm", "Describe risk without theatrical or militarized language."),
        ("Operational", "Prefer next-step clarity over promotional claims."),
        ("Compact", "Front-load meaning; move implementation detail into documentation."),
    ]
    for i, (name, detail) in enumerate(principles):
        x = 42 + (i % 2) * 375
        y = 170 - (i // 2) * 62
        c.setFillColor(C["copper_print"])
        c.setFont("Helvetica-Bold", 11)
        c.drawString(x, y, name)
        paragraph(c, detail, x, y - 18, 320, 9.5, 13, C["muted_dark"])
    c.showPage()


def draw_assets_page(c: canvas.Canvas) -> None:
    page_base(c, 5, "Digital asset family", "04 / Delivery")
    paragraph(c, "Use the packaged exports directly. Do not derive production icons by screenshotting the README logo; small sizes use optically simplified artwork for clarity.", 42, H - 110, 710)
    rounded_panel(c, 42, 225, 435, 235, C["dark"], C["dark"])
    fit_image(c, ASSETS / "social" / "apiary-open-graph-1200x630.png", 54, 237, 411, 211)
    label(c, "Open Graph / 1200 x 630", 42, 205)

    rounded_panel(c, 504, 225, 292, 235, C["light_surface"])
    sizes = [(16, "16"), (28, "32"), (40, "48"), (60, "180"), (82, "512")]
    x = 516
    for display, asset_size in sizes:
        path = ASSETS / "favicon" / (f"favicon-{asset_size}x{asset_size}.png" if asset_size in {"16", "32", "48"} else ("apple-touch-icon.png" if asset_size == "180" else "icon-512.png"))
        c.drawImage(image(path), x, 350 - display / 2, display, display, mask="auto")
        c.setFillColor(C["muted_dark"])
        c.setFont("Courier", 7)
        c.drawCentredString(x + display / 2, 288, f"{asset_size}px")
        x += display + 10
    label(c, "Favicon and app icons", 504, 205)

    label(c, "Web delivery checklist", 42, 170)
    checks = [
        "Theme-aware transparent logo variants",
        "ICO plus 16, 32, and 48 px PNG favicons",
        "180 px Apple touch icon and 192/512 px app icons",
        "site.webmanifest with theme and background colors",
        "PNG master plus compressed WebP hero background",
        "1200 x 630 Open Graph image and 1024 px avatar",
    ]
    for i, item in enumerate(checks):
        col, row = i % 2, i // 2
        x = 42 + col * 375
        y = 142 - row * 28
        c.setStrokeColor(C["copper_print"])
        c.setLineWidth(1)
        c.rect(x, y - 2, 9, 9, fill=0, stroke=1)
        c.line(x + 2, y + 2, x + 4, y)
        c.line(x + 4, y, x + 8, y + 6)
        c.setFillColor(C["text_dark"])
        c.setFont("Helvetica", 9.5)
        c.drawString(x + 18, y, item)
    c.showPage()


def draw_rules_page(c: canvas.Canvas) -> None:
    page_base(c, 6, "Application standards", "05 / Governance")
    paragraph(c, "Consistency comes from decisions, not from adding decoration. Start with the canonical assets and tokens, then let content hierarchy carry the experience.", 42, H - 110, 700)
    columns = [
        (42, "Do", C["green"], [
            "Use copper as a restrained brand accent.",
            "Keep large areas warm-neutral and low contrast.",
            "Use monospace for evidence and compact labels.",
            "Pair semantic colors with explicit status text.",
            "Use the light PDF palette for print-first reports.",
        ]),
        (W / 2 + 8, "Do not", C["red"], [
            "Add green, neon, glow, or cyberpunk effects.",
            "Place detailed marks below their minimum size.",
            "Stretch, crop, rotate, or retype the wordmark.",
            "Use severity colors as general decoration.",
            "Put the transparent mark over busy photography.",
        ]),
    ]
    for x, title, accent, items in columns:
        rounded_panel(c, x, 180, W / 2 - 58, 270, C["light_surface"])
        c.setFillColor(accent)
        c.setFont("Helvetica-Bold", 18)
        c.drawString(x + 22, 414, title)
        y = 374
        for item in items:
            c.setFillColor(accent)
            c.circle(x + 26, y + 3, 2.2, fill=1, stroke=0)
            paragraph(c, item, x + 38, y, W / 2 - 110, 10, 14, C["text_dark"])
            y -= 43

    label(c, "Canonical source", 42, 140)
    paragraph(c, "Repository path: branding/. Regenerate raster exports with branding/scripts/export_brand_assets.py and rebuild this guide with branding/scripts/build_brand_guide.py.", 42, 119, 720, 9.5, 13, C["muted_dark"])
    c.setFillColor(C["copper_print"])
    c.setFont("Helvetica-Bold", 13)
    c.drawString(42, 73, "Protect the signal. Keep the system quiet.")
    c.showPage()


def build() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(OUT), pagesize=(W, H), pageCompression=1)
    c.setTitle("APIARY Brand System")
    c.setAuthor("APIARY")
    c.setSubject("Logo, color, typography, web, favicon, social, and PDF branding guidance")
    draw_cover(c)
    draw_logo_page(c)
    draw_color_page(c)
    draw_type_page(c)
    draw_assets_page(c)
    draw_rules_page(c)
    c.save()
    print(OUT)


if __name__ == "__main__":
    build()
