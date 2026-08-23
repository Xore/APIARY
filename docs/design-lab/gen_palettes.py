#!/usr/bin/env python3
"""Generate AA-validated palette preset CSS for theme.css.

Per palette x theme(dark/light) we need:
  accent, accent-hover, accent-pressed, accent-soft,
  accent-text-on-soft, text-on-accent, text-link, text-link-hover
Checks (WCAG AA, >=4.5:1 for text):
  accent-text-on-soft vs surface-1        (badge/soft ink)
  text-link           vs surface-1        (links on cards)
  text-on-accent      vs accent           (primary button ink)
Auto-tunes lightness until every check passes.
"""
import colorsys

DARK_S1 = "#2c2c2a"
LIGHT_S1 = "#f4f2ed"

def hex2rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

def rgb2hex(r, g, b):
    return "#%02x%02x%02x" % (round(r), round(g), round(b))

def rel_lum(rgb):
    def f(c):
        c = c / 255
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (f(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b

def contrast(a, b):
    la, lb = rel_lum(hex2rgb(a)), rel_lum(hex2rgb(b))
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)

def adjust_l(h, dl):
    r, g, b = hex2rgb(h)
    hh, ll, ss = colorsys.rgb_to_hls(r/255, g/255, b/255)
    ll = min(1, max(0, ll + dl))
    r, g, b = colorsys.hls_to_rgb(hh, ll, ss)
    return rgb2hex(r*255, g*255, b*255)

def tune(color, bg, target=4.5, direction=+1, max_steps=60):
    c = color
    for _ in range(max_steps):
        if contrast(c, bg) >= target:
            return c
        c = adjust_l(c, 0.015 * direction)
    return c

def ink_for(accent):
    # pick near-black or near-white ink for text-on-accent, whichever passes better
    dark_ink = tune("#1c1613", accent, direction=-1)
    light_ink = tune("#ffffff", accent, direction=+1)
    cd, cl = contrast(dark_ink, accent), contrast(light_ink, accent)
    return dark_ink if cd >= cl else light_ink

# name -> (dark accent, light accent) seed hues
PALETTES = {
    "slate":    ("#8aa2c0", "#44618a"),
    "ocean":    ("#55a7d8", "#1f6fa8"),
    "sage":     ("#8fb27b", "#4d7a42"),
    "lavender": ("#ab93e3", "#6d4fc4"),
    "lime":     ("#b3cf5a", "#5f7d1f"),
    "amber":    ("#d9a842", "#96690e"),
    "rose":     ("#d98298", "#b04a66"),
    "neon":     ("#3ee6c8", "#0f8f7a"),
}

def block(name, accent, s1, theme):
    # soft ink must clear AA on surface-1; links likewise
    soft_ink = tune(accent, s1, direction=(+1 if theme == "dark" else -1))
    link = tune(accent, s1, direction=(+1 if theme == "dark" else -1))
    link_hover = adjust_l(link, +0.06 if theme == "dark" else -0.06)
    hover = adjust_l(accent, +0.05 if theme == "dark" else -0.04)
    pressed = adjust_l(accent, -0.05 if theme == "dark" else -0.08)
    r, g, b = hex2rgb(accent)
    soft = f"rgba({r}, {g}, {b}, {0.16 if theme == 'dark' else 0.13})"
    ink = ink_for(accent)
    toks = [
        ("--accent", accent), ("--accent-hover", hover), ("--accent-pressed", pressed),
        ("--accent-soft", soft), ("--accent-text-on-soft", soft_ink),
        ("--text-on-accent", ink), ("--text-link", link), ("--text-link-hover", link_hover),
    ]
    body = " ".join(f"{k}: {v};" for k, v in toks)
    # report
    checks = {
        "soft-ink": contrast(soft_ink, s1),
        "link": contrast(link, s1),
        "btn-ink": contrast(ink, accent),
    }
    assert all(v >= 4.5 for v in checks.values()), (name, theme, checks)
    return body, checks

out = []
report = []
out.append("/* ── Palette presets (per Xore): one-click accent palettes, selected in")
out.append("   Settings → Appearance and applied as data-hp-palette on <html>.")
out.append('   "claude" is the default token set above (no attribute). Every pair')
out.append("   below is WCAG-AA validated (soft ink + links vs surface-1, button")
out.append("   ink vs accent) in BOTH themes by scripts in the APIARY design lab;")
out.append("   status colors stay semantic across palettes. */")
for name, (dark, light) in PALETTES.items():
    d_body, d_checks = block(name, dark, DARK_S1, "dark")
    l_body, l_checks = block(name, light, LIGHT_S1, "light")
    out.append(f':root[data-hp-palette="{name}"] {{ {d_body} }}')
    out.append(f'[data-theme="light"][data-hp-palette="{name}"] {{ {l_body} }}')
    out.append("@media (prefers-color-scheme: light) {")
    out.append(f'  :root:not([data-theme])[data-hp-palette="{name}"] {{ {l_body} }}')
    out.append("}")
    report.append(f"{name}: dark {d_checks} | light {l_checks}")

open("/home/adminuser/.claude/jobs/e78c0b17/tmp/palettes.css", "w").write("\n".join(out) + "\n")
print("\n".join(report))
print("CSS written")
