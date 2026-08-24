// WCAG contrast scan for the current page (design lab).
// Returns unique low-contrast (fg,bg) pairs with a sample selector + text.
(() => {
  const lum = (r, g, b) => {
    const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
  };
  const parse = c => {
    const m = c.match(/rgba?\(([\d.]+),\s*([\d.]+),\s*([\d.]+)(?:,\s*([\d.]+))?\)/);
    return m ? [+m[1], +m[2], +m[3], m[4] === undefined ? 1 : +m[4]] : null;
  };
  const blend = (top, bottom) => {
    const a = top[3];
    return [top[0] * a + bottom[0] * (1 - a), top[1] * a + bottom[1] * (1 - a), top[2] * a + bottom[2] * (1 - a), 1];
  };
  const effBg = el => {
    let bg = [32, 32, 31, 1]; // app ground fallback
    const chain = [];
    for (let n = el; n && n !== document.documentElement; n = n.parentElement) chain.push(n);
    chain.reverse().forEach(n => {
      const c = parse(getComputedStyle(n).backgroundColor);
      if (c && c[3] > 0) bg = blend(c, bg);
    });
    return bg;
  };
  const ratio = (a, b) => {
    const l1 = lum(a[0], a[1], a[2]), l2 = lum(b[0], b[1], b[2]);
    const [hi, lo] = l1 > l2 ? [l1, l2] : [l2, l1];
    return (hi + 0.05) / (lo + 0.05);
  };
  const seen = new Map();
  document.querySelectorAll("body *").forEach(el => {
    if (!el.offsetParent && getComputedStyle(el).position !== "fixed") return;
    const text = [...el.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent.trim()).join(" ").trim();
    if (!text) return;
    const cs = getComputedStyle(el);
    const fg = parse(cs.color);
    if (!fg || fg[3] < 0.1) return;
    const bg = effBg(el);
    const fgB = fg[3] < 1 ? blend(fg, bg) : fg;
    const r = ratio(fgB, bg);
    const size = parseFloat(cs.fontSize);
    const bold = parseInt(cs.fontWeight, 10) >= 700;
    const large = size >= 24 || (size >= 18.66 && bold);
    const threshold = large ? 3 : 4.5;
    if (r >= threshold) return;
    const key = cs.color + "|" + JSON.stringify(bg.map(Math.round)) + "|" + (el.className || el.tagName);
    if (seen.has(key)) return;
    seen.set(key, {
      ratio: Math.round(r * 100) / 100,
      need: threshold,
      color: cs.color,
      bg: "rgb(" + bg.slice(0, 3).map(Math.round).join(",") + ")",
      el: el.tagName.toLowerCase() + (el.className ? "." + String(el.className).trim().split(/\s+/).slice(0, 2).join(".") : ""),
      text: text.slice(0, 40),
    });
  });
  return [...seen.values()].sort((a, b) => a.ratio - b.ratio).slice(0, 25);
})()
