// Debug helper (not committed): find elements wider than the mobile viewport.
import { chromium } from "@playwright/test";
import { FIXTURE_SESSION_COOKIE_NAME, FIXTURE_SESSION_COOKIE_VALUE } from "./e2e/fixture-session.mjs";

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
await ctx.addCookies([{ name: FIXTURE_SESSION_COOKIE_NAME, value: FIXTURE_SESSION_COOKIE_VALUE, domain: "127.0.0.1", path: "/", secure: true, httpOnly: true, sameSite: "Lax" }]);
const page = await ctx.newPage();
await page.goto("http://127.0.0.1:18080/source-health", { waitUntil: "domcontentloaded" });
await page.waitForTimeout(1500);
const tb = await page.evaluate(() => {
  const bar = document.querySelector(".app-toolbar");
  return [...bar.children].map(c => `${c.tagName}.${[...c.classList].join(".")} w=${Math.round(c.getBoundingClientRect().width)}`).concat(
    ["crumb-b w=" + Math.round(document.querySelector(".hp-crumb b")?.getBoundingClientRect().width || -1)],
    ["gridcols=" + getComputedStyle(document.querySelector(".app-shell")).gridTemplateColumns]);
});
console.log(tb.join("\n"));
const report = await page.evaluate(() => {
  const vw = innerWidth;
  const out = [];
  for (const el of document.querySelectorAll("*")) {
    const r = el.getBoundingClientRect();
    if (r.right > vw + 1 || r.width > vw + 1) {
      out.push(`${el.tagName}.${[...el.classList].join(".")} w=${Math.round(r.width)} right=${Math.round(r.right)}`);
    }
    if (out.length > 40) break;
  }
  return { overflow: document.documentElement.scrollWidth - vw, out };
});
console.log("overflow:", report.overflow);
console.log(report.out.join("\n"));
await browser.close();
