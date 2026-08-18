// Throwaway capture harness for the responsive/theme-drift pass -- NOT
// committed. Screenshots key pages at phone (390x844) and 4K (3840x2160),
// light and dark, into the job tmp dir, and records horizontal overflow.
import { test } from "@playwright/test";
import { mkdirSync, appendFileSync, writeFileSync } from "node:fs";
import { FIXTURE_SESSION_COOKIE_NAME, FIXTURE_SESSION_COOKIE_VALUE } from "./fixture-session.mjs";

const OUT = "/home/adminuser/.claude/jobs/e78c0b17/tmp/responsive";
mkdirSync(OUT, { recursive: true });
writeFileSync(`${OUT}/overflows.txt`, "");

const PAGES: Array<[string, string]> = [
  ["overview", "/"],
  ["events", "/events"],
  ["clusters", "/clusters"],
  ["campaigns", "/campaigns"],
  ["commands", "/commands"],
  ["payloads", "/payloads"],
  ["attackers", "/attackers"],
  ["kill-chain", "/kill-chain"],
  ["source-health", "/source-health"],
  ["reports", "/reports"],
  ["settings", "/settings"],
  ["sensors", "/sensors"],
  ["recordings", "/recordings"],
  ["ips", "/ips"],
];

const SIZES: Array<[string, number, number]> = [
  ["mobile", 390, 844],
  ["4k", 3840, 2160],
];

for (const scheme of ["dark", "light"] as const) {
  for (const [sizeName, width, height] of SIZES) {
    for (const [pageName, path] of PAGES) {
      test(`capture ${pageName} @ ${sizeName} ${scheme}`, async ({ page }) => {
        test.setTimeout(60_000);
        await page.context().addCookies([{
          name: FIXTURE_SESSION_COOKIE_NAME,
          value: FIXTURE_SESSION_COOKIE_VALUE,
          domain: "127.0.0.1",
          path: "/",
          secure: true,
          httpOnly: true,
          sameSite: "Lax",
        }]);
        await page.route("**/api/stream", (route) => route.abort());
        await page.emulateMedia({ colorScheme: scheme });
        await page.setViewportSize({ width, height });
        await page.goto(path).catch(() => {});
        await page.waitForTimeout(1500);
        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth - window.innerWidth,
        );
        if (overflow > 1) appendFileSync(`${OUT}/overflows.txt`, `${scheme} ${sizeName} ${pageName}: +${overflow}px\n`);
        await page.screenshot({
          path: `${OUT}/${scheme}-${sizeName}-${pageName}.png`,
          fullPage: sizeName === "mobile",
        });
      });
    }
  }
}
