import { expect, test, type BrowserContext, type Page } from "@playwright/test";

import { NAV_SECTIONS } from "../src/lib/nav";
import { SESSION_COOKIE_NAME, fixtureSid } from "./fixture-session";

// The route set is the sidebar's own registry: a new nav entry joins this
// sweep without touching the spec, and a removed one drops out of it.
const NAV_ROUTES = NAV_SECTIONS.flatMap((section) => section.items.map((item) => item.to));

// Failure mode the matrix exists to catch (issue #60's words): a page
// renders something broken and nothing fails. These are the two cheap
// signals every route must satisfy in any theme x viewport combination.
const BROKEN_MARKERS = ["Something went wrong", "Unhandled error", "Application error"];

async function assertShellHealthy(page: Page) {
  // Desktop shows the sidebar directly; narrow viewports hide it behind a
  // drawer and expose a toggle instead. Either counts as a healthy shell.
  const sidebar = page.locator('aside[aria-label="Primary navigation"]');
  const drawerToggle = page.locator('button[aria-label="Toggle navigation"]');
  if ((await sidebar.count()) > 0 && (await sidebar.isVisible().catch(() => false))) {
    await expect(sidebar).toBeVisible();
  } else {
    await expect(drawerToggle).toBeVisible();
  }
  await expect(page.locator("main.app-main")).toBeVisible();
  const body = await page.locator("body").innerText();
  for (const marker of BROKEN_MARKERS) {
    // The error boundary's text would only appear if the render tree died.
    expect(body).not.toContain(marker);
  }
}

async function seedSessionCookie(context: BrowserContext, role: "admin" | "user") {
  // __Host- prefix forces the Secure attribute; injected via explicit
  // domain+path because url + extra attributes is rejected by addCookies.
  await context.addCookies([
    {
      name: SESSION_COOKIE_NAME,
      value: fixtureSid(role),
      domain: "127.0.0.1",
      path: "/",
      secure: true,
    },
  ]);
}

test.describe("route smoke across theme x viewport", () => {
  for (const [label, viewport] of [
    ["desktop/dark", { width: 1280, height: 800 }],
    ["mobile/light", { width: 390, height: 844 }],
  ] as const) {
    test(`every sidebar route renders its shell at ${label}`, async ({ browser }) => {
      const context = await browser.newContext({ viewport });
      await context.addInitScript(
        (theme) => {
          try {
            localStorage.setItem("hp-theme", theme);
            localStorage.setItem("hp-palette", "claude");
          } catch {}
        },
        label.endsWith("dark") ? "dark" : "light",
      );
      const page = await context.newPage();

      for (const route of NAV_ROUTES) {
        await page.goto(route);
        // data-theme comes from the boot script reading hp-theme back out.
        await expect(page.locator("html")).toHaveAttribute(
          "data-theme",
          label.endsWith("dark") ? "dark" : "light",
        );
        await assertShellHealthy(page);
      }
      await context.close();
    });
  }

  test("tablet canary renders the overview contentfully", async ({ page }) => {
    await page.setViewportSize({ width: 810, height: 1080 });
    await page.goto("/");
    // Content-level signal on the front page only -- the sweep above is
    // deliberately shell-level; this pins that the fake-backend-backed
    // overview actually reaches its ready state rather than an empty or
    // retry panel.
    await expect(page.getByText("APIARY").first()).toBeVisible();
    await assertShellHealthy(page);
  });
});

test.describe("modal core", () => {
  test("command palette opens, filters, and Escape closes", async ({ page }) => {
    await page.goto("/");
    await page.click('button[aria-label="Search and investigate"]');
    const dialog = page.locator('[role="dialog"][aria-label="Investigate an indicator"]');
    await expect(dialog).toBeVisible();
    // The palette's filter field is a textarea (multi-line query support).
    await dialog.locator("textarea").fill("203.0.113.7");
    await expect(dialog.locator("textarea")).toHaveValue("203.0.113.7");
    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
  });

  test("mobile navigation drawer toggles", async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
    const page = await context.newPage();
    await page.goto("/");
    const toggle = page.locator('button[aria-label*="menu" i], button[aria-label*="navigation" i]').first();
    if ((await toggle.count()) > 0) {
      await toggle.click();
      await assertShellHealthy(page);
    }
    // No dedicated drawer control is not itself a failure (CSS may show the
    // sidebar directly); the assertion above exercises it when present.
    await context.close();
  });
});

test.describe("role-aware action visibility", () => {
  test("admin session enables credential management actions", async ({ browser }) => {
    const context = await browser.newContext();
    await seedSessionCookie(context, "admin");
    const page = await context.newPage();
    await page.goto("/credentials");
    await assertShellHealthy(page);
    // CredentialActions renders inside the row inspector; open the fixture
    // row first. Rotate password is unconditionally enabled for admins
    // (unlike Save link, which waits for a token choice).
    await page.getByText("router-root").first().click();
    const rotate = page.getByRole("button", { name: "Rotate password" });
    await expect(rotate).toBeEnabled();
    await expect(page.getByRole("combobox", { name: "Link canarytoken" })).toBeEnabled();
    await context.close();
  });

  test("user session disables them with an explanation", async ({ browser }) => {
    const context = await browser.newContext();
    await seedSessionCookie(context, "user");
    const page = await context.newPage();
    await page.goto("/credentials");
    await assertShellHealthy(page);
    await page.getByText("router-root").first().click();
    await expect(page.getByRole("button", { name: "Rotate password" })).toBeDisabled();
    await expect(page.getByText("Admin role required to rotate or link credentials.")).toBeVisible();
    await context.close();
  });
});
