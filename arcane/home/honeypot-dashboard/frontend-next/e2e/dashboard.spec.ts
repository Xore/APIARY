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
  // One test per nav entry (#2508), not one sweep: when the sweep lived in a
  // single loop a deep failure stranded every later route behind it and hid
  // which page actually broke unless you read a trace, while the 120s budget
  // was arithmetic over route count (#2480/#2481). Generated per route, each
  // probe keeps the default 30s budget, names its route in its own failure
  // artifacts, and lands on its own worker. Theme x viewport coverage below
  // and the tablet canary stay unchanged.
  for (const [label, viewport] of [
    ["desktop/dark", { width: 1280, height: 800 }],
    ["mobile/light", { width: 390, height: 844 }],
  ] as const) {
    const theme = label.endsWith("dark") ? "dark" : "light";
    test.describe(label, () => {
      for (const route of NAV_ROUTES) {
        test(`${route} renders its shell`, async ({ browser }) => {
          const context = await browser.newContext({ viewport });
          await context.addInitScript(
            (t) => {
              try {
                localStorage.setItem("hp-theme", t);
                localStorage.setItem("hp-palette", "claude");
              } catch {}
            },
            theme,
          );
          const page = await context.newPage();

          await page.goto(route);
          // data-theme comes from the boot script reading hp-theme back out.
          await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
          await assertShellHealthy(page);
          await context.close();
        });
      }
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

test.describe("reports studio content (#2507)", () => {
  // The route smoke above is shell-level by design; /reports is the one
  // route whose real UI never got exercised until its fixtures existed --
  // the bare {} catch-all shipped #2480's DefinitionsCard crash past every
  // sweep that timed out before reaching the route. These pins hold the
  // fixture-backed catalog, Library, and generated grid to their contentful
  // render paths.
  test("template gallery, library definitions, and generated grid render contentfully", async ({ page }) => {
    await page.goto("/reports");
    // Design step: the wizard's template gallery lists the fixture catalog
    // instead of "No report templates are available.".
    await expect(page.locator(".hp-rp-template", { hasText: "Executive report" })).toBeVisible();
    await expect(page.getByText("No report templates are available.")).toHaveCount(0);

    // Library step: saved definition with its schedule, plus the generated
    // PDF row the grid reads from /api/v1/store/generated-reports.
    await page.locator("#rp-library").click();
    await expect(page.getByText("Daily executive digest")).toBeVisible();
    await expect(page.getByText("daily @ 06:00 UTC")).toBeVisible();
    await expect(page.getByText("APIARY Executive Security Report").first()).toBeVisible();
    await expect(page.getByText("150 KB")).toBeVisible();
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

// #2130: "How a byte flows" on /topology is the one chart readers need to
// magnify and rearrange, so it gets roam (drag-to-pan), a component-owned
// zoom scalar (wheel + buttons), and draggable nodes -- while every other
// chart kind, kill-chain's sankey included, stays hands-off. These tests
// drive the real echarts canvas through the hermetic fixture; gesture
// assertions compare canvas screenshots because zrender draws to pixels
// and exposes no view-state API a test could read instead.
test.describe("topology sankey roam (#2130)", () => {
  const SETTLE = 1_500; // layout animation + the labelLayout reflow pass
  const zoomPct = (page: Page) => page.locator(".chip[aria-live]").innerText();
  const canvasShot = (page: Page) => page.locator("canvas").first().screenshot();

  // zrender marks elements it considers draggable by putting move/grab on
  // the chart root's cursor; hovering a coarse grid until that appears
  // finds a grabbable node without knowing fixture coordinates.
  async function findDraggablePoint(page: Page, box: { x: number; y: number; width: number; height: number }) {
    for (let gy = 1; gy <= 30; gy++) {
      for (let gx = 1; gx <= 12; gx++) {
        const x = box.x + (box.width * gx) / 13;
        const y = box.y + (box.height * gy) / 31;
        await page.mouse.move(x, y);
        const cursor = await page.evaluate(() => {
          const cv = document.querySelector("canvas") as HTMLCanvasElement;
          return `${cv.style.cursor}|${(cv.parentElement as HTMLElement).style.cursor}`;
        });
        if (/move|grab|pointer/.test(cursor)) return { x, y };
      }
    }
    throw new Error("no draggable element found under cursor grid");
  }

  async function openTopology(page: Page) {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto("/topology");
    await page.getByText("scroll to zoom").waitFor({ state: "visible", timeout: 20_000 });
    await page.waitForTimeout(SETTLE);
    return (await page.locator("canvas").first().boundingBox())!;
  }

  test("wheel zooms without scrolling the page; buttons and reset agree with the readout", async ({ page }) => {
    const box = await openTopology(page);
    expect(await zoomPct(page)).toBe("100%");
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForTimeout(300);
    const scrollBefore = await page.evaluate(() => window.scrollY);
    await page.mouse.wheel(0, -240);
    await page.mouse.wheel(0, -240);
    await page.waitForTimeout(400);
    // The wheel listener preventDefaults: hovering the chart must never
    // steal a page scroll the reader did not aim at the chart.
    expect(await page.evaluate(() => window.scrollY)).toBe(scrollBefore);
    expect(await zoomPct(page)).toBe("144%");
    await page.getByRole("button", { name: "Zoom out" }).click();
    expect(await zoomPct(page)).toBe("120%");
    await page.getByRole("button", { name: "reset" }).click();
    await page.waitForTimeout(SETTLE);
    expect(await zoomPct(page)).toBe("100%");
  });

  test("dragging background pans; node drags displace and persist; reset restores", async ({ page }) => {
    const box = await openTopology(page);
    await page.mouse.move(box.x + 30, box.y + 20);
    await page.waitForTimeout(300);
    const prePan = await canvasShot(page);
    await page.mouse.down();
    await page.mouse.move(box.x + 190, box.y + 140, { steps: 8 });
    await page.mouse.up();
    await page.waitForTimeout(400);
    expect((await canvasShot(page)).equals(prePan)).toBe(false);

    // Node drag must move MORE than hover-emphasis alone does and survive
    // mouseup -- the #2132 regression was drags that looked alive under the
    // cursor but were only emphasis highlights.
    const aim = await findDraggablePoint(page, box);
    await page.waitForTimeout(300);
    const beforeDrag = await canvasShot(page);
    await page.mouse.down();
    await page.mouse.move(aim.x + 70, aim.y + 55, { steps: 8 });
    await page.mouse.up();
    await page.waitForTimeout(300);
    const afterDrag = await canvasShot(page);
    expect(afterDrag.equals(beforeDrag)).toBe(false);
    await page.waitForTimeout(600);
    expect((await canvasShot(page)).equals(afterDrag)).toBe(true);

    await page.getByRole("button", { name: "reset" }).click();
    await page.waitForTimeout(SETTLE);
    expect(await zoomPct(page)).toBe("100%");
  });

  test("sankey labels hide overlap instead of overprinting the fleet band", async ({ page }) => {
    await openTopology(page);
    // Ground truth for the "cluttered white text" half of #2130: with the
    // LabelLayout feature registered, hideOverlap marks colliding labels
    // ignored, so the display list holds fewer visible text spans than node
    // rects. When the feature silently drops out of the bundle (the way it
    // did before echarts/features was use()d), every label paints and this
    // count goes equal -- that equality is the regression signature.
    const counts = await page.evaluate(() => {
      const host = document.querySelector("[_echarts_instance_]") as (HTMLElement & { __xoreChart?: { getZr: () => { storage: { getDisplayList: (b: boolean) => { type: string }[] } } } }) | null;
      if (!host || !host.__xoreChart) throw new Error("chart seam missing");
      const list = host.__xoreChart.getZr().storage.getDisplayList(false);
      return {
        rects: list.filter((el) => el.type === "rect").length,
        visibleLabels: list.filter((el) => el.type === "tspan").length,
      };
    });
    expect(counts.rects).toBeGreaterThan(50); // fixture density guard
    expect(counts.visibleLabels).toBeLessThan(counts.rects);
  });

  test("other charts stay control-free: kill-chain sankey has no zoom UI", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto("/kill-chain");
    await page.getByRole("heading", { level: 1 }).waitFor();
    await page.waitForTimeout(SETTLE);
    expect(await page.locator(".chip[aria-live]").count()).toBe(0);
    expect(await page.getByText("scroll to zoom").count()).toBe(0);
  });
});
