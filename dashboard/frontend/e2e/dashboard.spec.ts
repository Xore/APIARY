import { expect, test, type Page } from "@playwright/test";

const routes = [
  "/",
  "/source-health",
  "/alerts",
  "/events",
  "/ips",
  "/campaigns",
  "/clusters",
  "/commands",
  "/payloads",
  "/sandbox",
  "/ghidra",
  "/payload-workbench",
  "/payload-workbench/results",
  "/payload-workbench/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "/history",
  "/dead-letters",
  "/reports",
] as const;

const viewports = {
  desktop: { width: 1440, height: 900 },
  tablet: { width: 820, height: 1180 },
  mobile: { width: 390, height: 844 },
} as const;

async function isolateReadOnlyBrowserState(page: Page) {
  await page.route("**/api/stream", (route) => route.abort());
  await page.route("**/api/settings/**", (route) => route.fulfill({ status: 401, body: "signed out" }));
  await page.route("**/api/whoami", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ username: "browser-check", display_name: "Browser Check", role: "viewer" }),
  }));
  await page.route("https://tile.openstreetmap.org/**", (route) => route.abort());
}

test.describe("dark/light responsive acceptance matrix", () => {
  for (const [viewportName, viewport] of Object.entries(viewports)) {
    for (const theme of ["dark", "light"] as const) {
      for (const route of routes) {
        test(`${theme} ${viewportName} ${route}`, async ({ page }) => {
          await isolateReadOnlyBrowserState(page);
          await page.setViewportSize(viewport);
          await page.addInitScript((selectedTheme) => {
            localStorage.setItem("hp-theme", selectedTheme);
            localStorage.setItem("hp-prefs-migrated", "1");
          }, theme);

          const response = await page.goto(route, { waitUntil: "domcontentloaded" });
          expect(response?.status(), `${route} must remain an HTML route`).toBe(200);
          await expect(page.locator(".app-shell")).toBeVisible();
          await expect(page.locator(".app-toolbar")).toBeVisible();
          await expect(page.locator(".app-main")).toBeVisible();
          await expect(page.locator("[data-hp-page-content]")).toBeVisible();
          await expect(page.locator("html")).toHaveAttribute("data-theme", theme);

          const layout = await page.evaluate(() => {
            const main = document.querySelector(".app-main")?.getBoundingClientRect();
            const toolbar = document.querySelector(".app-toolbar")?.getBoundingClientRect();
            const heading = document.querySelector("[data-hp-page-content] h1")?.getBoundingClientRect();
            const bodyStyle = getComputedStyle(document.body);
            return {
              overflow: document.documentElement.scrollWidth - innerWidth,
              mainWidth: main?.width || 0,
              mainTop: main?.top || 0,
              toolbarBottom: toolbar?.bottom || 0,
              headingWidth: heading?.width || 0,
              background: bodyStyle.backgroundColor,
              color: bodyStyle.color,
            };
          });

          expect(layout.overflow, `${route} must not overflow the ${viewportName} viewport`).toBeLessThanOrEqual(1);
          expect(layout.mainWidth).toBeGreaterThan(viewport.width * 0.55);
          expect(layout.mainTop).toBeGreaterThanOrEqual(layout.toolbarBottom - 1);
          expect(layout.headingWidth).toBeGreaterThan(0);
          expect(layout.background).not.toBe("rgba(0, 0, 0, 0)");
          expect(layout.color).not.toBe("rgba(0, 0, 0, 0)");
        });
      }
    }
  }
});

test.describe("dashboard browser behaviour", () => {
  test.beforeEach(async ({ page }) => {
    await isolateReadOnlyBrowserState(page);
  });

  test("command dock focuses with slash and routes non-empty queries through /search", async ({ page }) => {
    await page.goto("/");
    const command = page.locator("[data-hp-investigate] textarea");
    const searchRequest = page.waitForRequest((request) => request.url().includes("/search?q=203.0.113.7"));
    await page.keyboard.press("/");
    await expect(command).toBeFocused();
    await command.fill("203.0.113.7");
    await command.press("Enter");
    await searchRequest;
    await expect(page).toHaveURL(/\/investigate\/ip\/203\.0\.113\.7$/);
    await expect(page.locator("[data-hp-page-content] h1")).toContainText("203.0.113.7");
  });

  test("remote event paging loads the next 25 rows through the accessible control", async ({ page }) => {
    await page.addInitScript(() => { delete window.IntersectionObserver; });
    await page.goto("/events");
    const rows = page.locator("table.recent tbody tr");
    await expect(rows).toHaveCount(25);
    const controls = page.locator("table.recent + .hp-lazy-controls");
    const total = Number(await page.locator("table.recent tbody").getAttribute("data-hp-total"));
    expect(total).toBeGreaterThan(25);
    await expect(controls).toContainText(`25 of ${total} entries`);
    await controls.getByRole("button", { name: "Load 25 more" }).click();
    await expect(rows).toHaveCount(50);
    await expect(controls).toContainText(`50 of ${total} entries`);
  });

  test("live overview replacement preserves the connected map node", async ({ page }) => {
    await page.goto("/");
    const result = await page.evaluate(() => {
      const live = document.querySelector('[data-dashboard-panel="live"]');
      if (!live) throw new Error("live panel missing");
      const mapCard = document.createElement("div");
      mapCard.dataset.attackMapCard = "";
      mapCard.innerHTML = '<div id="browser-map-sentinel">preserve me</div>';
      live.appendChild(mapCard);
      const original = mapCard.querySelector("#browser-map-sentinel");

      const incoming = document.createElement("div");
      incoming.innerHTML = `
        <div class="tabs" data-browser-replacement="tabs"></div>
        <div id="panel-live" data-dashboard-panel="live">
          <div data-browser-replacement="before"></div>
          <div data-attack-map-card><div id="replacement-map">replace me</div></div>
          <div data-browser-replacement="after"></div>
        </div>`;
      window.replaceHoneypotPage(incoming, { preserveMap: true });
      return {
        sameNode: document.querySelector("#browser-map-sentinel") === original,
        connected: Boolean(original?.isConnected),
        replacementDiscarded: !document.querySelector("#replacement-map"),
        surroundingContentUpdated: Boolean(document.querySelector('[data-browser-replacement="after"]')),
      };
    });
    expect(result).toEqual({
      sameNode: true,
      connected: true,
      replacementDiscarded: true,
      surroundingContentUpdated: true,
    });
  });

  test("confirmation modal owns focus, closes on Escape, and restores its trigger", async ({ page }) => {
    await page.goto("/events");
    const trigger = page.getByRole("button", { name: /export CSV/i });
    await trigger.click();
    const backdrop = page.locator("#hp-confirm-backdrop");
    await expect(backdrop).toHaveClass(/open/);
    await expect(backdrop).toHaveAttribute("aria-hidden", "false");
    await expect(page.locator("#hp-confirm-action")).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(backdrop).not.toHaveClass(/open/);
    await expect(backdrop).toHaveAttribute("aria-hidden", "true");
    await expect(trigger).toBeFocused();
  });

  test("viewer responses disable administrator-only report actions", async ({ page }) => {
    await page.route("**/api/reports/templates", (route) => route.fulfill({ status: 403, body: "administrator role required" }));
    await page.goto("/reports");
    await expect(page.locator("#hp-rp-admin-note")).toBeVisible();
    const controls = page.locator("#hp-rp-form input, #hp-rp-form select, #hp-rp-form button");
    expect(await controls.count()).toBeGreaterThan(0);
    await expect(controls.first()).toBeDisabled();
    expect(await controls.evaluateAll((items) => items.every((item) => (item as HTMLInputElement).disabled))).toBe(true);
  });

  test("administrator responses leave report actions available", async ({ page }) => {
    await page.route("**/api/reports/templates", (route) => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        templates: [{ id: "executive", name: "Executive", description: "Browser fixture", theme: "dark", elements: ["cover"] }],
        elements: [{ id: "cover", label: "Cover", description: "Title and scope" }],
        windows: ["24h"],
      }),
    }));
    await page.route("**/api/reports/definitions", (route) => route.fulfill({
      status: 200, contentType: "application/json", body: JSON.stringify({ definitions: [] }),
    }));
    await page.route("**/api/reports/generated", (route) => route.fulfill({
      status: 200, contentType: "application/json", body: JSON.stringify({ generated: [] }),
    }));
    await page.goto("/reports");
    await expect(page.locator("#hp-rp-templates")).toContainText("Executive");
    await expect(page.locator("#hp-rp-admin-note")).toBeHidden();
    await expect(page.locator("#hp-rp-save")).toBeEnabled();
    await expect(page.locator("#hp-rp-generate")).toBeEnabled();
  });

  test("payload workbench runs applicable analyzers and keeps external publication separate", async ({ page }) => {
    await page.goto("/payload-workbench/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    await expect(page.getByRole("heading", { name: "Payload workbench" })).toBeVisible();
    await expect(page.locator('[data-wb-analyzer][data-analyzer-id="deterministic"] input[type="checkbox"]')).toBeChecked();
    await expect(page.locator('[data-wb-analyzer][data-analyzer-id="revdeck"] input[type="checkbox"]')).toBeDisabled();
    await expect(page.getByText("never in Run all", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Start analysis run" }).focus();
    await expect(page.getByRole("button", { name: "Start analysis run" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator(".wb-run").first()).toContainText("completed");
    await expect(page.locator(".wb-run").first().getByRole("link", { name: /Open native result/ })).toHaveAttribute("href", /\/payload-analysis\//);
  });
});
