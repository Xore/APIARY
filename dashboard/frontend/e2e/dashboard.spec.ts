import { expect, test, type Page } from "@playwright/test";
import { FIXTURE_SESSION_COOKIE_NAME, FIXTURE_SESSION_COOKIE_VALUE } from "./fixture-session.mjs";

const routes = [
  "/",
  "/source-health",
  "/alerts",
  "/events",
  "/ips",
  "/campaigns",
  "/clusters",
  "/attackers",
  "/kill-chain",
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
  // #672: this matrix's own route list was missing 4 real, statically
  // routed pages (confirmed against dashboard/main.go's actual
  // http.HandleFunc registrations, not guessed from dashboard/ui/*.html
  // filenames -- intel.html has no standalone route, it renders embedded
  // elsewhere, so it's correctly absent).
  //
  // /revdeck/{hash} deliberately NOT added here despite being a real
  // route: unlike /payload-workbench/{hash} above (which renders a real
  // 200 "not found" page for an unknown hash, so a placeholder like that
  // one's works fine), /revdeck/{hash}'s handler genuinely
  // http.NotFound()s when revdeckData() can't resolve the hash -- a
  // placeholder here would just assert 404 == 200 and fail on every run,
  // not exercise any layout. Needs a real seeded Rev·Deck job in the fake
  // ES this harness runs against to test properly; out of scope for this
  // matrix's fixture data as it stands.
  "/llm-analysis",
  // /ml-anomalies deliberately NOT added despite being a real route:
  // gated behind Behavior.ShowMLPanels, an admin-only setting that
  // defaults to false (dashboard/settings_domain.go's
  // defaultDashboardConfig() -- ShowMLPanels is absent from that struct
  // literal, so it's Go's bool zero-value). isolateReadOnlyBrowserState
  // above deliberately mocks every /api/settings/** call as 401 "signed
  // out" for every test in this matrix, so there's no way to toggle it
  // on from here -- confirmed live, this route 404s exactly as designed
  // for a signed-out/default-config viewer, not a bug.
  // /agent-campaigns (#154 phase 5) is the same story as /ml-anomalies
  // immediately above -- also gated behind mlPanelsEnabled() server-side
  // (main.go), also 404s for this matrix's signed-out/default-config
  // viewer for the identical reason. Deliberately not added here either.
  "/github-analysis",
  // bare /search (no ?q=) 303-redirects to /events -- confirmed in
  // search.go's own serveSearch(), not a bug -- which page.goto() follows
  // transparently, so a bare route here would just silently re-test
  // /events a second time under a different test name. A real query
  // actually exercises search's own results-list template.
  "/search?q=203.0.113.1",
] as const;

const viewports = {
  desktop: { width: 1440, height: 900 },
  tablet: { width: 820, height: 1180 },
  mobile: { width: 390, height: 844 },
  // #672: iPhone 14 Pro's CSS viewport (Playwright's own `devices["iPhone
  // 14 Pro"]` preset -- 393x852 -- not a guessed size). deviceScaleFactor
  // doesn't affect CSS layout/overflow, only screenshot pixel density, so
  // this matrix (which only asserts on layout, not pixels) doesn't need
  // the full device descriptor -- that's used separately for the actual
  // showcase screenshots below.
  iphone: { width: 393, height: 852 },
  uhq: { width: 1920, height: 1080 },
  "4k": { width: 3840, height: 2160 },
} as const;

async function isolateReadOnlyBrowserState(page: Page) {
  // #1034: the global OIDC middleware gates every route this matrix
  // navigates to. start-dashboard.mjs seeds a matching session directly
  // into the fixture Redis (see fixture-session.mjs) instead of driving a
  // real login round trip; this just has to hand the browser the cookie
  // that points at it. __Host- cookies require Secure, which Chromium
  // honors over plain HTTP for loopback origins -- the same exception
  // dashboard/oidc_auth.go's own isLoopbackHost() relies on.
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
  await page.route("**/api/settings/**", (route) => route.fulfill({ status: 401, body: "signed out" }));
  await page.route("**/api/whoami", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ username: "browser-check", display_name: "Browser Check", role: "viewer" }),
  }));
  await page.route("https://tile.openstreetmap.org/**", (route) => route.abort());
}

// runLayoutChecks is the full per-page assertion set shared by both the
// dark/light x every-tier matrix below and the dedicated real-2x-DPR pass
// further down -- extracted so DPR gets the exact same checks the 1x
// matrix already has, not a second, drifting copy of them.
async function runLayoutChecks(
  page: Page,
  route: string,
  viewportName: string,
  viewport: { width: number; height: number },
  theme: "dark" | "light",
) {
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

  // #672: the checks above only ever caught whole-page overflow -- real
  // defects found on this issue (mobile table clutter, a clipped country
  // badge, #668/#669's settings-modal/alert-badge bugs) are all *this*
  // shape: one element with real content collapsed to zero size, not the
  // page as a whole overflowing. Flags any element carrying its own
  // direct text (not just inherited from children -- that would flag
  // every container) that renders at zero width or height while not
  // deliberately hidden.
  //
  // Scoped to [data-hp-page-content] only, not body * -- confirmed live
  // (first draft of this check) that the toolbar/header region has real,
  // deliberately-collapsed-until-opened UI (closed dropdown menu items,
  // unopened modals sitting in the DOM with height:0/clip rather than
  // display:none, .sr-only accessibility text) that isn't
  // display:none/visibility:hidden and isn't a layout bug either -- every
  // one of those lives outside the actual page content this issue is
  // about. Page content can still open its own modals/toasts (evidence
  // viewer, confirm dialogs), so this stays scoped rather than trying to
  // enumerate every legitimate closed-by-default class name, which would
  // just be the same false-positive problem with extra steps.
  //
  // Two more false-positive classes found live, both excluded below:
  // (1) <option> elements always report a zero rect in headless Chromium
  // regardless of real visibility -- native <select> internals aren't
  // laid out by the normal box model, a well-known browser-testing
  // quirk, not a page bug; (2) an element can have display != none *on
  // itself* while a display:none *ancestor* (e.g. events.html's per-row
  // detail block, collapsed until expanded) still means it renders
  // nothing -- getComputedStyle(el).display never reflects an ancestor's
  // display, only offsetParent reliably does (null for both a
  // display:none element and any of its descendants).
  const clipped = await page.evaluate(() => {
    const problems: string[] = [];
    const root = document.querySelector("[data-hp-page-content]");
    if (!root) return problems;
    for (const el of root.querySelectorAll<HTMLElement>("*")) {
      if (el.tagName === "OPTION") continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (el.offsetParent === null && style.position !== "fixed") continue;
      const hasOwnText = Array.from(el.childNodes).some(
        (n) => n.nodeType === Node.TEXT_NODE && (n.textContent ?? "").trim().length > 0,
      );
      if (!hasOwnText) continue;
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) {
        const cls = el.className ? `.${String(el.className).split(" ").join(".")}` : "";
        problems.push(`${el.tagName.toLowerCase()}${cls}: "${(el.textContent ?? "").trim().slice(0, 60)}"`);
      }
    }
    return problems;
  });
  expect(clipped, `${route} at ${viewportName}/${theme} has zero-size element(s) with real text content in the page content area`).toEqual([]);
}

test.describe("dark/light responsive acceptance matrix", () => {
  for (const [viewportName, viewport] of Object.entries(viewports)) {
    for (const theme of ["dark", "light"] as const) {
      for (const route of routes) {
        test(`${theme} ${viewportName} ${route}`, async ({ page }) => {
          await runLayoutChecks(page, route, viewportName, viewport, theme);
        });
      }
    }
  }
});

// #672: "UHQ / high-DPI" per the issue's own wording means a real 2x
// device-pixel-ratio panel, not just a bigger 1x viewport -- the "uhq"
// entry in the matrix above is 1920x1080 at whatever DPR this project's
// default device profile uses (Desktop Chrome's own default, 1), so it
// was never actually testing the "high-DPI" half of that tier's own
// name. deviceScaleFactor can only be set at browser-context creation,
// not via page.setViewportSize() after the fact (confirmed against
// Playwright's own API -- setViewportSize only ever changes CSS
// viewport dimensions) -- test.use() at describe scope is the real
// mechanism, hence this being a separate block rather than a 7th entry
// squeezed into the shared viewports object above.
//
// One theme (dark) rather than both: CSS layout geometry essentially
// never depends on device-pixel-ratio by itself (the exceptions are
// image-resolution/image-set() and rare @media (min-resolution) rules,
// none of which this codebase's vendored theme.css uses -- confirmed by
// grep before deciding this), so a real dark+light x 24-route x-2 pass
// here would mostly duplicate the 1x matrix's own coverage for double
// the runtime. Still real DPR, still worth running -- catches the class
// of bug the issue actually named ("assumes 1x"), just without doubling
// this specific block's cost for a dimension unlikely to interact with
// theme choice.
test.describe("UHQ tier at real 2x device-pixel-ratio", () => {
  test.use({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 2 });

  for (const route of routes) {
    test(`dark uhq-2x ${route}`, async ({ page }) => {
      await runLayoutChecks(page, route, "uhq-2x", { width: 1920, height: 1080 }, "dark");
    });
  }
});

// #672: "modals and toasts fully within the viewport" is explicitly named
// in the issue -- and unlike every check above, nothing exercises this at
// all, at any tier, before now. The existing single modal test
// ("confirmation modal owns focus...") only ever runs at this project's
// one default viewport. Both modals tested here (command palette,
// confirm dialog) are shell-level markup in partials/dashboard.html --
// present identically on every route, not per-page -- so testing them
// once per viewport tier here is the right scope, not testing them
// again on all 24 routes (that would just be re-proving the shell
// partial renders the same everywhere, which the matrix above already
// covers structurally).
test.describe("modals stay within the viewport at every tier", () => {
  for (const [viewportName, viewport] of Object.entries(viewports)) {
    test(`command palette at ${viewportName}`, async ({ page }) => {
      await isolateReadOnlyBrowserState(page);
      await page.setViewportSize(viewport);
      await page.goto("/");
      await page.keyboard.press("/");
      const palette = page.locator("#hp-command-palette");
      await expect(palette).toHaveAttribute("aria-hidden", "false");
      // aria-hidden flips synchronously in JS, well before the CSS
      // dialog-in transition (theme.css's --transition, 160ms) actually
      // finishes settling the modal into its resting position -- confirmed
      // live this test caught a real-looking but entirely transient
      // mid-animation geometry without this wait (a top: -210px reading
      // that was gone by 600ms, correct at rest).
      await page.waitForTimeout(300);
      const rect = await palette.evaluate((el) => el.getBoundingClientRect());
      expect(rect.left, `command palette left edge clipped at ${viewportName}`).toBeGreaterThanOrEqual(0);
      expect(rect.top, `command palette top edge clipped at ${viewportName}`).toBeGreaterThanOrEqual(0);
      expect(rect.right, `command palette right edge overflows at ${viewportName}`).toBeLessThanOrEqual(viewport.width + 1);
      expect(rect.bottom, `command palette bottom edge overflows at ${viewportName}`).toBeLessThanOrEqual(viewport.height + 1);
    });

    test(`confirm dialog at ${viewportName}`, async ({ page }) => {
      await isolateReadOnlyBrowserState(page);
      await page.setViewportSize(viewport);
      await page.goto("/events");
      await page.getByRole("button", { name: /export CSV/i }).click();
      const dialog = page.locator("#hp-confirm-backdrop .edit-dialog");
      await expect(page.locator("#hp-confirm-backdrop")).toHaveClass(/open/);
      const rect = await dialog.evaluate((el) => el.getBoundingClientRect());
      expect(rect.left, `confirm dialog left edge clipped at ${viewportName}`).toBeGreaterThanOrEqual(0);
      expect(rect.top, `confirm dialog top edge clipped at ${viewportName}`).toBeGreaterThanOrEqual(0);
      expect(rect.right, `confirm dialog right edge overflows at ${viewportName}`).toBeLessThanOrEqual(viewport.width + 1);
      expect(rect.bottom, `confirm dialog bottom edge overflows at ${viewportName}`).toBeLessThanOrEqual(viewport.height + 1);
    });
  }
});

test.describe("dashboard browser behaviour", () => {
  test.beforeEach(async ({ page }) => {
    await isolateReadOnlyBrowserState(page);
  });

  test("render-first collection batch keeps shaped placeholders until hydration completes", async ({ page }) => {
    const holdJSON = async (pattern: string, body: unknown) => {
      let release!: () => void;
      const gate = new Promise<void>((resolve) => { release = resolve; });
      await page.route(pattern, async (route) => {
        await gate;
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
      });
      return release;
    };

    const releaseAlerts = await holdJSON("**/api/alerts", []);
    await page.goto("/alerts", { waitUntil: "domcontentloaded" });
    await expect(page.locator("#alerts-results")).toHaveAttribute("aria-busy", "true");
    await expect(page.locator("#alert-rows .skeleton-line")).toHaveCount(3);
    releaseAlerts();
    await expect(page.locator("#alerts-results")).toHaveAttribute("aria-busy", "false");
    await expect(page.locator("#alert-empty")).toContainText("No alerts recorded");
    await page.unroute("**/api/alerts");

    const releaseHistory = await holdJSON("**/api/history**", { hits: { hits: [{ _source: { sensor: "fixture" } }] } });
    await page.goto("/history", { waitUntil: "domcontentloaded" });
    await expect(page.locator("#history-results .skeleton-line")).toHaveCount(6);
    releaseHistory();
    await expect(page.locator("#history-results")).toHaveAttribute("aria-busy", "false");
    await expect(page.locator("#history-results")).toContainText('"sensor": "fixture"');
    await page.unroute("**/api/history**");

    const releaseDeadLetters = await holdJSON("**/api/dead-letters**", { hits: { hits: [] } });
    await page.goto("/dead-letters", { waitUntil: "domcontentloaded" });
    await expect(page.locator("#dead-rows .hp-data-card")).toHaveCount(3);
    releaseDeadLetters();
    await expect(page.locator("#dead-rows")).toHaveAttribute("aria-busy", "false");
    await expect(page.locator("#dead-rows")).toContainText("No matching dead letters");
    await page.unroute("**/api/dead-letters**");

    const releaseTemplates = await holdJSON("**/api/reports/templates", {
      templates: [{ id: "executive", name: "Executive", description: "Fixture template", theme: "dark", elements: ["cover"] }],
      elements: [{ id: "cover", label: "Cover", description: "Title and scope" }],
      windows: ["24h"],
    });
    const releaseDefinitions = await holdJSON("**/api/reports/definitions", { definitions: [] });
    const releaseGenerated = await holdJSON("**/api/reports/generated", { generated: [] });
    await page.goto("/reports", { waitUntil: "domcontentloaded" });
    await expect(page.locator("#hp-rp-templates .skeleton-line")).toHaveCount(6);
    await expect(page.locator("#hp-rp-definitions .skeleton-line")).toHaveCount(3);
    await expect(page.locator("#hp-rp-generated .project-card")).toHaveCount(3);
    releaseTemplates(); releaseDefinitions(); releaseGenerated();
    await expect(page.locator("#hp-rp-templates")).toContainText("Executive");
    await expect(page.locator("#hp-rp-definitions")).toHaveAttribute("aria-busy", "false");
    await expect(page.locator("#hp-rp-generated")).toHaveAttribute("aria-busy", "false");
    await page.unroute("**/api/reports/templates");
    await page.unroute("**/api/reports/definitions");
    await page.unroute("**/api/reports/generated");

    const releaseSemantic = await holdJSON("**/api/llm/analysis/search**", {
      available: true,
      hits: [{ score: 0.91, "@timestamp": "2026-08-15T10:00:00Z", severity: "high", summary: "Fixture match", session_id: "fixture-session" }],
    });
    await page.goto("/llm-analysis", { waitUntil: "domcontentloaded" });
    await page.locator("#hp-llm-search-q").fill("credential exfiltration");
    await page.locator("#hp-llm-search-run").click();
    await expect(page.locator("#hp-llm-search-results")).toHaveAttribute("aria-busy", "true");
    await expect(page.locator("#hp-llm-search-rows .skeleton-line")).toHaveCount(3);
    releaseSemantic();
    await expect(page.locator("#hp-llm-search-results")).toHaveAttribute("aria-busy", "false");
    await expect(page.locator("#hp-llm-search-rows")).toContainText("Fixture match");
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

  test("live overview hydration preserves the connected map node", async ({ page }) => {
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
        <header id="overview-header"><h1>Hydrated overview</h1></header>
        <div id="panel-live" data-dashboard-panel="live">
          <div data-browser-replacement="before"></div>
          <div data-attack-map-card><div id="replacement-map">replace me</div></div>
          <div data-browser-replacement="after"></div>
        </div>`;
      (window as any).hydrateHoneypotOverview(incoming);
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

  test("overview refresh preserves tabs, modal focus, viewport, and focused controls", async ({ page }) => {
    const initial = await page.goto("/");
    expect(initial?.ok()).toBe(true);
    const refreshedHTML = (await initial!.text()).replaceAll("Honeypot command center", "Hydrated command center");
    await page.route(page.url(), (route) => route.fulfill({ status: 200, contentType: "text/html", body: refreshedHTML }));

    const threats = page.getByRole("tab", { name: /Threat landscape/ });
    await threats.click();
    await page.evaluate(() => {
      const tabs = document.querySelector<HTMLElement>('[role="tablist"][aria-label="Dashboard views"]');
      if (!tabs) throw new Error("overview tabs missing");
      tabs.dataset.hydrationSentinel = "connected";
      const root = document.querySelector<HTMLElement>("[data-hp-page-content]");
      if (!root) throw new Error("page root missing");
      root.style.paddingBottom = "2000px";
      const viewport = document.querySelector<HTMLElement>(".app-main");
      if (!viewport) throw new Error("page viewport missing");
      viewport.scrollTo(0, 700);
    });
    const scrollBefore = await page.locator(".app-main").evaluate((element) => element.scrollTop);
    expect(scrollBefore).toBeGreaterThan(0);

    await page.keyboard.press("/");
    const command = page.locator("#hp-investigation-query");
    await command.fill("operator draft");
    await expect(command).toBeFocused();
    await (page.evaluate(() => (window as any).refreshDashboard()) as Promise<void>);
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));

    await expect(page.locator("#overview-header h1")).toContainText("Hydrated command center");
    await expect(page.locator("#hp-command-palette")).toHaveClass(/open/);
    await expect(command).toHaveValue("operator draft");
    await expect(command).toBeFocused();
    await expect(threats).toHaveAttribute("aria-selected", "true");
    await expect(page.locator('[role="tablist"][data-hydration-sentinel="connected"]')).toHaveCount(1);
    expect(Math.abs((await page.locator(".app-main").evaluate((element) => element.scrollTop)) - scrollBefore)).toBeLessThanOrEqual(1);

    await page.keyboard.press("Escape");
    await page.getByRole("tab", { name: /Live operations/ }).click();
    const focusedControl = page.locator('#panel-live a[href="/events?since=24h"]');
    await focusedControl.evaluate((element) => { element.dataset.hydrationSentinel = "focused"; });
    await focusedControl.focus();
    await expect(focusedControl).toBeFocused();
    await (page.evaluate(() => (window as any).refreshDashboard()) as Promise<void>);
    await expect(page.locator('#panel-live a[data-hydration-sentinel="focused"]')).toHaveCount(1);
    await expect(focusedControl).toBeFocused();
  });

  test("failed overview refresh retains the current document", async ({ page }) => {
    await page.goto("/");
    await page.evaluate(() => {
      const root = document.querySelector<HTMLElement>("[data-hp-page-content]");
      if (!root) throw new Error("page root missing");
      root.dataset.refreshFailureSentinel = "retained";
    });
    await page.route(page.url(), (route) => route.fulfill({ status: 503, body: "temporarily unavailable" }));
    await (page.evaluate(() => (window as any).refreshDashboard()) as Promise<void>);
    await expect(page.locator('[data-hp-page-content][data-refresh-failure-sentinel="retained"]')).toHaveCount(1);
    await expect(page.locator("#overview-header")).toBeVisible();
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

  test("event explorer's IP-isolation panel shows a live checked count and bulk select", async ({ page }) => {
    // #514: real correlated-fingerprint fixture data (2+ IPs sharing one
    // fingerprint) isn't part of the e2e cowrie log fixture, so this
    // intercepts the real /events response and injects the same markup
    // fingerprintIPCorrelation would produce -- exercising the actual
    // client-side JS (hp-app.js's initIPFilterMenus), not a hand-rolled
    // substitute for it.
    await page.route("**/events", async (route) => {
      const response = await route.fetch();
      let body = await response.text();
      const panel = `<details class="hp-open-in"><summary>Isolate IP&hellip;</summary>
        <div class="dropdown hp-open-in-menu hp-ip-filter-menu">
          <div class="hp-open-in-heading">IPs behind this fingerprint <span class="hp-ip-filter-summary" data-hp-ip-filter-summary></span></div>
          <form method="get" action="/events">
            <div class="hp-ip-filter-bulk">
              <button class="btn btn-sm btn-secondary" type="button" data-hp-ip-filter-all>All</button>
              <button class="btn btn-sm btn-secondary" type="button" data-hp-ip-filter-none>None</button>
            </div>
            <div class="hp-ip-filter-list" data-hp-ip-filter-list>
              <label class="hp-ip-filter-row"><input type="checkbox" name="ips" value="203.0.113.1" checked><span>203.0.113.1</span></label>
              <label class="hp-ip-filter-row"><input type="checkbox" name="ips" value="203.0.113.2"><span>203.0.113.2</span></label>
              <label class="hp-ip-filter-row"><input type="checkbox" name="ips" value="203.0.113.3" checked><span>203.0.113.3</span></label>
            </div>
          </form>
        </div></details>`;
      body = body.replace("</main>", panel + "</main>");
      await route.fulfill({ response, body });
    });
    await page.goto("/events");
    await page.locator(".hp-open-in > summary", { hasText: "Isolate IP" }).click();
    const summary = page.locator("[data-hp-ip-filter-summary]");
    await expect(summary).toHaveText("(2 of 3 checked)");

    await page.locator("[data-hp-ip-filter-all]").click();
    await expect(summary).toHaveText("(3 of 3 checked)");
    for (const box of await page.locator(".hp-ip-filter-list input[type=checkbox]").all()) {
      await expect(box).toBeChecked();
    }

    await page.locator("[data-hp-ip-filter-none]").click();
    await expect(summary).toHaveText("(0 of 3 checked)");
    for (const box of await page.locator(".hp-ip-filter-list input[type=checkbox]").all()) {
      await expect(box).not.toBeChecked();
    }

    await page.locator('.hp-ip-filter-list input[value="203.0.113.2"]').check();
    await expect(summary).toHaveText("(1 of 3 checked)");
  });

  test("payload workbench runs applicable analyzers and keeps external publication separate", async ({ page }) => {
    await page.route("**/api/payload-workbench/model-status", route => route.fulfill({ status: 503, body: "fixture model source unavailable" }));
    await page.goto("/payload-workbench/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    await expect(page.getByRole("heading", { name: "Payload workbench" })).toBeVisible();
    await expect(page.locator('[data-wb-analyzer][data-analyzer-id="deterministic"] input[type="checkbox"]')).toBeChecked();
    await expect(page.locator('[data-wb-analyzer][data-analyzer-id="revdeck"] input[type="checkbox"]')).toBeDisabled();
    await expect(page.locator("[data-wb-model-status]")).toContainText("could not be loaded");
    await expect(page.locator("[data-wb-known]")).not.toHaveAttribute("aria-busy", "true");
    await expect(page.getByText("never in Run all", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Start analysis run" }).focus();
    await expect(page.getByRole("button", { name: "Start analysis run" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator(".wb-run").first()).toContainText("completed");
    await expect(page.locator(".wb-run").first().getByRole("link", { name: /Open native result/ })).toHaveAttribute("href", /\/payload-analysis\//);
  });

  test("clicking a payload card outside its action menu opens payload analysis (#1137)", async ({ page }) => {
    await page.goto("/payloads");
    const card = page.locator(".project-card").first();
    await expect(card).toBeVisible();
    await expect(card.getByRole("region", { name: "Byte preview" })).toContainText("00000000");
    await expect(card.getByRole("button", { name: "Preview bytes" })).toHaveCount(0);
    // .project-card__desc is plain text, not the title link or the action
    // menu -- exactly the "dead" part of the card #1137 reported.
    await card.locator(".project-card__desc").click();
    await expect(page).toHaveURL(/\/payload-analysis\//);
  });

  test("clicking a payload card's action menu opens the menu instead of navigating (#1137)", async ({ page }) => {
    await page.goto("/payloads");
    const card = page.locator(".project-card").first();
    await card.locator("summary").click();
    await expect(card.locator(".action-menu__popover")).toBeVisible();
    await expect(page).toHaveURL("/payloads");
  });

  test("attacker identities list shows the seeded entity and its graph (#1203)", async ({ page }) => {
    await page.goto("/attackers");
    await expect(page.locator("#attackers-table")).toContainText("e2efixtu");
    await expect(page.locator("#attackers-table")).toContainText("3"); // 3 member IPs
    await page.getByRole("link", { name: "graph →" }).first().click();
    await expect(page).toHaveURL(/\/attackers\?id=/);
    await expect(page.locator("#attackers-graph")).toBeVisible();
    // The graph itself renders to Cytoscape.js canvas layers (#1203
    // rework), not DOM text -- Cytoscape's own scratch layers (e.g. its
    // rubber-band selectbox canvas) are legitimately zero-sized until
    // used, so assert the fetch-then-render status line completed and
    // that canvases mounted at all, rather than any one canvas's
    // visibility or reading node labels off the canvas.
    await expect(page.locator("[data-attacker-graph-status]")).toContainText("member IP");
    await expect(page.locator("#attackers-graph canvas")).not.toHaveCount(0);
    // #1327 shell+hydrate: the selected entity's own metadata cards
    // (events/sensors/dates/evidence collections) used to render inline
    // inside #attackers-graph itself; it's now part of the
    // #attackers-root fragment hp-attackers-detail.js hydrates in
    // separately, alongside #attackers-graph rather than nested in it.
    await expect(page.locator("#attackers-selected-meta")).toContainText("root / fixture-0");
    // #1444: all selected fields use the shared card treatment, while
    // potentially long evidence collections and the entity table stay
    // inside bounded scroll regions.
    await expect(page.locator("#attackers-selected-meta > .card")).toHaveCount(9);
    await expect(page.getByRole("heading", { name: "Credential pairs (1)" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Fingerprints (1)" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Payload hashes (1)" })).toBeVisible();
    await expect(page.locator("#attackers-selected-meta .card__scroll")).toHaveCount(5);
    await expect(page.locator("#attackers-table > .card__scroll")).toBeVisible();
  });

  

  test("kill-chain analytics renders all three ECharts charts (#1224)", async ({ page }) => {
    await page.goto("/kill-chain");
    // All three have real fixture data and render to an actual ECharts
    // canvas -- same "canvas mounted, not any specific pixel" assertion
    // shape the attacker graph's own Cytoscape test above uses, for the
    // same reason (a charting library's internal canvas layout is its own
    // implementation detail, not this dashboard's contract).
    await expect(page.locator("#kill-chain-sankey-card canvas")).not.toHaveCount(0);
    await expect(page.locator("#kill-chain-timeline-card canvas")).not.toHaveCount(0);
    await expect(page.locator("#kill-chain-attck-card canvas")).not.toHaveCount(0);
    await expect(page.locator('[data-echart-status="/api/campaign-timeline"]')).toContainText("campaign");
    await expect(page.locator('[data-echart-status="/api/attck-coverage"]')).toContainText("technique");
    // The fixture's seeded events each touch exactly one ATT&CK tactic on
    // their own session, so both tactics still appear as Sankey nodes but
    // there's no same-session pair to flow between them -- a real,
    // legitimate "0 flows" state, not the genuinely-empty (0 nodes) case
    // initSankey guards separately (ECharts' own sankey layout throws on
    // a zero-node graph, confirmed live during #1224's own development).
    await expect(page.locator('[data-echart-status="/api/kill-chain-sankey"]')).toContainText("tactics observed, 0 flows");
  });

  test("payload analysis hydrates the aggregation cards after the initial render (#1142)", async ({ page }) => {
    await page.goto("/payload-analysis/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    // The fast path renders identity/hashes immediately; the three
    // aggregation cards start as skeletons and hp-payload-analysis.js
    // replaces them once /api/payload-analysis/<hash>/aggregation
    // resolves -- this fixture hash has no sandbox/GitHub/Ghidra/ES
    // results seeded, so hydration should land on each card's real empty
    // state, not leave the skeleton in place forever.
    await expect(page.locator("[data-hp-pl-sandbox-runs] .skeleton-line")).toHaveCount(0, { timeout: 5000 });
    await expect(page.locator("[data-hp-pl-sandbox-runs]")).toContainText("No completed KVM sandbox run");
    await expect(page.locator("[data-hp-pl-github-analysis]")).toContainText("Not published to Xore/honeypot");
    await expect(page.locator("[data-hp-pl-known-elsewhere]")).toContainText("not yet analyzed");
    await expect(page.locator("#hp-pl-known-elsewhere-heading")).toContainText("not seen elsewhere");
    await page.getByRole("tab", { name: /Content/ }).click();
    await expect(page.getByRole("heading", { name: "Hex / ASCII preview — first 512 bytes" })).toBeVisible();
    await expect(page.locator("[data-hp-pl-text] .card__scroll")).toContainText("example.invalid");
    await expect(page.getByRole("button", { name: /Printable strings|Open decoded candidates|Hex \/ ASCII preview/ })).toHaveCount(0);
    await page.getByRole("tab", { name: /Identity/ }).click();
    await expect(page.locator("[data-hp-pl-identity] .card__label", { hasText: "SHA-1" })).toBeVisible();
    await expect(page.locator("[data-hp-pl-identity] .card__label", { hasText: "MD5" })).toBeVisible();
    await expect(page.getByRole("button", { name: "More hashes" })).toHaveCount(0);
  });

  test("Ghidra AI reports put single-line prose sentences on separate lines (#1442)", async ({ page }) => {
    await page.goto("/");
    await page.addScriptTag({ url: "/static/marked.js" });
    await page.addScriptTag({ url: "/static/dompurify.min.js" });
    await page.evaluate(() => {
      const report = document.createElement("div");
      report.className = "hp-ai-report__body";
      report.setAttribute("data-markdown", "");
      report.textContent = [
        "First sentence. Second sentence! Third sentence?",
        "",
        "- List sentence one. List sentence two.",
        "",
        "A [linked sentence.](https://example.com/report) Next sentence.",
        "",
        "```text",
        "code.example. must stay untouched.",
        "```",
      ].join("\n");
      document.body.appendChild(report);
    });
    await page.addScriptTag({ url: "/static/hp-ghidra-markdown.js" });

    const report = page.locator(".hp-ai-report__body");
    await expect(report.locator("p").first().locator("br")).toHaveCount(2);
    await expect(report.locator("li br")).toHaveCount(1);
    await expect(report.locator('a[href="https://example.com/report"]')).toHaveCount(1);
    await expect(report.locator("pre code br")).toHaveCount(0);
    await expect(report.locator("pre code")).toHaveText("code.example. must stay untouched.\n");
  });

  test("Ghidra detail keeps its shaped shell and all datasets visible in bounded cards", async ({ page }) => {
    const hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let releaseFragment!: () => void;
    const fragmentGate = new Promise<void>(resolve => { releaseFragment = resolve; });
    let releaseGraph!: () => void;
    const graphGate = new Promise<void>(resolve => { releaseGraph = resolve; });
    await page.route(`**/ghidra/${hash}/fragment`, async route => {
      const response = await route.fetch();
      await fragmentGate;
      await route.fulfill({ response });
    });
    await page.route(`**/api/ghidra-callgraph/${hash}`, async route => {
      const response = await route.fetch();
      await graphGate;
      await route.fulfill({ response });
    });

    await page.goto(`/ghidra/${hash}`);
    const root = page.locator("#ghidra-detail-root");
    await expect(root).toHaveAttribute("aria-busy", "true");
    await expect(root.getByRole("tab", { name: /Overview/ })).toBeVisible();
    await expect(root.getByRole("heading", { name: "Analysis identity" })).toBeVisible();
    await expect(root.locator(".card.wide")).toHaveCount(18);

    releaseFragment();
    await expect(root).not.toHaveAttribute("aria-busy", "true");
    await root.getByRole("tab", { name: /Code/ }).click();
    await expect(root.locator('[aria-label="Full import list"]')).toContainText("CreateFileW");
    await expect(root.locator("[data-ghidra-callgraph-loading]")).toBeVisible();
    await expect(root.getByRole("button", { name: /Open the full|Open the recovered|Open the recovery/ })).toHaveCount(0);

    releaseGraph();
    await expect(root.locator("[data-ghidra-callgraph-url]")).toHaveAttribute("aria-busy", "false");
    await expect(root.locator("[data-ghidra-callgraph-status]")).toContainText("function");
    await root.getByRole("tab", { name: /Deep dive/ }).click();
    await expect(root.locator('[aria-label="Full type list"]')).toContainText("FIXTURE");
    await root.getByRole("tab", { name: /Data/ }).click();
    await expect(root.locator('[aria-label="Full string table"]')).toContainText("browser-fixture.example");

    await page.unroute(`**/api/ghidra-callgraph/${hash}`);
    await page.route(`**/api/ghidra-callgraph/${hash}`, route => route.fulfill({ status: 503, body: "fixture graph source unavailable" }));
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`/ghidra/${hash}`);
    await page.locator("#ghidra-detail-root").getByRole("tab", { name: /Code/ }).click();
    const failedGraph = page.locator("[data-ghidra-callgraph-url]");
    await expect(failedGraph).toHaveAttribute("role", "alert");
    await expect(failedGraph).toContainText("Call graph failed to load");
    expect((await failedGraph.boundingBox())?.width ?? 391).toBeLessThanOrEqual(390);

    await page.unroute(`**/api/ghidra-callgraph/${hash}`);
    await page.route(`**/api/ghidra-callgraph/${hash}`, route => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ nodes: [], edges: [] }) }));
    await page.goto(`/ghidra/${hash}`);
    await page.locator("#ghidra-detail-root").getByRole("tab", { name: /Code/ }).click();
    await expect(page.locator("[data-ghidra-callgraph-url]")).toHaveAttribute("role", "status");
    await expect(page.locator("[data-ghidra-callgraph-url]")).toContainText("No caller/callee cross-references");
  });

  test("sandbox detail hydrates from a job-scoped fragment (#1441)", async ({ page }) => {
    await page.goto("/sandbox/windows-ghosts-browser-fixture");
    const root = page.locator("#sandbox-detail-root");
    await expect(root).not.toHaveAttribute("aria-busy", "true");
    await expect(root.locator(".card__row", { hasText: "SHA-1" })).toContainText("bbbbbbbb");
    await expect(root.locator(".card__row", { hasText: "MD5" })).toContainText("aaaaaaaa");
    await expect(page.getByRole("button", { name: "More hashes" })).toHaveCount(0);
    await expect(root.locator("#sandbox-detail-actions")).toBeVisible();
    await expect(root).toContainText("PE32 browser fixture");
    await expect(root.locator('[data-hp-evidence-body="sb-stdout"]')).toBeVisible();
    await expect(root.locator('[data-hp-evidence-body="sb-stdout"] .card__scroll')).toContainText("sandbox fixture standard output");
    await expect(root.locator('[data-hp-evidence-body="sb-ascii-strings"]')).toContainText("sandbox visible string");
    await expect(root.locator("[data-hp-evidence]")).toHaveCount(0);
    await expect(root.locator("#syscalls-chart canvas")).not.toHaveCount(0);
  });

  test("CAPE detail hydrates a shaped shell and renders its analyzer log inline", async ({ page }) => {
    const hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    await page.route(`**/cape/${hash}/fragment`, async route => {
      const response = await route.fetch();
      await gate;
      await route.fulfill({ response });
    });
    await page.goto(`/cape/${hash}`);
    const root = page.locator("#cape-detail-root");
    await expect(root).toHaveAttribute("aria-busy", "true");
    await expect(root.getByRole("heading", { name: "Analyzer log" })).toBeVisible();
    await expect(root.locator(".card.wide")).toHaveCount(6);
    release();
    await expect(root).not.toHaveAttribute("aria-busy", "true");
    await expect(root.locator('[aria-label="Analyzer log output"]')).toContainText("CAPE analyzer fixture line");
    await expect(root.getByRole("button", { name: "Open the analyzer log" })).toHaveCount(0);
  });

  test("cache-warming skeletons auto-reload after an SPA navigation, not just a hard refresh (#1384)", async ({ page }) => {
    // The warming retry used to be an inline <script nonce=...> next to
    // each warming marker -- fine on a real page load, but hp-dynamic-nav.js's
    // SPA-style swap (hp-app.js's mountPage -> pageContent.replaceChildren)
    // never executes a <script> inserted via DOM APIs, so a page reached
    // via an in-app link (not a hard refresh) got a skeleton that never
    // retried. hp-warming-reload.js fixes this by living outside the
    // swapped content and listening for the "hp-dynamic-nav" event itself.
    await page.goto("/payloads");
    // A marker set in this JS realm only survives if nothing actually
    // reloads -- confirming its absence afterward proves a real navigation
    // happened, not just that some in-page timer fired.
    await page.evaluate(() => {
      (window as unknown as Record<string, unknown>).__hpPreReloadMarker = true;
    });
    const reloaded = page.waitForEvent("load", { timeout: 5000 });
    // Simulate exactly what mountPage leaves behind: a swapped-in warming
    // panel plus the same event hp-dynamic-nav.js dispatches after every
    // in-family navigation -- no real second navigation needed to trigger it.
    await page.evaluate(() => {
      const container = document.querySelector("[data-hp-page-content]") ?? document.body;
      const marker = document.createElement("div");
      marker.setAttribute("data-payload-warming", "");
      container.appendChild(marker);
      document.dispatchEvent(new CustomEvent("hp-dynamic-nav"));
    });
    await reloaded;
    expect(
      await page.evaluate(() => (window as unknown as Record<string, unknown>).__hpPreReloadMarker),
    ).toBeUndefined();
  });
});
