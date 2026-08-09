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
          // #1038: /reports' h1 collapses to zero width at exactly the
          // tablet tier (820x1180) in both themes -- reproduces on real
          // Xore/theme CSS (.overview-header's minmax(0, 1fr) column vs.
          // .live-panel's unwrapped .gen text, in the gap between the
          // 800px stacking breakpoint and where both columns' natural
          // widths actually fit). The fix belongs in Xore/theme, not a
          // local override of the vendored stylesheet -- tracked there,
          // not fixed here.
          test.fixme(viewportName === "tablet" && route === "/reports", "https://github.com/Xore/APIARY/issues/1038");
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
