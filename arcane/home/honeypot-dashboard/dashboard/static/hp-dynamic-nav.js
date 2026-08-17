/* #1141: makes the #1139 consolidated payload/results page family (Captured
   payloads, payload-analysis, the workbench artifact picker, payload
   workbench, Analysis results and its Sandbox/GitHub tabs, and the sandbox/
   GitHub-analysis detail pages) navigate in place instead of a full page
   load on every selection -- built directly on hp-app.js's own mountPage
   (window.replaceHoneypotPage), the same fetch-and-swap mechanism
   overview.html's 60s/SSE refresh already uses, just triggered by a click
   instead of a timer, plus history.pushState so the URL/back/forward/
   refresh/bookmarks all still resolve to the right view -- see the issue's
   own text for why a plain SSE-timer refresh never had to solve that.

   Scoped to exactly the routes #1139 actually consolidated (not a
   site-wide router): a card whose target happens to fall outside this
   family (e.g. a workbench run's ResultURL pointing at /ghidra/<hash> or
   /revdeck/<hash>, neither part of this consolidation) simply isn't
   matched below and falls through to a normal, full page navigation --
   no special-casing needed, the route list is the single source of truth. */
(() => {
  "use strict";

  /* #1564: loaded from the shared "style" partial on every page now; the
     #1139 family pages still carry their own <script> tag, so guard
     against double registration of the document-level click handler. */
  if (window.__hpDynamicNav) return;
  window.__hpDynamicNav = true;

  const pageNonce = document.querySelector("script[nonce], style[nonce]")?.nonce || "";

  const DYNAMIC_ROUTES = [
    /^\/payloads$/,
    /^\/payload-analysis\/[^/]+$/,
    /^\/payload-workbench\/results$/,
    // Excludes /payload-workbench/results itself (already matched above)
    // and the bare /payload-workbench index, which 302s (#1139) rather
    // than rendering a page a fetch-and-swap could use.
    /^\/payload-workbench\/(?!results$)[^/]+$/,
    // Excludes /sandbox/vnc (registered ahead of the job-id prefix route in
    // main.go -- a VNC viewer target, not a result detail page) and the
    // bare /sandbox index, which also 302s.
    /^\/sandbox\/(?!vnc$)[^/]+$/,
    /^\/github-analysis\/[^/]+$/,
    // #1564 (design refresh): shell routes navigate in place -- "one
    // flawless page" -- but ONLY pages whose behaviour comes entirely from
    // the shell scripts (hp-app.js delegation + hp-page-mounted
    // re-attachers). Pages that ship their own bottom-of-content scripts
    // (overview/ips/attackers/kill-chain/commands/ml-anomalies/reports/
    // canarytokens/sessions/investigate: cytoscape graphs, ECharts
    // hydration, studio bindings) stay full document loads until those
    // scripts learn the mount/unmount convention -- a dynamically appended
    // script executes once per session, so a second visit through a swap
    // would leave their views stuck loading (caught by the browser matrix
    // on the attackers graph). Also deliberately excluded: /settings
    // (page mode resolves at script load), /sandbox/vnc, /tty/*,
    // /revdeck/*, /auth/*, and anything that isn't a shell page (/api,
    // /static, /export, /metrics, PDFs).
    /^\/events$/,
    /^\/search$/,
    /^\/clusters$/,
    /^\/campaigns$/,
    /^\/history$/,
    /^\/dead-letters$/,
    /^\/source-health$/,
    /^\/alerts$/,
    /^\/auth-events$/,
    /^\/llm-analysis$/,
    /^\/agent-campaigns$/,
    /^\/recordings$/,
    /^\/sensors$/,
  ];
  const isDynamicRoute = pathname => DYNAMIC_ROUTES.some(re => re.test(pathname));

  const reNonceTree = root => {
    if (!pageNonce || !root.querySelectorAll) return;
    root.querySelectorAll("[nonce]").forEach(el => {
      el.nonce = pageNonce;
      el.setAttribute("nonce", pageNonce);
    });
  };

  /* Pages in this family carry optional extra markup that hp-app.js's
     mountPage never touches (it only swaps [data-hp-page-content]) --
     payloads.html's PDF-viewer modal (a .app-shell sibling in <body>) and
     github_analysis.html's report-viewer modal (nested inside .app-shell,
     after </main> -- a genuine inconsistency between the two templates,
     not something to rely on a fixed nesting depth for), each paired with
     a script (hp-payload-report.js, hp-payload-analysis.js,
     hp-github-analysis.js) that binds to it once, by id, at IIFE-execution
     time; payload-workbench's own hp-workbench.js is a <head> script, not
     even in <body> at all. Re-creating an already-present element on every
     visit would orphan those bindings and duplicate-register their own
     document-level listeners (hp-payload-analysis.js/hp-github-analysis.js/
     hp-payload-report.js all attach one) -- so this walks the WHOLE fetched
     document (not a fixed nesting level) and only ever ADDS an id'd
     element or script the first time a target page needs it, matched by
     id/src, never replacing or removing one already present. */
  const mergeExtraContent = doc => {
    doc.querySelectorAll("[id]").forEach(node => {
      if (node.closest("[data-hp-page-content]") || node.matches(".app-shell")) return;
      if (document.getElementById(node.id)) return;
      const clone = document.importNode(node, true);
      reNonceTree(clone);
      document.body.appendChild(clone);
    });
    doc.querySelectorAll("script[src]").forEach(s => {
      const src = s.getAttribute("src");
      if (document.querySelector(`script[src="${CSS.escape(src)}"]`)) return;
      const el = document.createElement("script");
      el.src = src;
      // #1564 regression fix: dynamically-inserted scripts are async by
      // default, so a page whose scripts have a load-order dependency
      // (attackers.html: cytoscape.min.js -> hp-echarts-theme.js ->
      // hp-attackers.js) could execute out of order -- hp-attackers.js ran
      // before cytoscape existed and bailed, leaving the graph stuck on
      // "Loading graph…". async=false restores insertion-order execution,
      // matching how the server-rendered defer tags behave.
      el.async = false;
      if (pageNonce) el.nonce = pageNonce;
      document.body.appendChild(el);
    });
  };

  let navigating = false;
  const navigate = async (url, {push = true} = {}) => {
    if (navigating) return;
    navigating = true;
    try {
      const r = await fetch(url, {cache: "no-store"});
      if (!r.ok) { location.href = url; return; }
      const doc = new DOMParser().parseFromString(await r.text(), "text/html");
      const next = doc.querySelector("[data-hp-page-content]");
      if (!next || !window.replaceHoneypotPage) { location.href = url; return; }
      // Update location before deriving tab state below: initDashboardTabs
      // reads location.hash, and a click-driven nav (push=true) needs its
      // own pushState to land before that read, exactly like a
      // popstate-driven nav (push=false) already has the browser's own
      // back/forward update location before the event fires.
      if (push) history.pushState({hpDynamic: true}, "", r.url || url);
      window.replaceHoneypotPage(next);
      mergeExtraContent(doc);
      document.title = doc.title;
      // #1141 regression risk: activateDashboardTab prefers
      // window.honeypotDashboardTab (hp-app.js) over location.hash once
      // it's ever been set, so a stale tab name from the PREVIOUS page
      // would otherwise silently outlive this navigation and could pick
      // the wrong (or, if invalid for the new page, merely the first)
      // tab on the page just swapped in instead of honoring the URL.
      window.honeypotDashboardTab = undefined;
      window.initDashboardTabs?.();
      window.scrollTo(0, 0);
      // Per-page hydration scripts (hp-payload-analysis.js, hp-workbench.js,
      // hp-github-analysis.js) read data-* attributes off [data-hp-page-content]
      // once at their own top-level IIFE scope. mergeExtraContent above only
      // ever injects a given <script src> the first time this page family is
      // visited -- correct for avoiding duplicate listener registration
      // (this file's own header comment), but it means navigating from one
      // page in a route family to ANOTHER (e.g. /payload-analysis/{hashA} ->
      // /payload-analysis/{hashB}) swaps in a fresh DOM with nothing left to
      // re-run the already-loaded script's hydration logic against it --
      // caught live: skeleton cards stayed skeletons until a full reload.
      // Scripts that need to re-hydrate on every navigation (not just their
      // own first load) listen for this.
      document.dispatchEvent(new CustomEvent("hp-dynamic-nav"));
    } catch {
      location.href = url;
    } finally {
      navigating = false;
    }
  };

  document.addEventListener("click", e => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const a = e.target.closest("a[href]");
    if (!a || a.target === "_blank" || a.hasAttribute("download") || a.origin !== location.origin) return;
    if (!isDynamicRoute(a.pathname)) return;
    e.preventDefault();
    navigate(a.href);
  });

  window.addEventListener("popstate", () => navigate(location.href, {push: false}));
})();
