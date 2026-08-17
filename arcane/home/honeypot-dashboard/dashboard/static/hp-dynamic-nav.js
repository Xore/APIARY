/* #1141/#1564: shell-wide SPA router. Intercepts same-origin clicks on
   in-app links and fetch-and-swaps [data-hp-page-content] instead of doing
   a full page load -- built directly on hp-app.js's own mountPage
   (window.replaceHoneypotPage), the same fetch-and-swap mechanism the
   overview's live refresh (hp-app.js's refreshDashboardOverview) already
   uses, just triggered by a click instead of a timer, plus
   history.pushState so the URL/back/forward/refresh/bookmarks all still
   resolve to the right view.

   #1141 originally scoped this to only the #1139 consolidated payload/
   results page family, as an allow-list (DYNAMIC_ROUTES). #1564 promotes
   it to the shell's default behavior: every route is dynamic UNLESS it
   matches FULL_NAV_ROUTES below, which is now the single source of truth
   for what still needs a real navigation, split into two reasons:

     1. Genuinely different documents -- not an [data-hp-page-content] page
        at all (an API/export/download endpoint, the noVNC viewer, a raw
        session-recording file, an auth redirect). Fetching one of these
        anyway would be harmless (the fallback below already catches a
        response with no [data-hp-page-content] and falls through to
        location.href), but excluding them up front skips a wasted fetch.

     2. Real shell pages whose own bottom-of-content scripts don't (yet)
        support being re-run against a freshly-swapped DOM -- cytoscape
        graphs, ECharts hydration, studio bindings, and the like, written
        as a plain "run once at IIFE load" the same way every page's own
        script used to be written before this file's mount/unmount
        convention (window.initHoneypot* re-entry points, the
        "hp-dynamic-nav" event, hp-page-mounted) existed. A dynamically
        appended <script src> executes once per session (mergeExtraContent
        below dedups by src) -- so a second visit through a swap, with
        nothing left to re-run that script's hydration logic, would leave
        that page's own view stuck loading, exactly the bug this file's
        own async=false fix and hp-warming-reload.js both exist to avoid
        for the pages that ARE converted. Kept as full navigation rather
        than risk shipping a broken mount; see the #1564 PR body for the
        maintained list of which pages fall in this bucket and why. */
(() => {
  "use strict";

  /* #1564: loaded from the shared "style" partial on every page now; the
     #1139 family pages still carry their own <script> tag, so guard
     against double registration of the document-level click handler. */
  if (window.__hpDynamicNav) return;
  window.__hpDynamicNav = true;

  const pageNonce = document.querySelector("script[nonce], style[nonce]")?.nonce || "";

  const FULL_NAV_ROUTES = [
    // -- Not a shell page at all --
    /^\/api\//,
    /^\/static\//,
    /^\/export\//,
    /^\/metrics$/,
    /^\/auth\//,
    /^\/admin\//,
    /^\/healthz$/,
    /^\/payload\//,       // raw captured-sample download (distinct from the /payloads list)
    /^\/tty\//,           // xterm.js replay page + its own .cast/.raw downloads
    /^\/sandbox\/vnc$/,   // noVNC viewer, not a result detail page
    // Bare index routes that 302 elsewhere rather than rendering a page a
    // fetch-and-swap could use (their own sub-paths stay dynamic below).
    /^\/payload-workbench$/,
    /^\/sandbox$/,
    /^\/github-analysis$/,

    // -- Real shell pages not yet converted to the mount/unmount
    //    convention (category 2 above) --
    /^\/kill-chain$/,
    /^\/commands$/,
    /^\/ml-anomalies$/,
    /^\/reports$/,
    /^\/canarytokens$/,
    /^\/settings$/,          // page mode resolves at script load
    /^\/sessions\//,
    /^\/investigate\/ip\/[^/]+$/,
    /^\/investigate\/cidr\//,
    /^\/investigate\/cluster/,
    /^\/ghidra(\/|$)/,
    /^\/revdeck(\/|$)/,
    /^\/cape(\/|$)/,
  ];
  const isDynamicRoute = pathname => !FULL_NAV_ROUTES.some(re => re.test(pathname));

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
