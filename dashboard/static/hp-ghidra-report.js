/* Ghidra detail page: fetch-and-hydrate the fragment, plus the report
 * viewer overlay.
 *
 * #1288/#1285/#1286 shell+hydrate: /ghidra/{sha} now renders a skeleton
 * shell with no Elasticsearch read on the request path (ghidraDetailShell
 * in ghidra.go) -- #ghidra-detail-root carries the real content's URL in
 * data-hp-gh-fragment-url, and hydrateDetail() below does the one fetch
 * that resolves it, same shape as payload_analysis.go's
 * payloadAnalysisShell/servePayloadStaticAnalysis split (see that file's
 * own comment for the general reasoning). The fragment is server-rendered
 * HTML (the "ghidra-detail-body" Go template, executed against a real
 * ghidraData() result), not a second, hand-written JS reimplementation of
 * this page's ~20 cards and dozen evidence bodies -- html/template's
 * escaping guarantees stay in force for every field this page renders,
 * including the AI-generated/attacker-influenced ones (#1285/#1286).
 *
 * Once the fragment lands, three other page scripts need a nudge: Prism
 * (#1288), hp-ghidra-markdown.js (#1285/#1286), and hp-ghidra-
 * callgraph.js (#1287) each only look at whatever's in the document at
 * the moment they're invoked, and none of it exists in the DOM until
 * this fetch resolves. hp-evidence.js needs no such nudge -- its click
 * listener and evidence-body lookups are already live-DOM/delegated, so
 * newly-inserted evidence buttons and bodies just work (see
 * hp-evidence.js's own open()).
 *
 * The report viewer overlay (unchanged behavior from before #1288) opens
 * a #hp-gh-report-view button. That button lives inside the fragment, but
 * the modal/backdrop/frame it opens are page chrome in the shell, present
 * from the start -- only the button's own click listener needs wiring
 * after each fragment load, not the whole modal setup.
 */
(() => {
  "use strict";

  const backdrop = document.getElementById("hp-gh-viewer-backdrop");
  const modal = document.getElementById("hp-gh-viewer");
  const frame = document.getElementById("hp-gh-viewer-frame");
  const closeButton = document.getElementById("hp-gh-viewer-close");
  const hasViewer = backdrop && modal && frame && closeButton;

  let isOpen = false;
  let restoreFocus = null;
  let trap = null;

  if (hasViewer) {
    // Tab-cycling/initial-focus/return-focus delegated to focus-trap
    // (vendored, dashboard/static/vendor/focus-trap/); Escape stays
    // hand-rolled below.
    trap = window.focusTrap.createFocusTrap(modal, {
      escapeDeactivates: false,
      clickOutsideDeactivates: false,
      initialFocus: () => closeButton,
      fallbackFocus: () => closeButton,
      setReturnFocus: () => (restoreFocus?.isConnected ? restoreFocus : false),
    });
  }

  function openViewer(url) {
    if (!hasViewer || isOpen || !url) return;
    isOpen = true;
    restoreFocus = document.activeElement;
    frame.src = url;
    backdrop.inert = false;
    backdrop.setAttribute("aria-hidden", "false");
    backdrop.classList.add("open");
    modal.inert = false;
    modal.setAttribute("aria-hidden", "false");
    modal.classList.add("open");
    trap.activate();
  }

  function closeViewer() {
    if (!hasViewer || !isOpen) return;
    isOpen = false;
    trap.deactivate();
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    modal.inert = true;
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
    backdrop.inert = true;
    frame.src = "about:blank";
    // Not nulled here: focus-trap's deactivate() restores focus via a
    // setTimeout(0), so setReturnFocus's closure must still see this value
    // when that deferred callback runs. openViewer() overwrites it next time.
  }

  if (hasViewer) {
    closeButton.addEventListener("click", closeViewer);
    backdrop.addEventListener("click", closeViewer);
    document.addEventListener("keydown", (event) => {
      if (!isOpen) return;
      if (window.HoneypotModals?.isOpen()) return;
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeViewer();
      }
    });
  }

  // The trigger button only exists once the fragment has loaded (it's
  // part of "ghidra-detail-body"), so its own listener is wired from
  // hydrateDetail() below rather than at top-level script load.
  function wireReportViewerTrigger() {
    const button = document.getElementById("hp-gh-report-view");
    if (!button) return;
    button.addEventListener("click", () => openViewer(button.dataset.hpGhReportUrl));
  }

  function hydrateDetail() {
    const root = document.getElementById("ghidra-detail-root");
    const url = root?.dataset.hpGhFragmentUrl;
    if (!root || !url) return;
    fetch(url, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      })
      .then((html) => {
        root.innerHTML = html;
        root.removeAttribute("aria-busy");
        window.initDashboardTabs?.();
        window.Prism?.highlightAll();
        window.HoneypotGhidraMarkdown?.render();
        // #1287: the interactive call graph's own [data-ghidra-callgraph-
        // url] canvas is part of this same fragment -- hp-ghidra-
        // callgraph.js's own <script defer> already ran once, before this
        // fetch resolved, and found nothing.
        window.initHoneypotGhidraCallGraph?.();
        wireReportViewerTrigger();
      })
      .catch(() => {
        root.removeAttribute("aria-busy");
        root.innerHTML = '<p class="empty">Could not load this analysis. It may not exist, or Elasticsearch was unreachable &mdash; try reloading.</p>';
      });
  }

  hydrateDetail();
})();
