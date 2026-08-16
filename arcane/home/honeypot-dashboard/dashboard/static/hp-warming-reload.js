/* Shared "cache still warming" auto-reload for the #1139 consolidated
 * payload/results page family (payloads.html, and ghidra.html/sandbox.html/
 * github_analysis.html's own *resultspanel templates, embedded in
 * /payload-workbench/results).
 *
 * Each of those pages used to schedule its own reload with an inline
 * <script nonce="{{.Nonce}}">setTimeout(()=>location.reload(),1500)</script>
 * tag, right next to its own [data-*-warming] marker. That only ever
 * executes on a real page load or refresh: hp-dynamic-nav.js's SPA-style
 * navigation (hp-app.js's mountPage, `pageContent.replaceChildren(...)`)
 * never executes a <script> that arrived via DOM APIs rather than the
 * browser's own HTML parser -- the exact same reason hp-dynamic-nav.js's
 * own header comment already documents for *external* per-page hydration
 * scripts ("caught live: skeleton cards stayed skeletons until a full
 * reload"), just never applied to this inline-script case. A cold-cache
 * visit reached via an in-app link (not a hard refresh or a freshly typed
 * URL) left the warming skeleton and its "this page will update
 * automatically" message stuck forever.
 *
 * This file is itself an external <script src>, loaded once and persisting
 * across SPA navigations the same way hp-workbench.js/hp-payload-analysis.js
 * do -- so it re-checks the live DOM for a warming marker on both real page
 * load and every "hp-dynamic-nav" event, and the retry actually fires
 * regardless of how the page was reached. Checking for ANY of the four
 * existing marker attributes rather than renaming them to one shared name
 * keeps this a pure addition -- no risk of missing a call site that still
 * matches an old name. */
(() => {
  "use strict";

  const WARMING_SELECTOR = "[data-payload-warming], [data-ghidra-warming], [data-sandbox-warming], [data-github-analysis-warming]";

  function checkWarming() {
    if (document.querySelector(WARMING_SELECTOR)) {
      setTimeout(() => location.reload(), 1500);
    }
  }

  checkWarming();
  document.addEventListener("hp-dynamic-nav", checkWarming);
})();
