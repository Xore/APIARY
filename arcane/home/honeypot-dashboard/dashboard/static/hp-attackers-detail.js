/* Attacker identities page: fetch-and-hydrate the fragment.
 *
 * #1327 shell+hydrate: /attackers now renders a skeleton shell with no
 * Elasticsearch read on the request path (attackersShell in attackers.go)
 * -- #attackers-root carries the real content's URL in
 * data-hp-attackers-fragment-url, and hydrateBody() below does the one
 * fetch that resolves it, same shape as hp-ghidra-report.js's own
 * hydrateDetail (see that file's own comment for the general reasoning).
 * The fragment is server-rendered HTML (the "attackers-body" Go template,
 * executed against a real attackersData() result), not a second,
 * hand-written JS reimplementation of the identity counts, selected
 * entity's metadata grid, and full entity table.
 *
 * The selected entity's graph (Cytoscape, hp-attackers.js) and fingerprint
 * fusion chart (ECharts, hp-kill-chain.js) are unaffected by this file --
 * both cards render in the shell itself, keyed only on the "id" query
 * parameter the shell already knows synchronously, and each already does
 * its own independent client-side fetch against /api/attacker-graph and
 * /api/attacker-fusion.
 *
 * #1564: same re-init story as hp-attackers.js -- exposed as
 * window.initHoneypotAttackersDetail so hp-app.js's mountPage can re-run
 * this against the freshly-mounted #attackers-root on every later
 * navigation to /attackers, not just the first time this script ever
 * loads. Without it, navigating from one page to /attackers a second time
 * in the same SPA session would leave #attackers-root's skeleton loading
 * forever -- the exact bug hp-dynamic-nav.js's own header comment
 * describes for this whole page family, just not yet fixed here.
 */
(() => {
  "use strict";

  function hydrateBody() {
    const root = document.getElementById("attackers-root");
    const url = root?.dataset.hpAttackersFragmentUrl;
    if (!root || !url) return;
    root.setAttribute("aria-busy", "true");
    fetch(url, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      })
      .then((html) => {
        root.innerHTML = html;
        root.removeAttribute("aria-busy");
      })
      .catch(() => {
        root.removeAttribute("aria-busy");
        root.innerHTML = '<p class="empty">Could not load attacker identities. Elasticsearch may be unreachable &mdash; try reloading.</p>';
      });
  }

  hydrateBody();
  window.initHoneypotAttackersDetail = hydrateBody;
})();
