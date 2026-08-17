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
 * #1540: the shell also tabs the selected-entity dossier into "panel-
 * overview" (graph + fusion chart + 4 cards) and "panel-indicators" (the
 * other 5 cards), via the generic data-dashboard-tab/data-dashboard-panel
 * convention. The fragment still returns one flat HTML blob -- chip bar,
 * then (if an entity is selected) the "attackers-overview-cards" and
 * "attackers-indicators-cards" grids, then the identities table -- but the
 * two card grids belong inside the shell's pre-existing panels, not
 * #attackers-root, since the chip bar and table stay untabbed. Pull each
 * grid out of the fetched markup by id and swap it into its matching
 * shell skeleton before mounting whatever's left (chip bar + table) into
 * #attackers-root.
 */
(() => {
  "use strict";

  const FRAGMENT_PANEL_IDS = ["attackers-overview-cards", "attackers-indicators-cards"];

  function hydrateBody() {
    const root = document.getElementById("attackers-root");
    const url = root?.dataset.hpAttackersFragmentUrl;
    if (!root || !url) return;
    fetch(url, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      })
      .then((html) => {
        const parsed = document.createElement("div");
        parsed.innerHTML = html;

        FRAGMENT_PANEL_IDS.forEach((id) => {
          const incoming = parsed.querySelector("#" + id);
          if (!incoming) return;
          const placeholder = document.getElementById(id);
          // No selected entity in the shell (id-less visit, or the fetch
          // raced a navigation away from ?id=) to receive it -- drop the
          // fragment's copy rather than leaving a second one lying around.
          if (placeholder) placeholder.replaceWith(incoming);
          else incoming.remove();
        });

        root.replaceChildren(...parsed.childNodes);
        root.removeAttribute("aria-busy");
      })
      .catch(() => {
        root.removeAttribute("aria-busy");
        root.innerHTML = '<p class="empty">Could not load attacker identities. Elasticsearch may be unreachable &mdash; try reloading.</p>';
      });
  }

  hydrateBody();
})();
