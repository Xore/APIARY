/* Render-first hydration for correlation-backed list and investigation
 * regions. The server owns all HTML escaping and presentation; this client
 * only replaces the shape-matched shell with the corresponding fragment.
 */
(() => {
  "use strict";

  function hydrate(root) {
    if (!root || root.dataset.hpHydrationStarted === "true") return;
    const url = root.dataset.hpIntelFragmentUrl || root.dataset.hpCorrelationFragmentUrl;
    if (!url) return;
    root.dataset.hpHydrationStarted = "true";
    fetch(url, { cache: "no-store", headers: { Accept: "text/html" } })
      .then(response => {
        if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
        return response.text();
      })
      .then(html => {
        root.innerHTML = html;
        root.removeAttribute("aria-busy");
        const prefs = window.HpPreferences?.prefs;
        window.HpPreferences?.applyTimeDisplay?.(prefs?.timezone, prefs?.clock);
      })
      .catch(error => {
        root.removeAttribute("aria-busy");
        root.setAttribute("role", "alert");
        const message = document.createElement("p");
        message.className = "empty";
        message.textContent = `${root.dataset.hpHydrationError || "Correlation data could not be loaded"}: ${error.message}`;
        root.replaceChildren(message);
      });
  }

  function hydrateAll(scope = document) {
    scope.querySelectorAll("[data-hp-intel-fragment-url], [data-hp-correlation-fragment-url]").forEach(hydrate);
  }

  hydrateAll();
  document.addEventListener("hp-dynamic-nav", () => hydrateAll());
})();
