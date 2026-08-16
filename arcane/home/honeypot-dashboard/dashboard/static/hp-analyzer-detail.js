/* Hash-scoped analyzer detail hydration. Fragments remain server-rendered so
 * escaping, links, status ribbons, and report-viewer attributes have one
 * authoritative implementation.
 */
(() => {
  "use strict";

  function hydrate(root) {
    if (!root || root.dataset.hpHydrationStarted === "true") return;
    const url = root.dataset.hpAnalyzerFragmentUrl;
    if (!url) return;
    root.dataset.hpHydrationStarted = "true";
    fetch(url, { cache: "no-store", headers: { Accept: "text/html" } })
      .then(async response => {
        if (response.status === 404) {
          root.removeAttribute("aria-busy");
          root.setAttribute("role", "status");
          const message = document.createElement("p");
          message.className = "empty";
          message.textContent = root.dataset.hpAnalyzerMissing || "No analyzer result was found for this hash.";
          root.replaceChildren(message);
          return null;
        }
        if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
        return response.text();
      })
      .then(html => {
        if (html === null) return;
        root.innerHTML = html;
        root.removeAttribute("aria-busy");
        const prefs = window.HpPreferences?.prefs;
        window.HpPreferences?.applyTimeDisplay?.(prefs?.timezone, prefs?.clock);
        window.initDashboardTabs?.();
        document.dispatchEvent(new CustomEvent("hp-analyzer-hydrated", { detail: { root } }));
      })
      .catch(error => {
        root.removeAttribute("aria-busy");
        root.setAttribute("role", "alert");
        const message = document.createElement("p");
        message.className = "empty";
        message.textContent = `Analyzer result could not be loaded: ${error.message}`;
        root.replaceChildren(message);
      });
  }

  function hydrateAll(scope = document) {
    scope.querySelectorAll("[data-hp-analyzer-fragment-url]").forEach(hydrate);
  }

  hydrateAll();
  document.addEventListener("hp-dynamic-nav", () => hydrateAll());
})();
