/* Sandbox detail shell hydration.
 *
 * /sandbox/{job} contains only page chrome and a skeleton. This fetches the
 * server-rendered detail fragment after first paint, keeping Elasticsearch and
 * artifact lookups off the initial navigation path while preserving Go
 * templates as the single source of truth for the detail markup.
 */
(() => {
  "use strict";

  const root = document.getElementById("sandbox-detail-root");
  const url = root?.dataset.hpSandboxFragmentUrl;
  if (!root || !url) return;

  fetch(url, { cache: "no-store" })
    .then(response => {
      if (!response.ok) throw new Error("HTTP " + response.status);
      return response.text();
    })
    .then(html => {
      root.innerHTML = html;
      root.removeAttribute("aria-busy");
      window.initHoneypotSyscallsChart?.();
    })
    .catch(() => {
      root.removeAttribute("aria-busy");
      root.innerHTML = '<p class="empty">Could not load this sandbox result. It may not exist, or Elasticsearch was unreachable &mdash; try reloading.</p>';
    });
})();
