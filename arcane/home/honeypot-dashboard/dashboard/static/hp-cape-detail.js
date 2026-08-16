/* CAPE detail shell hydration: the initial route renders only the SHA-aware
   final card geometry; the bounded ES lookup and report parsing happen here. */
(() => {
  "use strict";
  const root = document.getElementById("cape-detail-root");
  const url = root?.dataset.hpCapeFragmentUrl;
  if (!root || !url) return;
  fetch(url, {cache: "no-store"})
    .then(response => {
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response.text();
    })
    .then(html => {
      root.innerHTML = html;
      root.removeAttribute("aria-busy");
    })
    .catch(error => {
      root.removeAttribute("aria-busy");
      root.innerHTML = `<p class="empty">Could not load this CAPE result (${error.message}). It may not exist, or Elasticsearch was unreachable — try reloading.</p>`;
    });
})();
