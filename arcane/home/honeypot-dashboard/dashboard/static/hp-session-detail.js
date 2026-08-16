/* Session detail page: fetch-and-hydrate the fragment.
 *
 * #1327/#1328 shell+hydrate: /sessions/{id} now renders a skeleton shell
 * with no event-cache scan on the request path (sessionShell in
 * intelligence.go) -- #session-detail-root carries the real content's URL
 * in data-hp-session-fragment-url, and hydrateDetail() below does the one
 * fetch that resolves it, same shape as hp-ghidra-report.js's own
 * hydrateDetail (see that file's own comment for the general reasoning).
 * The fragment is server-rendered HTML (the "session-body" Go template,
 * executed against a real sessionData() result), not a second,
 * hand-written JS reimplementation of this page's tables and
 * chronological replay -- html/template's escaping guarantees stay in
 * force for every field this page renders.
 *
 * data-hp-utc timestamps only exist inside the fragment (the shell has
 * none of its own), so the timezone/clock-format preference (#282, #346)
 * that hp-app.js applies once at page load never reaches them without an
 * explicit re-apply here, the same way mountPage's own reapplyTimezone
 * covers SPA-navigated content.
 */
(() => {
  "use strict";

  function hydrateDetail() {
    const root = document.getElementById("session-detail-root");
    const url = root?.dataset.hpSessionFragmentUrl;
    if (!root || !url) return;
    fetch(url, { cache: "no-store" })
      .then((r) => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      })
      .then((html) => {
        root.innerHTML = html;
        root.removeAttribute("aria-busy");
        const prefs = window.HpPreferences?.prefs;
        window.HpPreferences?.applyTimeDisplay?.(prefs?.timezone, prefs?.clock);
      })
      .catch(() => {
        root.removeAttribute("aria-busy");
        root.innerHTML = '<p class="empty">Could not load this session. It may not exist, or Elasticsearch was unreachable &mdash; try reloading.</p>';
      });
  }

  hydrateDetail();
})();
