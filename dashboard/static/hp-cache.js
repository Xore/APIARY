/* Per-tab cache for ES-polled JSON views (#486).
   Not a flat TTL: an in-memory Map, scoped to this one browser tab (never
   shared across tabs/users, so "per session" falls out for free without any
   server-side statefulness), consulted before /api/map-points,
   /api/heatmap and /api/attack-vectors re-fetch a URL they've already seen
   recently. Unloaded on an idle timer instead of a fixed schedule: reset on
   every debounced interaction while the tab is visible, shortened once the
   tab goes hidden, so a quiet or backgrounded tab actually frees its cache
   rather than being kept warm indefinitely. See the design writeup on #486
   for the alternatives this rejected (a server-side per-session cache would
   reintroduce the exact unbounded-memory-growth risk this avoids). */
(() => {
  "use strict";

  // Short enough that a picked-again sensor or a re-triggered map update
  // feels instant without ever serving meaningfully stale attack data.
  const freshnessMS = 15000;
  // How long with no interaction before the whole cache unloads -- shorter
  // once hidden (an operator who switched tabs is less likely to be right
  // back) than while visible but momentarily idle.
  const idleEvictVisibleMS = 10 * 60 * 1000;
  const idleEvictHiddenMS = 2 * 60 * 1000;
  const interactionDebounceMS = 1000;

  const cache = new Map(); // url -> {data, fetchedAt}
  let idleTimer = null;
  let lastInteractionRecordedAt = 0;

  const armIdleTimer = ms => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => cache.clear(), ms);
  };

  if (typeof document !== "undefined") {
    armIdleTimer(idleEvictVisibleMS);
    document.addEventListener("visibilitychange", () => {
      armIdleTimer(document.visibilityState === "hidden" ? idleEvictHiddenMS : idleEvictVisibleMS);
    });
    const recordInteraction = () => {
      if (document.visibilityState !== "visible") return;
      const now = Date.now();
      if (now - lastInteractionRecordedAt < interactionDebounceMS) return;
      lastInteractionRecordedAt = now;
      armIdleTimer(idleEvictVisibleMS);
    };
    ["mousemove", "keydown", "click", "scroll"].forEach(type =>
      document.addEventListener(type, recordInteraction, {passive: true})
    );
  }

  // cachedJSON fetches url as JSON, serving a same-URL response fetched
  // within the last freshnessMS instead of round-tripping again. Matches
  // the throw-on-!ok / parsed-JSON-return shape callers already expect from
  // a plain `fetch(url); .json()` pair, so swapping one in for the other is
  // a drop-in change.
  const cachedJSON = async (url, options) => {
    const cached = cache.get(url);
    if (cached && Date.now() - cached.fetchedAt < freshnessMS) return cached.data;
    const response = await fetch(url, Object.assign({cache: "no-store"}, options));
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    cache.set(url, {data, fetchedAt: Date.now()});
    return data;
  };

  // invalidate drops one cached URL (or, with no argument, everything) --
  // for a caller that just changed the data a cached view reads and knows
  // the next read must not be served stale.
  const invalidate = url => { url === undefined ? cache.clear() : cache.delete(url); };

  window.HoneypotCache = Object.freeze({cachedJSON, invalidate});
})();
