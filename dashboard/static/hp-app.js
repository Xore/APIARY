/* Honeypot dashboard enhancement layer (framework-free).
   The app shell (sidebar + topbar) is server-rendered; this script adds the
   interactive behavior on top: live refresh, maps, tabs, lazy rows, the
   investigation command dock, recents, alert badge, and sidebar state. */
(() => {
  "use strict";

  /* The CSP nonce enforced for THIS already-loaded page (style-src/script-src
     'nonce-<this value>'), read once from an inline element the browser has
     already accepted -- getAttribute("nonce") is deliberately hidden by
     browsers as a CSP hardening measure (so injected markup can't read and
     replay a real nonce), but the .nonce IDL property still returns it for
     script running on the trusted page itself. Needed by reNonce below. */
  const pageNonce = document.querySelector("script[nonce], style[nonce]")?.nonce || "";

  /* Live refresh (mountPage below) inserts DOM fetched via a plain fetch()
     into the already-loaded page. That fetch is a fresh server response with
     its OWN freshly generated per-request nonce baked into any nonce'd
     <style>/<script> it contains -- fetch never re-navigates, so the CSP the
     browser enforces stays pinned to the ORIGINAL page load's nonce. Any
     nonce'd element carried over from the fetched document therefore has the
     wrong nonce and gets silently rejected (style-src-elem/-attr CSP
     violations, sheet stays null) -- confirmed live: this silently dropped
     the activity heatmap's per-cell --v custom properties on every refresh,
     rendering it permanently empty until a real page reload, since toggling
     tab visibility afterward can't resurrect CSS rules the browser never
     accepted in the first place (#... live-refresh heatmap-empty bug).
     Rewriting every nonce'd element in a fetched subtree to the current
     page's own already-trusted nonce, before it's inserted, is the
     documented fix for exactly this fetch-and-splice pattern. */
  const reNonce = root => {
    if (!pageNonce) return;
    root.querySelectorAll("[nonce]").forEach(el => {
      el.nonce = pageNonce;
      el.setAttribute("nonce", pageNonce);
    });
  };

  /* ---------- navigation model ---------- */
  const navGroups = [
    ["Monitor", [
      ["Overview", "/"],
      ["Sensor & pipeline health", "/source-health"],
      ["Alerts", "/alerts"],
    ]],
    ["Investigate", [
      ["Event explorer", "/events"],
      ["Attack sources", "/ips"],
      ["Campaigns", "/campaigns"],
      ["Infrastructure clusters", "/clusters"],
      ["Executed commands", "/commands"],
    ]],
    ["Evidence", [
      ["Captured payloads", "/payloads"],
      ["Analysis workbench", "/payload-workbench"],
      ["Workbench results", "/payload-workbench/results"],
      ["Sandbox results", "/sandbox"],
      ["Elasticsearch history", "/history"],
      ["Ingest dead letters", "/dead-letters"],
    ]]
  ];

  const pageName = () => {
    const path = location.pathname;
    if (path === "/") return "Overview";
    if (path.startsWith("/payload-analysis")) return "Payload analysis";
    if (path.startsWith("/sessions/")) return "Session replay";
    if (path.startsWith("/investigate/ip/")) return "Attacker profile";
    for (const [, items] of navGroups) {
      for (const [label, href] of items) if (path === href) return label;
    }
    return "Operations";
  };

  const activeHref = () => {
    const path = location.pathname;
    if (path.startsWith("/payload-analysis") || path.startsWith("/payload/")) return "/payloads";
    if (path === "/payload-workbench/results") return "/payload-workbench/results";
    if (path.startsWith("/payload-workbench/")) return "/payload-workbench";
    if (path.startsWith("/sandbox/")) return "/sandbox";
    if (path.startsWith("/sessions/")) return "/events";
    if (path.startsWith("/investigate/ip/")) return "/ips";
    return path;
  };

  /* Investigation routing is server-side (/search): the dock is a plain GET
     form, so a query that names no entity lands on grouped results instead of
     the 404 a client-side format guess produced. */

  /* ---------- live refresh state (toolbar LIVE toggle) ----------
     One switch for every refresh path: the overview's in-place reload, the
     alert-bell poll, and the SSE new-event toast. The choice is persisted, so
     reading a stalled table is not undone by navigating to the next page. */
  const livePausedKey = "hp-live-paused";
  const liveListeners = new Set();
  let livePaused = false;
  try { livePaused = localStorage.getItem(livePausedKey) === "1"; } catch {}
  const setLivePaused = paused => {
    if (paused === livePaused) return;
    livePaused = paused;
    try { localStorage.setItem(livePausedKey, paused ? "1" : "0"); } catch {}
    liveListeners.forEach(listener => { try { listener(paused); } catch {} });
  };
  /* #210: connection health is tracked separately from the paused switch --
     a page's own EventSource (this file's, on non-overview pages, or the
     overview page's own in-place-refresh one) reports here so the single
     global toolbar indicator reflects a stalled/reconnecting SSE connection
     no matter which page actually holds it open. Native EventSource retries
     with its own backoff after onerror; this only reflects that state, it
     does not implement reconnection itself. */
  const liveConnListeners = new Set();
  let liveConnHealthy = true;
  const setLiveConnHealthy = healthy => {
    if (healthy === liveConnHealthy) return;
    liveConnHealthy = healthy;
    liveConnListeners.forEach(listener => { try { listener(healthy); } catch {} });
  };
  window.HoneypotLive = Object.freeze({
    paused: () => livePaused,
    pause: () => setLivePaused(true),
    resume: () => setLivePaused(false),
    toggle: () => setLivePaused(!livePaused),
    onChange: listener => { liveListeners.add(listener); return () => liveListeners.delete(listener); },
    connectionHealthy: () => liveConnHealthy,
    setConnectionHealthy: setLiveConnHealthy,
    onConnectionChange: listener => { liveConnListeners.add(listener); return () => liveConnListeners.delete(listener); },
  });

  /* ---------- lazy loading (sentinel + offset fetching) ---------- */
  // Keep long investigation views responsive without traditional page links.
  // The first 25 rows are visible immediately; another 25 are revealed when
  // the sentinel approaches the viewport or the accessible button is pressed.
  const lazyPageSize = 25;
  const lazyTables = new WeakMap();
  const lazyLists = new WeakMap();
  // Backs both a remote-paginated <table> (keyed by the table, body is its
  // tBodies[0]) and a remote-paginated card list (keyed by the list div
  // itself, body === the same div) -- the logic below only ever counts
  // body.children and appends via insertAdjacentHTML, neither of which
  // cares whether body is a <tbody> or a plain container.
  const remoteContainers = new WeakMap();
  const lazyObserver = "IntersectionObserver" in window ? new IntersectionObserver(entries => {
    entries.filter(entry => entry.isIntersecting).forEach(entry => {
      const table = entry.target.__hpLazyTable;
      if (table) revealLazyRows(table);
      const list = entry.target.__hpLazyList;
      if (list) revealLazyItems(list);
      const remote = entry.target.__hpRemoteContainer;
      if (remote) loadRemoteItems(remote);
    });
  }, {rootMargin: "500px 0px"}) : null;

  const lazyControlsHTML = () =>
    `<span></span><button class="btn btn-secondary btn-sm" type="button">Load 25 more</button><span class="hp-lazy-sentinel" aria-hidden="true"></span>`;

  const updateLazyTable = table => {
    const state = lazyTables.get(table);
    if (!state) return;
    const rows = [...(table.tBodies[0]?.rows || [])];
    if (rows.length <= lazyPageSize) state.shown = lazyPageSize;
    state.shown = Math.min(state.shown, rows.length);
    rows.forEach((row, index) => { row.hidden = index >= state.shown; });
    state.counter.textContent = `${Math.min(state.shown, rows.length)} of ${rows.length} entries`;
    state.controls.hidden = rows.length <= lazyPageSize;
    const more = state.shown < rows.length;
    state.button.hidden = !more;
    state.sentinel.hidden = !more;
    if (!more) lazyObserver?.unobserve(state.sentinel);
    else lazyObserver?.observe(state.sentinel);
  };

  const revealLazyRows = table => {
    const state = lazyTables.get(table);
    if (!state) return;
    const total = table.tBodies[0]?.rows.length || 0;
    state.shown = Math.min(total, state.shown + lazyPageSize);
    updateLazyTable(table);
  };

  const updateRemoteContainer = key => {
    const state = remoteContainers.get(key);
    if (!state) return;
    const loadedThrough = state.offset + state.body.children.length;
    state.counter.textContent = `${Math.min(loadedThrough, state.total)} of ${state.total} entries`;
    const more = loadedThrough < state.total;
    state.controls.hidden = state.total <= lazyPageSize;
    state.button.hidden = !more;
    state.sentinel.hidden = !more;
    if (!more) lazyObserver?.unobserve(state.sentinel);
    else lazyObserver?.observe(state.sentinel);
  };

  const loadRemoteItems = async key => {
    const state = remoteContainers.get(key);
    const nextOffset = state ? state.offset + state.body.children.length : 0;
    if (!state || state.loading || nextOffset >= state.total) return;
    state.loading = true;
    state.button.disabled = true;
    const separator = state.url.includes("?") ? "&" : "?";
    try {
      const response = await fetch(`${state.url}${separator}offset=${nextOffset}`, {
        cache: "no-store",
        credentials: "same-origin",
        headers: {"X-Requested-With": "honeypot-dashboard"},
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const items = await response.text();
      if (!items.trim()) state.total = nextOffset;
      else state.body.insertAdjacentHTML("beforeend", items);
      updateRemoteContainer(key);
    } catch (error) {
      state.counter.textContent = `Could not load more entries (${error.message})`;
    } finally {
      state.loading = false;
      state.button.disabled = false;
    }
  };

  const attachRemoteContainer = (key, body) => {
    const controls = document.createElement("div");
    controls.className = "hp-lazy-controls";
    controls.setAttribute("aria-live", "polite");
    controls.innerHTML = lazyControlsHTML();
    key.after(controls);
    const state = {
      body,
      total: Number.parseInt(body.dataset.hpTotal || `${body.children.length}`, 10),
      offset: Number.parseInt(body.dataset.hpOffset || "0", 10),
      url: body.dataset.hpPageUrl,
      controls,
      counter: controls.querySelector("span"),
      button: controls.querySelector("button"),
      sentinel: controls.querySelector(".hp-lazy-sentinel"),
      loading: false,
    };
    state.sentinel.__hpRemoteContainer = key;
    state.button.addEventListener("click", () => loadRemoteItems(key));
    remoteContainers.set(key, state);
    updateRemoteContainer(key);
  };

  const attachLazyTable = table => {
    if (lazyTables.has(table) || remoteContainers.has(table) || table.dataset.hpNoLazy !== undefined) return;
    const body = table.tBodies[0];
    if (!body) return;
    if (body.dataset.hpPageUrl) {
      attachRemoteContainer(table, body);
      return;
    }
    const controls = document.createElement("div");
    controls.className = "hp-lazy-controls";
    controls.setAttribute("aria-live", "polite");
    controls.innerHTML = lazyControlsHTML();
    table.after(controls);
    const state = {
      shown: lazyPageSize,
      controls,
      counter: controls.querySelector("span"),
      button: controls.querySelector("button"),
      sentinel: controls.querySelector(".hp-lazy-sentinel"),
      scheduled: false,
    };
    state.sentinel.__hpLazyTable = table;
    state.button.addEventListener("click", () => revealLazyRows(table));
    lazyTables.set(table, state);
    new MutationObserver(records => {
      if (records.some(record => record.removedNodes.length)) state.shown = lazyPageSize;
      if (state.scheduled) return;
      state.scheduled = true;
      queueMicrotask(() => {
        state.scheduled = false;
        updateLazyTable(table);
      });
    }).observe(body, {childList: true});
    updateLazyTable(table);
  };

  const lazyListItems = list => [...list.children].filter(child => !child.matches(".hp-lazy-controls"));

  const updateLazyList = list => {
    const state = lazyLists.get(list);
    if (!state) return;
    const items = lazyListItems(list);
    if (items.length <= lazyPageSize) state.shown = lazyPageSize;
    state.shown = Math.min(state.shown, items.length);
    items.forEach((item, index) => { item.hidden = index >= state.shown; });
    state.counter.textContent = `${Math.min(state.shown, items.length)} of ${items.length} entries`;
    state.controls.hidden = items.length <= lazyPageSize;
    const more = state.shown < items.length;
    state.button.hidden = !more;
    state.sentinel.hidden = !more;
    if (!more) lazyObserver?.unobserve(state.sentinel);
    else lazyObserver?.observe(state.sentinel);
  };

  const revealLazyItems = list => {
    const state = lazyLists.get(list);
    if (!state) return;
    state.shown = Math.min(lazyListItems(list).length, state.shown + lazyPageSize);
    updateLazyList(list);
  };

  const attachLazyList = list => {
    if (lazyLists.has(list) || remoteContainers.has(list)) return;
    if (list.dataset.hpPageUrl) {
      attachRemoteContainer(list, list);
      return;
    }
    const controls = document.createElement("div");
    controls.className = "hp-lazy-controls";
    controls.setAttribute("aria-live", "polite");
    controls.innerHTML = lazyControlsHTML();
    list.after(controls);
    const state = {
      shown: lazyPageSize,
      controls,
      counter: controls.querySelector("span"),
      button: controls.querySelector("button"),
      sentinel: controls.querySelector(".hp-lazy-sentinel"),
      scheduled: false,
    };
    state.sentinel.__hpLazyList = list;
    state.button.addEventListener("click", () => revealLazyItems(list));
    lazyLists.set(list, state);
    new MutationObserver(records => {
      if (records.some(record => record.removedNodes.length)) state.shown = lazyPageSize;
      if (state.scheduled) return;
      state.scheduled = true;
      queueMicrotask(() => {
        state.scheduled = false;
        updateLazyList(list);
      });
    }).observe(list, {childList: true});
    updateLazyList(list);
  };

  const initLazyViews = root => {
    root.querySelectorAll("table").forEach(attachLazyTable);
    root.querySelectorAll("[data-hp-lazy-list]").forEach(attachLazyList);
  };

  /* ---------- live toast ---------- */
  const showLiveToast = (message, href = "/events") => {
    let stack = document.querySelector("[data-hp-toast-stack]");
    if (!stack) {
      stack = document.createElement("div");
      stack.dataset.hpToastStack = "";
      stack.className = "hp-toast-stack";
      document.body.appendChild(stack);
    }
    const toast = document.createElement("a");
    toast.href = href;
    toast.className = "toast hp-toast";
    toast.textContent = message;
    stack.appendChild(toast);
    setTimeout(() => toast.remove(), 8000);
  };

  /* ---------- Leaflet attack map ---------- */
  // #228: a fixed pixel radius via circleMarker, not a real-world-meters
  // L.circle sized by event count. A count-scaled L.circle on a
  // high-traffic country-level point (GeoIP resolved no city) could reach
  // tens of kilometers of real radius -- zoomed in on an actual city inside
  // that country, the huge circle visually swallowed the city's own,
  // separate marker. A constant on-screen size never grows to cover
  // anything else, at any zoom.
  const attackMarkerRadius = 7;
  const attackDetails = p => {
    // #228: one marker per city (or country, when GeoIP never resolved a
    // city) accumulating every IP that landed there, not one marker per IP.
    const box = document.createElement("div"), title = document.createElement("strong");
    const place = p.city && p.country ? [p.city, p.country].join(", ") : p.city || p.country || "Unknown location";
    title.textContent = place + " — " + p.count + " events";
    box.append(title);
    box.append(document.createElement("br"), document.createTextNode(p.ip_count + (p.ip_count === 1 ? " source IP" : " source IPs")));
    box.append(document.createElement("br"));
    const hint = document.createElement("span");
    hint.textContent = "Select marker to show all related events";
    hint.style.color = "var(--accent)";
    box.append(hint);
    return box;
  };
  const showMapFallback = (shell, message) => {
    const map = shell.querySelector(".leaflet-map"), fallback = shell.querySelector(".map-fallback"), note = shell.querySelector("[data-map-status]");
    if (map) map.hidden = true;
    if (fallback) fallback.hidden = false;
    if (note) note.textContent = message;
  };
  const initMaps = () => document.querySelectorAll(".leaflet-map:not([data-map-ready])").forEach(container => {
    const shell = container.closest(".map-shell"), status = shell.querySelector("[data-map-status]");
    container.dataset.mapReady = "1";
    if (!window.L) { showMapFallback(shell, "Interactive map library unavailable — showing offline map"); return; }
    const savedView = window.honeypotLeafletView || {center: [20, 0], zoom: 2};
    const map = L.map(container, {minZoom: 1, maxZoom: 12, maxBounds: [[-85, -180], [85, 180]], maxBoundsViscosity: 0.75, worldCopyJump: false}).setView(savedView.center, savedView.zoom);
    const tileURL = decodeURIComponent(container.dataset.tileUrl), attributionText = container.dataset.attribution || "OpenStreetMap contributors";
    const safeAttribution = document.createElement("span");
    safeAttribution.textContent = attributionText;
    let tileErrors = 0;
    const tiles = L.tileLayer(tileURL, {maxZoom: 19, noWrap: true, attribution: '<a href="https://www.openstreetmap.org/copyright">' + safeAttribution.innerHTML + "</a>"})
      .on("tileerror", () => { if (++tileErrors >= 8) showMapFallback(shell, "Map tiles unavailable — showing offline fallback"); })
      .on("load", () => {
        tileErrors = 0;
        container.hidden = false;
        const fallback = shell.querySelector(".map-fallback");
        if (fallback) fallback.hidden = true;
      })
      .addTo(map);
    const origins = L.layerGroup().addTo(map);
    const saveView = () => { const c = map.getCenter(); window.honeypotLeafletView = {center: [c.lat, c.lng], zoom: map.getZoom()}; };
    map.on("moveend zoomend", saveView);
    const Home = L.Control.extend({options: {position: "topright"}, onAdd: () => {
      const b = L.DomUtil.create("button", "leaflet-control-home");
      b.type = "button";
      b.title = "Reset world view";
      b.setAttribute("aria-label", "Reset world view");
      b.textContent = "World";
      L.DomEvent.disableClickPropagation(b);
      L.DomEvent.on(b, "click", () => map.setView([20, 0], 2));
      return b;
    }});
    map.addControl(new Home());
    const update = async () => {
      try {
        const r = await fetch("/api/map-points", {cache: "no-store"});
        if (!r.ok) throw new Error("HTTP " + r.status);
        const data = await r.json();
        origins.clearLayers();
        L.geoJSON(data, {
          pointToLayer: (feature, latlng) => L.circleMarker(latlng, {radius: attackMarkerRadius, color: "#fecaca", weight: 1.2, opacity: 0.92, fillColor: "#f87171", fillOpacity: 0.58}),
          onEachFeature: (feature, layer) => {
            const p = feature.properties;
            layer.bindTooltip(attackDetails(p), {className: "attack-tooltip", sticky: true, direction: "top"});
            layer.on("click", () => location.assign(p.events_url));
            layer.on("add", () => {
              const el = layer.getElement();
              if (!el) return;
              el.setAttribute("tabindex", "0");
              el.setAttribute("role", "link");
              el.setAttribute("aria-label", (p.city && p.country ? p.city + ", " + p.country : p.city || p.country || "Unknown location") + ", " + p.count + " events");
              el.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); location.assign(p.events_url); } });
            });
          }
        }).addTo(origins);
        status.textContent = data.features.length + " geolocated locations • zoom " + map.getZoom();
      } catch (e) {
        status.textContent = "Attack origin update failed: " + e.message;
      }
    };
    map.on("zoomend", () => { status.textContent = status.textContent.replace(/zoom \d+$/, "zoom " + map.getZoom()); });
    window.honeypotLeaflet = {map, origins, tiles, container, shell, update};
    window.updateHoneypotMap = update;
    update();
    setTimeout(() => map.invalidateSize(false), 0);
  });
  window.initHoneypotMaps = initMaps;

  /* ---------- workspace tabs ----------
     Any page can group its cards: render .tabs buttons with
     data-dashboard-tab and matching [data-dashboard-panel] sections. The valid
     names come from the DOM, so a page declares its own views without this
     controller knowing them. The first tab is the default. */
  const tabButtons = () => Array.from(document.querySelectorAll("[data-dashboard-tab]"));
  const activateDashboardTab = name => {
    const buttons = tabButtons();
    if (!buttons.length) return;
    const valid = buttons.map(b => b.dataset.dashboardTab);
    if (!valid.includes(name)) name = valid[0];
    window.honeypotDashboardTab = name;
    document.querySelectorAll("[data-dashboard-panel]").forEach(p => p.hidden = p.dataset.dashboardPanel !== name);
    buttons.forEach(b => {
      const active = b.dataset.dashboardTab === name;
      b.classList.toggle("active", active);
      b.setAttribute("aria-selected", String(active));
      b.tabIndex = active ? 0 : -1;
    });
    // Leaflet cannot size itself while its container is hidden.
    const shown = document.querySelector(`[data-dashboard-panel="${CSS.escape(name)}"]`);
    if (shown?.querySelector(".leaflet-map") && window.honeypotLeaflet?.map) {
      setTimeout(() => window.honeypotLeaflet.map.invalidateSize(false), 0);
    }
  };
  window.initDashboardTabs = () => activateDashboardTab(window.honeypotDashboardTab || location.hash.replace("#", ""));

  /* ---------- live page mounting (SSE / interval refresh) ---------- */
  const pageContent = document.querySelector("[data-hp-page-content]");
  const refreshOverviewPreservingMap = source => {
    const currentLive = pageContent.querySelector("#panel-live");
    const incomingLive = source.querySelector("#panel-live");
    const mapCard = currentLive?.querySelector(":scope > [data-attack-map-card]");
    const incomingMap = incomingLive?.querySelector(":scope > [data-attack-map-card]");
    if (!currentLive || !incomingLive || !mapCard || !incomingMap) return false;

    const childKey = element => {
      if (element.id) return `#${element.id}`;
      if (element.matches(".tabs")) return "overview-tabs";
      return "";
    };
    [...source.children].forEach(incoming => {
      if (incoming === incomingLive) return;
      const key = childKey(incoming);
      if (!key) return;
      const current = key.startsWith("#")
        ? pageContent.querySelector(`:scope > ${key}`)
        : pageContent.querySelector(":scope > .tabs");
      current?.replaceWith(incoming);
    });

    // Rebuild the live panel around the existing map node. The Leaflet
    // container never leaves the connected DOM, so its viewport is untouched.
    [...currentLive.children].forEach(child => {
      if (child !== mapCard) child.remove();
    });
    let afterMap = false;
    [...incomingLive.children].forEach(incoming => {
      if (incoming === incomingMap) {
        afterMap = true;
        return;
      }
      if (afterMap) currentLive.appendChild(incoming);
      else currentLive.insertBefore(incoming, mapCard);
    });
    source.remove();
    return true;
  };

  const mountPage = (source, options = {}) => {
    if (!pageContent) { source.remove?.(); return; }
    reNonce(source);
    if (options.preserveMap && refreshOverviewPreservingMap(source)) {
      initLazyViews(pageContent);
      applyTimezone(prefState.prefs?.timezone);
      return;
    }
    pageContent.replaceChildren(...source.children);
    source.remove();
    initLazyViews(pageContent);
    applyTimezone(prefState.prefs?.timezone);
  };
  window.replaceHoneypotPage = mountPage;

  /* ---------- shell wiring ---------- */
  addEventListener("DOMContentLoaded", () => {
    initMaps();
    window.initDashboardTabs();
    initLazyViews(document);
    document.addEventListener("click", e => {
      const b = e.target.closest("[data-dashboard-tab]");
      if (!b) return;
      activateDashboardTab(b.dataset.dashboardTab);
      history.replaceState(null, "", "#" + b.dataset.dashboardTab);
    });
    document.addEventListener("keydown", e => {
      const b = e.target.closest?.("[data-dashboard-tab]");
      if (!b || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
      const tabs = [...document.querySelectorAll("[data-dashboard-tab]")];
      let i = tabs.indexOf(b);
      if (e.key === "Home") i = 0;
      else if (e.key === "End") i = tabs.length - 1;
      else i = (i + (e.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      e.preventDefault();
      tabs[i].focus();
      tabs[i].click();
    });
    addEventListener("hashchange", () => activateDashboardTab(location.hash.replace("#", "")));

    const shell = document.querySelector(".app-shell");
    if (!shell) return;

    /* Active nav + page identity */
    const current = activeHref();
    shell.querySelectorAll("[data-hp-nav]").forEach(link => {
      const active = link.dataset.hpNav === current;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page");
    });
    const identity = shell.querySelector("[data-hp-page-name]");
    if (identity) identity.textContent = pageName();

    /* The recent-investigations rail was removed; drop anything an earlier
       version of the dashboard left behind in this browser. */
    try { localStorage.removeItem("hp-recent-investigations"); } catch {}
    /* Ditto for the command bar's old show/hide preference: it's a modal
       now (#193), there's nothing left to hide. */
    try { localStorage.removeItem("hp-command-dock-hidden"); } catch {}

    /* Sidebar collapse (persisted) / mobile off-canvas open */
    const collapseStorageKey = "hp-sidebar-collapsed";
    const setSidebarCollapsed = collapsed => {
      shell.classList.toggle("hp-collapsed", collapsed);
      try { localStorage.setItem(collapseStorageKey, collapsed ? "1" : "0"); } catch {}
    };
    if (innerWidth > 520 && localStorage.getItem(collapseStorageKey) === "1") shell.classList.add("hp-collapsed");
    shell.querySelector("[data-hp-sidebar-toggle]")?.addEventListener("click", () => {
      if (innerWidth <= 520) {
        shell.classList.toggle("hp-nav-open");
      } else {
        const collapsed = shell.classList.toggle("hp-collapsed");
        try { localStorage.setItem(collapseStorageKey, collapsed ? "1" : "0"); } catch {}
        savePrefs({collapsed_sidebar: collapsed});
      }
    });
    shell.querySelectorAll("[data-hp-nav]").forEach(link => link.addEventListener("click", () => {
      if (innerWidth <= 520) shell.classList.remove("hp-nav-open");
    }));

    /* Investigation command palette (#193, closing #183): a modal, not a
       permanently-docked bar. Follows the same application-managed modal
       contract (Xore/theme docs/MODALS.md) as hp-evidence.js/hp-settings.js:
       inert + aria-hidden when closed, focus moved in on open and restored
       on close, Escape and a backdrop click close it. */
    const commandPalette = document.getElementById("hp-command-palette");
    const commandPaletteBackdrop = document.getElementById("hp-command-palette-backdrop");
    const commandPaletteOpener = shell.querySelector("[data-hp-command-palette-open]");
    const search = commandPalette?.querySelector("[data-hp-investigate]");
    const searchInput = search?.querySelector("textarea");
    let commandPaletteRestoreFocus = null;

    const openCommandPalette = trigger => {
      if (!commandPalette || !commandPaletteBackdrop) return;
      commandPaletteRestoreFocus = trigger || document.activeElement;
      commandPaletteBackdrop.removeAttribute("inert");
      commandPaletteBackdrop.setAttribute("aria-hidden", "false");
      commandPaletteBackdrop.classList.add("open");
      commandPalette.removeAttribute("inert");
      commandPalette.setAttribute("aria-hidden", "false");
      commandPalette.classList.add("open");
      searchInput?.focus();
    };
    const closeCommandPalette = () => {
      if (!commandPalette || !commandPaletteBackdrop) return;
      commandPalette.classList.remove("open");
      commandPalette.setAttribute("aria-hidden", "true");
      commandPalette.setAttribute("inert", "");
      commandPaletteBackdrop.classList.remove("open");
      commandPaletteBackdrop.setAttribute("aria-hidden", "true");
      commandPaletteBackdrop.setAttribute("inert", "");
      if (commandPaletteRestoreFocus?.isConnected) commandPaletteRestoreFocus.focus();
      commandPaletteRestoreFocus = null;
    };
    commandPaletteOpener?.addEventListener("click", () => openCommandPalette(commandPaletteOpener));
    commandPalette?.querySelector("[data-hp-command-palette-close]")?.addEventListener("click", closeCommandPalette);
    commandPaletteBackdrop?.addEventListener("click", closeCommandPalette);
    addEventListener("keydown", event => {
      if (event.key !== "Escape") return;
      if (commandPalette?.classList.contains("open")) closeCommandPalette();
      else shell.classList.remove("hp-nav-open");
    });

    /* Enter submits, Shift+Enter adds a line, "/" opens the palette from
       anywhere (matching the old always-focused-bar shortcut). */
    const resizeSearch = () => {
      searchInput.style.height = "auto";
      searchInput.style.height = `${Math.min(120, searchInput.scrollHeight)}px`;
    };
    searchInput?.addEventListener("input", resizeSearch);

    /* Live quick-search preview (#213): the palette's own results list, fed
       by /api/quick-search, which reuses the same grouped-search backend the
       /search page renders from. This is a preview, not a replacement for
       Enter -- Enter still submits the form to /search unless a row is
       keyboard-highlighted or the row itself is clicked. */
    const resultsBox = commandPalette?.querySelector("[data-hp-command-palette-results]");
    const emptyHint = commandPalette?.querySelector("[data-hp-command-palette-empty]");
    let quickSearchRows = [];
    let activeRow = -1;
    let quickSearchAbort = null;
    let quickSearchTimer = null;

    const renderRow = hit => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "command-palette__row";
      row.setAttribute("role", "option");
      row.setAttribute("aria-selected", "false");
      row.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
      const title = document.createElement("span");
      title.className = "command-palette__row-title";
      title.textContent = hit.title;
      const meta = document.createElement("span");
      meta.className = "command-palette__row-meta";
      meta.textContent = hit.meta;
      meta.dataset.group = hit.meta;
      row.append(title, meta);
      row.addEventListener("click", () => { location.href = hit.url; });
      return row;
    };

    // The active row trades its group/category label for a keyboard hint --
    // the rest keep showing which source they matched from.
    const setActiveRow = index => {
      const rows = resultsBox ? [...resultsBox.children] : [];
      rows.forEach((row, i) => {
        const active = i === index;
        row.classList.toggle("active", active);
        row.setAttribute("aria-selected", active ? "true" : "false");
        const meta = row.querySelector(".command-palette__row-meta");
        if (meta) meta.textContent = active ? "Enter" : meta.dataset.group;
      });
      activeRow = index;
      if (index >= 0) rows[index]?.scrollIntoView({ block: "nearest" });
    };

    const clearQuickSearch = () => {
      quickSearchAbort?.abort();
      quickSearchRows = [];
      activeRow = -1;
      if (resultsBox) { resultsBox.hidden = true; resultsBox.replaceChildren(); }
      if (emptyHint) emptyHint.hidden = false;
    };

    const runQuickSearch = query => {
      quickSearchAbort?.abort();
      if (!query) { clearQuickSearch(); return; }
      quickSearchAbort = new AbortController();
      fetch(`/api/quick-search?q=${encodeURIComponent(query)}`, { signal: quickSearchAbort.signal })
        .then(res => (res.ok ? res.json() : { results: [] }))
        .then(data => {
          quickSearchRows = data.results || [];
          activeRow = -1;
          if (!resultsBox) return;
          if (quickSearchRows.length === 0) {
            resultsBox.hidden = true;
            resultsBox.replaceChildren();
            if (emptyHint) emptyHint.hidden = false;
            return;
          }
          resultsBox.replaceChildren(...quickSearchRows.map(renderRow));
          resultsBox.hidden = false;
          if (emptyHint) emptyHint.hidden = true;
          setActiveRow(0);
        })
        .catch(() => {});
    };

    searchInput?.addEventListener("input", () => {
      clearTimeout(quickSearchTimer);
      const query = searchInput.value.trim();
      quickSearchTimer = setTimeout(() => runQuickSearch(query), 150);
    });

    searchInput?.addEventListener("keydown", event => {
      if (event.key === "ArrowDown" && quickSearchRows.length) {
        event.preventDefault();
        setActiveRow(Math.min(activeRow + 1, quickSearchRows.length - 1));
        return;
      }
      if (event.key === "ArrowUp" && quickSearchRows.length) {
        event.preventDefault();
        setActiveRow(Math.max(activeRow - 1, -1));
        return;
      }
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        if (activeRow >= 0 && quickSearchRows[activeRow]) {
          location.href = quickSearchRows[activeRow].url;
          return;
        }
        search.requestSubmit();
      }
    });
    // The form is a plain GET to /search; only block the empty submission.
    search?.addEventListener("submit", event => {
      if (!searchInput?.value.trim()) event.preventDefault();
    });
    addEventListener("keydown", event => {
      if (event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "")) {
        event.preventDefault();
        openCommandPalette();
      }
    });

    /* Theme preference: cycle system -> dark -> light (persisted) */
    const themeStorageKey = "hp-theme";
    const themeOrder = ["system", "dark", "light"];
    const currentTheme = () => {
      try {
        const value = localStorage.getItem(themeStorageKey);
        return value === "dark" || value === "light" ? value : "system";
      } catch { return "system"; }
    };
    const themeToggle = shell.querySelector("[data-hp-theme-toggle]");
    const applyTheme = mode => {
      if (mode === "system") delete document.documentElement.dataset.theme;
      else document.documentElement.dataset.theme = mode;
      try {
        if (mode === "system") localStorage.removeItem(themeStorageKey);
        else localStorage.setItem(themeStorageKey, mode);
      } catch {}
      themeToggle?.setAttribute("title", `Theme: ${mode}`);
      themeToggle?.querySelectorAll("[data-hp-theme-icon]").forEach(icon => {
        icon.hidden = icon.dataset.hpThemeIcon !== mode;
      });
    };
    applyTheme(currentTheme());
    themeToggle?.addEventListener("click", () => {
      const next = themeOrder[(themeOrder.indexOf(currentTheme()) + 1) % themeOrder.length];
      applyTheme(next);
      savePrefs({theme: next});
    });

    /* ---------- server-backed preferences (roadmap Milestone C) ----------
       The server is the source of truth when reachable; localStorage stays a
       per-browser mirror so the pre-JS theme bootstrap and offline behavior
       are unchanged. Recognized legacy keys are migrated to the server once. */
    /* #156: hp-settings.js (the settings modal, part of this same shell)
       used to track its own independent copy of the preferences ETag. Any
       write from here -- the theme toggle below, or the one-time
       localStorage migration -- advanced the server's per-subject revision
       without hp-settings.js knowing, so its next save carried a stale
       If-Match and failed with a false "changed in another session"
       conflict on the very first settings edit after a page load. Sharing
       one object as the single source of truth for the current ETag/prefs
       fixes that at the source instead of just recovering from the 409. */
    const prefState = window.HpPreferences = window.HpPreferences || {ready: false, etag: "", prefs: null};
    const prefHeaders = () => ({
      "Content-Type": "application/json",
      ...(prefState.etag ? {"If-Match": prefState.etag} : {}),
    });
    const readPrefResponse = async response => {
      if (!response.ok) return null;
      prefState.etag = response.headers.get("ETag") || prefState.etag;
      const data = await response.json().catch(() => null);
      if (data && data.preferences) prefState.prefs = data.preferences;
      return data && data.preferences ? data.preferences : null;
    };
    /* Fire-and-forget write; a conflict means another browser won, so resync
       and let the server state win (multi-browser consistency). */
    const savePrefs = patch => {
      if (!prefState.ready) return;
      fetch("/api/settings/me/preferences", {
        method: "PATCH", headers: prefHeaders(), body: JSON.stringify(patch),
      }).then(response => {
        if (response.status === 409) return syncPrefs().then(() => null);
        return readPrefResponse(response);
      }).catch(() => {});
    };
    /* Timezone display conversion (#282): every event timestamp is a fixed
       UTC string baked in once by the server's shared, cross-viewer event
       cache (rebuild() in aggregate.go), long before any per-viewer
       preference is known -- alongside a machine-readable data-hp-utc twin.
       Reformat client-side into whichever zone this viewer's own preference
       resolves to: "browser" defers entirely to the browser's own locale/
       zone (Intl's default when no timeZone option is given), "utc" is a
       no-op (the server-rendered fallback already is UTC), anything else is
       an explicit IANA zone name. formatToParts, not a locale's own
       punctuation, keeps the "YYYY-MM-DD HH:MM:SS" shape consistent with
       the server-rendered fallback regardless of the browser's locale. */
    const applyTimezone = tz => {
      if (!tz || tz === "utc") return;
      const options = {year: "numeric", month: "2-digit", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false};
      if (tz !== "browser") options.timeZone = tz;
      let formatter;
      try { formatter = new Intl.DateTimeFormat("en-CA", options); }
      catch { return; } // an invalid IANA zone name: leave the UTC fallback showing
      document.querySelectorAll("[data-hp-utc]").forEach(el => {
        const parsed = new Date(el.dataset.hpUtc);
        if (Number.isNaN(parsed.getTime())) return;
        const parts = {};
        formatter.formatToParts(parsed).forEach(p => { parts[p.type] = p.value; });
        if (!parts.year) return;
        el.textContent = `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
      });
    };
    const applyEffectivePrefs = prefs => {
      if (!prefs) return;
      if (prefs.theme === "dark" || prefs.theme === "light" || prefs.theme === "system") applyTheme(prefs.theme);
      if (innerWidth > 520 && typeof prefs.collapsed_sidebar === "boolean") setSidebarCollapsed(prefs.collapsed_sidebar);
      applyTimezone(prefs.timezone);
    };
    /* One-time migration of recognized localStorage preferences. The marker
       is set before the write so a failed migration never loops. */
    const migrateLocalPrefs = async () => {
      const marker = "hp-prefs-migrated";
      try { if (localStorage.getItem(marker)) return null; } catch { return null; }
      const patch = {};
      const theme = currentTheme();
      if (theme !== "system") patch.theme = theme;
      try {
        const collapsed = localStorage.getItem(collapseStorageKey);
        if (collapsed === "1") patch.collapsed_sidebar = true;
        else if (collapsed === "0") patch.collapsed_sidebar = false;
      } catch {}
      try { localStorage.setItem(marker, "1"); } catch {}
      if (!Object.keys(patch).length) return null;
      try {
        return await readPrefResponse(await fetch("/api/settings/me/preferences", {
          method: "PATCH", headers: prefHeaders(), body: JSON.stringify(patch),
        }));
      } catch { return null; }
    };
    const syncPrefs = async () => {
      try {
        const response = await fetch("/api/settings/me", {cache: "no-store"});
        if (!response.ok) return; // logged out or offline: local mirror stays authoritative
        prefState.etag = response.headers.get("ETag") || "";
        const data = await response.json().catch(() => null);
        if (!data || !data.preferences) return;
        prefState.prefs = data.preferences;
        prefState.ready = true;
        const migrated = await migrateLocalPrefs();
        applyEffectivePrefs(migrated || prefState.prefs);
      } catch {}
    };
    syncPrefs();

    /* Sidebar profile row from live auth-backend session introspection */
    fetch("/api/whoami", {cache: "no-store"}).then(r => r.ok ? r.json() : null).then(identity => {
      if (!identity || !identity.username) return;
      const name = shell.querySelector("[data-hp-user-name]");
      const avatar = shell.querySelector("[data-hp-user-avatar]");
      const role = shell.querySelector("[data-hp-user-role]");
      const label = identity.display_name || identity.username;
      if (name) name.textContent = label;
      if (avatar) avatar.textContent = label.trim().slice(0, 2).toUpperCase();
      if (role && identity.role) {
        role.textContent = identity.role;
        role.classList.toggle("badge--accent", identity.role === "admin");
        role.classList.toggle("badge--muted", identity.role !== "admin");
        role.hidden = false;
      }
    }).catch(() => {});

    /* Alert bell badge (60s polling) */
    const refreshAlertCount = async () => {
      if (window.HoneypotLive.paused()) return;
      try {
        const records = await (await fetch("/api/alerts", {cache: "no-store"})).json();
        const count = records.filter(record => !record.Acknowledged).length;
        const badge = shell.querySelector("[data-hp-alert-count]");
        if (!badge) return;
        badge.textContent = count > 99 ? "99+" : String(count);
        badge.hidden = count === 0;
      } catch {}
    };
    refreshAlertCount();
    setInterval(refreshAlertCount, 60000);

    /* LIVE toggle: one switch over every refresh path, and (#210) the single
       global indicator for connection health too -- there is no separate
       per-page pill any more. */
    const liveToggle = shell.querySelector("[data-hp-live-toggle]");
    if (liveToggle) {
      const liveLabel = liveToggle.querySelector("[data-hp-live-label]");
      const renderLiveState = () => {
        const paused = window.HoneypotLive.paused();
        const stalled = !paused && !window.HoneypotLive.connectionHealthy();
        liveToggle.classList.toggle("hp-live-state--paused", paused);
        liveToggle.classList.toggle("hp-live-state--stalled", stalled);
        liveToggle.setAttribute("aria-pressed", paused ? "true" : "false");
        liveToggle.title = paused
          ? "Dashboard refresh is paused — resume it"
          : stalled
            ? "Live connection lost — reconnecting automatically"
            : "Dashboard refresh is active — pause it";
        if (liveLabel) liveLabel.textContent = paused ? "Paused" : stalled ? "Reconnecting…" : "Live";
      };
      renderLiveState();
      window.HoneypotLive.onChange(renderLiveState);
      window.HoneypotLive.onConnectionChange(renderLiveState);
      liveToggle.addEventListener("click", () => {
        window.HoneypotLive.toggle();
        // Resuming shows current data rather than whatever went stale while
        // updates were suppressed.
        if (!window.HoneypotLive.paused()) {
          refreshAlertCount();
          dispatchEvent(new CustomEvent("hp-live-resumed"));
        }
      });
    }

    /* SSE live updates on non-overview pages (overview refreshes in place) */
    if (location.pathname !== "/" && window.EventSource) {
      let knownTotal = null;
      fetch("/api/events?per_page=25", {cache: "no-store"}).then(r => r.json()).then(data => { knownTotal = data.Total; }).catch(() => {});
      const stream = new EventSource("/api/stream");
      stream.addEventListener("open", () => window.HoneypotLive.setConnectionHealthy(true));
      stream.onerror = () => window.HoneypotLive.setConnectionHealthy(false);
      stream.addEventListener("update", async () => {
        if (window.HoneypotLive.paused()) return;
        try {
          const data = await (await fetch("/api/events?per_page=25", {cache: "no-store"})).json();
          if (knownTotal !== null && data.Total > knownTotal) showLiveToast(`${data.Total - knownTotal} new honeypot event${data.Total - knownTotal === 1 ? "" : "s"}`, "/events");
          knownTotal = data.Total;
        } catch {}
      });
    }
  });
})();
