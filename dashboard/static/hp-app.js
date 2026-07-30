/* Honeypot dashboard enhancement layer (framework-free).
   The app shell (sidebar + topbar) is server-rendered; this script adds the
   interactive behavior on top: live refresh, maps, tabs, lazy rows, the
   investigation command dock, recents, alert badge, and sidebar state. */
(() => {
  "use strict";

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
    if (path.startsWith("/sandbox/")) return "/sandbox";
    if (path.startsWith("/sessions/")) return "/events";
    if (path.startsWith("/investigate/ip/")) return "/ips";
    return path;
  };

  /* Investigation routing is server-side (/search): the dock is a plain GET
     form, so a query that names no entity lands on grouped results instead of
     the 404 a client-side format guess produced. */

  /* ---------- lazy loading (sentinel + offset fetching) ---------- */
  // Keep long investigation views responsive without traditional page links.
  // The first 25 rows are visible immediately; another 25 are revealed when
  // the sentinel approaches the viewport or the accessible button is pressed.
  const lazyPageSize = 25;
  const lazyTables = new WeakMap();
  const lazyLists = new WeakMap();
  const remoteTables = new WeakMap();
  const lazyObserver = "IntersectionObserver" in window ? new IntersectionObserver(entries => {
    entries.filter(entry => entry.isIntersecting).forEach(entry => {
      const table = entry.target.__hpLazyTable;
      if (table) revealLazyRows(table);
      const list = entry.target.__hpLazyList;
      if (list) revealLazyItems(list);
      const remote = entry.target.__hpRemoteTable;
      if (remote) loadRemoteRows(remote);
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

  const updateRemoteTable = table => {
    const state = remoteTables.get(table);
    if (!state) return;
    const loadedThrough = state.offset + state.body.rows.length;
    state.counter.textContent = `${Math.min(loadedThrough, state.total)} of ${state.total} entries`;
    const more = loadedThrough < state.total;
    state.controls.hidden = state.total <= lazyPageSize;
    state.button.hidden = !more;
    state.sentinel.hidden = !more;
    if (!more) lazyObserver?.unobserve(state.sentinel);
    else lazyObserver?.observe(state.sentinel);
  };

  const loadRemoteRows = async table => {
    const state = remoteTables.get(table);
    const nextOffset = state ? state.offset + state.body.rows.length : 0;
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
      const rows = await response.text();
      if (!rows.trim()) state.total = nextOffset;
      else state.body.insertAdjacentHTML("beforeend", rows);
      updateRemoteTable(table);
    } catch (error) {
      state.counter.textContent = `Could not load more entries (${error.message})`;
    } finally {
      state.loading = false;
      state.button.disabled = false;
    }
  };

  const attachRemoteTable = (table, body) => {
    const controls = document.createElement("div");
    controls.className = "hp-lazy-controls";
    controls.setAttribute("aria-live", "polite");
    controls.innerHTML = lazyControlsHTML();
    table.after(controls);
    const state = {
      body,
      total: Number.parseInt(body.dataset.hpTotal || `${body.rows.length}`, 10),
      offset: Number.parseInt(body.dataset.hpOffset || "0", 10),
      url: body.dataset.hpPageUrl,
      controls,
      counter: controls.querySelector("span"),
      button: controls.querySelector("button"),
      sentinel: controls.querySelector(".hp-lazy-sentinel"),
      loading: false,
    };
    state.sentinel.__hpRemoteTable = table;
    state.button.addEventListener("click", () => loadRemoteRows(table));
    remoteTables.set(table, state);
    updateRemoteTable(table);
  };

  const attachLazyTable = table => {
    if (lazyTables.has(table) || remoteTables.has(table) || table.dataset.hpNoLazy !== undefined) return;
    const body = table.tBodies[0];
    if (!body) return;
    if (body.dataset.hpPageUrl) {
      attachRemoteTable(table, body);
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
    if (lazyLists.has(list)) return;
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
    toast.className = "hp-toast";
    toast.textContent = message;
    stack.appendChild(toast);
    setTimeout(() => toast.remove(), 8000);
  };

  /* ---------- Leaflet attack map ---------- */
  const attackRadius = count => Math.min(350000, 35000 + Math.sqrt(Math.max(1, count)) * 8000);
  const attackDetails = p => {
    const box = document.createElement("div"), title = document.createElement("strong");
    title.textContent = p.ip + " — " + p.count + " events";
    box.append(title);
    const rows = [p.city && p.country ? [p.city, p.country].join(", ") : p.city || p.country, p.asn ? "AS" + p.asn + (p.organization ? " " + p.organization : "") : p.organization, p.intel || p.provider_type].filter(Boolean);
    rows.forEach(v => { box.append(document.createElement("br"), document.createTextNode(v)); });
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
          pointToLayer: (feature, latlng) => L.circle(latlng, {radius: attackRadius(feature.properties.count), color: "#fecaca", weight: 1.2, opacity: 0.92, fillColor: "#f87171", fillOpacity: 0.58}),
          onEachFeature: (feature, layer) => {
            const p = feature.properties;
            layer.bindTooltip(attackDetails(p), {className: "attack-tooltip", sticky: true, direction: "top"});
            layer.on("click", () => location.assign(p.events_url));
            layer.on("add", () => {
              const el = layer.getElement();
              if (!el) return;
              el.setAttribute("tabindex", "0");
              el.setAttribute("role", "link");
              el.setAttribute("aria-label", p.ip + ", " + p.count + " events");
              el.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); location.assign(p.events_url); } });
            });
          }
        }).addTo(origins);
        status.textContent = data.features.length + " geolocated sources • zoom " + map.getZoom();
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

  /* ---------- overview workspace tabs ---------- */
  const activateDashboardTab = name => {
    const valid = ["live", "threats", "behavior", "evidence"];
    if (!valid.includes(name)) name = "live";
    window.honeypotDashboardTab = name;
    document.querySelectorAll("[data-dashboard-panel]").forEach(p => p.hidden = p.dataset.dashboardPanel !== name);
    document.querySelectorAll("[data-dashboard-tab]").forEach(b => {
      const active = b.dataset.dashboardTab === name;
      b.classList.toggle("active", active);
      b.setAttribute("aria-selected", String(active));
      b.tabIndex = active ? 0 : -1;
    });
    if (name === "live" && window.honeypotLeaflet?.map) setTimeout(() => window.honeypotLeaflet.map.invalidateSize(false), 0);
  };
  window.initDashboardTabs = () => activateDashboardTab(window.honeypotDashboardTab || location.hash.replace("#", "") || "live");

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
      if (element.matches(".dashboard-tabs")) return "overview-tabs";
      return "";
    };
    [...source.children].forEach(incoming => {
      if (incoming === incomingLive) return;
      const key = childKey(incoming);
      if (!key) return;
      const current = key.startsWith("#")
        ? pageContent.querySelector(`:scope > ${key}`)
        : pageContent.querySelector(":scope > .dashboard-tabs");
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
    if (options.preserveMap && refreshOverviewPreservingMap(source)) {
      initLazyViews(pageContent);
      return;
    }
    pageContent.replaceChildren(...source.children);
    source.remove();
    initLazyViews(pageContent);
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
    addEventListener("keydown", event => {
      if (event.key === "Escape") shell.classList.remove("hp-nav-open");
    });

    /* Command dock (server-rendered as part of the shell; theme .command-bar
       positions it and sidebar collapse inherits). Enter submits, Shift+Enter
       adds a line, "/" focuses it from anywhere. */
    const search = shell.querySelector("[data-hp-investigate]");
    const searchInput = search?.querySelector("textarea");
    const resizeSearch = () => {
      searchInput.style.height = "auto";
      searchInput.style.height = `${Math.min(120, searchInput.scrollHeight)}px`;
    };
    searchInput?.addEventListener("input", resizeSearch);
    searchInput?.addEventListener("keydown", event => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
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
        searchInput?.focus();
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
    const prefState = {ready: false, etag: "", prefs: null};
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
    const applyEffectivePrefs = prefs => {
      if (!prefs) return;
      if (prefs.theme === "dark" || prefs.theme === "light" || prefs.theme === "system") applyTheme(prefs.theme);
      if (innerWidth > 520 && typeof prefs.collapsed_sidebar === "boolean") setSidebarCollapsed(prefs.collapsed_sidebar);
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

    /* SSE live updates on non-overview pages (overview refreshes in place) */
    if (location.pathname !== "/" && window.EventSource) {
      let knownTotal = null;
      fetch("/api/events?per_page=25", {cache: "no-store"}).then(r => r.json()).then(data => { knownTotal = data.Total; }).catch(() => {});
      const stream = new EventSource("/api/stream");
      stream.addEventListener("update", async () => {
        try {
          const data = await (await fetch("/api/events?per_page=25", {cache: "no-store"})).json();
          if (knownTotal !== null && data.Total > knownTotal) showLiveToast(`${data.Total - knownTotal} new honeypot event${data.Total - knownTotal === 1 ? "" : "s"}`, "/events");
          knownTotal = data.Total;
        } catch {}
      });
    }
  });
})();
