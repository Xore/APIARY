/* AdminLTE 4.1 frontend adapter for the honeypot API/server views. */
(() => {
  const navGroups = [
    ["Monitor", "bi-house", [
      ["bi-speedometer2", "Overview", "/"],
      ["bi-heart-pulse", "Sensor & pipeline health", "/source-health"],
      ["bi-shield-exclamation", "Alerts", "/alerts"],
    ]],
    ["Investigate", "bi-search", [
      ["bi-list-ul", "Event explorer", "/events"],
      ["bi-globe2", "Attack sources", "/ips"],
      ["bi-diagram-3", "Campaigns", "/campaigns"],
      ["bi-bezier2", "Infrastructure clusters", "/clusters"],
      ["bi-terminal", "Executed commands", "/commands"],
    ]],
    ["Evidence", "bi-fingerprint", [
      ["bi-file-earmark-binary", "Captured payloads", "/payloads"],
      ["bi-box", "Sandbox results", "/sandbox"],
      ["bi-database", "Elasticsearch history", "/history"],
      ["bi-exclamation-diamond", "Ingest dead letters", "/dead-letters"],
    ]]
  ];

  const pageName = () => {
    const path = location.pathname;
    if (path === "/") return "Overview";
    if (path.startsWith("/payload-analysis")) return "Payload analysis";
    if (path.startsWith("/sessions/")) return "Session replay";
    if (path.startsWith("/investigate/ip/")) return "Attacker profile";
    for (const [, , items] of navGroups) {
      for (const [, label, href] of items) if (path === href) return label;
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

  const activeWorkspace = () => {
    const href = activeHref();
    return navGroups.find(([, , items]) => items.some(([, , itemHref]) => itemHref === href))?.[0] || "Monitor";
  };

  const navHTML = () => navGroups.map(([heading, , items]) =>
    `<li class="nav-header" data-hp-workspace-group="${heading}">${heading}</li>` + items.map(([icon, label, href]) =>
      `<li class="nav-item" data-hp-workspace-group="${heading}"><a href="${href}" class="nav-link${activeHref() === href ? " active" : ""}"${activeHref() === href ? ' aria-current="page"' : ""}><i class="nav-icon bi ${icon}" aria-hidden="true"></i><p>${label}</p></a></li>`
    ).join("")
  ).join("");

  const workspaceTabsHTML = () => navGroups.map(([heading, icon]) =>
    `<button type="button" class="hp-workspace-tab${activeWorkspace() === heading ? " active" : ""}" data-hp-workspace="${heading}" aria-selected="${activeWorkspace() === heading}"><i class="bi ${icon}" aria-hidden="true"></i><span>${heading}</span></button>`
  ).join("");

  const escapeHTML = value => String(value).replace(/[&<>"']/g, character => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[character]));
  const recentStorageKey = "hp-recent-investigations";
  const readRecents = () => {
    try { return JSON.parse(localStorage.getItem(recentStorageKey) || "[]"); } catch { return []; }
  };
  const rememberCurrentInvestigation = () => {
    if (location.pathname === "/" || ["/source-health", "/alerts"].includes(location.pathname)) return;
    const url = location.pathname + location.search + location.hash;
    const record = {url, label: pageName(), detail: new URLSearchParams(location.search).values().next().value || "", seen: Date.now()};
    const records = [record, ...readRecents().filter(item => item.url !== url)].slice(0, 12);
    try { localStorage.setItem(recentStorageKey, JSON.stringify(records)); } catch {}
  };
  const recentHTML = () => readRecents().map(item =>
    `<a class="hp-recent-link" href="${escapeHTML(item.url)}"><i class="bi bi-clock-history" aria-hidden="true"></i><span><strong>${escapeHTML(item.label)}</strong>${item.detail ? `<small>${escapeHTML(item.detail)}</small>` : ""}</span></a>`
  ).join("") || `<p class="hp-recents-empty">Investigations you open will appear here.</p>`;

  const themeStorageKey = "hp-adminlte-theme";
  const selectedTheme = () => localStorage.getItem(themeStorageKey) || "light";
  const applyTheme = theme => {
    const resolved = theme === "system" ? (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : theme;
    document.documentElement.dataset.bsTheme = resolved;
    document.documentElement.dataset.theme = resolved;
    localStorage.setItem(themeStorageKey, theme);
    document.querySelectorAll("[data-hp-theme]").forEach(button => {
      const active = button.dataset.hpTheme === theme;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
  };

  const bootstrapClass = (nodes, ...classes) => nodes.forEach(node => node.classList.add(...classes));

  const investigationURL = value => {
    const query = value.trim();
    if (!query) return "";
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(query) || query.includes(":")) return `/investigate/ip/${encodeURIComponent(query)}`;
    if (/^[a-f\d]{32,64}$/i.test(query)) return `/payload-analysis/${encodeURIComponent(query)}`;
    if (/^as\d+$/i.test(query)) return `/events?asn=${encodeURIComponent(query.replace(/^as/i, ""))}`;
    if (query.startsWith("/")) return `/events?path=${encodeURIComponent(query)}`;
    if (/^[a-f\d]{8,31}$/i.test(query)) return `/sessions/${encodeURIComponent(query)}`;
    return `/events?q=${encodeURIComponent(query)}`;
  };

  const normalizeCards = root => {
    root.querySelectorAll(".card").forEach(card => {
      if (card.querySelector(":scope > .card-body")) return;
      const title = card.querySelector(":scope > h2");
      if (title) {
        const header = document.createElement("div");
        header.className = "card-header";
        title.className = "card-title";
        header.appendChild(title);
        card.prepend(header);
      }
	  const header = card.querySelector(":scope > .card-header");
	  if (header && !header.querySelector(".card-tools")) {
		const tools = document.createElement("div");
		tools.className = "card-tools";
		tools.innerHTML = `<button type="button" class="btn btn-tool" data-lte-toggle="card-collapse" title="Collapse"><i data-lte-icon="expand" class="bi bi-plus-lg"></i><i data-lte-icon="collapse" class="bi bi-dash-lg"></i></button><button type="button" class="btn btn-tool" data-lte-toggle="card-maximize" title="Maximize"><i data-lte-icon="maximize" class="bi bi-arrows-fullscreen"></i><i data-lte-icon="minimize" class="bi bi-fullscreen-exit"></i></button>`;
		header.appendChild(tools);
	  }
      const body = document.createElement("div");
      body.className = "card-body";
      [...card.children].filter(child => !child.classList.contains("card-header")).forEach(child => body.appendChild(child));
      card.appendChild(body);
    });

    root.querySelectorAll("table").forEach(table => {
      table.classList.add("table", "table-hover", "table-sm", "align-middle", "mb-0");
      if (!table.parentElement.classList.contains("table-responsive")) {
        const responsive = document.createElement("div");
        responsive.className = "table-responsive";
        table.before(responsive);
        responsive.appendChild(table);
      }
    });
  };

  const normalizeControls = root => {
    root.querySelectorAll(".dashboard-tabs").forEach(tabs => tabs.classList.add("nav", "nav-pills", "nav-fill", "mb-3"));
    const tabIcons = {live: "bi-broadcast", threats: "bi-globe-americas", behavior: "bi-person-lines-fill", evidence: "bi-fingerprint"};
    root.querySelectorAll(".dashboard-tab").forEach(tab => {
      tab.classList.add("nav-link");
      tab.querySelector("span")?.remove();
      if (!tab.querySelector("i")) tab.insertAdjacentHTML("afterbegin", `<i class="bi ${tabIcons[tab.dataset.dashboardTab] || "bi-circle"} me-2" aria-hidden="true"></i>`);
    });
    bootstrapClass(root.querySelectorAll(".filters"), "d-flex", "flex-wrap", "gap-2", "align-items-center", "mb-3");
    root.querySelectorAll("a.chip").forEach(chip => chip.classList.add("btn", "btn-sm", "btn-outline-secondary"));
    root.querySelectorAll("span.chip").forEach(chip => chip.classList.add("badge", "text-bg-secondary"));
    bootstrapClass(root.querySelectorAll("button.copy"), "btn", "btn-sm", "btn-outline-secondary");
    bootstrapClass(root.querySelectorAll("input.search"), "form-control", "form-control-sm");

    const sensorColors = {
      cowrie: "text-bg-primary", http: "text-bg-success", multipot: "text-bg-warning",
      dionaea: "text-bg-danger", conpot: "text-bg-info", tanner: "text-bg-secondary", suricata: "text-bg-dark",
    };
    root.querySelectorAll(".badge").forEach(badge => {
      const sensor = [...badge.classList].find(name => name.startsWith("b-"))?.slice(2);
      badge.classList.add(sensorColors[sensor] || "text-bg-secondary");
    });
    root.querySelectorAll(".section-link").forEach(link => link.classList.add("btn", "btn-sm", "btn-outline-primary"));
    root.querySelectorAll(".eventmeta > a.lnk, a.cc").forEach(link => link.classList.add("hp-meta-link"));
  };

  const enhanceTables = root => {
    root.querySelectorAll("table").forEach(table => {
      const headers = [...table.querySelectorAll("thead th")];
      if (!headers.length || table.dataset.hpEnhanced) return;
      table.dataset.hpEnhanced = "true";
      headers.forEach((header, column) => {
        header.style.cursor = "pointer";
        header.title = `${header.title ? header.title + ". " : ""}Select to sort this page by ${header.textContent.trim() || "column"}`;
        header.tabIndex = 0;
        let ascending = true;
        const sort = () => {
          const body = table.tBodies[0];
          if (!body) return;
          const rows = [...body.rows];
          rows.sort((a, b) => {
            const av = a.cells[column]?.innerText.trim() || "", bv = b.cells[column]?.innerText.trim() || "";
            const an = Number(av.replace(/[^\d.-]/g, "")), bn = Number(bv.replace(/[^\d.-]/g, ""));
            const compared = av && bv && Number.isFinite(an) && Number.isFinite(bn) ? an - bn : av.localeCompare(bv, undefined, {numeric: true, sensitivity: "base"});
            return ascending ? compared : -compared;
          });
          rows.forEach(row => body.appendChild(row));
          headers.forEach(h => h.removeAttribute("aria-sort"));
          header.setAttribute("aria-sort", ascending ? "ascending" : "descending");
          ascending = !ascending;
        };
        header.addEventListener("click", sort);
        header.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); sort(); } });
      });

      if (table.classList.contains("recent") && headers.length >= 5) {
        [...table.tBodies[0]?.rows || []].forEach(row => {
          const last = row.cells[row.cells.length - 1];
          if (!last || last.querySelector("details[data-hp-record]")) return;
          const record = Object.fromEntries(headers.map((header, i) => [header.textContent.trim() || `column_${i + 1}`, row.cells[i]?.innerText.trim() || ""]));
          const details = document.createElement("details");
          details.dataset.hpRecord = "";
          details.className = "mt-2";
          details.innerHTML = `<summary class="small text-secondary">Normalized row JSON</summary><pre class="code mt-2 mb-0"></pre>`;
          details.querySelector("pre").textContent = JSON.stringify(record, null, 2);
          last.appendChild(details);
        });
      }

      if (headers.length > 3) {
        const card = table.closest(".card"), header = card?.querySelector(":scope > .card-header");
        if (header && !header.querySelector("[data-hp-columns]")) {
          const picker = document.createElement("details");
          picker.dataset.hpColumns = "";
          picker.className = "ms-auto me-2 small";
          picker.innerHTML = `<summary class="btn btn-sm btn-tool" title="Choose visible columns"><i class="bi bi-layout-three-columns"></i></summary><div class="position-absolute end-0 bg-body border rounded shadow p-2" style="z-index:1080;min-width:180px"></div>`;
          const menu = picker.lastElementChild;
          headers.forEach((columnHeader, index) => {
            const label = document.createElement("label");
            label.className = "d-block text-nowrap";
            label.innerHTML = `<input class="form-check-input me-2" type="checkbox" checked> ${columnHeader.textContent.trim() || `Column ${index + 1}`}`;
            label.querySelector("input").addEventListener("change", event => {
              table.querySelectorAll("tr").forEach(row => { if (row.cells[index]) row.cells[index].hidden = !event.target.checked; });
            });
            menu.appendChild(label);
          });
          header.querySelector(".card-tools")?.before(picker);
        }
      }
    });
  };

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
    controls.className = "hp-lazy-controls d-flex align-items-center justify-content-center gap-2 py-3";
    controls.setAttribute("aria-live", "polite");
    controls.innerHTML = `<span class="small text-body-secondary"></span><button class="btn btn-sm btn-outline-secondary" type="button"><i class="bi bi-chevron-down me-1"></i>Load 25 more</button><span class="hp-lazy-sentinel" aria-hidden="true"></span>`;
    const anchor = table.closest(".table-responsive") || table;
    anchor.after(controls);
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
    controls.className = "hp-lazy-controls d-flex align-items-center justify-content-center gap-2 py-3";
    controls.setAttribute("aria-live", "polite");
    controls.innerHTML = `<span class="small text-body-secondary"></span><button class="btn btn-sm btn-outline-secondary" type="button"><i class="bi bi-chevron-down me-1"></i>Load 25 more</button><span class="hp-lazy-sentinel" aria-hidden="true"></span>`;
    const anchor = table.closest(".table-responsive") || table;
    anchor.after(controls);
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
    controls.className = "hp-lazy-controls d-flex align-items-center justify-content-center gap-2 py-3";
    controls.setAttribute("aria-live", "polite");
    controls.innerHTML = `<span class="small text-body-secondary"></span><button class="btn btn-sm btn-outline-secondary" type="button"><i class="bi bi-chevron-down me-1"></i>Load 25 more</button><span class="hp-lazy-sentinel" aria-hidden="true"></span>`;
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

  const showLiveToast = (message, href = "/events") => {
    let stack = document.querySelector("[data-hp-toast-stack]");
    if (!stack) { stack = document.createElement("div"); stack.dataset.hpToastStack = ""; stack.className = "toast-container position-fixed top-0 end-0 p-3"; stack.style.zIndex = 2000; document.body.appendChild(stack); }
    const toast = document.createElement("a");
    toast.href = href;
    toast.className = "alert alert-info shadow text-decoration-none d-block";
    toast.innerHTML = `<i class="bi bi-broadcast-pin me-2"></i>${message}`;
    stack.appendChild(toast);
    setTimeout(() => toast.remove(), 8000);
  };

  addEventListener("DOMContentLoaded", () => {
    const legacy = document.querySelector("body > .wrap");
    if (!legacy || document.querySelector(".app-wrapper")) return;

    document.addEventListener("click", event => {
      document.querySelectorAll("details.hp-open-in[open]").forEach(menu => {
        if (!menu.contains(event.target)) menu.removeAttribute("open");
      });
    });
    document.addEventListener("keydown", event => {
      if (event.key === "Escape") document.querySelectorAll("details.hp-open-in[open]").forEach(menu => menu.removeAttribute("open"));
    });

    document.querySelector(".appnav")?.remove();
    rememberCurrentInvestigation();
    const wrapper = document.createElement("div");
    wrapper.className = "app-wrapper hp-workspace-shell tw:min-h-screen tw:bg-hp-canvas tw:text-hp-ink dark:tw:bg-stone-950 dark:tw:text-stone-100";
    wrapper.innerHTML = `
      <nav class="app-header navbar navbar-expand bg-body" aria-label="Application toolbar">
        <div class="container-fluid">
          <ul class="navbar-nav"><li class="nav-item"><button class="nav-link" type="button" data-hp-sidebar-toggle aria-label="Toggle navigation"><i class="bi bi-list" aria-hidden="true"></i></button></li></ul>
          <span class="navbar-text fw-semibold ms-2">${pageName()}</span>
          <form class="d-none d-lg-flex ms-3" role="search" data-hp-investigate><div class="input-group input-group-sm"><span class="input-group-text"><i class="bi bi-search"></i></span><input class="form-control" type="search" placeholder="Investigate IP, hash, session, path…" aria-label="Investigate"><button class="btn btn-outline-secondary" type="submit">Open</button></div></form>
          <ul class="navbar-nav ms-auto align-items-center">
            <li class="nav-item d-none d-md-block"><a class="nav-link" href="/events?since=24h"><i class="bi bi-clock-history me-1"></i>Last 24 hours</a></li>
            <li class="nav-item d-none d-md-block"><a class="nav-link" href="/source-health"><i class="bi bi-activity me-1"></i>Pipeline health</a></li>
            <li class="nav-item"><a class="nav-link position-relative" href="/alerts" title="Open alerts"><i class="bi bi-bell"></i><span class="position-absolute top-0 start-100 translate-middle badge rounded-pill text-bg-danger d-none" data-hp-alert-count>0</span></a></li>
            <li class="nav-item"><span class="nav-link text-success" title="Dashboard refresh is active"><i class="bi bi-broadcast-pin me-1"></i><span class="d-none d-sm-inline">Live</span></span></li>
            <li class="nav-item"><div class="btn-group btn-group-sm ms-2" role="group" aria-label="Color theme">
              <button class="btn btn-outline-secondary" type="button" data-hp-theme="light" title="Use light theme"><i class="bi bi-sun-fill"></i><span class="visually-hidden">Light</span></button>
              <button class="btn btn-outline-secondary" type="button" data-hp-theme="dark" title="Use dark theme"><i class="bi bi-moon-stars-fill"></i><span class="visually-hidden">Dark</span></button>
              <button class="btn btn-outline-secondary" type="button" data-hp-theme="system" title="Follow system theme"><i class="bi bi-display"></i><span class="visually-hidden">Auto</span></button>
            </div></li>
          </ul>
        </div>
      </nav>
      <aside class="app-sidebar bg-body-secondary shadow" data-bs-theme="dark" aria-label="Primary navigation">
        <div class="sidebar-brand"><a href="/" class="brand-link"><i class="brand-image bi bi-shield-lock-fill" aria-hidden="true"></i><span class="brand-text fw-light">Honeypot Operations</span></a></div>
        <div class="sidebar-wrapper"><nav class="mt-2"><ul class="nav sidebar-menu flex-column" data-lte-toggle="treeview" role="menu" data-accordion="false">${navHTML()}</ul></nav></div>
      </aside>
      <main class="app-main">
        <div class="app-content-header"><div class="container-fluid" data-hp-page-header></div></div>
        <div class="app-content"><div class="container-fluid" data-hp-page-content></div></div>
      </main>
      <footer class="app-footer"><strong>Honeypot Operations</strong><span class="float-end d-none d-sm-inline">AdminLTE 4.1.0</span></footer>`;

    document.body.insertBefore(wrapper, legacy);
    const toolbar = wrapper.querySelector(".app-header");
    toolbar.className = "app-header hp-topbar navbar tw:flex tw:items-center tw:gap-3";
    toolbar.innerHTML = `
      <button class="hp-icon-button" type="button" data-hp-sidebar-toggle aria-label="Toggle navigation" title="Toggle navigation"><i class="bi bi-layout-sidebar-inset" aria-hidden="true"></i></button>
      <div class="hp-page-identity"><span>Honeypot operations</span><strong>${pageName()}</strong></div>
      <div class="hp-topbar-actions tw:ml-auto tw:flex tw:items-center tw:gap-1">
        <a class="hp-icon-button" href="/events?since=24h" title="Events from the last 24 hours"><i class="bi bi-clock-history" aria-hidden="true"></i><span class="visually-hidden">Last 24 hours</span></a>
        <a class="hp-icon-button" href="/source-health" title="Pipeline health"><i class="bi bi-activity" aria-hidden="true"></i><span class="visually-hidden">Pipeline health</span></a>
        <a class="hp-icon-button position-relative" href="/alerts" title="Open alerts"><i class="bi bi-bell" aria-hidden="true"></i><span class="position-absolute top-0 start-100 translate-middle badge rounded-pill text-bg-danger d-none" data-hp-alert-count>0</span></a>
        <span class="hp-live-state" title="Dashboard refresh is active"><span></span>Live</span>
      </div>`;

    const sidebar = wrapper.querySelector(".app-sidebar");
    sidebar.className = "app-sidebar hp-sidebar tw:flex tw:flex-col";
    sidebar.removeAttribute("data-bs-theme");
    sidebar.innerHTML = `
      <div class="hp-sidebar-head">
        <a href="/" class="hp-brand"><span class="hp-brand-mark"><i class="bi bi-shield-lock-fill" aria-hidden="true"></i></span><span><strong>XORE//HP</strong><small>Defensive operations</small></span></a>
      </div>
      <div class="hp-workspace-tabs" role="tablist" aria-label="Dashboard workspace">${workspaceTabsHTML()}</div>
      <button class="hp-new-investigation" type="button" data-hp-focus-investigation><i class="bi bi-plus-lg" aria-hidden="true"></i><span>New investigation</span><kbd>/</kbd></button>
      <div class="sidebar-wrapper">
        <nav aria-label="Dashboard sections"><ul class="nav sidebar-menu flex-column" role="menu">${navHTML()}</ul></nav>
        <section class="hp-recents" aria-labelledby="hp-recents-heading">
          <div class="hp-sidebar-label"><span id="hp-recents-heading">Recent investigations</span><button type="button" data-hp-clear-recents title="Clear recent investigations"><i class="bi bi-x-lg" aria-hidden="true"></i></button></div>
          <div data-hp-recents>${recentHTML()}</div>
        </section>
      </div>
      <div class="hp-sidebar-footer">
        <div class="hp-theme-switcher" role="group" aria-label="Color theme">
          <button type="button" data-hp-theme="light" title="Use light theme"><i class="bi bi-sun-fill"></i><span>Light</span></button>
          <button type="button" data-hp-theme="dark" title="Use dark theme"><i class="bi bi-moon-stars-fill"></i><span>Dark</span></button>
          <button type="button" data-hp-theme="system" title="Follow system theme"><i class="bi bi-display"></i><span>Auto</span></button>
        </div>
        <a class="hp-profile-row" href="/source-health"><span class="hp-avatar">XO</span><span><strong>Operations</strong><small>Private telemetry</small></span><i class="bi bi-chevron-right" aria-hidden="true"></i></a>
      </div>`;

    wrapper.querySelector(".app-footer")?.remove();
    wrapper.insertAdjacentHTML("beforeend", `
      <form class="hp-command-dock" role="search" data-hp-investigate>
        <label class="visually-hidden" for="hp-investigation-query">Investigate an indicator</label>
        <textarea id="hp-investigation-query" rows="1" placeholder="Investigate an IP, ASN, payload hash, session, HTTP path or free textâ€¦" aria-label="Investigate an indicator"></textarea>
        <div class="hp-command-actions">
          <span><i class="bi bi-search" aria-hidden="true"></i> Investigation command</span>
          <span class="hp-command-hint">Enter to open</span>
          <button type="submit" title="Open investigation"><i class="bi bi-arrow-up" aria-hidden="true"></i><span class="visually-hidden">Open investigation</span></button>
        </div>
      </form>`);

    const headerTarget = wrapper.querySelector("[data-hp-page-header]");
    const pageContent = wrapper.querySelector("[data-hp-page-content]");
    const refreshOverviewPreservingMap = source => {
      const currentLive = pageContent.querySelector("#panel-live");
      const incomingLive = source.querySelector("#panel-live");
      const mapCard = currentLive?.querySelector(":scope > [data-attack-map-card]");
      const incomingMap = incomingLive?.querySelector(":scope > [data-attack-map-card]");
      if (!currentLive || !incomingLive || !mapCard || !incomingMap) return false;

      const pageHeader = source.querySelector(":scope > header");
      headerTarget.replaceChildren(...(pageHeader ? [pageHeader] : []));
      source.querySelector(":scope > footer")?.remove();

      const childKey = element => {
        if (element.id) return `#${element.id}`;
        if (element.matches(".row.g-3")) return "overview-kpis";
        if (element.matches(".dashboard-tabs")) return "overview-tabs";
        return "";
      };
      [...source.children].forEach(incoming => {
        if (incoming === incomingLive) return;
        const key = childKey(incoming);
        if (!key) return;
        const current = key.startsWith("#")
          ? pageContent.querySelector(`:scope > ${key}`)
          : pageContent.querySelector(key === "overview-kpis" ? ":scope > .row.g-3" : ":scope > .dashboard-tabs");
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
      if (options.preserveMap && refreshOverviewPreservingMap(source)) {
        normalizeControls(pageContent);
        normalizeCards(pageContent);
        enhanceTables(pageContent);
        initLazyViews(pageContent);
        return;
      }
      const pageHeader = source.querySelector(":scope > header");
      headerTarget.replaceChildren(...(pageHeader ? [pageHeader] : []));
      source.querySelector(":scope > footer")?.remove();
      pageContent.replaceChildren(...source.children);
      source.remove();
      normalizeControls(pageContent);
      normalizeCards(pageContent);
      enhanceTables(pageContent);
      initLazyViews(pageContent);
    };
    window.replaceHoneypotPage = mountPage;
    mountPage(legacy);
    document.body.classList.add("layout-fixed", "sidebar-expand-lg", "bg-body-tertiary", "hp-shell-ready");
    wrapper.querySelectorAll("[data-hp-theme]").forEach(button => button.addEventListener("click", () => applyTheme(button.dataset.hpTheme)));
    applyTheme(selectedTheme());

    const setWorkspace = name => {
      wrapper.querySelectorAll("[data-hp-workspace-group]").forEach(item => { item.hidden = item.dataset.hpWorkspaceGroup !== name; });
      wrapper.querySelectorAll("[data-hp-workspace]").forEach(tab => {
        const active = tab.dataset.hpWorkspace === name;
        tab.classList.toggle("active", active);
        tab.setAttribute("aria-selected", String(active));
      });
    };
    wrapper.querySelectorAll("[data-hp-workspace]").forEach(tab => tab.addEventListener("click", () => setWorkspace(tab.dataset.hpWorkspace)));
    setWorkspace(activeWorkspace());

    const search = wrapper.querySelector("[data-hp-investigate]");
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
    search?.addEventListener("submit", event => {
      event.preventDefault();
      const target = investigationURL(searchInput.value);
      if (target) location.assign(target);
    });
    wrapper.querySelector("[data-hp-focus-investigation]")?.addEventListener("click", () => searchInput?.focus());
    wrapper.querySelector("[data-hp-clear-recents]")?.addEventListener("click", () => {
      localStorage.removeItem(recentStorageKey);
      wrapper.querySelector("[data-hp-recents]").innerHTML = recentHTML();
    });
    addEventListener("keydown", event => {
      if (event.key === "/" && !event.ctrlKey && !event.metaKey && !event.altKey && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "")) {
        event.preventDefault();
        searchInput?.focus();
      }
    });
	const refreshAlertCount = async () => {
	  try {
		const records = await (await fetch("/api/alerts", {cache: "no-store"})).json();
		const count = records.filter(record => !record.Acknowledged).length;
		const badge = wrapper.querySelector("[data-hp-alert-count]");
		badge.textContent = count > 99 ? "99+" : String(count);
		badge.classList.toggle("d-none", count === 0);
	  } catch {}
	};
	refreshAlertCount();
	setInterval(refreshAlertCount, 60000);

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

    const sidebarToggle = wrapper.querySelector("[data-hp-sidebar-toggle]");
    sidebarToggle.addEventListener("click", event => {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      const mobile = innerWidth <= 991.98;
      if (mobile) {
        const opening = !document.body.classList.contains("sidebar-open");
        document.body.classList.toggle("sidebar-open", opening);
        document.body.classList.toggle("sidebar-collapse", !opening);
      } else {
        document.body.classList.toggle("sidebar-collapse");
      }
    });
    wrapper.querySelectorAll(".sidebar-menu .nav-link").forEach(link => link.addEventListener("click", () => {
      if (innerWidth <= 991.98) {
        document.body.classList.remove("sidebar-open");
        document.body.classList.add("sidebar-collapse");
      }
    }));

    const systemQuery = matchMedia("(prefers-color-scheme: dark)");
    systemQuery.addEventListener?.("change", () => { if (selectedTheme() === "system") applyTheme("system"); });
  });
})();
