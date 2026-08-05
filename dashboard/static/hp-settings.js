/* Dashboard settings — centered modal controller (framework-free).
 *
 * There is no standalone /settings page: the account menu's "Dashboard
 * settings" entry (or a #settings hash) opens the settings UI as a centered
 * application-managed modal on top of the current page, per the theme modal
 * contract (MODALS.md). The markup is fetched once per session from
 * /api/settings/modal — a server-rendered fragment whose admin panes exist
 * only for live-introspected admins — and injected into #hp-dash-settings-root.
 * Escape, the backdrop, and the close button dismiss the modal; the nested
 * save/reset confirmation is a native dialog descendant that owns Escape and
 * Tab while it is open.
 *
 * Data flow:
 *   GET   /api/settings/me                → {preferences} + ETag
 *   PATCH /api/settings/me/preferences    (If-Match, JSON patch, same-origin)
 *   POST  /api/settings/me/preferences/reset
 * Identity comes from /api/whoami; credential mutation stays on the auth
 * origin (account pane links out, never edits).
 */
(() => {
  "use strict";

  const trigger = document.querySelector("[data-hp-account-dashboard-settings]");
  const host = document.getElementById("hp-dash-settings-root");
  if (!trigger || !host) return;

  let ready = false;
  let loading = null;
  let isOpen = false;
  let restoreFocus = null;
  let modal = null;
  let backdrop = null;

  function announceLoadFailure() {
    const status = document.getElementById("hp-flash");
    if (!status) return;
    status.textContent = "Settings could not be loaded — retry in a moment.";
    status.dataset.state = "error";
    status.classList.add("open");
    window.setTimeout(() => status.classList.remove("open"), 5000);
  }

  function ensureLoaded() {
    if (ready) return Promise.resolve(true);
    if (!loading) {
      loading = fetch("/api/settings/modal", { cache: "no-store" })
        .then(response => {
          if (!response.ok) throw new Error(String(response.status));
          return response.text();
        })
        .then(html => {
          host.innerHTML = html;
          modal = document.getElementById("hp-settings");
          backdrop = document.getElementById("hp-dash-settings-backdrop");
          initController(host);
          const closeButton = modal.querySelector("[data-hp-settings-close]");
          if (closeButton) closeButton.addEventListener("click", closeSettings);
          backdrop.addEventListener("click", closeSettings);
          ready = true;
        })
        .catch(() => {
          loading = null;
          announceLoadFailure();
        });
    }
    return loading.then(() => ready);
  }

  function openSettings() {
    ensureLoaded().then(ok => {
      if (!ok || isOpen) return;
      isOpen = true;
      restoreFocus = document.activeElement;
      if (window.HoneypotAccountMenu) window.HoneypotAccountMenu.close();
      backdrop.inert = false;
      backdrop.setAttribute("aria-hidden", "false");
      backdrop.classList.add("open");
      modal.inert = false;
      modal.setAttribute("aria-hidden", "false");
      modal.classList.add("open");
      const closeButton = modal.querySelector("[data-hp-settings-close]");
      if (closeButton) closeButton.focus();
    });
  }

  function closeSettings() {
    if (!isOpen) return;
    isOpen = false;
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    modal.inert = true;
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
    backdrop.inert = true;
    if (restoreFocus && restoreFocus.isConnected) restoreFocus.focus();
    restoreFocus = null;
  }

  trigger.addEventListener("click", event => {
    event.preventDefault();
    openSettings();
  });
  // #settings keeps old /settings bookmarks meaningful: any dashboard page
  // loaded with the hash opens the modal directly.
  if (window.location.hash === "#settings") openSettings();
  window.addEventListener("hashchange", () => {
    if (window.location.hash === "#settings") openSettings();
  });

  /* Keyboard contract: while the nested native confirmation is open it owns
     Escape and Tab; otherwise Escape closes the modal and Tab cycles inside
     it. */
  document.addEventListener("keydown", event => {
    if (!isOpen || !modal) return;
    const confirm = modal.querySelector("#hp-settings-confirm");
    if (confirm && confirm.open) return;
    // The shared destructive confirmation can also sit above this modal; it
    // owns Escape while open, so the settings surface must not close too.
    if (window.HoneypotModals?.isOpen()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeSettings();
      return;
    }
    if (event.key === "Tab") {
      const controls = Array.from(modal.querySelectorAll(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )).filter(el => !el.hidden && el.offsetParent !== null);
      if (!controls.length) return;
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && (document.activeElement === first || !modal.contains(document.activeElement))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
  });

  /* ================= modal internals =================
   * Everything below runs once, after the fragment is injected. All queries
   * are scoped to the injected root so the host page can never collide with
   * the settings DOM. */
  function initController(root) {
    const q = selector => root.querySelector(selector);
    const qa = selector => Array.from(root.querySelectorAll(selector));

    /* ---- element handles ---- */
    const title = q("#hp-dash-settings-title");
    const paneDesc = q("[data-hp-pane-desc]");
    const status = q("[data-hp-settings-status]");
    const search = q("[data-hp-settings-search]");
    const navItems = qa("[data-hp-pane-nav]");
    const panes = qa("[data-hp-pane]");
    const saveButtons = qa("[data-hp-save]");
    const resetAll = q("[data-hp-reset-all]");
    const confirmDialog = q("#hp-settings-confirm");
    const confirmTitle = q("#hp-settings-confirm-title");
    const confirmDesc = q("#hp-settings-confirm-desc");
    const confirmWarning = q("#hp-settings-confirm-warning");
    const confirmCancel = confirmDialog && confirmDialog.querySelector("[data-hp-confirm-cancel]");
    const confirmAction = confirmDialog && confirmDialog.querySelector("[data-hp-confirm-action]");

    const PANE_META = {
      account:    { title: "Account",                desc: "Your identity as provided by the auth service. Credentials are managed there, never here." },
      appearance: { title: "Appearance",             desc: "Theme, density, motion, and readability of the dashboard." },
      navigation: { title: "Navigation & tables",    desc: "Where you land, how the sidebar behaves, and how tables render." },
      time:       { title: "Time & live data",       desc: "Timezone, clock formats, refresh cadence, and notifications." },
      map:        { title: "Map & investigation",    desc: "Basemap, clustering, and drill-down defaults for investigations." },
      branding:   { title: "Branding & text",        desc: "Product labels, help links, notices, and footer copy. Plain text; https links only." },
      "report-presets": { title: "Report Studio presets", desc: "Names and descriptions shown for each report template. Structural fields (theme, window, elements) are report logic, not editable here." },
      behavior:   { title: "Dashboard behavior",     desc: "Safe bounded defaults and feature visibility for every user." },
      honeypot:   { title: "Honeypot operations",    desc: "Staged operational thresholds. Saving never restarts anything — apply with an operator-run restart." },
      users:      { title: "Users",                  desc: "Read-only projection of dashboard activity. Accounts are managed in the auth service." },
      services:   { title: "Services",                desc: "Live container status for sensors, probes, and analysis workers, with start/stop/restart and logs." },
      elasticsearch: { title: "Elasticsearch history", desc: "Raw query_string search across every indexed honeypot and Suricata document." },
      "dead-letters": { title: "Ingest dead letters", desc: "Documents Elasticsearch rejected, with their original error and field shape." },
      history:    { title: "Configuration history",  desc: "Retained configuration revisions with rollback." },
      audit:      { title: "Audit log",              desc: "Settings changes with actor, fields, and result." }
    };
    const ADMIN_PANES = ["branding", "report-presets", "behavior", "honeypot", "users", "services", "elasticsearch", "dead-letters", "history", "audit"];
    const isAdmin = navItems.some(nav => ADMIN_PANES.includes(nav.dataset.hpPaneNav));

    /* ---- state ----
       #156: the ETag/prefs fields are read from and written back to
       window.HpPreferences (hp-app.js's own preferences client, part of the
       same page shell) instead of being tracked independently here. hp-app.js
       writes preferences too (theme toggle, one-time localStorage
       migration); an independent copy here would fall out of date the
       moment either of those fired, and the next save would be rejected as
       a false conflict even though nothing was actually edited concurrently
       by another session. */
    const shared = () => window.HpPreferences || (window.HpPreferences = {ready: false, etag: "", prefs: null});
    const state = { snapshot: {}, dirty: {}, confirmCallback: null, confirmInitiator: null };
    Object.defineProperty(state, "etag", {
      get() { return shared().etag; },
      set(value) { shared().etag = value; },
    });
    Object.defineProperty(state, "prefs", {
      get() { return shared().prefs; },
      set(value) { shared().prefs = value; shared().ready = true; },
    });

    /* ---- control helpers (three control types, keyed by data-pref) ---- */
    const controls = qa("[data-pref]");

    function readControl(el) {
      if (el.classList.contains("segmented")) {
        const active = el.querySelector("[data-value].active, [data-value][aria-pressed='true']");
        return active ? active.dataset.value : "";
      }
      if (el.type === "checkbox") return el.checked;
      if (el.tagName === "SELECT") return el.value;
      return el.value.trim();
    }

    function writeControl(el, value) {
      if (el.classList.contains("segmented")) {
        el.querySelectorAll("[data-value]").forEach(btn => {
          const on = btn.dataset.value === String(value);
          btn.classList.toggle("active", on);
          btn.setAttribute("aria-pressed", on ? "true" : "false");
        });
        return;
      }
      if (el.type === "checkbox") { el.checked = Boolean(value); return; }
      el.value = value == null ? "" : String(value);
    }

    function controlValue(el) {
      const name = el.dataset.pref;
      const raw = readControl(el);
      if (el.type === "checkbox") return raw;
      if (name === "rows_per_page" || name === "refresh_interval_seconds") {
        const n = parseInt(raw, 10);
        return Number.isNaN(n) ? raw : n;
      }
      return raw;
    }

    function paneOf(el) { return (el.closest("[data-hp-pane]") || {}).dataset ? el.closest("[data-hp-pane]").dataset.hpPane : ""; }

    /* ---- dirty tracking ---- */
    function computeDirty() {
      state.dirty = {};
      if (state.snapshot) {
        controls.forEach(el => {
          const name = el.dataset.pref;
          const pane = paneOf(el);
          if (!pane) return;
          const current = controlValue(el);
          const original = state.snapshot[name];
          if (JSON.stringify(current) !== JSON.stringify(original)) state.dirty[pane] = true;
        });
      }
      if (isAdmin && cfg.loaded) computeCfgDirty();
      saveButtons.forEach(btn => { btn.disabled = !state.dirty[btn.dataset.hpSave]; });
      navItems.forEach(nav => nav.classList.toggle("is-dirty", Boolean(state.dirty[nav.dataset.hpPaneNav])));
    }

    function anyDirty() { return Object.keys(state.dirty).some(pane => state.dirty[pane]); }

    window.addEventListener("beforeunload", event => {
      if (!anyDirty()) return;
      event.preventDefault();
      event.returnValue = "";
    });

    /* ---- status line ---- */
    let statusTimer = null;
    function setStatus(text, kind) {
      status.textContent = text;
      status.classList.toggle("is-error", kind === "error");
      status.classList.toggle("is-ok", kind === "ok");
      if (statusTimer) clearTimeout(statusTimer);
      if (kind === "ok") statusTimer = setTimeout(() => { status.textContent = ""; status.classList.remove("is-ok"); }, 5000);
    }

    /* ---- panes ---- */
    function activePaneFromNav() {
      const active = navItems.find(n => n.classList.contains("active"));
      return active ? active.dataset.hpPaneNav : "account";
    }

    function showPane(name) {
      // Unknown names — and admin panes absent for non-admins — fall back.
      if (!PANE_META[name] || !panes.some(p => p.dataset.hpPane === name)) name = "account";
      panes.forEach(p => { p.hidden = p.dataset.hpPane !== name; });
      navItems.forEach(nav => nav.classList.toggle("active", nav.dataset.hpPaneNav === name));
      title.textContent = PANE_META[name].title;
      paneDesc.textContent = PANE_META[name].desc;
      if (search) { search.value = ""; }
      clearSearch();
      if (isAdmin) {
        if (name === "branding" || name === "behavior" || name === "honeypot") loadConfig();
        else if (name === "users") loadUsers();
        else if (name === "services") loadServices();
        else if (name === "elasticsearch") { loadEsStorageStats(); loadElasticsearchHistory(); }
        else if (name === "dead-letters") loadDeadLetters();
        else if (name === "history") loadHistory();
        else if (name === "audit") loadAudit();
      }
    }

    navItems.forEach(nav => nav.addEventListener("click", () => showPane(nav.dataset.hpPaneNav)));

    /* ---- search: empty query = pane mode; non-empty = filter across all panes ---- */
    function clearSearch() {
      panes.forEach(p => { p.hidden = p.dataset.hpPane !== activePaneFromNav(); });
      qa(".hp-field").forEach(f => { f.hidden = false; });
      navItems.forEach(n => { n.hidden = false; });
    }
    if (search) {
      search.addEventListener("input", () => {
        const query = search.value.trim().toLowerCase();
        if (!query) { clearSearch(); return; }
        panes.forEach(p => {
          let visible = 0;
          p.querySelectorAll(".hp-field").forEach(field => {
            const hay = ((field.dataset.hpSearch || "") + " " + field.textContent).toLowerCase();
            const match = hay.includes(query);
            field.hidden = !match;
            if (match) visible++;
          });
          p.hidden = visible === 0;
        });
        navItems.forEach(n => {
          const pane = panes.find(p => p.dataset.hpPane === n.dataset.hpPaneNav);
          n.hidden = !pane || pane.hidden;
        });
      });
      search.addEventListener("keydown", event => {
        if (event.key === "Escape") { search.value = ""; clearSearch(); event.stopPropagation(); }
      });
    }

    /* ---- nested confirmation (a native dialog descendant of the modal) ---- */
    function openConfirm({ titleText, descText, warningText, actionLabel, danger, initiator, onConfirm }) {
      if (!confirmDialog) { onConfirm(); return; }
      state.confirmCallback = onConfirm;
      state.confirmInitiator = initiator || null;
      confirmTitle.textContent = titleText;
      confirmDesc.textContent = descText;
      confirmWarning.hidden = !warningText;
      confirmWarning.textContent = warningText || "";
      confirmAction.textContent = actionLabel;
      confirmAction.classList.toggle("btn-danger", Boolean(danger));
      confirmAction.classList.toggle("btn-primary", !danger);
      try { confirmDialog.showModal(); } catch { /* already open */ }
      confirmAction.focus();
    }

    function closeConfirm(refocus = true) {
      state.confirmCallback = null;
      if (confirmDialog && confirmDialog.open) confirmDialog.close();
      if (refocus && state.confirmInitiator) state.confirmInitiator.focus();
      state.confirmInitiator = null;
    }

    if (confirmDialog) {
      confirmCancel.addEventListener("click", () => closeConfirm());
      confirmAction.addEventListener("click", () => {
        // Execute exactly once: clear the callback before running it.
        const callback = state.confirmCallback;
        state.confirmCallback = null;
        closeConfirm(false);
        if (callback) callback();
        if (state.confirmInitiator) { state.confirmInitiator.focus(); state.confirmInitiator = null; }
      });
      // Native Esc on the confirm closes ONLY the confirm (modal stays open).
      confirmDialog.addEventListener("close", () => {
        if (state.confirmCallback) { // closed via Escape, not via the action
          state.confirmCallback = null;
          if (state.confirmInitiator) { state.confirmInitiator.focus(); state.confirmInitiator = null; }
        }
      });
      // Enter confirms unless focus is on Cancel.
      confirmDialog.addEventListener("keydown", event => {
        if (event.key === "Enter" && document.activeElement !== confirmCancel) {
          event.preventDefault();
          confirmAction.click();
        }
      });
    }

    /* ---- API ---- */
    async function apiOnce(path, options) {
      const response = await fetch(path, {
        cache: "no-store",
        ...options,
        headers: { Accept: "application/json", ...(options.headers || {}) }
      });
      if (!response.ok) {
        const error = new Error(await response.text().catch(() => response.statusText));
        error.status = response.status;
        throw error;
      }
      const etag = response.headers.get("ETag") || "";
      const body = await response.json();
      return { body, etag };
    }

    // #212: `docker compose up -d dashboard` recreates the container --
    // there is a real several-to-tens-of-seconds window with no listener at
    // all, which Cloudflare/Traefik surface as a 502/503/504 whose raw JSON
    // body used to get dumped straight into the status line. GETs are safe
    // to retry blind; a single retry after the gap has historically closed
    // clears most of these without the caller ever seeing an error. Writes
    // are never retried here -- a blind retry on a POST/PATCH risks a
    // double-write if the first attempt actually landed.
    async function api(path, options = {}) {
      const method = (options.method || "GET").toUpperCase();
      try {
        return await apiOnce(path, options);
      } catch (error) {
        if (method !== "GET" || ![502, 503, 504].includes(error.status)) throw error;
        await new Promise(resolve => setTimeout(resolve, 4000));
        try {
          return await apiOnce(path, options);
        } catch (retryError) {
          if (![502, 503, 504].includes(retryError.status)) throw retryError;
          const friendly = new Error("the server is temporarily unavailable, possibly redeploying — try again in a moment");
          friendly.status = retryError.status;
          throw friendly;
        }
      }
    }

    async function reloadPreferences(note) {
      const { body, etag } = await api("/api/settings/me");
      state.etag = etag;
      state.prefs = body.preferences || {};
      state.snapshot = { ...state.prefs };
      controls.forEach(el => writeControl(el, state.prefs[el.dataset.pref]));
      computeDirty();
      if (note) setStatus(note, "ok");
    }

    function saveError(error) {
      if (error.status === 409) {
        reloadPreferences().then(() => setStatus("Preferences changed in another session — reloaded latest values.", "error"));
        return;
      }
      if (error.status === 422) { setStatus("Not saved: " + error.message.trim(), "error"); return; }
      if (error.status === 429) { setStatus("Too many saves in a short time — wait a moment and retry.", "error"); return; }
      if (error.status === 401 || error.status === 403) { setStatus("Your session no longer permits saving — reload the page.", "error"); return; }
      setStatus("Preferences could not be saved — " + error.message.trim(), "error");
    }

    /* Preference side effects that other dashboard pages read from
       localStorage: keep the mirrors in sync immediately on save. */
    function applySideEffects(prefs) {
      try {
        if (prefs.theme === "light" || prefs.theme === "dark") {
          document.documentElement.dataset.theme = prefs.theme;
          localStorage.setItem("hp-theme", prefs.theme);
        } else if (prefs.theme === "system") {
          document.documentElement.removeAttribute("data-theme");
          localStorage.removeItem("hp-theme");
        }
        if (prefs.collapsed_sidebar) localStorage.setItem("hp-sidebar-collapsed", "1");
        else localStorage.removeItem("hp-sidebar-collapsed");
      } catch { /* storage may be unavailable */ }
      // Timezone/clock format (#346): without this, a saved change to
      // either only takes effect on the next full page load (whenever
      // hp-app.js's own DOMContentLoaded syncPrefs() happens to run), same
      // as theme/sidebar above already apply instantly rather than making
      // the operator reload to see their own save take effect.
      window.HpPreferences?.applyTimeDisplay?.(prefs.timezone, prefs.clock);
    }

    /* #479: admin config side effects other pages' DOM depends on -- same
       "apply instantly, don't make the operator reload to see their own
       save take effect" rule applySideEffects above already applies to user
       preferences. Currently only the ML/LLM nav link (#181's
       behavior.show_ml_panels, the concrete example the issue reported) has
       a known DOM effect; any future config field that gates a nav item the
       same way can reuse the same data-hp-behavior-nav marker convention. */
    function applyCfgSideEffects(config) {
      const showMLPanels = Boolean(config?.behavior?.show_ml_panels);
      qa('[data-hp-behavior-nav="show_ml_panels"]').forEach(el => { el.hidden = !showMLPanels; });
    }

    /* ---- save flow ---- */
    function collectPatch(pane) {
      const patch = {};
      controls.forEach(el => {
        if (paneOf(el) !== pane) return;
        const name = el.dataset.pref;
        const current = controlValue(el);
        if (JSON.stringify(current) !== JSON.stringify(state.snapshot[name])) patch[name] = current;
      });
      return patch;
    }

    function requestSave(pane, initiator) {
      const patch = collectPatch(pane);
      const fields = Object.keys(patch);
      if (!fields.length) return;
      openConfirm({
        titleText: "Save preferences?",
        descText: "Apply these changes: " + fields.join(", ") + ".",
        actionLabel: "Save preferences",
        initiator,
        onConfirm: async () => {
          try {
            const { body, etag } = await api("/api/settings/me/preferences", {
              method: "PATCH",
              headers: { "Content-Type": "application/json", "If-Match": state.etag },
              body: JSON.stringify(patch)
            });
            state.etag = etag;
            state.prefs = body.preferences || {};
            state.snapshot = { ...state.prefs };
            controls.forEach(el => writeControl(el, state.prefs[el.dataset.pref]));
            computeDirty();
            applySideEffects(state.prefs);
            setStatus("Preferences saved.", "ok");
          } catch (error) { saveError(error); }
        }
      });
    }

    saveButtons.forEach(btn => btn.addEventListener("click", () => requestSave(btn.dataset.hpSave, btn)));

    /* Enter inside a field opens the same confirmation as its pane's Save. */
    controls.forEach(el => {
      el.addEventListener("keydown", event => {
        if (event.key !== "Enter") return;
        if (el.tagName === "SELECT") return; // Enter opens the native picker
        const pane = paneOf(el);
        if (!pane || !state.dirty[pane]) return;
        event.preventDefault();
        requestSave(pane, el);
      });
      el.addEventListener("change", computeDirty);
      if (el.tagName === "INPUT" && el.type !== "checkbox") el.addEventListener("input", computeDirty);
    });

    /* Segmented buttons behave like radio groups. */
    qa(".segmented[data-pref]").forEach(group => {
      group.querySelectorAll("[data-value]").forEach(btn => {
        btn.addEventListener("click", () => {
          writeControl(group, btn.dataset.value);
          computeDirty();
        });
      });
    });

    /* ---- reset all ---- */
    if (resetAll) {
      resetAll.addEventListener("click", () => {
        openConfirm({
          titleText: "Reset all preferences?",
          descText: "Every preference returns to its default. This cannot be undone.",
          warningText: "This resets appearance, navigation, time, and map preferences in one step.",
          actionLabel: "Reset everything",
          danger: true,
          initiator: resetAll,
          onConfirm: async () => {
            try {
              const { body, etag } = await api("/api/settings/me/preferences/reset", {
                method: "POST",
                headers: { "If-Match": state.etag }
              });
              state.etag = etag;
              state.prefs = body.preferences || {};
              state.snapshot = { ...state.prefs };
              controls.forEach(el => writeControl(el, state.prefs[el.dataset.pref]));
              computeDirty();
              applySideEffects(state.prefs);
              setStatus("All preferences reset to defaults.", "ok");
            } catch (error) { saveError(error); }
          }
        });
      });
    }

    /* ---- identity (read-only; credentials live on the auth origin) ---- */
    async function loadIdentity() {
      const nameEl = q("[data-hp-acct-name]");
      const subjectEl = q("[data-hp-acct-subject]");
      const roleEl = q("[data-hp-acct-role]");
      const capsEl = q("[data-hp-acct-caps]");
      const linkEl = q("[data-hp-acct-link]");
      const logoutEl = q("[data-hp-acct-logout]");
      try {
        const response = await fetch("/api/whoami", { cache: "no-store" });
        if (!response.ok) throw new Error(String(response.status));
        const identity = await response.json();
        const display = identity.display_name || identity.username || "Unknown user";
        nameEl.textContent = display;
        subjectEl.textContent = identity.subject || "";
        roleEl.textContent = identity.role || "user";
        capsEl.textContent = "";
        (identity.capabilities || []).forEach(cap => {
          const badge = document.createElement("span");
          badge.className = "badge badge--muted";
          badge.textContent = cap;
          capsEl.appendChild(badge);
        });
        const accountURL = typeof identity.auth_account_url === "string" ? identity.auth_account_url.trim() : "";
        if (accountURL) {
          try {
            const base = new URL(accountURL);
            linkEl.href = accountURL;
            logoutEl.href = base.origin + "/_auth/logout";
            linkEl.hidden = false;
            logoutEl.hidden = false;
            // Stable deep links into the auth app's panes (Milestone F): the
            // auth origin owns every credential mutation; the dashboard only
            // ever links there.
            qa("[data-hp-acct-deep]").forEach(a => {
              const deep = new URL(accountURL);
              deep.searchParams.set("pane", a.dataset.hpAcctDeep);
              a.href = deep.toString();
              a.hidden = false;
            });
          } catch { linkEl.hidden = true; logoutEl.hidden = true; }
        } else { linkEl.hidden = true; logoutEl.hidden = true; }
      } catch {
        nameEl.textContent = "Identity unavailable";
        subjectEl.textContent = "";
      }
    }

    /* ================= administration (Milestone E) =================
     * Everything below only runs when the server rendered the admin panes
     * (live-introspected admin role); the markup is absent otherwise. Config
     * edits go through the validate preview → confirm → PATCH flow, honeypot
     * fields pinned by the deployment environment are disabled with their
     * source shown, and rollback restores a retained revision as a new one. */

    const cfgControls = isAdmin ? qa("[data-cfg]") : [];
    const cfgSaveButtons = isAdmin ? qa("[data-hp-cfg-save]") : [];
    const cfg = { loaded: false, loading: false, etag: "", snapshot: {}, sources: {}, pinned: {} };

    function flattenConfig(obj, prefix, out) {
      Object.keys(obj || {}).forEach(key => {
        const value = obj[key];
        const dotted = prefix ? prefix + "." + key : key;
        if (value && typeof value === "object" && !Array.isArray(value)) flattenConfig(value, dotted, out);
        else out[dotted] = value;
      });
      return out;
    }

    function readCfgControl(el) {
      if (el.type === "checkbox") return el.checked;
      const kind = el.dataset.cfgKind || "string";
      const raw = el.value.trim();
      if (kind === "int" || kind === "int64") {
        const n = parseInt(raw, 10);
        return Number.isNaN(n) ? raw : n;
      }
      if (kind === "ints") {
        if (!raw) return [];
        return raw.split(",").map(part => {
          const n = parseInt(part.trim(), 10);
          return Number.isNaN(n) ? part.trim() : n;
        });
      }
      if (kind === "float") {
        const n = parseFloat(raw);
        return Number.isNaN(n) ? raw : n;
      }
      return raw;
    }

    function writeCfgControl(el, value) {
      if (el.type === "checkbox") { el.checked = Boolean(value); return; }
      if (Array.isArray(value)) { el.value = value.join(", "); return; }
      el.value = value == null ? "" : String(value);
    }

    // computeCfgDirty adds admin-pane dirtiness into state.dirty; it is called
    // from computeDirty (which owns the reset) and never runs standalone.
    function computeCfgDirty() {
      cfgControls.forEach(el => {
        const pane = paneOf(el);
        if (!pane || el.disabled) return;
        const current = readCfgControl(el);
        const original = cfg.snapshot[el.dataset.cfg];
        if (JSON.stringify(current) !== JSON.stringify(original)) state.dirty[pane] = true;
      });
      cfgSaveButtons.forEach(btn => { btn.disabled = !state.dirty[btn.dataset.hpCfgSave]; });
    }

    function applyCfgToControls() {
      cfgControls.forEach(el => {
        writeCfgControl(el, cfg.snapshot[el.dataset.cfg]);
        const pinned = cfg.sources[el.dataset.cfg] === "environment";
        el.disabled = pinned;
      });
      qa("[data-cfg-source]").forEach(badge => {
        const field = badge.dataset.cfgSource;
        const source = cfg.sources[field] || "persisted";
        if (source === "environment") {
          const envValue = cfg.pinned[field.replace(/^honeypot\./, "")];
          badge.innerHTML = "active: <strong></strong> (environment) — pinned; the staged value applies only if the pin is removed";
          badge.querySelector("strong").textContent = envValue != null ? String(envValue) : "";
        } else if (source === "staged") {
          badge.textContent = "staged — applies on the next service restart";
        } else if (source === "compiled") {
          badge.textContent = "compiled default — the configuration store is unavailable";
        } else {
          badge.textContent = "persisted";
        }
      });
    }

    async function loadConfig() {
      if (!isAdmin || cfg.loading) return;
      cfg.loading = true;
      try {
        const { body, etag } = await api("/api/settings/config");
        cfg.etag = etag;
        cfg.snapshot = flattenConfig(body.config, "", {});
        cfg.sources = body.sources || {};
        cfg.pinned = body.pinned_environment || {};
        cfg.loaded = true;
        applyCfgToControls();
        applyCfgSideEffects(body.config);
        computeDirty();
      } catch (error) {
        setStatus("Configuration could not be loaded — " + error.message.trim(), "error");
      } finally { cfg.loading = false; }
    }

    function collectCfgPatch(pane) {
      const patch = {};
      cfgControls.forEach(el => {
        if (paneOf(el) !== pane || el.disabled) return;
        const dotted = el.dataset.cfg;
        const current = readCfgControl(el);
        if (JSON.stringify(current) === JSON.stringify(cfg.snapshot[dotted])) return;
        const [namespace, field] = dotted.split(".");
        if (!patch[namespace]) patch[namespace] = {};
        patch[namespace][field] = current;
      });
      return patch;
    }

    function requestCfgSave(pane, initiator) {
      const patch = collectCfgPatch(pane);
      if (!Object.keys(patch).length) return;
      // Validate first: the preview names every changed field with its impact
      // class, so the operator confirms restart-required staging explicitly.
      api("/api/settings/config/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch)
      }).then(({ body }) => {
        if (!body.valid) {
          setStatus("Not saved: " + (body.problems || []).join("; "), "error");
          return;
        }
        const changes = (body.changes || []).map(c => c.field + " (" + c.impact + ")");
        const staged = (body.changes || []).some(c => c.impact === "restart-required");
        openConfirm({
          titleText: staged ? "Stage configuration?" : "Save configuration?",
          descText: "Apply these changes: " + changes.join(", ") + ".",
          warningText: staged ? "Restart-required values are staged only. Saving never restarts a service — apply them with an operator-run restart." : "",
          actionLabel: staged ? "Stage changes" : "Save configuration",
          danger: staged,
          initiator,
          onConfirm: async () => {
            try {
              const { body: saved, etag } = await api("/api/settings/config", {
                method: "PATCH",
                headers: { "Content-Type": "application/json", "If-Match": cfg.etag },
                body: JSON.stringify(patch)
              });
              cfg.etag = etag;
              cfg.snapshot = flattenConfig(saved.config, "", {});
              cfg.sources = saved.sources || {};
              cfg.pinned = saved.pinned_environment || {};
              applyCfgToControls();
              applyCfgSideEffects(saved.config);
              computeDirty();
              setStatus(staged ? "Changes staged — they apply on the next service restart." : "Configuration saved.", "ok");
            } catch (error) {
              if (error.status === 409) {
                cfg.loaded = false;
                loadConfig().then(() => setStatus("Configuration changed in another session — reloaded latest values.", "error"));
              } else {
                setStatus("Not saved: " + error.message.trim(), "error");
              }
            }
          }
        });
      }).catch(error => setStatus("Validation failed: " + error.message.trim(), "error"));
    }

    cfgSaveButtons.forEach(btn => btn.addEventListener("click", () => requestCfgSave(btn.dataset.hpCfgSave, btn)));
    cfgControls.forEach(el => {
      el.addEventListener("change", computeDirty);
      if (el.tagName === "INPUT" && el.type !== "checkbox" || el.tagName === "TEXTAREA") {
        el.addEventListener("input", computeDirty);
        el.addEventListener("keydown", event => {
          if (event.key !== "Enter" || el.tagName === "TEXTAREA") return;
          const pane = paneOf(el);
          if (!pane || !state.dirty[pane]) return;
          event.preventDefault();
          requestCfgSave(pane, el);
        });
      }
    });

    /* #477: Report Studio preset name/description overrides. A nested map
       keyed by a dynamic set of template ids doesn't fit collectCfgPatch's
       flat one-level-per-namespace assumption (see the pane's own comment
       in settings_modal.html), so this pane has its own small save path
       instead of going through the generic data-cfg controls above -- same
       PATCH endpoint and etag, just a hand-built patch body. */
    const reportPresetCards = isAdmin ? qa("[data-hp-report-preset]") : [];
    const reportPresetSaveButton = q("[data-hp-report-preset-save]");
    reportPresetCards.forEach(card => {
      const nameEl = card.querySelector("[data-hp-report-preset-name]");
      const descEl = card.querySelector("[data-hp-report-preset-description]");
      // defaultValue/the textarea's initial textContent are the browser's
      // own unmodified-since-page-load baseline -- exactly the server-
      // rendered override this pane should treat as "not dirty" against,
      // with no extra state to keep in sync.
      const dirty = () => nameEl.value !== nameEl.defaultValue || descEl.value !== descEl.defaultValue;
      const onInput = () => { if (reportPresetSaveButton) reportPresetSaveButton.disabled = !reportPresetCards.some(dirty); };
      nameEl.addEventListener("input", onInput);
      descEl.addEventListener("input", onInput);
    });
    reportPresetSaveButton?.addEventListener("click", () => {
      const overrides = {};
      reportPresetCards.forEach(card => {
        const id = card.dataset.hpReportPreset;
        const name = card.querySelector("[data-hp-report-preset-name]").value.trim();
        const description = card.querySelector("[data-hp-report-preset-description]").value.trim();
        if (name || description) overrides[id] = { name, description };
      });
      openConfirm({
        titleText: "Save Report Studio preset text?",
        descText: "Apply the edited name/description overrides. Presets left blank keep their compiled default.",
        actionLabel: "Save changes",
        initiator: reportPresetSaveButton,
        onConfirm: async () => {
          try {
            const { body: saved, etag } = await api("/api/settings/config", {
              method: "PATCH",
              headers: { "Content-Type": "application/json", "If-Match": cfg.etag },
              body: JSON.stringify({ presentation: { report_presets: overrides } })
            });
            cfg.etag = etag;
            const savedOverrides = saved.config?.presentation?.report_presets || {};
            reportPresetCards.forEach(card => {
              const id = card.dataset.hpReportPreset;
              const nameEl = card.querySelector("[data-hp-report-preset-name]");
              const descEl = card.querySelector("[data-hp-report-preset-description]");
              const override = savedOverrides[id] || { name: "", description: "" };
              nameEl.value = nameEl.defaultValue = override.name || "";
              descEl.value = descEl.defaultValue = override.description || "";
            });
            reportPresetSaveButton.disabled = true;
            setStatus("Report Studio preset text saved.", "ok");
          } catch (error) {
            if (error.status === 409) setStatus("Configuration changed in another session — reopen settings and retry.", "error");
            else setStatus("Not saved: " + error.message.trim(), "error");
          }
        }
      });
    });

    /* ---- users (read-only projection) ---- */
    async function loadUsers() {
      const list = q("[data-hp-users-list]");
      const adminLink = q("[data-hp-users-admin-link]");
      if (!list) return;
      try {
        const { body } = await api("/api/settings/users");
        list.textContent = "";
        const users = body.users || [];
        if (!users.length) {
          list.innerHTML = '<tr><td colspan="5">No projected users yet.</td></tr>';
          return;
        }
        users.forEach(user => {
          const row = document.createElement("tr");
          [user.last_display_name || user.last_username, user.role_snapshot, user.first_seen_at, user.last_seen_at, String(user.preferences_version)]
            .forEach(text => {
              const cell = document.createElement("td");
              cell.textContent = text;
              row.appendChild(cell);
            });
          list.appendChild(row);
        });
        if (adminLink) {
          try {
            const response = await fetch("/api/whoami", { cache: "no-store" });
            const identity = response.ok ? await response.json() : null;
            const accountURL = identity && identity.auth_account_url ? identity.auth_account_url.trim() : "";
            if (accountURL) {
              // Deep links into the auth app's admin panes (Milestone F).
              const users = new URL(accountURL);
              users.searchParams.set("pane", "admin-users");
              adminLink.href = users.toString();
              adminLink.hidden = false;
              const auditLink = q("[data-hp-users-audit-link]");
              if (auditLink) {
                const logs = new URL(accountURL);
                logs.searchParams.set("pane", "admin-logs");
                auditLink.href = logs.toString();
                auditLink.hidden = false;
              }
            }
          } catch { /* links stay hidden */ }
        }
      } catch (error) {
        list.innerHTML = '<tr><td colspan="5">Users could not be loaded.</td></tr>';
        setStatus("Users could not be loaded — " + error.message.trim(), "error");
      }
    }

    /* ---- services: status + start/stop/restart/logs (#197) ----
       Every action crosses hp-services-adapter's own AF_UNIX socket
       (services_control.go); this pane only ever sees whatever that adapter
       chooses to report, and the adapter -- not this code -- enforces which
       container names are ever reachable. */
    const SERVICE_STATE_BADGE = {
      running: "badge--success",
      restarting: "badge--warning",
      created: "badge--warning",
      paused: "badge--muted",
      removing: "badge--muted",
      exited: "badge--danger",
      dead: "badge--danger",
      not_found: "badge--muted",
      unknown: "badge--muted"
    };
    const SERVICE_HEALTH_BADGE = {
      healthy: "badge--success",
      starting: "badge--warning",
      unhealthy: "badge--danger"
    };
    // A service "needs attention" if it isn't cleanly running+healthy (or
    // running with no healthcheck configured at all, svc.health == null) --
    // matches the summary metric above the table to what the State/Health
    // badges in each row already say, rather than a second definition of
    // "healthy" that could silently disagree with them.
    function serviceNeedsAttention(svc) {
      if (svc.state !== "running" && svc.state !== "restarting") return true;
      return svc.health != null && svc.health !== "healthy";
    }

    async function loadServices() {
      const list = q("[data-hp-services-list]");
      if (!list) return;
      list.innerHTML = '<tr><td colspan="5">Loading&hellip;</td></tr>';
      try {
        const { body } = await api("/api/settings/services");
        renderServices(body.services || []);
        if (body.available === false) {
          setStatus("Services adapter unavailable" + (body.reason ? " — " + body.reason : "") + ".", "error");
        }
      } catch (error) {
        list.innerHTML = '<tr><td colspan="5">Services could not be loaded.</td></tr>';
        setStatus("Services could not be loaded — " + error.message.trim(), "error");
      }
    }

    function renderServicesSummary(services) {
      const summary = q("[data-hp-services-summary]");
      if (!summary) return;
      if (!services.length) { summary.hidden = true; return; }
      const attention = services.filter(serviceNeedsAttention).length;
      const healthy = services.length - attention;
      summary.hidden = false;
      q('[data-hp-services-metric="healthy"]').textContent = healthy + "/" + services.length;
      q('[data-hp-services-metric="attention"]').textContent = String(attention);
      q('[data-hp-services-metric="total"]').textContent = String(services.length);
      const attentionTrend = q('[data-hp-services-metric-trend="attention"]');
      attentionTrend.textContent = attention === 0 ? "None" : (attention === 1 ? "1 service" : attention + " services");
      attentionTrend.className = "metric__trend " + (attention === 0 ? "text-secondary" : "text-danger");
    }

    function renderServices(services) {
      const list = q("[data-hp-services-list]");
      list.textContent = "";
      renderServicesSummary(services);
      if (!services.length) { list.innerHTML = '<tr><td colspan="5">No services reported.</td></tr>'; return; }
      services.forEach(svc => {
        const row = document.createElement("tr");

        const nameCell = document.createElement("td");
        nameCell.textContent = svc.name;
        row.appendChild(nameCell);

        const stateCell = document.createElement("td");
        const stateBadge = document.createElement("span");
        stateBadge.className = "badge " + (SERVICE_STATE_BADGE[svc.state] || "badge--muted");
        stateBadge.textContent = svc.state;
        stateCell.appendChild(stateBadge);
        row.appendChild(stateCell);

        const healthCell = document.createElement("td");
        if (svc.health) {
          const healthBadge = document.createElement("span");
          healthBadge.className = "badge " + (SERVICE_HEALTH_BADGE[svc.health] || "badge--muted");
          healthBadge.textContent = svc.health;
          healthCell.appendChild(healthBadge);
        } else {
          healthCell.textContent = "—";
        }
        row.appendChild(healthCell);

        const restartCell = document.createElement("td");
        restartCell.textContent = svc.restart_count == null ? "—" : String(svc.restart_count);
        row.appendChild(restartCell);

        const actionsCell = document.createElement("td");
        actionsCell.className = "hp-services-actions";
        if (svc.state === "running" || svc.state === "restarting") {
          actionsCell.appendChild(serviceActionButton(svc.name, "stop", "Stop", true));
          actionsCell.appendChild(serviceActionButton(svc.name, "restart", "Restart", true));
        } else {
          actionsCell.appendChild(serviceActionButton(svc.name, "start", "Start", false));
        }
        const logsButton = document.createElement("button");
        logsButton.className = "btn btn-ghost btn-sm";
        logsButton.type = "button";
        logsButton.textContent = "Logs";
        logsButton.disabled = svc.state === "not_found";
        logsButton.addEventListener("click", () => viewServiceLogs(svc.name));
        actionsCell.appendChild(logsButton);
        row.appendChild(actionsCell);

        list.appendChild(row);
      });
    }

    function serviceActionButton(name, action, label, danger) {
      const button = document.createElement("button");
      button.className = "btn btn-sm " + (danger ? "btn-secondary" : "btn-primary");
      button.type = "button";
      button.textContent = label;
      button.addEventListener("click", () => requestServiceAction(name, action, button));
      return button;
    }

    function requestServiceAction(name, action, initiator) {
      openConfirm({
        titleText: action[0].toUpperCase() + action.slice(1) + " " + name + "?",
        descText: "This sends " + action + " to the live container through the services adapter.",
        warningText: action === "stop" ? name + " stops accepting connections until it is started again." : "",
        actionLabel: action[0].toUpperCase() + action.slice(1),
        danger: action !== "start",
        initiator,
        onConfirm: async () => {
          try {
            await api("/api/settings/services/" + encodeURIComponent(name) + "/" + action, { method: "POST" });
            setStatus(name + ": " + action + " succeeded.", "ok");
          } catch (error) {
            setStatus(name + ": " + action + " failed — " + error.message.trim(), "error");
          } finally {
            loadServices();
          }
        }
      });
    }

    async function viewServiceLogs(name) {
      const trigger = q("[data-hp-services-log-trigger]");
      const source = q('[data-hp-evidence-body="services-log"]');
      const pre = q("[data-hp-services-log-pre]");
      if (!trigger || !source || !pre) return;
      pre.textContent = "Loading…";
      source.dataset.hpEvidenceTitle = "Logs: " + name;
      trigger.click();
      // The evidence viewer clones the source node's children at open time,
      // so once it's open the clone -- not this hidden source -- is what's
      // visible; update both so a later re-open also starts from the latest.
      const modalPre = document.querySelector('#hp-evidence-modal [data-hp-evidence-body-target] pre');
      try {
        const { body } = await api("/api/settings/services/" + encodeURIComponent(name) + "/logs?lines=500");
        const text = body.log || "(no output)";
        pre.textContent = text;
        if (modalPre) modalPre.textContent = text;
      } catch (error) {
        const text = "Logs could not be loaded — " + error.message.trim();
        pre.textContent = text;
        if (modalPre) modalPre.textContent = text;
      }
    }

    const servicesRefresh = q("[data-hp-services-refresh]");
    if (servicesRefresh) servicesRefresh.addEventListener("click", loadServices);

    /* ---- Elasticsearch storage stats (#647): a brief cluster/storage
       glance above the history search below. ---- */
    function formatEsStorageBytes(bytes) {
      if (!bytes) return "0 B";
      const units = ["B", "KB", "MB", "GB", "TB"];
      let value = bytes, i = 0;
      while (value >= 1024 && i < units.length - 1) { value /= 1024; i++; }
      return (i === 0 ? String(value) : value.toFixed(1)) + " " + units[i];
    }
    async function loadEsStorageStats() {
      const summary = q("[data-hp-es-storage-summary]");
      const errorEl = q("[data-hp-es-storage-error]");
      if (!summary || !errorEl) return;
      errorEl.hidden = true;
      try {
        const { body } = await api("/api/settings/es-storage-stats");
        if (!body.available) {
          summary.hidden = true;
          errorEl.hidden = false;
          errorEl.textContent = "Storage stats unavailable" + (body.reason ? " — " + body.reason : "") + ".";
          return;
        }
        const stats = body.stats;
        summary.hidden = false;
        q('[data-hp-es-storage-metric="status"]').textContent = stats.cluster_status || "—";
        const statusTrend = q('[data-hp-es-storage-metric-trend="status"]');
        statusTrend.textContent = stats.data_nodes + (stats.data_nodes === 1 ? " node" : " nodes");
        statusTrend.className = "metric__trend " + (stats.cluster_status === "green" ? "text-secondary" : (stats.cluster_status === "yellow" ? "text-warning" : "text-danger"));
        q('[data-hp-es-storage-metric="indices"]').textContent = String(stats.index_count);
        q('[data-hp-es-storage-metric="docs"]').textContent = stats.doc_count.toLocaleString();
        q('[data-hp-es-storage-metric="size"]').textContent = formatEsStorageBytes(stats.store_size_bytes);
      } catch (error) {
        summary.hidden = true;
        errorEl.hidden = false;
        errorEl.textContent = "Storage stats could not be loaded — " + error.message.trim();
      }
    }

    /* ---- Elasticsearch history (#257: moved out of the primary Evidence
       nav into an admin-only pane; same /api/history + /export/history.json
       endpoints the standalone /history page used) ---- */
    async function loadElasticsearchHistory() {
      const out = q("#hp-es-history-results"), meta = q("#hp-es-history-meta"), exportLink = q("#hp-es-history-export");
      const input = q("#hp-es-history-q");
      if (!out || !meta || !input) return;
      const query = input.value.trim();
      const suffix = query ? "&q=" + encodeURIComponent(query) : "";
      if (exportLink) exportLink.href = "/export/history.json?limit=500" + suffix;
      meta.textContent = "loading…";
      try {
        const { body } = await api("/api/history?limit=200" + suffix);
        const hits = body.hits?.hits || [];
        meta.textContent = hits.length + " documents shown";
        out.textContent = hits.map(h => JSON.stringify(h._source, null, 2)).join("\n\n");
      } catch (error) {
        meta.textContent = "query failed";
        out.textContent = error.message;
      }
    }
    const esHistoryRun = q("#hp-es-history-run"), esHistoryQ = q("#hp-es-history-q");
    if (esHistoryRun) esHistoryRun.addEventListener("click", loadElasticsearchHistory);
    if (esHistoryQ) esHistoryQ.addEventListener("keydown", e => { if (e.key === "Enter") loadElasticsearchHistory(); });

    /* ---- ingest dead letters (#257: same move, reusing /api/dead-letters
       for both listing and the destructive purge) ---- */
    let deadLettersShownCount = 0;
    async function loadDeadLetters() {
      const rows = q("#hp-dead-letters-rows"), meta = q("#hp-dead-letters-meta"), input = q("#hp-dead-letters-q");
      if (!rows || !meta || !input) return;
      const query = input.value.trim();
      meta.textContent = "loading";
      try {
        const { body } = await api("/api/dead-letters?limit=200" + (query ? "&q=" + encodeURIComponent(query) : ""));
        const hits = body.hits?.hits || [];
        deadLettersShownCount = hits.length;
        meta.textContent = hits.length + " rejected documents shown";
        rows.textContent = "";
        if (!hits.length) { rows.textContent = "No matching dead letters."; return; }
        hits.forEach(hit => {
          const detail = document.createElement("details");
          detail.className = "tw:border-b tw:border-subtle tw:py-2";
          const source = hit._source || {};
          const stamp = source["@timestamp"] || "";
          const errorText = source.error?.message || source.error?.type || "rejected document";
          const summary = document.createElement("summary");
          summary.className = "v";
          summary.textContent = stamp + " - " + errorText;
          const pre = document.createElement("pre");
          pre.className = "code tw:mt-2";
          pre.textContent = JSON.stringify(source, null, 2);
          detail.append(summary, pre);
          rows.appendChild(detail);
        });
      } catch (error) {
        meta.textContent = "query failed";
        rows.textContent = error.message;
      }
    }
    const deadLettersRun = q("#hp-dead-letters-run"), deadLettersQ = q("#hp-dead-letters-q"), deadLettersPurge = q("#hp-dead-letters-purge");
    if (deadLettersRun) deadLettersRun.addEventListener("click", loadDeadLetters);
    if (deadLettersQ) deadLettersQ.addEventListener("keydown", e => { if (e.key === "Enter") loadDeadLetters(); });
    if (deadLettersPurge) deadLettersPurge.addEventListener("click", () => {
      const query = deadLettersQ ? deadLettersQ.value.trim() : "";
      const scope = query ? `matching "${query}"` : "every retained dead letter (no query is set)";
      openConfirm({
        titleText: "Purge these dead letters?",
        descText: `Permanently deletes ${scope} from Elasticsearch. This cannot be undone.`,
        warningText: `${deadLettersShownCount} shown right now; the purge itself is not limited to what is shown and removes every retained document matching the same query.`,
        actionLabel: "Purge dead letters",
        danger: true,
        initiator: deadLettersPurge,
        onConfirm: async () => {
          try {
            const { body } = await api("/api/dead-letters" + (query ? "?q=" + encodeURIComponent(query) : ""), { method: "DELETE" });
            const deleted = body.deleted || 0;
            await loadDeadLetters();
            setStatus(`${deleted} dead letter${deleted === 1 ? "" : "s"} purged.`, "ok");
          } catch (error) {
            setStatus("Purge failed: " + error.message.trim(), "error");
          }
        }
      });
    });

    /* ---- configuration history + rollback ---- */
    async function loadHistory() {
      const list = q("[data-hp-history-list]");
      if (!list) return;
      try {
        const { body } = await api("/api/settings/config/history");
        list.textContent = "";
        const entries = body.entries || [];
        if (!entries.length) { list.innerHTML = '<p class="card__meta">No retained revisions.</p>'; return; }
        entries.forEach(entry => {
          const row = document.createElement("div");
          row.className = "hp-rev-row";
          const meta = document.createElement("div");
          meta.className = "hp-rev-meta";
          const label = document.createElement("div");
          label.textContent = "Revision " + entry.revision + " — " + entry.action + (entry.revision === body.current_revision ? " (current)" : "");
          const detail = document.createElement("small");
          detail.textContent = entry.time + " · " + (entry.actor_username || entry.actor_subject) + ((entry.fields || []).length ? " · " + entry.fields.join(", ") : "");
          meta.appendChild(label);
          meta.appendChild(detail);
          row.appendChild(meta);
          if (entry.revision !== body.current_revision) {
            const button = document.createElement("button");
            button.className = "btn btn-ghost btn-sm";
            button.type = "button";
            button.textContent = "Rollback";
            button.addEventListener("click", () => requestRollback(entry.revision, button));
            row.appendChild(button);
          }
          list.appendChild(row);
        });
      } catch (error) {
        list.innerHTML = '<p class="card__meta">History could not be loaded.</p>';
        setStatus("History could not be loaded — " + error.message.trim(), "error");
      }
    }

    function requestRollback(revision, initiator) {
      openConfirm({
        titleText: "Roll back configuration?",
        descText: "Restore revision " + revision + " as a new revision. The current state stays in history.",
        warningText: "Every configuration field returns to the retained snapshot of revision " + revision + ".",
        actionLabel: "Roll back",
        danger: true,
        initiator,
        onConfirm: async () => {
          try {
            const { body, etag } = await api("/api/settings/config/rollback", {
              method: "POST",
              headers: { "Content-Type": "application/json", "If-Match": cfg.etag },
              body: JSON.stringify({ revision })
            });
            cfg.etag = etag;
            cfg.snapshot = flattenConfig(body.config, "", {});
            cfg.sources = body.sources || {};
            cfg.pinned = body.pinned_environment || {};
            applyCfgToControls();
            applyCfgSideEffects(body.config);
            computeDirty();
            setStatus("Configuration rolled back to revision " + revision + ".", "ok");
            loadHistory();
          } catch (error) {
            if (error.status === 409) setStatus("Configuration changed in another session — reload and retry.", "error");
            else setStatus("Rollback failed: " + error.message.trim(), "error");
          }
        }
      });
    }

    /* ---- audit log ---- */
    async function loadAudit() {
      const list = q("[data-hp-audit-list]");
      const filter = q("[data-hp-audit-filter]");
      if (!list) return;
      const action = filter ? filter.value : "";
      try {
        const { body } = await api("/api/settings/audit" + (action ? "?action=" + encodeURIComponent(action) : ""));
        list.textContent = "";
        const events = body.events || [];
        if (!events.length) { list.innerHTML = '<p class="card__meta">No audit events.</p>'; return; }
        events.forEach(event => {
          const row = document.createElement("div");
          row.className = "hp-audit-row";
          const time = event.time ? new Date(event.time).toLocaleString() : "";
          const fields = (event.fields || []).length ? " — " + event.fields.join(", ") : "";
          row.textContent = time + " · " + (event.actor_username || event.actor_subject) + " · " + event.action + fields + " · " + event.result;
          list.appendChild(row);
        });
      } catch (error) {
        list.innerHTML = '<p class="card__meta">Audit log could not be loaded.</p>';
        setStatus("Audit log could not be loaded — " + error.message.trim(), "error");
      }
    }
    const auditFilter = q("[data-hp-audit-filter]");
    if (auditFilter) auditFilter.addEventListener("change", loadAudit);

    /* ---- boot ---- */
    showPane("account");
    loadIdentity();
    reloadPreferences().catch(() => setStatus("Preferences could not be loaded — you can keep browsing, but saving may fail.", "error"));
  }
})();
