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
      behavior:   { title: "Dashboard behavior",     desc: "Safe bounded defaults and feature visibility for every user." },
      honeypot:   { title: "Honeypot operations",    desc: "Staged operational thresholds. Saving never restarts anything — apply with an operator-run restart." },
      users:      { title: "Users",                  desc: "Read-only projection of dashboard activity. Accounts are managed in the auth service." },
      history:    { title: "Configuration history",  desc: "Retained configuration revisions with rollback." },
      audit:      { title: "Audit log",              desc: "Settings changes with actor, fields, and result." }
    };
    const ADMIN_PANES = ["branding", "behavior", "honeypot", "users", "history", "audit"];
    const isAdmin = navItems.some(nav => ADMIN_PANES.includes(nav.dataset.hpPaneNav));

    /* ---- state ---- */
    const state = { etag: "", prefs: null, snapshot: {}, dirty: {}, confirmCallback: null, confirmInitiator: null };

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
    async function api(path, options = {}) {
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
