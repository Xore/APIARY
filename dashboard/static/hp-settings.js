/* /settings — permanent dialog controller (framework-free).
 *
 * The page IS a permanent modal per the theme modal contract (MODALS.md):
 * it opens with showModal() on load and never closes — Escape is swallowed,
 * the only way out is the explicit "Back to dashboard" navigation. The
 * nested save/reset confirmation lives INSIDE the permanent dialog so the
 * browser top-layer invariant holds.
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

  const dialog = document.getElementById("hp-settings");
  if (!dialog) return;

  /* ---- permanent dialog: open once, never close ---- */
  try { dialog.showModal(); } catch { /* already open */ }
  dialog.addEventListener("cancel", event => event.preventDefault());

  /* ---- element handles ---- */
  const title = document.getElementById("hp-settings-title");
  const paneDesc = document.querySelector("[data-hp-pane-desc]");
  const status = document.querySelector("[data-hp-settings-status]");
  const search = document.querySelector("[data-hp-settings-search]");
  const navItems = Array.from(document.querySelectorAll("[data-hp-pane-nav]"));
  const panes = Array.from(document.querySelectorAll("[data-hp-pane]"));
  const saveButtons = Array.from(document.querySelectorAll("[data-hp-save]"));
  const resetAll = document.querySelector("[data-hp-reset-all]");
  const confirmBackdrop = document.getElementById("hp-settings-confirm-backdrop");
  const confirmDialog = document.getElementById("hp-settings-confirm");
  const confirmTitle = document.getElementById("hp-settings-confirm-title");
  const confirmDesc = document.getElementById("hp-settings-confirm-desc");
  const confirmWarning = document.getElementById("hp-settings-confirm-warning");
  const confirmCancel = confirmDialog && confirmDialog.querySelector("[data-hp-confirm-cancel]");
  const confirmAction = confirmDialog && confirmDialog.querySelector("[data-hp-confirm-action]");

  const PANE_META = {
    account:    { title: "Account",                desc: "Your identity as provided by the auth service. Credentials are managed there, never here." },
    appearance: { title: "Appearance",             desc: "Theme, density, motion, and readability of the dashboard." },
    navigation: { title: "Navigation & tables",    desc: "Where you land, how the sidebar behaves, and how tables render." },
    time:       { title: "Time & live data",       desc: "Timezone, clock formats, refresh cadence, and notifications." },
    map:        { title: "Map & investigation",    desc: "Basemap, clustering, and drill-down defaults for investigations." }
  };
  const PANE_NAMES = Object.keys(PANE_META);

  /* ---- state ---- */
  const state = { etag: "", prefs: null, snapshot: {}, dirty: {}, confirmCallback: null, confirmInitiator: null };

  /* ---- control helpers (three control types, keyed by data-pref) ---- */
  const controls = Array.from(document.querySelectorAll("[data-pref]"));

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
    if (!state.snapshot) return;
    controls.forEach(el => {
      const name = el.dataset.pref;
      const pane = paneOf(el);
      if (!pane) return;
      const current = controlValue(el);
      const original = state.snapshot[name];
      if (JSON.stringify(current) !== JSON.stringify(original)) state.dirty[pane] = true;
    });
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
  function activePane() {
    const open = panes.find(p => !p.hidden);
    return open ? open.dataset.hpPane : "account";
  }

  function showPane(name, replace = true) {
    if (!PANE_META[name]) name = "account"; // ?pane= fallback for unknown names
    panes.forEach(p => { p.hidden = p.dataset.hpPane !== name; });
    navItems.forEach(nav => nav.classList.toggle("active", nav.dataset.hpPaneNav === name));
    title.textContent = PANE_META[name].title;
    paneDesc.textContent = PANE_META[name].desc;
    if (search) { search.value = ""; }
    clearSearch();
    if (replace) {
      const url = new URL(window.location.href);
      url.searchParams.set("pane", name);
      history.replaceState(null, "", url);
    }
  }

  navItems.forEach(nav => nav.addEventListener("click", () => showPane(nav.dataset.hpPaneNav)));

  /* ---- search: empty query = pane mode; non-empty = filter across all panes ---- */
  function clearSearch() {
    panes.forEach(p => { p.hidden = p.dataset.hpPane !== activePaneFromNav(); });
    document.querySelectorAll(".hp-field").forEach(f => { f.hidden = false; });
    navItems.forEach(n => { n.hidden = false; });
  }
  function activePaneFromNav() {
    const active = navItems.find(n => n.classList.contains("active"));
    return active ? active.dataset.hpPaneNav : "account";
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

  /* ---- nested confirmation (inside the permanent dialog) ---- */
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
    confirmBackdrop.classList.add("open");
    confirmBackdrop.inert = false;
    try { confirmDialog.showModal(); } catch { /* already open */ }
    confirmAction.focus();
  }

  function closeConfirm(refocus = true) {
    state.confirmCallback = null;
    if (confirmDialog && confirmDialog.open) confirmDialog.close();
    confirmBackdrop.classList.remove("open");
    confirmBackdrop.inert = true;
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
    // Native Esc on the confirm closes ONLY the confirm (permanent stays open).
    confirmDialog.addEventListener("close", () => {
      confirmBackdrop.classList.remove("open");
      confirmBackdrop.inert = true;
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
    const target = el.classList.contains("segmented") ? el : el;
    target.addEventListener("keydown", event => {
      if (event.key !== "Enter") return;
      if (el.tagName === "SELECT") return; // Enter opens the native picker
      const pane = paneOf(el);
      if (!pane || !state.dirty[pane]) return;
      event.preventDefault();
      requestSave(pane, el);
    });
    target.addEventListener("change", computeDirty);
    if (el.tagName === "INPUT" && el.type !== "checkbox") el.addEventListener("input", computeDirty);
  });

  /* Segmented buttons behave like radio groups. */
  document.querySelectorAll(".segmented[data-pref]").forEach(group => {
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
    const nameEl = document.querySelector("[data-hp-acct-name]");
    const subjectEl = document.querySelector("[data-hp-acct-subject]");
    const roleEl = document.querySelector("[data-hp-acct-role]");
    const capsEl = document.querySelector("[data-hp-acct-caps]");
    const linkEl = document.querySelector("[data-hp-acct-link]");
    const logoutEl = document.querySelector("[data-hp-acct-logout]");
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
          linkEl.href = accountURL;
          logoutEl.href = new URL(accountURL).origin + "/_auth/logout";
          linkEl.hidden = false;
          logoutEl.hidden = false;
        } catch { linkEl.hidden = true; logoutEl.hidden = true; }
      } else { linkEl.hidden = true; logoutEl.hidden = true; }
    } catch {
      nameEl.textContent = "Identity unavailable";
      subjectEl.textContent = "";
    }
  }

  /* ---- boot ---- */
  const initialPane = new URLSearchParams(window.location.search).get("pane") || "account";
  showPane(initialPane, false);
  loadIdentity();
  reloadPreferences().catch(() => setStatus("Preferences could not be loaded — you can keep browsing, but saving may fail.", "error"));
})();
