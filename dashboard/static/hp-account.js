/* Sidebar account menu, settings popup, and logout (framework-free).
   The profile row opens a floating menu built from the theme's .dropdown
   primitive. "Settings" embeds the auth-backend settings app (/auth/app) in
   a centered theme .modal popup, so account credentials, passkeys, sessions,
   and — for administrators — admin configuration stay entirely on the auth
   origin (see docs/settings-user-configuration-roadmap.md, Milestone F).
   "Log out" ends the SSO session at the auth backend. */
(() => {
  "use strict";

  const trigger = document.querySelector("[data-hp-account-trigger]");
  const menu = document.querySelector("[data-hp-account-menu]");
  const settingsItem = document.querySelector("[data-hp-account-settings]");
  const logoutItem = document.querySelector("[data-hp-account-logout]");
  const note = document.querySelector("[data-hp-account-note]");
  const backdrop = document.querySelector("[data-hp-settings-backdrop]");
  const dialog = document.getElementById("hp-settings-dialog");
  if (!trigger || !menu || !settingsItem || !logoutItem || !note || !backdrop || !dialog) return;
  const closeButton = dialog.querySelector("[data-hp-settings-close]");
  const external = dialog.querySelector("[data-hp-settings-external]");
  const frame = dialog.querySelector("[data-hp-settings-frame]");

  let accountURL = "";
  let menuOpen = false;
  let settingsOpen = false;
  let frameRequested = false;
  let restoreFocus = null;

  /* Identity: the settings app and the logout endpoint live on the auth
     origin. The backend-provided account URL drives both menu actions. */
  const settleIdentity = available => {
    settingsItem.hidden = !available;
    logoutItem.hidden = !available;
    note.hidden = available;
    trigger.disabled = false;
  };
  fetch("/api/whoami", {cache: "no-store"}).then(response => response.ok ? response.json() : null).then(identity => {
    accountURL = identity && typeof identity.auth_account_url === "string" ? identity.auth_account_url.trim() : "";
    let logoutURL = "";
    try {
      if (accountURL) logoutURL = new URL(accountURL).origin + "/_auth/logout";
    } catch { accountURL = ""; }
    if (accountURL) {
      logoutItem.href = logoutURL;
      external.href = accountURL;
    }
    settleIdentity(Boolean(accountURL));
  }).catch(() => settleIdentity(false));

  /* ---- floating menu ---- */
  const openMenu = () => {
    menuOpen = true;
    menu.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    const first = menu.querySelector(".dropdown__item:not([hidden])");
    if (first) first.focus();
  };
  const closeMenu = (refocus = false) => {
    if (!menuOpen) return;
    menuOpen = false;
    menu.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    if (refocus) trigger.focus();
  };
  trigger.addEventListener("click", () => { menuOpen ? closeMenu() : openMenu(); });
  document.addEventListener("click", event => {
    if (menuOpen && !event.target.closest("[data-hp-account]")) closeMenu();
  });

  /* ---- settings popup (application-managed overlay per theme MODALS.md) ---- */
  const openSettings = () => {
    if (!accountURL) return;
    closeMenu();
    settingsOpen = true;
    restoreFocus = document.activeElement;
    if (!frameRequested) {
      frameRequested = true;
      frame.src = accountURL;
    }
    backdrop.inert = false;
    backdrop.setAttribute("aria-hidden", "false");
    backdrop.classList.add("open");
    dialog.inert = false;
    dialog.setAttribute("aria-hidden", "false");
    dialog.classList.add("open");
    closeButton.focus();
  };
  const closeSettings = () => {
    if (!settingsOpen) return;
    settingsOpen = false;
    dialog.classList.remove("open");
    dialog.setAttribute("aria-hidden", "true");
    dialog.inert = true;
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
    backdrop.inert = true;
    if (restoreFocus && restoreFocus.isConnected) restoreFocus.focus();
    restoreFocus = null;
  };
  settingsItem.addEventListener("click", openSettings);
  closeButton.addEventListener("click", closeSettings);
  backdrop.addEventListener("click", closeSettings);

  /* Let sibling controllers (the dashboard settings modal) dismiss the
     floating menu when they take over from one of its items. */
  window.HoneypotAccountMenu = Object.freeze({ close: () => closeMenu() });

  /* Keyboard contract: Escape closes the deepest temporary layer first; Tab
     stays inside the open popup. */
  document.addEventListener("keydown", event => {
    if (settingsOpen) {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeSettings();
        return;
      }
      if (event.key === "Tab") {
        const controls = [...dialog.querySelectorAll("button:not([disabled]), a[href], iframe")];
        if (!controls.length) return;
        const first = controls[0];
        const last = controls[controls.length - 1];
        if (event.shiftKey && (document.activeElement === first || !dialog.contains(document.activeElement))) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
      return;
    }
    if (menuOpen && event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeMenu(true);
    }
  });
})();
