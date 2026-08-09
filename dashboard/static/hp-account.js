/* Sidebar identity menu backed exclusively by the dashboard's native
   Keycloak session. Credential management opens Keycloak top-level: normal
   account pages intentionally remain non-frameable. */
(() => {
  "use strict";

  const root = document.querySelector("[data-hp-account]");
  if (!root) return;
  const trigger = root.querySelector("[data-hp-account-trigger]");
  const menu = root.querySelector("[data-hp-account-menu]");
  const account = root.querySelector("[data-hp-account-settings]");
  const logout = root.querySelector("[data-hp-account-logout]");
  const note = root.querySelector("[data-hp-account-note]");
  const name = root.querySelector("[data-hp-user-name]");
  const role = root.querySelector("[data-hp-user-role]");
  const avatar = root.querySelector("[data-hp-user-avatar]");
  if (!trigger || !menu || !account || !logout || !note) return;

  let menuOpen = false;
  const close = (focus = false) => {
    menuOpen = false;
    menu.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    if (focus) trigger.focus();
  };
  const open = () => {
    menuOpen = true;
    menu.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    menu.querySelector(".dropdown__item:not([hidden])")?.focus();
  };

  fetch("/api/whoami", { cache: "no-store" })
    .then(response => response.ok ? response.json() : Promise.reject(new Error(String(response.status))))
    .then(identity => {
      const display = identity.display_name || identity.username || "Account";
      name.textContent = display;
      role.textContent = identity.role || "user";
      role.hidden = false;
      avatar.textContent = display.trim().charAt(0).toUpperCase() || "?";
      const actions = identity.account_actions || {};
      if (actions.manage_account) {
        account.href = actions.manage_account;
        account.hidden = false;
      }
      logout.href = actions.logout || "/auth/logout";
      logout.hidden = false;
      note.hidden = true;
      trigger.disabled = false;
    })
    .catch(() => {
      name.textContent = "Identity unavailable";
      account.hidden = true;
      logout.hidden = true;
      note.hidden = false;
      trigger.disabled = false;
    });

  trigger.addEventListener("click", () => menuOpen ? close() : open());
  document.addEventListener("click", event => {
    if (menuOpen && !event.target.closest("[data-hp-account]")) close();
  });
  document.addEventListener("keydown", event => {
    if (menuOpen && event.key === "Escape") {
      event.preventDefault();
      close(true);
    }
  });
  window.HoneypotAccountMenu = Object.freeze({ close });
})();
