/* Ghidra report viewer — opens the generated analysis report inline instead
 * of only as a download. Same overlay shape and open/close mechanics as the
 * Reports Studio viewer (hp-reports.js) and the dashboard settings modal
 * (hp-settings.js): application-managed overlay, inert + aria-hidden when
 * closed, focus moved in on open and restored on close, focus trapped while
 * open, Escape closes unless a destructive confirmation is stacked above it.
 *
 * Simpler than hp-reports.js's viewer: there is exactly one report per page
 * (this analysis's own), its URL is already in the server-rendered button's
 * dataset, so there is no report list/id lookup to do first.
 */
(() => {
  "use strict";

  const button = document.getElementById("hp-gh-report-view");
  const backdrop = document.getElementById("hp-gh-viewer-backdrop");
  const modal = document.getElementById("hp-gh-viewer");
  const frame = document.getElementById("hp-gh-viewer-frame");
  const closeButton = document.getElementById("hp-gh-viewer-close");
  if (!button || !backdrop || !modal || !frame || !closeButton) return;

  let isOpen = false;
  let restoreFocus = null;

  // Tab-cycling/initial-focus/return-focus delegated to focus-trap (vendored,
  // dashboard/static/vendor/focus-trap/); Escape stays hand-rolled below.
  const trap = window.focusTrap.createFocusTrap(modal, {
    escapeDeactivates: false,
    clickOutsideDeactivates: false,
    initialFocus: () => closeButton,
    fallbackFocus: () => closeButton,
    setReturnFocus: () => (restoreFocus?.isConnected ? restoreFocus : false),
  });

  function open() {
    if (isOpen) return;
    const url = button.dataset.hpGhReportUrl;
    if (!url) return;
    isOpen = true;
    restoreFocus = document.activeElement;
    frame.src = url;
    backdrop.inert = false;
    backdrop.setAttribute("aria-hidden", "false");
    backdrop.classList.add("open");
    modal.inert = false;
    modal.setAttribute("aria-hidden", "false");
    modal.classList.add("open");
    trap.activate();
  }

  function close() {
    if (!isOpen) return;
    isOpen = false;
    trap.deactivate();
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    modal.inert = true;
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
    backdrop.inert = true;
    frame.src = "about:blank";
    // Not nulled here: focus-trap's deactivate() restores focus via a
    // setTimeout(0), so setReturnFocus's closure must still see this value
    // when that deferred callback runs. open() overwrites it next time.
  }

  button.addEventListener("click", open);
  closeButton.addEventListener("click", close);
  backdrop.addEventListener("click", close);

  document.addEventListener("keydown", (event) => {
    if (!isOpen) return;
    if (window.HoneypotModals?.isOpen()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      close();
    }
  });
})();
