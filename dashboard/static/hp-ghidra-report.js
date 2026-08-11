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

  const focusable = () => Array.from(modal.querySelectorAll(
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
  )).filter(el => !el.hidden && el.offsetParent !== null);

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
    closeButton.focus();
  }

  function close() {
    if (!isOpen) return;
    isOpen = false;
    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    modal.inert = true;
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
    backdrop.inert = true;
    frame.src = "about:blank";
    if (restoreFocus?.isConnected) restoreFocus.focus();
    restoreFocus = null;
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
      return;
    }
    if (event.key !== "Tab") return;
    const controls = focusable();
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
  });
})();
