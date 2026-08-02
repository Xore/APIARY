/* GitHub-analysis Report viewer (#309): a single application-managed modal,
   opened by the detail page's Report card -- a plain .project-card
   (theme.css), same as reports studio's own generated-report cards, just
   one of them here instead of a grid/list. It has no nested Download/
   Delete actions the way reports studio's card does, so it's a real
   role="button" the whole card activates, with its own Enter/Space
   handling below (a native <button> gets that for free; a plain
   role="button" element does not). Mirrors hp-reports.js's openViewer/
   closeViewer shape, not its code -- that file's version is wired to a
   list of many generated reports this page has no equivalent of. */
(() => {
  "use strict";

  const backdrop = document.getElementById("hp-ga-viewer-backdrop");
  const viewer = document.getElementById("hp-ga-viewer");
  const frame = document.getElementById("hp-ga-viewer-frame");
  const closeButton = document.getElementById("hp-ga-viewer-close");
  const trigger = document.querySelector("[data-hp-ga-view-report]");
  if (!backdrop || !viewer || !frame || !closeButton || !trigger) return;

  let open = false;
  let restoreFocus = null;

  const openViewer = () => {
    if (open) return;
    open = true;
    restoreFocus = document.activeElement;
    frame.src = trigger.dataset.hpGaViewReport;
    backdrop.inert = false;
    backdrop.setAttribute("aria-hidden", "false");
    backdrop.classList.add("open");
    viewer.inert = false;
    viewer.setAttribute("aria-hidden", "false");
    viewer.classList.add("open");
    closeButton.focus();
  };

  const closeViewer = () => {
    if (!open) return;
    open = false;
    viewer.classList.remove("open");
    viewer.setAttribute("aria-hidden", "true");
    viewer.inert = true;
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
    backdrop.inert = true;
    frame.src = "about:blank";
    if (restoreFocus?.isConnected) restoreFocus.focus();
    restoreFocus = null;
  };

  trigger.addEventListener("click", openViewer);
  trigger.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    openViewer();
  });
  closeButton.addEventListener("click", closeViewer);
  backdrop.addEventListener("click", closeViewer);

  // Keyboard contract (Xore/theme docs/MODALS.md), same as hp-reports.js's
  // own viewer: Escape closes unless a destructive confirmation is stacked
  // above it, Tab stays inside the open modal.
  document.addEventListener("keydown", event => {
    if (!open) return;
    if (window.HoneypotModals?.isOpen()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeViewer();
      return;
    }
    if (event.key !== "Tab") return;
    const controls = [...viewer.querySelectorAll(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    )].filter(el => !el.hidden && el.offsetParent !== null);
    if (!controls.length) return;
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && (document.activeElement === first || !viewer.contains(document.activeElement))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });
})();
