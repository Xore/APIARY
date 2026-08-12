/* GitHub-analysis Report viewer (#309): a single application-managed modal,
   opened by the detail page's Report card -- a plain .project-card
   (theme.css), same as reports studio's own generated-report cards, just
   one of them here instead of a grid/list. It has no nested Download/
   Delete actions the way reports studio's card does, so it's a real
   role="button" the whole card activates, with its own Enter/Space
   handling below (a native <button> gets that for free; a plain
   role="button" element does not). Mirrors hp-reports.js's openViewer/
   closeViewer shape, not its code -- that file's version is wired to a
   list of many generated reports this page has no equivalent of.

   The modal itself (backdrop/viewer/frame/closeButton) lives outside
   [data-hp-page-content] (a .app-shell sibling, per hp-dynamic-nav.js's
   own mergeExtraContent comment) so it persists unchanged across SPA
   navigations within /github-analysis/{hash}'s DYNAMIC_ROUTES family --
   set up once, below. The trigger card, though, is INSIDE
   [data-hp-page-content] and gets swapped for a fresh, listener-less
   element on every such navigation -- wireTrigger() re-queries it and
   reattaches on both initial load and every "hp-dynamic-nav" event, or
   navigating from one hash's page to another's would leave "View PDF
   report" a dead click on the second one. */
(() => {
  "use strict";

  const backdrop = document.getElementById("hp-ga-viewer-backdrop");
  const viewer = document.getElementById("hp-ga-viewer");
  const frame = document.getElementById("hp-ga-viewer-frame");
  const closeButton = document.getElementById("hp-ga-viewer-close");
  if (!backdrop || !viewer || !frame || !closeButton) return;

  let open = false;
  let restoreFocus = null;
  let trigger = null;

  // Tab-cycling/initial-focus/return-focus delegated to focus-trap (vendored,
  // dashboard/static/vendor/focus-trap/); Escape stays hand-rolled below.
  const trap = window.focusTrap.createFocusTrap(viewer, {
    escapeDeactivates: false,
    clickOutsideDeactivates: false,
    initialFocus: () => closeButton,
    fallbackFocus: () => closeButton,
    setReturnFocus: () => (restoreFocus?.isConnected ? restoreFocus : false),
  });

  const openViewer = () => {
    if (open || !trigger) return;
    open = true;
    restoreFocus = document.activeElement;
    frame.src = trigger.dataset.hpGaViewReport;
    backdrop.inert = false;
    backdrop.setAttribute("aria-hidden", "false");
    backdrop.classList.add("open");
    viewer.inert = false;
    viewer.setAttribute("aria-hidden", "false");
    viewer.classList.add("open");
    trap.activate();
  };

  const closeViewer = () => {
    if (!open) return;
    open = false;
    trap.deactivate();
    viewer.classList.remove("open");
    viewer.setAttribute("aria-hidden", "true");
    viewer.inert = true;
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
    backdrop.inert = true;
    frame.src = "about:blank";
    // Not nulled here: focus-trap's deactivate() restores focus via a
    // setTimeout(0), so setReturnFocus's closure must still see this value
    // when that deferred callback runs. openViewer() overwrites it next time.
  };

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
    }
  });

  function wireTrigger() {
    trigger = document.querySelector("[data-hp-ga-view-report]");
    if (!trigger) return;
    trigger.addEventListener("click", openViewer);
    trigger.addEventListener("keydown", event => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      openViewer();
    });
  }

  wireTrigger();
  document.addEventListener("hp-dynamic-nav", wireTrigger);
})();
