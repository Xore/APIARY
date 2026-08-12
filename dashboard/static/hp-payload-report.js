/* Payload PDF report generation + viewer (#474): a single application-
   managed modal, opened by the payload analysis page's "Generate PDF
   report" chip. Unlike hp-github-analysis.js's viewer (which just opens an
   already-existing upstream PDF), this one first POSTs
   /api/reports/payloads/{hash}/generate -- report_pdf.go's writer is an
   in-process, hand-rolled PDF emitter with no external process to poll, so
   the button's own disabled/label state during that fetch is the whole
   "inline spinner" the ask calls for; no background job, no polling.
   Mirrors hp-reports.js's openViewer/closeViewer shape, not its code --
   that file's version is wired to a list of many generated reports this
   page has no equivalent of (same reasoning hp-github-analysis.js's own
   header comment already gives). */
(() => {
  "use strict";

  const trigger = document.querySelector("[data-hp-pl-generate-report]");
  const backdrop = document.getElementById("hp-pl-viewer-backdrop");
  const viewer = document.getElementById("hp-pl-viewer");
  const frame = document.getElementById("hp-pl-viewer-frame");
  const closeButton = document.getElementById("hp-pl-viewer-close");
  if (!trigger || !backdrop || !viewer || !frame || !closeButton) return;

  let open = false;
  let restoreFocus = null;
  const idleLabel = trigger.textContent;

  // Tab-cycling/initial-focus/return-focus delegated to focus-trap (vendored,
  // dashboard/static/vendor/focus-trap/); Escape stays hand-rolled below.
  const trap = window.focusTrap.createFocusTrap(viewer, {
    escapeDeactivates: false,
    clickOutsideDeactivates: false,
    initialFocus: () => closeButton,
    fallbackFocus: () => closeButton,
    setReturnFocus: () => (restoreFocus?.isConnected ? restoreFocus : false),
  });

  const openViewer = report => {
    if (open) return;
    open = true;
    restoreFocus = document.activeElement;
    frame.src = `/api/reports/generated/${report.id}/pdf`;
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

  trigger.addEventListener("click", async () => {
    if (trigger.disabled) return;
    trigger.disabled = true;
    trigger.textContent = "Generating…";
    try {
      const response = await fetch(`/api/reports/payloads/${encodeURIComponent(trigger.dataset.hpPlHash)}/generate`, { method: "POST" });
      if (!response.ok) {
        const text = (await response.text()).trim();
        throw new Error(text || `request failed (${response.status})`);
      }
      const payload = await response.json();
      openViewer(payload.generated);
    } catch (error) {
      trigger.textContent = "Generate failed — retry";
      trigger.title = error.message;
      trigger.disabled = false;
      return;
    }
    trigger.textContent = idleLabel;
    trigger.disabled = false;
  });

  closeButton.addEventListener("click", closeViewer);
  backdrop.addEventListener("click", closeViewer);

  // Keyboard contract (Xore/theme docs/MODALS.md), same as
  // hp-github-analysis.js's own viewer.
  document.addEventListener("keydown", event => {
    if (!open) return;
    if (window.HoneypotModals?.isOpen()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeViewer();
    }
  });
})();
