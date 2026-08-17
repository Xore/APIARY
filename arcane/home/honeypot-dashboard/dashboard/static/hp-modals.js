(() => {
  "use strict";

  const backdrop = document.getElementById("hp-confirm-backdrop");
  if (!backdrop) return;

  const panel = backdrop.querySelector(".edit-dialog");
  const title = document.getElementById("hp-confirm-title");
  const description = document.getElementById("hp-confirm-description");
  const warning = document.getElementById("hp-confirm-warning");
  const confirmButton = document.getElementById("hp-confirm-action");
  const cancelButton = backdrop.querySelector("[data-hp-modal-cancel]");
  const status = document.getElementById("hp-flash");

  let pendingAction = null;
  let initiatingControl = null;
  let running = false;

  // Tab-cycling/initial-focus/return-focus is delegated to focus-trap
  // (vendored, dashboard/static/vendor/focus-trap/); Escape stays hand-rolled
  // below since it has to coordinate with the settings modal's own
  // document-level Escape listener via stopImmediatePropagation, which
  // escapeDeactivates:false here defers to entirely.
  const trap = window.focusTrap.createFocusTrap(panel, {
    escapeDeactivates: false,
    clickOutsideDeactivates: false,
    initialFocus: () => confirmButton,
    fallbackFocus: () => confirmButton,
    setReturnFocus: () => (initiatingControl?.isConnected ? initiatingControl : false),
  });

  function announce(message, failed = false) {
    if (!status) return;
    status.textContent = message;
    status.dataset.state = failed ? "error" : "success";
    status.classList.add("open");
    window.setTimeout(() => status.classList.remove("open"), 5000);
  }

  function close({ restoreFocus = true } = {}) {
    pendingAction = null;
    running = false;
    trap.deactivate({ returnFocus: restoreFocus });
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
    backdrop.inert = true;
    confirmButton.disabled = false;
    confirmButton.textContent = "Confirm";
    // Not nulled here: focus-trap's deactivate() restores focus via a
    // setTimeout(0), so setReturnFocus's closure must still see this value
    // when that deferred callback runs. open() overwrites it next time.
  }

  function open(options) {
    pendingAction = options.onConfirm;
    initiatingControl = options.trigger || document.activeElement;
    title.textContent = options.title || "Confirm action";
    description.textContent = options.description || "";
    warning.textContent = options.warning || "";
    warning.hidden = !options.warning;
    confirmButton.textContent = options.confirmLabel || "Confirm";
    confirmButton.className = options.danger === false ? "btn btn-primary" : "btn btn-danger";
    backdrop.inert = false;
    backdrop.setAttribute("aria-hidden", "false");
    backdrop.classList.add("open");
    trap.activate();
  }

  async function confirmOnce() {
    if (running || typeof pendingAction !== "function") return;
    running = true;
    const action = pendingAction;
    pendingAction = null;
    confirmButton.disabled = true;
    confirmButton.textContent = "Working…";
    try {
      const message = await action();
      close({ restoreFocus: false });
      if (message) announce(message);
    } catch (error) {
      pendingAction = action;
      running = false;
      confirmButton.disabled = false;
      confirmButton.textContent = "Try again";
      announce(error instanceof Error ? error.message : String(error), true);
      confirmButton.focus();
    }
  }

  confirmButton.addEventListener("click", confirmOnce);
  cancelButton.addEventListener("click", () => close());
  backdrop.addEventListener("click", (event) => {
    if (event.target === backdrop && !running) close();
  });

  document.addEventListener("keydown", (event) => {
    if (!backdrop.classList.contains("open")) return;
    if (event.key === "Escape" && !running) {
      // Escape closes the deepest temporary layer only. Both this controller
      // and the settings modal listen on document, so ordinary propagation
      // stopping would not reach the sibling listener.
      event.preventDefault();
      event.stopImmediatePropagation();
      close();
      return;
    }
    if (event.key === "Enter" && event.target !== cancelButton && !(event.target instanceof HTMLTextAreaElement)) {
      event.preventDefault();
      confirmOnce();
    }
  });

  document.addEventListener("submit", (event) => {
    // All three analysis spools confirm before queueing, but they are not the
    // same action and must not claim to be: the sandbox executes the payload,
    // Ghidra only reads it, and GitHub analysis publishes it externally to a
    // public repository and third-party scanners. The default warning below
    // describes detonation, so any form whose consequence differs has to
    // state its own — a Ghidra re-run warning about "network, process, and
    // filesystem activity" would be plainly false, and a confirmation nobody
    // believes is worse than none. github-analysis/submit always sets its own
    // text (below in payloads.html) precisely because "will be detonated" is
    // wrong for it in the other direction: publication is not local at all.
    // #1566: /ml-anomalies/ack-all (ml_anomalies.html's bulk-acknowledge
    // button) reuses this same listener rather than alerts.html's separate
    // fetch-driven confirm -- it always sets its own text too, same as
    // github-analysis/submit, so the sandbox-specific default below never
    // shows for it.
    const form = event.target.closest(
      'form[action="/sandbox/submit"], form[action="/ghidra/submit"], form[action="/github-analysis/submit"], form[action="/ml-anomalies/ack-all"]',
    );
    if (!form || form.dataset.hpConfirmed === "true") return;
    // Only forms that opt in are interrupted. The payloads page carries a
    // Ghidra button on every row, and a modal per row for a read-only action
    // is confirmation fatigue; the re-analysis forms set these attributes
    // because those overwrite an existing result. Sandbox and github-analysis
    // both always confirm — this skip is Ghidra-specific.
    if (form.action.endsWith("/ghidra/submit") && !form.dataset.hpConfirmTitle) return;
    event.preventDefault();
    const hash = form.querySelector('input[name="hash"]')?.value || "selected payload";
    // A form may reword the confirmation (re-analysis reads differently from a
    // first submission); the consequence warning stays identical either way.
    open({
      trigger: event.submitter || form,
      title: form.dataset.hpConfirmTitle || "Submit payload to the sandbox?",
      description: form.dataset.hpConfirmDescription
        || "This queues the captured artifact for execution in the isolated malware-analysis environment.",
      warning: form.dataset.hpConfirmWarning
        || `The payload ${hash} will be detonated and may generate network, process, and filesystem activity.`,
      confirmLabel: form.dataset.hpConfirmLabel || "Submit to sandbox",
      onConfirm: () => {
        form.dataset.hpConfirmed = "true";
        form.requestSubmit(event.submitter || undefined);
      },
    });
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-hp-alert-ack-all]");
    if (!button) return;
    // The page shows the newest 200 records; the server acknowledges every open
    // one. Say so before confirming, and report the number the server actually
    // changed afterwards rather than the number that happened to be on screen.
    const shown = Number(button.dataset.hpAlertOpenCount || "0");
    open({
      trigger: button,
      title: "Acknowledge every open alert?",
      description:
        "Acknowledging suppresses repeat notifications until each alert is reopened. Reopening is one alert at a time.",
      warning: `${shown} open alert${shown === 1 ? "" : "s"} listed here, plus any older ones this page does not show.`,
      confirmLabel: "Acknowledge all",
      danger: true,
      onConfirm: async () => {
        const response = await fetch("/api/alerts", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ scope: "all", ack: "true" }),
        });
        if (!response.ok) throw new Error(`Alert update failed (${response.status})`);
        const { changed = 0 } = await response.json();
        if (typeof window.loadAlerts === "function") await window.loadAlerts();
        return `${changed} alert${changed === 1 ? "" : "s"} acknowledged.`;
      },
    });
  });

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-hp-alert-ack]");
    if (!button) return;
    const acknowledge = button.dataset.hpAlertAck === "true";
    const key = button.dataset.hpAlertKey || "";
    const message = button.dataset.hpAlertMessage || key;
    open({
      trigger: button,
      title: acknowledge ? "Acknowledge this alert?" : "Reopen this alert?",
      description: acknowledge
        ? "Acknowledging suppresses repeat notifications until the alert is reopened."
        : "Reopening makes the alert active and eligible for notifications again.",
      warning: message,
      confirmLabel: acknowledge ? "Acknowledge alert" : "Reopen alert",
      danger: acknowledge,
      onConfirm: async () => {
        const response = await fetch("/api/alerts", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ key, ack: String(acknowledge) }),
        });
        if (!response.ok) throw new Error(`Alert update failed (${response.status})`);
        if (typeof window.loadAlerts === "function") await window.loadAlerts();
        return acknowledge ? "Alert acknowledged." : "Alert reopened.";
      },
    });
  });

  document.addEventListener("click", (event) => {
    // Export options (#59): confirms the exact scope about to be downloaded
    // before navigating, so a filter the operator forgot was active can't
    // silently produce a CSV that doesn't match what they think they're
    // getting. The URL itself already carries the current filter query
    // string -- server-computed (pages_data.go's eventsData/ExportURL), not
    // reconstructed here, so this can never drift from what the page shows.
    const button = event.target.closest("[data-hp-export-url]");
    if (!button) return;
    const url = button.dataset.hpExportUrl;
    const count = Number(button.dataset.hpExportCount || "0");
    const label = button.dataset.hpExportLabel || "row";
    open({
      trigger: button,
      title: "Export the current filtered view?",
      description: `Downloads a CSV of exactly the ${count} ${label}${count === 1 ? "" : "s"} matching the filters shown on this page, not the full unfiltered set.`,
      confirmLabel: "Download CSV",
      danger: false,
      onConfirm: () => {
        window.location.href = url;
        return "Export started.";
      },
    });
  });

  // isOpen lets another controller yield Escape to this layer without relying
  // on which script registered its document listener first.
  window.HoneypotModals = Object.freeze({
    confirm: open,
    close,
    isOpen: () => backdrop.classList.contains("open"),
  });
})();
