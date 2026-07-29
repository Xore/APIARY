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

  const focusable = () => Array.from(panel.querySelectorAll(
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
  )).filter((element) => !element.hidden);

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
    backdrop.classList.remove("open");
    backdrop.setAttribute("aria-hidden", "true");
    backdrop.inert = true;
    confirmButton.disabled = false;
    confirmButton.textContent = "Confirm";
    if (restoreFocus && initiatingControl?.isConnected) initiatingControl.focus();
    initiatingControl = null;
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
    confirmButton.focus();
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
      event.preventDefault();
      close();
      return;
    }
    if (event.key === "Enter" && event.target !== cancelButton && !(event.target instanceof HTMLTextAreaElement)) {
      event.preventDefault();
      confirmOnce();
      return;
    }
    if (event.key !== "Tab") return;
    const controls = focusable();
    if (!controls.length) return;
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });

  document.addEventListener("submit", (event) => {
    const form = event.target.closest('form[action="/sandbox/submit"]');
    if (!form || form.dataset.hpConfirmed === "true") return;
    event.preventDefault();
    const hash = form.querySelector('input[name="hash"]')?.value || "selected payload";
    open({
      trigger: event.submitter || form,
      title: "Submit payload to the sandbox?",
      description: "This queues the captured artifact for execution in the isolated malware-analysis environment.",
      warning: `The payload ${hash} will be detonated and may generate network, process, and filesystem activity.`,
      confirmLabel: "Submit to sandbox",
      onConfirm: () => {
        form.dataset.hpConfirmed = "true";
        form.requestSubmit(event.submitter || undefined);
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

  window.HoneypotModals = Object.freeze({ confirm: open, close });
})();
