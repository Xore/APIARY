/* "Report a problem" button (#1147) — a floating button present on every
 * page (when admin-enabled via behavior.show_problem_report_button),
 * backed by a continuous, in-memory ring buffer of recent activity so a
 * submitted report captures what led UP TO a problem, not just what
 * happens after an operator notices something is wrong and reaches for
 * the button.
 *
 * Framework-free, matching hp-settings.js's own pattern -- no build step,
 * loaded directly as a plain <script defer> from every page.
 *
 * Capture scope (operator decision, see #1147): click/navigation trail,
 * console errors, failed fetch requests (with truncated request/response
 * bodies for same-origin /api/ calls only -- see apiCallCache below), and
 * a DOM snapshot of <html> at the moment "Report a problem" is clicked.
 * Redaction happens twice: a light client-side pass here (never send an
 * Authorization/Cookie header value off this page even transiently) and a
 * real, pattern-based pass server-side (problem_reports.go's
 * redactCapturedText) that is the actual trust boundary -- this file's own
 * redaction is defense in depth, not the thing anything should rely on.
 */
(function () {
  "use strict";

  const root = document.getElementById("hp-problem-report-root");
  if (!root) return; // feature disabled server-side; nothing to do

  const MAX_TRAIL = 100;
  const MAX_CONSOLE_ERRORS = 30;
  const MAX_NETWORK_FAILURES = 30;
  const MAX_API_CALLS = 20;
  const MAX_DOM_SNAPSHOT = 200000;
  const MAX_BODY_CAPTURE = 4000; // per request/response body, before server-side redaction/truncation

  const trail = [];
  const consoleErrors = [];
  const networkFailures = [];
  const apiCalls = [];

  function pushCapped(arr, item, max) {
    arr.push(item);
    if (arr.length > max) arr.shift();
  }

  function recordAction(kind, detail) {
    pushCapped(trail, { at: new Date().toISOString(), kind, detail }, MAX_TRAIL);
  }

  // Click trail: capture enough to identify the element without capturing
  // its full text content (which could carry real event/investigation data
  // for a click inside a data table, not just chrome).
  document.addEventListener(
    "click",
    event => {
      const el = event.target && event.target.closest
        ? event.target.closest("button, a, [role=button], input, select")
        : null;
      if (!el) return;
      const label =
        el.getAttribute("aria-label") ||
        el.getAttribute("title") ||
        (el.tagName === "A" ? el.getAttribute("href") : null) ||
        el.id ||
        el.tagName.toLowerCase();
      recordAction("click", `${el.tagName.toLowerCase()}: ${String(label).slice(0, 200)}`);
    },
    { capture: true }
  );

  recordAction("navigation", location.pathname + location.search);
  window.addEventListener("popstate", () => recordAction("navigation", location.pathname + location.search));
  for (const fn of ["pushState", "replaceState"]) {
    const original = history[fn];
    history[fn] = function (...args) {
      const result = original.apply(this, args);
      recordAction("navigation", location.pathname + location.search);
      return result;
    };
  }

  const originalConsoleError = console.error.bind(console);
  console.error = function (...args) {
    try {
      pushCapped(
        consoleErrors,
        `${new Date().toISOString()} ${args.map(a => (a instanceof Error ? a.stack || a.message : String(a))).join(" ")}`.slice(0, 2000),
        MAX_CONSOLE_ERRORS
      );
    } catch (_) {
      /* never let capture itself break console.error */
    }
    originalConsoleError(...args);
  };

  window.addEventListener("error", event => {
    pushCapped(
      consoleErrors,
      `${new Date().toISOString()} uncaught: ${event.message} (${event.filename}:${event.lineno})`,
      MAX_CONSOLE_ERRORS
    );
  });
  window.addEventListener("unhandledrejection", event => {
    pushCapped(
      consoleErrors,
      `${new Date().toISOString()} unhandled rejection: ${event.reason instanceof Error ? event.reason.message : String(event.reason)}`,
      MAX_CONSOLE_ERRORS
    );
  });

  // fetch wrapper: records every failed (network error or >=400) call, and
  // separately caches request/response bodies for same-origin /api/ calls
  // specifically -- the dashboard's own API surface, the highest-signal
  // capture target and the one #1147 explicitly asked for. Third-party
  // requests (map tiles, etc.) are recorded as failures but never have
  // their bodies captured.
  const originalFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const url = typeof input === "string" ? input : input && input.url;
    const method = (init && init.method) || (typeof input !== "string" && input && input.method) || "GET";
    const isSameOriginAPI = typeof url === "string" && url.startsWith("/api/");
    let requestBody = "";
    if (isSameOriginAPI && init && typeof init.body === "string") {
      requestBody = init.body.slice(0, MAX_BODY_CAPTURE);
    }
    try {
      const response = await originalFetch(input, init);
      if (!response.ok) {
        pushCapped(
          networkFailures,
          `${new Date().toISOString()} ${method} ${url} -> ${response.status}`,
          MAX_NETWORK_FAILURES
        );
      }
      if (isSameOriginAPI) {
        let responseBody = "";
        try {
          responseBody = (await response.clone().text()).slice(0, MAX_BODY_CAPTURE);
        } catch (_) {
          /* body already consumed elsewhere, or not text -- skip */
        }
        pushCapped(
          apiCalls,
          {
            at: new Date().toISOString(),
            method,
            url,
            status: response.status,
            request_body: requestBody,
            response_body: responseBody,
          },
          MAX_API_CALLS
        );
      }
      return response;
    } catch (err) {
      pushCapped(
        networkFailures,
        `${new Date().toISOString()} ${method} ${url} -> network error: ${err && err.message}`,
        MAX_NETWORK_FAILURES
      );
      throw err;
    }
  };

  /* ---- UI: floating button + modal ---- */

  const button = document.createElement("button");
  button.type = "button";
  button.className = "btn btn-secondary hp-problem-report-button";
  button.textContent = "Report a problem";
  button.style.position = "fixed";
  button.style.right = "1rem";
  button.style.bottom = "1rem";
  button.style.zIndex = "40";
  root.appendChild(button);

  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop";
  backdrop.setAttribute("aria-hidden", "true");
  backdrop.hidden = true;

  const dialog = document.createElement("section");
  dialog.className = "modal";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");
  dialog.setAttribute("aria-label", "Report a problem");
  dialog.hidden = true;
  dialog.innerHTML = `
    <div class="modal__header">
      <h2 class="modal__header-title">Report a problem</h2>
      <button type="button" class="modal__close" data-hp-pr-close aria-label="Close">&#10005;</button>
    </div>
    <form data-hp-pr-form>
      <div class="hp-field">
        <label class="form-label" for="hp-pr-expected">What did you expect to happen? *</label>
        <textarea class="form-input" id="hp-pr-expected" name="expected" rows="3" required></textarea>
      </div>
      <div class="hp-field">
        <label class="form-label" for="hp-pr-actual">What actually happened?</label>
        <textarea class="form-input" id="hp-pr-actual" name="actual" rows="3"></textarea>
      </div>
      <p class="settings-field__desc">
        This report automatically includes your recent click/navigation trail, console errors,
        failed requests, and a snapshot of the current page -- reviewed by an admin, never shared
        outside this dashboard.
      </p>
      <div class="edit-dialog__actions">
        <button type="button" class="btn btn-secondary" data-hp-pr-close>Cancel</button>
        <button type="submit" class="btn btn-primary">Submit report</button>
      </div>
      <p class="hp-modal-status" data-hp-pr-status role="status" aria-live="polite"></p>
    </form>`;

  root.appendChild(backdrop);
  root.appendChild(dialog);

  let restoreFocus = null;

  // Tab-cycling/initial-focus/return-focus via focus-trap (vendored,
  // dashboard/static/vendor/focus-trap/); Escape handled below. This modal
  // previously had no keyboard containment at all -- #1244's audit flagged
  // it as one of two dialogs in the dashboard missing the trap every other
  // one already implements.
  const trap = window.focusTrap.createFocusTrap(dialog, {
    escapeDeactivates: false,
    clickOutsideDeactivates: false,
    initialFocus: () => dialog.querySelector("#hp-pr-expected") || dialog,
    fallbackFocus: () => dialog,
    setReturnFocus: () => (restoreFocus?.isConnected ? restoreFocus : false),
  });

  function openModal() {
    restoreFocus = document.activeElement;
    backdrop.hidden = false;
    dialog.hidden = false;
    backdrop.setAttribute("aria-hidden", "false");
    trap.activate();
  }
  function closeModal() {
    trap.deactivate();
    backdrop.hidden = true;
    dialog.hidden = true;
    backdrop.setAttribute("aria-hidden", "true");
    // Not nulled here: focus-trap's deactivate() restores focus via a
    // setTimeout(0), so setReturnFocus's closure must still see this value
    // when that deferred callback runs. openModal() overwrites it next time.
  }

  button.addEventListener("click", openModal);
  backdrop.addEventListener("click", closeModal);
  dialog.querySelectorAll("[data-hp-pr-close]").forEach(el => el.addEventListener("click", closeModal));
  document.addEventListener("keydown", event => {
    if (dialog.hidden) return;
    if (window.HoneypotModals?.isOpen()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeModal();
    }
  });

  dialog.querySelector("[data-hp-pr-form]").addEventListener("submit", async event => {
    event.preventDefault();
    const status = dialog.querySelector("[data-hp-pr-status]");
    const expected = dialog.querySelector("#hp-pr-expected").value.trim();
    const actual = dialog.querySelector("#hp-pr-actual").value.trim();
    if (!expected) return;

    let domSnapshot = "";
    try {
      domSnapshot = document.documentElement.outerHTML.slice(0, MAX_DOM_SNAPSHOT);
    } catch (_) {
      /* snapshot is best-effort */
    }

    status.textContent = "Submitting…";
    try {
      const response = await fetch("/api/problem-reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          page: location.pathname + location.search,
          expected,
          actual,
          action_trail: trail,
          console_errors: consoleErrors,
          network_failures: networkFailures,
          api_calls: apiCalls,
          dom_snapshot: domSnapshot,
          user_agent: navigator.userAgent,
        }),
      });
      if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      status.textContent = "Report submitted. Thank you.";
      setTimeout(closeModal, 1200);
      dialog.querySelector("#hp-pr-expected").value = "";
      dialog.querySelector("#hp-pr-actual").value = "";
    } catch (err) {
      status.textContent = "Failed to submit report: " + (err && err.message ? err.message : "unknown error");
    }
  });
})();
