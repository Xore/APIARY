/* /admin/problem-reports page controller (#1147): status changes and a
 * details modal showing the full captured context (action trail, console
 * errors, network failures, API calls, DOM snapshot) for one report.
 * window.__hpProblemReports is inlined server-side (problem_reports.html)
 * so this page needs no extra round-trip just to show what already
 * rendered in the table.
 */
(function () {
  "use strict";

  const reports = window.__hpProblemReports || [];
  const byId = new Map(reports.map(r => [r.id, r]));

  document.querySelectorAll("[data-hp-pr-status]").forEach(select => {
    select.addEventListener("change", async () => {
      const id = select.dataset.id;
      const status = select.value;
      try {
        const response = await fetch("/api/problem-reports/" + encodeURIComponent(id), {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status }),
        });
        if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
      } catch (err) {
        alert("Failed to update status: " + (err && err.message ? err.message : "unknown error"));
      }
    });
  });

  const backdrop = document.getElementById("hp-pr-detail-backdrop");
  const modal = document.getElementById("hp-pr-detail-modal");
  const body = modal ? modal.querySelector("[data-hp-pr-detail-body]") : null;

  let restoreFocus = null;

  // Tab-cycling/initial-focus/return-focus via focus-trap (vendored,
  // dashboard/static/vendor/focus-trap/); this modal previously had no
  // keyboard containment at all -- #1244's audit flagged it as one of two
  // dialogs in the dashboard missing the trap every other one already
  // implements. It shows other users' captured report data (DOM snapshot,
  // API bodies) to an admin, so the gap mattered more here than most.
  const trap = modal ? window.focusTrap.createFocusTrap(modal, {
    escapeDeactivates: false,
    clickOutsideDeactivates: false,
    initialFocus: () => modal.querySelector("[data-hp-pr-detail-close]") || modal,
    fallbackFocus: () => modal,
    setReturnFocus: () => (restoreFocus?.isConnected ? restoreFocus : false),
  }) : null;

  function esc(s) {
    const div = document.createElement("div");
    div.textContent = s == null ? "" : String(s);
    return div.innerHTML;
  }

  function renderDetail(report) {
    const trail = (report.action_trail || [])
      .map(a => `<div>${esc(a.at)} — ${esc(a.kind)}: ${esc(a.detail)}</div>`)
      .join("");
    const errors = (report.console_errors || []).map(e => `<div>${esc(e)}</div>`).join("");
    const failures = (report.network_failures || []).map(f => `<div>${esc(f)}</div>`).join("");
    const apiCalls = (report.api_calls || [])
      .map(
        c =>
          `<div><strong>${esc(c.method)} ${esc(c.url)} -&gt; ${esc(c.status)}</strong>` +
          (c.request_body ? `<pre>${esc(c.request_body)}</pre>` : "") +
          (c.response_body ? `<pre>${esc(c.response_body)}</pre>` : "") +
          `</div>`
      )
      .join("");
    body.innerHTML = `
      <h3>Action trail</h3>${trail || "<p class=\"note\">None captured.</p>"}
      <h3>Console errors</h3>${errors || "<p class=\"note\">None captured.</p>"}
      <h3>Failed network requests</h3>${failures || "<p class=\"note\">None captured.</p>"}
      <h3>API calls</h3>${apiCalls || "<p class=\"note\">None captured.</p>"}
      <h3>DOM snapshot</h3><pre>${esc(report.dom_snapshot || "")}</pre>
      <h3>User agent</h3><p>${esc(report.user_agent || "")}</p>
    `;
  }

  document.querySelectorAll("[data-hp-pr-details]").forEach(btn => {
    btn.addEventListener("click", () => {
      const report = byId.get(btn.dataset.id);
      if (!report || !body) return;
      renderDetail(report);
      restoreFocus = btn;
      backdrop.hidden = false;
      modal.hidden = false;
      // theme.css's .modal/.modal-backdrop are display:none by default --
      // only .open (not the hidden attribute) actually makes them visible.
      backdrop.classList.add("open");
      modal.classList.add("open");
      trap.activate();
    });
  });

  function closeModal() {
    trap.deactivate();
    backdrop.hidden = true;
    modal.hidden = true;
    backdrop.classList.remove("open");
    modal.classList.remove("open");
    // Not nulled here: focus-trap's deactivate() restores focus via a
    // setTimeout(0), so setReturnFocus's closure must still see this value
    // when that deferred callback runs. The click handler above overwrites
    // it next time.
  }
  const closeBtn = modal ? modal.querySelector("[data-hp-pr-detail-close]") : null;
  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (backdrop) backdrop.addEventListener("click", closeModal);
  document.addEventListener("keydown", event => {
    if (!modal || modal.hidden) return;
    if (window.HoneypotModals?.isOpen()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeModal();
    }
  });
})();
