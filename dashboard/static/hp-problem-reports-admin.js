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
      backdrop.hidden = false;
      modal.hidden = false;
    });
  });

  function closeModal() {
    backdrop.hidden = true;
    modal.hidden = true;
  }
  const closeBtn = modal ? modal.querySelector("[data-hp-pr-detail-close]") : null;
  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (backdrop) backdrop.addEventListener("click", closeModal);
})();
