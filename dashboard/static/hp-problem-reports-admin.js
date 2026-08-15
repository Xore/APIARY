/* /admin/problem-reports controller: status changes plus an in-flow,
 * bounded master/detail view of the complete captured report context.
 * The reports are already embedded by problem_reports.html, so selecting a
 * row hydrates the visible card collection without another request.
 */
(function () {
  "use strict";

  const reports = Array.isArray(window.__hpProblemReports) ? window.__hpProblemReports : [];
  const byId = new Map(reports.map(report => [report.id, report]));
  const panel = document.getElementById("hp-pr-detail-panel");
  const body = panel?.querySelector("[data-hp-pr-detail-body]");
  let selectedID = "";

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }

  function empty(text) {
    return el("p", "empty", text);
  }

  function scrollList(items, render) {
    if (!items?.length) return empty("None captured.");
    const scroll = el("div", "card__scroll");
    items.forEach((item, index) => scroll.appendChild(render(item, index)));
    return scroll;
  }

  function card(title, className = "wide") {
    const node = el("article", `card ${className}`);
    node.appendChild(el("h3", "", title));
    return node;
  }

  function row(label, value, mono = false) {
    const node = el("div", "card__row");
    node.appendChild(el("span", "card__label", label));
    node.appendChild(el("span", `card__value${mono ? " card__value--mono" : ""}`, value || "—"));
    return node;
  }

  function textCard(title, value, className = "half") {
    const node = card(title, className);
    const scroll = el("div", "card__scroll");
    scroll.appendChild(el("pre", "code", value || "None captured."));
    node.appendChild(scroll);
    return node;
  }

  function renderDetail(report) {
    if (!body || !panel || !report) return;
    selectedID = report.id;
    body.replaceChildren();
    const grid = el("div", "tw:grid tw:grid-cols-12 tw:gap-3.5");

    const identity = card("Report identity");
    const submitted = row("submitted", report.submitted_at || "—", true);
    const submittedValue = submitted.querySelector(".card__value");
    if (report.submitted_at && submittedValue) submittedValue.dataset.hpUtc = report.submitted_at;
    identity.append(
      row("report ID", report.id, true),
      submitted,
      row("submitted by", report.submitted_by_name || report.submitted_by || "—"),
      row("identity subject", report.submitted_by || "—", true),
      row("page", report.page || "—", true),
      row("status", report.status || "open"),
    );
    grid.append(identity, textCard("Expected behavior", report.expected), textCard("Actual behavior", report.actual));

    const trail = card("Action trail");
    trail.appendChild(scrollList(report.action_trail, action => {
      const item = el("div", "card__row");
      item.append(el("span", "card__label", `${action.at || "unknown time"} · ${action.kind || "action"}`), el("span", "card__value card__value--mono", action.detail || "—"));
      return item;
    }));
    grid.appendChild(trail);

    const consoleCard = card("Console errors", "half");
    consoleCard.appendChild(scrollList(report.console_errors, error => row("error", error, true)));
    const networkCard = card("Failed network requests", "half");
    networkCard.appendChild(scrollList(report.network_failures, failure => row("failure", failure, true)));
    grid.append(consoleCard, networkCard);

    const apiCard = card("API calls");
    apiCard.appendChild(scrollList(report.api_calls, call => {
      const item = el("article", "project-card");
      item.appendChild(el("div", "project-card__title", `${call.method || "GET"} ${call.url || "—"} → ${call.status ?? "—"}`));
      if (call.at) item.appendChild(el("p", "note", call.at));
      if (call.request_body) item.appendChild(textCard("Request body", call.request_body));
      if (call.response_body) item.appendChild(textCard("Response body", call.response_body));
      return item;
    }));
    grid.appendChild(apiCard);

    grid.append(textCard("DOM snapshot", report.dom_snapshot, "wide"), textCard("User agent", report.user_agent, "wide"));
    body.appendChild(grid);
    panel.setAttribute("aria-busy", "false");
    document.querySelectorAll("[data-hp-pr-details]").forEach(button => {
      const active = button.dataset.id === selectedID;
      button.setAttribute("aria-pressed", String(active));
      button.textContent = active ? "Selected" : "Select";
    });
    window.applyHoneypotTimezone?.(body);
  }

  document.querySelectorAll("[data-hp-pr-status]").forEach(select => {
    select.addEventListener("change", async () => {
      const id = select.dataset.id;
      const report = byId.get(id);
      const previous = report?.status || "open";
      try {
        const response = await fetch("/api/problem-reports/" + encodeURIComponent(id), {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: select.value }),
        });
        if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
        if (report) report.status = select.value;
        if (id === selectedID) renderDetail(report);
      } catch (err) {
        select.value = previous;
        alert("Failed to update status: " + (err?.message || "unknown error"));
      }
    });
  });

  document.querySelectorAll("[data-hp-pr-details]").forEach(button => {
    button.addEventListener("click", () => {
      const report = byId.get(button.dataset.id);
      if (!report) return;
      renderDetail(report);
      panel?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    });
  });

  if (reports.length) renderDetail(reports[0]);
})();
