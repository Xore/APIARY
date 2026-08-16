/* hp-canarytokens.js -- #1487: the standalone /canarytokens page (Tokens /
 * Create bait / Reports tabs). The page ships an instant skeleton with no
 * server-side query (routes.go's GET /canarytokens just renders the shell);
 * every tab hydrates itself here, in parallel, on load -- not lazily on tab
 * activation -- so all three are populated in the background regardless of
 * which one the operator lands on first, same convention as the rest of
 * this dashboard's shell+hydrate pages.
 *
 * Reuses the existing #1508 endpoints as-is (/api/settings/canarytokens*)
 * plus the existing generic /api/events?sensor=canarytokens for the Reports
 * tab (classify.go already classifies canarytokens-adapter's fired-token
 * events, #1426) -- no new backend surface for Reports.
 *
 * Tab switching itself is the dashboard-wide data-dashboard-tab/
 * data-dashboard-panel delegated handler already in hp-app.js; nothing here
 * re-implements it.
 */
(() => {
  "use strict";

  function q(id) { return document.getElementById(id); }

  async function api(path, options) {
    const response = await fetch(path, { cache: "no-store", ...options });
    if (!response.ok) {
      const error = new Error(await response.text().catch(() => response.statusText));
      error.status = response.status;
      throw error;
    }
    return response.json();
  }

  function fmtTime(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
  }

  function setSkeletonState(tbody, emptyEl, errorEl, rows, renderRow, colspan, emptyMessage) {
    tbody.removeAttribute("aria-busy");
    tbody.textContent = "";
    if (errorEl) errorEl.hidden = true;
    if (!rows || !rows.length) {
      if (emptyEl) { emptyEl.hidden = false; if (emptyMessage) emptyEl.textContent = emptyMessage; }
      return;
    }
    if (emptyEl) emptyEl.hidden = true;
    rows.forEach(row => tbody.appendChild(renderRow(row)));
  }

  function showLoadError(tbody, emptyEl, errorEl, error) {
    tbody.removeAttribute("aria-busy");
    tbody.textContent = "";
    if (emptyEl) emptyEl.hidden = true;
    if (errorEl) { errorEl.hidden = false; errorEl.textContent = "Could not load — " + error.message.trim(); }
  }

  /* ---------------- Tokens tab ---------------- */

  let typesByKey = null;

  function artifactCell(record) {
    const cell = document.createElement("td");
    if (record.download_url) {
      const link = document.createElement("a");
      link.className = "btn btn-ghost btn-sm";
      link.href = record.download_url;
      link.textContent = "Download";
      cell.appendChild(link);
    } else if (record.token_url) {
      const link = document.createElement("a");
      link.className = "btn btn-ghost btn-sm";
      link.href = record.token_url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Embed URL";
      cell.appendChild(link);
    } else {
      cell.textContent = "—";
    }
    return cell;
  }

  function renderTokenRow(record) {
    const row = document.createElement("tr");
    const type = document.createElement("td");
    type.textContent = (typesByKey && typesByKey[record.token_type] && typesByKey[record.token_type].label) || record.token_type;
    row.appendChild(type);
    const memo = document.createElement("td");
    memo.textContent = record.memo || "—";
    row.appendChild(memo);
    const created = document.createElement("td");
    created.textContent = fmtTime(record.created_at);
    row.appendChild(created);
    const by = document.createElement("td");
    by.textContent = record.created_by || "—";
    row.appendChild(by);
    row.appendChild(artifactCell(record));
    return row;
  }

  async function loadTokens() {
    const tbody = q("ct-tokens-tbody");
    const emptyEl = q("ct-tokens-empty");
    const errorEl = q("ct-tokens-error");
    try {
      const body = await api("/api/settings/canarytokens");
      setSkeletonState(tbody, emptyEl, errorEl, body.tokens, renderTokenRow, 5);
    } catch (error) {
      showLoadError(tbody, emptyEl, errorEl, error);
    }
  }

  /* ---------------- Create bait tab ---------------- */

  function updateCreateFormForType() {
    if (!typesByKey) return;
    const info = typesByKey[q("ct-type").value] || {};
    const desc = q("ct-type-desc");
    if (desc) desc.textContent = info.description || "";
    const uploadRow = q("ct-upload-row");
    if (uploadRow) uploadRow.hidden = !info.requires_upload;
    const fileInput = q("ct-file");
    if (fileInput) fileInput.required = Boolean(info.requires_upload);
    const snippetRow = q("ct-snippet-row");
    if (snippetRow) snippetRow.hidden = !info.supports_snippet;
  }

  async function loadTypesAndWireForm() {
    const unavailable = q("ct-create-unavailable");
    const form = q("ct-create-form");
    const select = q("ct-type");
    try {
      const body = await api("/api/settings/canarytokens/types");
      typesByKey = {};
      (body.types || []).forEach(t => { typesByKey[t.key] = t; });
      select.removeAttribute("aria-busy");
      select.textContent = "";
      (body.types || []).forEach(t => {
        const option = document.createElement("option");
        option.value = t.key;
        option.textContent = t.label;
        select.appendChild(option);
      });
      if (unavailable) unavailable.hidden = Boolean(body.available);
      form.removeAttribute("aria-busy");
      if (!body.available) {
        Array.from(form.elements).forEach(el => { el.disabled = true; });
      }
      updateCreateFormForType();
    } catch (error) {
      form.removeAttribute("aria-busy");
      if (unavailable) { unavailable.hidden = false; unavailable.textContent = "Canarytoken types could not be loaded — " + error.message.trim(); }
      Array.from(form.elements).forEach(el => { el.disabled = true; });
    }
  }

  function wireCreateForm() {
    q("ct-type").addEventListener("change", updateCreateFormForType);
    const snippetToggle = q("ct-snippet-toggle");
    snippetToggle.addEventListener("change", () => { q("ct-snippet-text").disabled = !snippetToggle.checked; });

    q("ct-create-form").addEventListener("submit", async event => {
      event.preventDefault();
      const resultEl = q("ct-create-result");
      const submitBtn = q("ct-create-submit");
      const info = (typesByKey && typesByKey[q("ct-type").value]) || {};
      const fileInput = q("ct-file");

      if (info.requires_upload && (!fileInput.files || !fileInput.files.length)) {
        resultEl.hidden = false;
        resultEl.textContent = "Choose a file to upload first.";
        return;
      }

      const formData = new FormData();
      formData.set("token_type", q("ct-type").value);
      formData.set("memo", q("ct-memo").value.trim());
      if (info.supports_snippet && snippetToggle.checked) {
        formData.set("include_text_snippet", "true");
        formData.set("text_snippet", q("ct-snippet-text").value);
      }
      if (info.requires_upload && fileInput.files.length) formData.set("file", fileInput.files[0]);

      submitBtn.disabled = true;
      try {
        const record = await api("/api/settings/canarytokens/create", { method: "POST", body: formData });
        resultEl.hidden = false;
        resultEl.textContent = record.embed_only
          ? "Created. Embed this URL wherever the image should live: " + record.token_url
          : "Created. Use the Download link on the Tokens tab to get the artifact.";
        q("ct-memo").value = "";
        if (fileInput) fileInput.value = "";
        await loadTokens();
      } catch (error) {
        resultEl.hidden = false;
        resultEl.textContent = "Creation failed — " + error.message.trim();
      } finally {
        submitBtn.disabled = false;
      }
    });
  }

  /* ---------------- Reports tab ---------------- */

  function renderFiredRow(ev) {
    const row = document.createElement("tr");
    const time = document.createElement("td");
    time.textContent = ev.Time || ev.UTC || "—";
    row.appendChild(time);
    const ip = document.createElement("td");
    ip.className = "mono";
    ip.textContent = ev.SrcIP || "—";
    row.appendChild(ip);
    const country = document.createElement("td");
    country.textContent = ev.Country || "—";
    row.appendChild(country);
    const proto = document.createElement("td");
    proto.textContent = ev.Proto || "—";
    row.appendChild(proto);
    const detail = document.createElement("td");
    detail.textContent = ev.Detail || "—";
    row.appendChild(detail);
    const manage = document.createElement("td");
    if (ev.Path) {
      const link = document.createElement("a");
      link.className = "btn btn-ghost btn-sm";
      link.href = ev.Path;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Manage token";
      manage.appendChild(link);
    } else {
      manage.textContent = "—";
    }
    row.appendChild(manage);
    return row;
  }

  async function loadReports() {
    const tbody = q("ct-reports-tbody");
    const emptyEl = q("ct-reports-empty");
    const errorEl = q("ct-reports-error");
    try {
      const body = await api("/api/events?sensor=canarytokens&page=1&per_page=50");
      setSkeletonState(tbody, emptyEl, errorEl, body.Events, renderFiredRow, 6);
    } catch (error) {
      showLoadError(tbody, emptyEl, errorEl, error);
    }
  }

  /* ---------------- init ---------------- */

  document.addEventListener("DOMContentLoaded", () => {
    wireCreateForm();
    // All three tabs hydrate together, in the background, regardless of
    // which one is active on load -- not gated on tab activation.
    loadTokens();
    loadTypesAndWireForm();
    loadReports();
    q("ct-tokens-refresh").addEventListener("click", loadTokens);
    q("ct-reports-refresh").addEventListener("click", loadReports);
  });
})();
