/* Reports studio — designer, saved definitions, and generated reports.
 *
 * Framework-free controller for /reports against the admin-only API:
 *   GET    /api/reports/templates                  catalog (templates, elements)
 *   GET    /api/reports/definitions                list (+ ETag)
 *   POST   /api/reports/definitions                create
 *   PATCH  /api/reports/definitions/{id}           replace (If-Match)
 *   DELETE /api/reports/definitions/{id}
 *   POST   /api/reports/definitions/{id}/generate  render + store the PDF
 *   GET    /api/reports/generated                  history (newest first)
 *   GET    /api/reports/generated/{id}/pdf         inline; ?download=1 attachment
 *   DELETE /api/reports/generated/{id}
 * Sandbox jobs come from the existing /api/sandbox listing. Destructive
 * actions confirm through the shared HoneypotModals dialog.
 */
(() => {
  "use strict";

  const root = document.querySelector("[data-hp-reports]");
  if (!root) return;

  const $ = (id) => document.getElementById(id);
  const els = {
    templates: $("hp-rp-templates"),
    form: $("hp-rp-form"),
    name: $("hp-rp-name"),
    window: $("hp-rp-window"),
    appendix: $("hp-rp-appendix"),
    theme: $("hp-rp-theme"),
    elements: $("hp-rp-elements"),
    elementsSection: $("hp-rp-elements-section"),
    scopeSection: $("hp-rp-scope-section"),
    sandboxSection: $("hp-rp-sandbox-section"),
    sandboxJob: $("hp-rp-sandbox-job"),
    brandTitle: $("hp-rp-brand-title"),
    brandAuthor: $("hp-rp-brand-author"),
    brandHeaderLeft: $("hp-rp-brand-header-left"),
    brandHeaderRight: $("hp-rp-brand-header-right"),
    brandFooter: $("hp-rp-brand-footer"),
    brandClassification: $("hp-rp-brand-classification"),
    schedEnabled: $("hp-rp-sched-enabled"),
    schedFrequency: $("hp-rp-sched-frequency"),
    schedHour: $("hp-rp-sched-hour"),
    schedMinute: $("hp-rp-sched-minute"),
    schedWeekday: $("hp-rp-sched-weekday"),
    schedWeekdayField: $("hp-rp-sched-weekday-field"),
    schedMonthDay: $("hp-rp-sched-monthday"),
    schedMonthDayField: $("hp-rp-sched-monthday-field"),
    save: $("hp-rp-save"),
    generate: $("hp-rp-generate"),
    reset: $("hp-rp-reset"),
    status: $("hp-rp-status"),
    definitions: $("hp-rp-definitions"),
    definitionsEmpty: $("hp-rp-definitions-empty"),
    generated: $("hp-rp-generated"),
    generatedEmpty: $("hp-rp-generated-empty"),
    viewerBackdrop: $("hp-rp-viewer-backdrop"),
    viewer: $("hp-rp-viewer"),
    viewerTitle: $("hp-rp-viewer-title"),
    viewerFrame: $("hp-rp-viewer-frame"),
    viewerClose: $("hp-rp-viewer-close"),
    adminNote: $("hp-rp-admin-note"),
  };

  const state = {
    templates: [],
    elements: [],
    windows: [],
    definitions: [],
    generated: [],
    etag: "",
    editing: null, // definition id loaded into the designer
    template: null, // currently selected template object
    theme: "dark",
    forbidden: false,
    // True while a save/generate triggered from the designer (Save
    // definition, Generate now, or a native Enter-key submit of the name
    // field) is in flight. Both buttons share one flag rather than each
    // guarding itself: Enter in #hp-rp-name fires the form's native submit
    // (Save) independently of a near-simultaneous click on Generate, and
    // without a shared guard both call saveDefinition() concurrently,
    // producing a genuine 409 for whichever read the ETag second (#211).
    busy: false,
    viewerOpen: false,
    viewerRestoreFocus: null,
  };

  function setStatus(message, kind) {
    els.status.textContent = message || "";
    els.status.dataset.state = kind || "";
    if (kind) {
      window.setTimeout(() => {
        if (els.status.dataset.state === kind) {
          els.status.textContent = "";
          els.status.dataset.state = "";
        }
      }, 6000);
    }
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      cache: "no-store",
      ...options,
      headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) },
    });
    if (response.status === 403) {
      state.forbidden = true;
      showForbidden();
      throw new Error("administrator role required");
    }
    if (!response.ok) {
      const text = (await response.text()).trim();
      throw new Error(text || `request failed (${response.status})`);
    }
    return response;
  }

  async function apiJSON(path, options) {
    return (await api(path, options)).json();
  }

  function showForbidden() {
    els.adminNote.hidden = false;
    els.form.querySelectorAll("input, select, button").forEach((control) => { control.disabled = true; });
  }

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // -------------------------------------------------------------------------
  // Designer
  // -------------------------------------------------------------------------

  function renderTemplates() {
    els.templates.innerHTML = state.templates.map((template) => `
      <button type="button" class="hp-rp-template" data-template="${escapeHTML(template.id)}" aria-pressed="${state.template && state.template.id === template.id}">
        <strong>${escapeHTML(template.name)}</strong>
        <span>${escapeHTML(template.description)}</span>
      </button>`).join("");
    els.templates.querySelectorAll("[data-template]").forEach((button) => {
      button.addEventListener("click", () => selectTemplate(button.dataset.template, true));
    });
  }

  function renderElementChoices() {
    els.elements.innerHTML = state.elements.map((element) => `
      <label title="${escapeHTML(element.description)}">
        <input type="checkbox" value="${escapeHTML(element.id)}">
        <span>${escapeHTML(element.label)}<small>${escapeHTML(element.description)}</small></span>
      </label>`).join("");
  }

  function renderWindowChoices() {
    els.window.innerHTML = `<option value="">full observation window</option>` +
      state.windows.map((w) => `<option value="${escapeHTML(w)}">last ${escapeHTML(w)}</option>`).join("");
  }

  function currentTemplate() {
    return state.templates.find((template) => template.id === (state.template && state.template.id)) || null;
  }

  /* Show or hide one studio step. If the step being hidden is the one on
     screen, fall back to Design rather than leaving the operator on a blank
     panel. */
  function setStepAvailable(name, available) {
    const tab = document.querySelector(`[data-dashboard-tab="${name}"]`);
    if (!tab) return;
    tab.hidden = !available;
    if (!available && tab.classList.contains("active")) {
      document.querySelector('[data-dashboard-tab="design"]')?.click();
    }
  }

  function selectTemplate(id, applyPreset) {
    const template = state.templates.find((candidate) => candidate.id === id);
    if (!template) return;
    state.template = template;
    renderTemplates();
    const sandbox = !!template.sandbox;
    els.sandboxSection.hidden = !sandbox;
    els.elementsSection.hidden = sandbox;
    els.scopeSection.hidden = sandbox;
    // A sandbox report is scoped by its analysis job, so the Scope step does
    // not apply: hide the tab too, or it would open an empty panel.
    setStepAvailable("scope", !sandbox);
    if (sandbox) loadSandboxJobs();
    if (applyPreset) {
      state.editing = null;
      els.save.textContent = "Save definition";
      setTheme(template.theme || "dark");
      els.window.value = template.window || "";
      els.elements.querySelectorAll("input[type=checkbox]").forEach((box) => {
        box.checked = (template.elements || []).includes(box.value);
      });
      if (!els.name.value || els.name.dataset.touched !== "true") els.name.value = "";
      setStatus(`Template “${template.name}” loaded — adjust anything, then save or generate.`);
    }
  }

  function setTheme(theme) {
    state.theme = theme === "light" ? "light" : "dark";
    els.theme.querySelectorAll("button[data-theme]").forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.theme === state.theme));
    });
  }

  els.theme.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-theme]");
    if (button) setTheme(button.dataset.theme);
  });
  els.name.addEventListener("input", () => { els.name.dataset.touched = "true"; });

  function readDesigner() {
    const template = currentTemplate();
    if (!template) throw new Error("pick a template first");
    const scope = {
      window: els.window.value,
      ip: $("hp-rp-scope-ip").value.trim(),
      network: $("hp-rp-scope-network").value.trim(),
      sensor: $("hp-rp-scope-sensor").value.trim(),
      port: $("hp-rp-scope-port").value.trim(),
      signature: $("hp-rp-scope-signature").value.trim(),
      country: $("hp-rp-scope-country").value.trim(),
      asn: $("hp-rp-scope-asn").value.trim(),
      type: $("hp-rp-scope-type").value,
      session: $("hp-rp-scope-session").value.trim(),
      text: $("hp-rp-scope-text").value.trim(),
    };
    const definition = {
      name: els.name.value.trim(),
      template: template.id,
      theme: state.theme,
      branding: {
        title: els.brandTitle.value.trim(),
        author: els.brandAuthor.value.trim(),
        header_left: els.brandHeaderLeft.value.trim(),
        header_right: els.brandHeaderRight.value.trim(),
        footer_left: els.brandFooter.value.trim(),
        classification: els.brandClassification.value.trim(),
      },
      scope,
      appendix_limit: Math.max(0, Math.min(500, parseInt(els.appendix.value, 10) || 0)),
    };
    if (template.sandbox) {
      scope.job = els.sandboxJob.value;
      if (!scope.job) throw new Error("select a sandbox analysis job");
    } else {
      definition.elements = Array.from(els.elements.querySelectorAll("input[type=checkbox]:checked")).map((box) => box.value);
      if (definition.elements.length === 0) throw new Error("select at least one report element");
    }
    if (!definition.name) throw new Error("give the report a name");
    if (els.schedEnabled.checked) {
      definition.schedule = {
        enabled: true,
        frequency: els.schedFrequency.value,
        hour: Math.max(0, Math.min(23, parseInt(els.schedHour.value, 10) || 0)),
        minute: Math.max(0, Math.min(59, parseInt(els.schedMinute.value, 10) || 0)),
      };
      if (definition.schedule.frequency === "weekly") {
        definition.schedule.weekday = parseInt(els.schedWeekday.value, 10) || 0;
      } else if (definition.schedule.frequency === "monthly") {
        definition.schedule.month_day = Math.max(1, Math.min(28, parseInt(els.schedMonthDay.value, 10) || 1));
      }
    }
    // Keep empty objects out of the payload.
    if (Object.values(definition.branding).every((value) => !value)) delete definition.branding;
    Object.keys(scope).forEach((key) => { if (!scope[key]) delete scope[key]; });
    if (Object.keys(scope).length === 0) delete definition.scope;
    return definition;
  }

  function fillDesigner(definition) {
    state.editing = definition.id;
    els.save.textContent = "Update definition";
    els.name.value = definition.name || "";
    els.name.dataset.touched = "true";
    selectTemplate(definition.template, false);
    setTheme(definition.theme || "dark");
    const scope = definition.scope || {};
    els.window.value = scope.window || "";
    $("hp-rp-scope-ip").value = scope.ip || "";
    $("hp-rp-scope-network").value = scope.network || "";
    $("hp-rp-scope-sensor").value = scope.sensor || "";
    $("hp-rp-scope-port").value = scope.port || "";
    $("hp-rp-scope-signature").value = scope.signature || "";
    $("hp-rp-scope-country").value = scope.country || "";
    $("hp-rp-scope-asn").value = scope.asn || "";
    $("hp-rp-scope-type").value = scope.type || "";
    $("hp-rp-scope-session").value = scope.session || "";
    $("hp-rp-scope-text").value = scope.text || "";
    els.appendix.value = definition.appendix_limit || 120;
    const branding = definition.branding || {};
    els.brandTitle.value = branding.title || "";
    els.brandAuthor.value = branding.author || "";
    els.brandHeaderLeft.value = branding.header_left || "";
    els.brandHeaderRight.value = branding.header_right || "";
    els.brandFooter.value = branding.footer_left || "";
    els.brandClassification.value = branding.classification || "";
    const schedule = definition.schedule;
    els.schedEnabled.checked = !!(schedule && schedule.enabled);
    if (schedule && schedule.enabled) {
      els.schedFrequency.value = schedule.frequency || "daily";
      els.schedHour.value = schedule.hour ?? 6;
      els.schedMinute.value = schedule.minute ?? 30;
      els.schedWeekday.value = String(schedule.weekday ?? 1);
      els.schedMonthDay.value = schedule.month_day || 1;
    }
    syncScheduleFields();
    els.elements.querySelectorAll("input[type=checkbox]").forEach((box) => {
      box.checked = (definition.elements || []).includes(box.value);
    });
    if (scope.job) {
      loadSandboxJobs().then(() => { els.sandboxJob.value = scope.job; });
    }
    setStatus(`Editing “${definition.name}” — save to update, or generate a fresh PDF.`);
  }

  async function loadSandboxJobs() {
    if (els.sandboxJob.dataset.loaded === "true") return;
    try {
      const rows = await apiJSON("/api/sandbox");
      const jobs = (Array.isArray(rows) ? rows : []).filter((row) => row && row.job);
      els.sandboxJob.innerHTML = `<option value="">select an analysis run…</option>` + jobs.map((row) => {
        const label = `${row.job} — ${String(row.sha256 || "").slice(0, 12)}… (${escapeHTML(row.risk_level || "unrated")})`;
        return `<option value="${escapeHTML(row.job)}">${label}</option>`;
      }).join("");
      els.sandboxJob.dataset.loaded = "true";
    } catch {
      els.sandboxJob.innerHTML = `<option value="">sandbox results unavailable</option>`;
    }
  }

  async function saveDefinition() {
    const definition = readDesigner();
    const editing = state.editing;
    const path = editing ? `/api/reports/definitions/${editing}` : "/api/reports/definitions";
    const response = await api(path, {
      method: editing ? "PATCH" : "POST",
      body: JSON.stringify(definition),
      headers: state.etag ? { "If-Match": state.etag } : {},
    });
    const payload = await response.json();
    state.etag = response.headers.get("ETag") || state.etag;
    state.editing = payload.definition.id;
    els.save.textContent = "Update definition";
    setStatus(`Definition “${payload.definition.name}” saved.`, "ok");
    await refreshDefinitions();
    return payload.definition;
  }

  async function generateFrom(definitionID) {
    const response = await api(`/api/reports/definitions/${definitionID}/generate`, { method: "POST" });
    const payload = await response.json();
    await refreshGenerated();
    setStatus("Report generated — opening the viewer.", "ok");
    openViewer(payload.generated);
    return payload.generated;
  }

  function withDesignerBusy(task) {
    if (state.busy) return;
    state.busy = true;
    els.save.disabled = true;
    els.generate.disabled = true;
    task().catch((error) => setStatus(error.message, "error")).finally(() => {
      state.busy = false;
      // showForbidden() disables every control in the form permanently on a
      // 403 (role revoked mid-session); do not undo that.
      if (state.forbidden) return;
      els.save.disabled = false;
      els.generate.disabled = false;
    });
  }

  els.form.addEventListener("submit", (event) => {
    event.preventDefault();
    withDesignerBusy(saveDefinition);
  });

  els.generate.addEventListener("click", () => {
    setStatus("Generating…");
    withDesignerBusy(async () => {
      const definition = await saveDefinition(); // keep the stored design in sync before rendering
      await generateFrom(definition.id);
    });
  });

  els.reset.addEventListener("click", () => {
    if (state.template) selectTemplate(state.template.id, true);
    els.form.querySelectorAll(".hp-rp-field input").forEach((input) => { input.value = ""; });
    els.appendix.value = 120;
    els.schedEnabled.checked = false;
    state.editing = null;
    els.save.textContent = "Save definition";
  });

  function syncScheduleFields() {
    const frequency = els.schedFrequency.value;
    els.schedWeekdayField.hidden = frequency !== "weekly";
    els.schedMonthDayField.hidden = frequency !== "monthly";
  }
  els.schedFrequency.addEventListener("change", syncScheduleFields);

  const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

  function scheduleSummary(schedule) {
    if (!schedule || !schedule.enabled) return `<span class="hp-rp-tag">off</span>`;
    const time = `${String(schedule.hour).padStart(2, "0")}:${String(schedule.minute).padStart(2, "0")} UTC`;
    let cadence = `daily ${time}`;
    if (schedule.frequency === "weekly") cadence = `${WEEKDAYS[schedule.weekday] || "weekly"} ${time}`;
    if (schedule.frequency === "monthly") cadence = `day ${schedule.month_day} ${time}`;
    const next = schedule.next_run_at ? `<br><small>next ${escapeHTML(formatTime(schedule.next_run_at))}</small>` : "";
    return `${escapeHTML(cadence)}${next}`;
  }

  // -------------------------------------------------------------------------
  // Saved definitions
  // -------------------------------------------------------------------------

  async function refreshDefinitions() {
    const response = await api("/api/reports/definitions");
    state.etag = response.headers.get("ETag") || state.etag;
    const payload = await response.json();
    state.definitions = payload.definitions || [];
    els.definitionsEmpty.hidden = state.definitions.length > 0;
    els.definitions.innerHTML = state.definitions.map((definition) => `
      <tr>
        <td><strong>${escapeHTML(definition.name)}</strong></td>
        <td><span class="hp-rp-tag">${escapeHTML(definition.template)}</span></td>
        <td>${escapeHTML(definition.theme)}</td>
        <td>${escapeHTML((definition.scope && definition.scope.window) || "full")}</td>
        <td>${scheduleSummary(definition.schedule)}</td>
        <td>${escapeHTML(formatTime(definition.updated))}</td>
        <td><div class="hp-rp-row-actions">
          <button class="btn btn-sm btn-secondary" type="button" data-edit="${escapeHTML(definition.id)}">Edit</button>
          <button class="btn btn-sm btn-primary" type="button" data-run="${escapeHTML(definition.id)}">Generate</button>
          <button class="btn btn-sm btn-danger" type="button" data-drop="${escapeHTML(definition.id)}" data-name="${escapeHTML(definition.name)}">Delete</button>
        </div></td>
      </tr>`).join("");
  }

  els.definitions.addEventListener("click", (event) => {
    const edit = event.target.closest("[data-edit]");
    const run = event.target.closest("[data-run]");
    const drop = event.target.closest("[data-drop]");
    if (edit) {
      const definition = state.definitions.find((candidate) => candidate.id === edit.dataset.edit);
      if (definition) {
        fillDesigner(definition);
        window.scrollTo({ top: 0, behavior: "smooth" });
      }
    } else if (run) {
      // Per-row guard, independent of the designer's shared busy flag and of
      // every other row's own button: nothing here needs saveDefinition(),
      // so only this one button double-clicking can double-generate (#211).
      if (run.disabled) return;
      run.disabled = true;
      generateFrom(run.dataset.run)
        .catch((error) => setStatus(error.message, "error"))
        .finally(() => { if (!state.forbidden) run.disabled = false; });
    } else if (drop) {
      confirmAction(drop, {
        title: `Delete “${drop.dataset.name}”?`,
        description: "The saved design is removed. Reports already generated from it stay in the history below.",
        confirmLabel: "Delete definition",
        onConfirm: async () => {
          await api(`/api/reports/definitions/${drop.dataset.drop}`, {
            method: "DELETE",
            headers: state.etag ? { "If-Match": state.etag } : {},
          });
          if (state.editing === drop.dataset.drop) {
            state.editing = null;
            els.save.textContent = "Save definition";
          }
          await refreshDefinitions();
          return "Definition deleted.";
        },
      });
    }
  });

  // -------------------------------------------------------------------------
  // Generated reports
  // -------------------------------------------------------------------------

  function formatTime(value) {
    if (!value) return "";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function formatSize(bytes) {
    if (!bytes) return "0 KB";
    if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  // Each report is a .project-card (#227) -- selecting it opens the same
  // inline viewer the old "View" button did. It can't be a real <a> (the
  // Download link and Delete button inside it are both interactive content,
  // which HTML forbids nesting inside a link), so it gets a role="button"
  // and its own click/keydown handling below instead, exactly mirroring
  // what a native <a>/<button> would give for free.
  async function refreshGenerated() {
    const payload = await apiJSON("/api/reports/generated");
    state.generated = payload.generated || [];
    els.generatedEmpty.hidden = state.generated.length > 0;
    els.generated.innerHTML = state.generated.map((report) => `
      <article class="project-card" data-hp-report-card="${escapeHTML(report.id)}" role="button" tabindex="0" aria-label="View ${escapeHTML(report.title || report.name)}">
        <div class="project-card__header">
          <span class="project-card__icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></span>
          <span class="project-card__title">${escapeHTML(report.title || report.name)}</span>
          <div class="project-card__badges">
            <span class="badge badge--muted">${escapeHTML(report.template)}</span>
            <span class="badge badge--muted">${escapeHTML(report.theme)}</span>
          </div>
        </div>
        <p class="project-card__desc">${escapeHTML(report.origin)} &bull; ${escapeHTML(formatSize(report.size_bytes))}</p>
        <div class="project-card__meta">
          <span>${escapeHTML(formatTime(report.created_at))}</span>
          <div class="hp-rp-row-actions" data-hp-report-actions>
            <a class="btn btn-sm btn-primary" href="/api/reports/generated/${escapeHTML(report.id)}/pdf?download=1">Download</a>
            <button class="btn btn-sm btn-danger" type="button" data-purge="${escapeHTML(report.id)}" data-name="${escapeHTML(report.title || report.name)}">Delete</button>
          </div>
        </div>
      </article>`).join("");
  }

  // Centered application-managed overlay, opened/closed the same way as the
  // dashboard settings modal (hp-settings.js): inert + aria-hidden toggled
  // alongside .open, focus moved to the close control on open and restored
  // to the trigger on close, Escape/Tab handled below (#211 -- this used to
  // render inline below the generated-reports grid instead of as a modal).
  function openViewer(report) {
    if (state.viewerOpen) return;
    state.viewerOpen = true;
    state.viewerRestoreFocus = document.activeElement;
    els.viewerTitle.textContent = report.title || report.name || "Generated report";
    els.viewerFrame.src = `/api/reports/generated/${report.id}/pdf`;
    els.viewerBackdrop.inert = false;
    els.viewerBackdrop.setAttribute("aria-hidden", "false");
    els.viewerBackdrop.classList.add("open");
    els.viewer.inert = false;
    els.viewer.setAttribute("aria-hidden", "false");
    els.viewer.classList.add("open");
    els.viewerClose.focus();
  }

  function closeViewer() {
    if (!state.viewerOpen) return;
    state.viewerOpen = false;
    els.viewer.classList.remove("open");
    els.viewer.setAttribute("aria-hidden", "true");
    els.viewer.inert = true;
    els.viewerBackdrop.classList.remove("open");
    els.viewerBackdrop.setAttribute("aria-hidden", "true");
    els.viewerBackdrop.inert = true;
    els.viewerFrame.src = "about:blank";
    if (state.viewerRestoreFocus?.isConnected) state.viewerRestoreFocus.focus();
    state.viewerRestoreFocus = null;
  }

  els.viewerClose.addEventListener("click", closeViewer);
  els.viewerBackdrop.addEventListener("click", closeViewer);

  // Keyboard contract (Xore/theme docs/MODALS.md), same as hp-settings.js:
  // Escape closes the modal unless a destructive confirmation is stacked
  // above it, and Tab stays inside the open modal.
  document.addEventListener("keydown", (event) => {
    if (!state.viewerOpen) return;
    if (window.HoneypotModals?.isOpen()) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      closeViewer();
      return;
    }
    if (event.key !== "Tab") return;
    const controls = Array.from(els.viewer.querySelectorAll(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    )).filter((el) => !el.hidden && el.offsetParent !== null);
    if (!controls.length) return;
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && (document.activeElement === first || !els.viewer.contains(document.activeElement))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  });

  function openReportCard(card) {
    const report = state.generated.find((candidate) => candidate.id === card.dataset.hpReportCard);
    if (report) openViewer(report);
  }

  els.generated.addEventListener("click", (event) => {
    const purge = event.target.closest("[data-purge]");
    if (purge) {
      confirmAction(purge, {
        title: `Delete “${purge.dataset.name}”?`,
        description: "The generated PDF is removed from the history and from disk. The design that produced it is kept.",
        confirmLabel: "Delete report",
        onConfirm: async () => {
          await api(`/api/reports/generated/${purge.dataset.purge}`, { method: "DELETE" });
          closeViewer();
          await refreshGenerated();
          return "Report deleted.";
        },
      });
      return;
    }
    if (event.target.closest("[data-hp-report-actions]")) return; // let Download navigate natively
    const card = event.target.closest("[data-hp-report-card]");
    if (card) openReportCard(card);
  });

  els.generated.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    // Only the card's own role="button" activates this way -- a focused
    // Download link or Delete button already gets its native Enter/Space
    // behavior and must not also trigger the card underneath it.
    if (event.target.dataset?.hpReportCard === undefined) return;
    event.preventDefault();
    openReportCard(event.target);
  });

  function confirmAction(trigger, options) {
    if (window.HoneypotModals && typeof window.HoneypotModals.confirm === "function") {
      window.HoneypotModals.confirm({ trigger, ...options });
    } else if (window.confirm(options.title)) {
      Promise.resolve(options.onConfirm()).catch((error) => setStatus(error.message, "error"));
    }
  }

  // -------------------------------------------------------------------------
  // Boot
  // -------------------------------------------------------------------------

  (async () => {
    try {
      const catalog = await apiJSON("/api/reports/templates");
      state.templates = catalog.templates || [];
      state.elements = catalog.elements || [];
      state.windows = catalog.windows || [];
      renderTemplates();
      renderElementChoices();
      renderWindowChoices();
      selectTemplate("executive", true);
      await Promise.all([refreshDefinitions(), refreshGenerated()]);
    } catch (error) {
      if (!state.forbidden) setStatus(error.message, "error");
    }
  })();
})();
