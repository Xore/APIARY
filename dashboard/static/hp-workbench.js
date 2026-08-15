/* Render-first controller for /payload-workbench/{sha256}. Every independent
   source hydrates its own card, including after hp-dynamic-nav swaps pages. */
(() => {
  "use strict";
  let pollTimer = 0;

  function run() {
    clearTimeout(pollTimer);
    const root = document.querySelector("[data-wb-root]");
    if (!root) return;

    const sha256 = root.dataset.payloadSha256;
    const form = root.querySelector("[data-wb-form]");
    const message = root.querySelector("[data-wb-message]");
    const runsRoot = root.querySelector("[data-wb-runs]");
    const recipeSelect = root.querySelector("[data-wb-recipe-select]");
    const analyzersRoot = root.querySelector("[data-wb-analyzers]");
    const classificationRoot = root.querySelector("[data-wb-classification]");
    const classificationLabel = root.querySelector("[data-wb-classification-label]");
    const knownRoot = root.querySelector("[data-wb-known]");
    const modelRoot = root.querySelector("[data-wb-model-status]");
    const runAll = root.querySelector("[data-wb-run-all]");
    const saveButton = root.querySelector("[data-wb-save]");
    const runButton = root.querySelector("[data-wb-run]");
    let recipes = [];

    const escapeHTML = value => String(value ?? "").replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
    const say = (value, error = false) => {
      message.textContent = value;
      message.classList.toggle("tw:text-red", error);
    };
    const api = async (path, init = {}) => {
      const response = await fetch(path, {cache: "no-store", ...init});
      if (!response.ok) throw new Error((await response.text()).trim() || `${response.status} ${response.statusText}`);
      return response.json();
    };
    const renderError = (target, label, error) => {
      target.setAttribute("aria-busy", "false");
      target.replaceChildren();
      const text = document.createElement("p");
      text.className = "empty";
      text.textContent = `${label} could not be loaded: ${error.message}`;
      target.appendChild(text);
    };

    function renderClassification(classification) {
      classificationLabel.textContent = classification.label || classification.code || "unclassified payload";
      classificationRoot.innerHTML = `<div class="card__row"><span class="card__label">identified type</span><span class="card__value"><strong>${escapeHTML(classification.label)}</strong> <span class="badge badge--muted">${escapeHTML(classification.code)}</span></span></div><div class="card__row"><span class="card__label">platform / category</span><span class="card__value card__value--mono">${escapeHTML(classification.platform)} / ${escapeHTML(classification.category)}</span></div><div class="card__row"><span class="card__label">analysis path</span><span class="card__value card__value--mono">${escapeHTML(classification.analysis_path)}</span></div><div class="card__row"><span class="card__label">dynamic execution</span><span class="card__value">${classification.dynamic ? "supported for this payload type" : "static analysis only"}</span></div>`;
      classificationRoot.setAttribute("aria-busy", "false");
    }

    function analyzerCard(analyzer) {
      const ready = !!(analyzer.applicable && analyzer.available);
      const article = document.createElement("article");
      article.className = `wb-analyzer${ready ? "" : " is-disabled"}`;
      article.dataset.wbAnalyzer = "";
      article.dataset.analyzerId = analyzer.id;
      article.dataset.ready = String(ready);
      article.dataset.requiresOptIn = String(!!analyzer.requires_opt_in);

      const head = document.createElement("div");
      head.className = "wb-analyzer-head";
      const input = document.createElement("input");
      input.id = `wb-${analyzer.id}`;
      input.type = "checkbox";
      input.value = analyzer.id;
      input.disabled = !ready;
      input.checked = ready && !analyzer.requires_opt_in;
      input.setAttribute("aria-describedby", `wb-${analyzer.id}-reason`);
      const label = document.createElement("label");
      label.htmlFor = input.id;
      const strong = document.createElement("strong");
      strong.textContent = analyzer.display_name;
      label.appendChild(strong);
      head.append(input, label);
      const addBadge = (text, className = "badge--muted", title = "") => {
        const badge = document.createElement("span");
        badge.className = `badge ${className}`;
        badge.textContent = text;
        if (title) badge.title = title;
        head.appendChild(badge);
      };
      addBadge(analyzer.detonates ? "detonation" : "static", analyzer.detonates ? "badge--red" : "badge--muted");
      if (analyzer.gpu_consuming) addBadge("shared GPU");
      if (analyzer.local_only) addBadge("local only");
      if (analyzer.requires_opt_in) addBadge("opt-in required", "badge--red", "Reaches real internet infrastructure; select deliberately.");
      article.appendChild(head);

      const description = document.createElement("p");
      description.textContent = analyzer.description;
      const reason = document.createElement("p");
      reason.className = "note";
      reason.id = `wb-${analyzer.id}-reason`;
      const availability = document.createElement("strong");
      availability.textContent = analyzer.availability;
      reason.append(availability, document.createTextNode(` — ${analyzer.reason}`));
      article.append(description, reason);

      if (ready) {
        const details = document.createElement("details");
        details.className = "wb-options";
        const summary = document.createElement("summary");
        summary.textContent = "Orchestration options";
        const grid = document.createElement("div");
        grid.className = "wb-option-grid";
        const numberField = (title, name, min, max, value) => {
          const field = document.createElement("label");
          field.append(document.createTextNode(title));
          const control = document.createElement("input");
          control.className = "form-input";
          control.type = "number";
          control.name = name;
          control.min = String(min);
          control.max = String(max);
          control.value = String(value);
          field.appendChild(control);
          return field;
        };
        const schema = analyzer.option_schema || {};
        const defaults = analyzer.default_options || {};
        grid.append(
          numberField("Timeout (seconds)", `${analyzer.id}-timeout`, schema.timeout_min_seconds, schema.timeout_max_seconds, defaults.timeout_seconds),
          numberField("Maximum queue age (seconds)", `${analyzer.id}-queue-age`, schema.queue_age_min_seconds, schema.queue_age_max_seconds, defaults.max_queue_age_seconds),
          numberField("Retry allowance", `${analyzer.id}-retry`, 0, schema.retry_limit_max, defaults.retry_limit),
        );
        details.append(summary, grid);
        article.appendChild(details);
      }
      return article;
    }

    function renderAnalyzers(analyzers) {
      analyzersRoot.replaceChildren();
      analyzers.forEach(analyzer => analyzersRoot.appendChild(analyzerCard(analyzer)));
      if (!analyzers.length) {
        const empty = document.createElement("p");
        empty.className = "empty";
        empty.textContent = "No analyzers are registered for this payload.";
        analyzersRoot.appendChild(empty);
      }
      analyzersRoot.setAttribute("aria-busy", "false");
      runAll.disabled = analyzers.length === 0;
      saveButton.disabled = analyzers.length === 0;
      runButton.disabled = analyzers.length === 0;
    }

    async function loadRegistry() {
      const data = await api(`/api/payload-workbench/registry/${encodeURIComponent(sha256)}`);
      renderClassification(data.classification || {});
      renderAnalyzers(data.analyzers || []);
    }

    function renderKnown(correlation) {
      knownRoot.replaceChildren();
      const note = document.createElement("p");
      note.className = "note";
      note.textContent = correlation.known ? "This payload was already analyzed or observed elsewhere. Queueing a fresh run remains available." : "No prior native analysis or indexed telemetry sighting was found. This is advisory and never blocks a run.";
      knownRoot.appendChild(note);
      if (correlation.known) {
        const chips = document.createElement("div");
        chips.className = "tw:flex tw:flex-wrap tw:gap-2";
        if (correlation.ghidra) {
          const link = document.createElement("a");
          link.className = "chip";
          link.href = `/ghidra/${encodeURIComponent(sha256)}`;
          link.textContent = `Ghidra: ${correlation.ghidra.exit_status || "recorded"}`;
          chips.appendChild(link);
        }
        if (correlation.sandbox_count) {
          const chip = document.createElement("span"); chip.className = "chip"; chip.textContent = `Sandbox: ${correlation.sandbox_count} run(s)`; chips.appendChild(chip);
        }
        if (correlation.github) {
          const chip = document.createElement("span"); chip.className = "chip"; chip.textContent = `GitHub analysis: ${correlation.github.exit_status || "recorded"}`; chips.appendChild(chip);
        }
        if (correlation.es_available && correlation.es_sightings) {
          const chip = document.createElement("span"); chip.className = "chip"; chip.textContent = `Elasticsearch: ${correlation.es_sightings} sighting(s)`; chips.appendChild(chip);
        }
        knownRoot.appendChild(chips);
      }
      const link = document.createElement("a");
      link.className = "lnk";
      link.href = `/payload-analysis/${encodeURIComponent(sha256)}`;
      link.textContent = "Full correlation →";
      knownRoot.appendChild(link);
      knownRoot.setAttribute("aria-busy", "false");
    }

    async function loadCorrelation() {
      const data = await api(`/api/payload-workbench/correlation/${encodeURIComponent(sha256)}`);
      renderKnown(data.correlation || {});
    }

    function renderModel(status) {
      modelRoot.replaceChildren();
      const head = document.createElement("div");
      head.className = "tw:flex tw:flex-wrap tw:gap-2";
      const badge = document.createElement("span");
      badge.className = `badge ${status.available ? `wb-state--${String(status.overall).replace(/[^a-z_]/g, "")}` : "badge--muted"}`;
      badge.textContent = status.available ? status.overall : "unavailable";
      head.appendChild(badge);
      const note = document.createElement("p");
      note.className = "note";
      note.textContent = status.available ? `Checked ${status.checked_at} through the privileged read-only adapter. Drift or unavailability never disables deterministic analysis.` : `${status.reason || "Model-status adapter is unavailable"}. Deterministic analysis remains available.`;
      modelRoot.append(head, note);
      if (status.available) {
        const slots = document.createElement("div");
        slots.className = "tw:flex tw:flex-wrap tw:gap-2";
        Object.entries(status.slots || {}).forEach(([name, slot]) => {
          const chip = document.createElement("span");
          chip.className = "chip";
          chip.textContent = `${name}: ${slot.status}${(slot.codes || []).length ? ` • ${slot.codes.join(" • ")}` : ""}`;
          slots.appendChild(chip);
        });
        modelRoot.appendChild(slots);
      }
      modelRoot.setAttribute("aria-busy", "false");
    }

    async function loadModelStatus() {
      const data = await api("/api/payload-workbench/model-status");
      renderModel(data.model_status || {});
    }

    function selections() {
      return [...root.querySelectorAll("[data-wb-analyzer]")]
        .filter(card => card.querySelector('input[type="checkbox"]')?.checked)
        .map(card => {
          const id = card.dataset.analyzerId;
          return {analyzer_id: id, options: {
            timeout_seconds: Number(card.querySelector(`[name="${id}-timeout"]`)?.value || 0),
            max_queue_age_seconds: Number(card.querySelector(`[name="${id}-queue-age"]`)?.value || 0),
            retry_limit: Number(card.querySelector(`[name="${id}-retry"]`)?.value || 0),
          }};
        });
    }

    function applyRecipe(recipe) {
      const chosen = new Map(recipe.analyzers.map(item => [item.analyzer_id, item.options]));
      root.querySelectorAll("[data-wb-analyzer]").forEach(card => {
        const id = card.dataset.analyzerId;
        const checkbox = card.querySelector('input[type="checkbox"]');
        checkbox.checked = !checkbox.disabled && chosen.has(id);
        const options = chosen.get(id);
        if (!options) return;
        const timeout = card.querySelector(`[name="${id}-timeout"]`);
        const queueAge = card.querySelector(`[name="${id}-queue-age"]`);
        const retry = card.querySelector(`[name="${id}-retry"]`);
        if (timeout) timeout.value = options.timeout_seconds;
        if (queueAge) queueAge.value = options.max_queue_age_seconds;
        if (retry) retry.value = options.retry_limit;
      });
      root.querySelector("[data-wb-recipe-name]").value = recipe.name;
      root.querySelector("[data-wb-recipe-description]").value = recipe.description || "";
      root.querySelector("[data-wb-recipe-scope]").value = recipe.scope;
    }

    async function loadRecipes() {
      try {
        const data = await api("/api/payload-workbench/recipes");
        recipes = data.recipes || [];
        recipeSelect.replaceChildren(new Option("One-off selection", ""));
        recipes.forEach(recipe => recipeSelect.add(new Option(`${recipe.name} · r${recipe.revision}`, `${recipe.id}@${recipe.revision}`)));
      } catch (error) {
        recipeSelect.replaceChildren(new Option("Saved recipes unavailable", ""));
        say(`Saved recipes could not be loaded: ${error.message}`, true);
      } finally {
        recipeSelect.setAttribute("aria-busy", "false");
      }
    }

    function stateBadge(state) {
      const span = document.createElement("span");
      span.className = `badge wb-state wb-state--${String(state).replace(/[^a-z_]/g, "")}`;
      span.textContent = String(state).replaceAll("_", " ");
      return span;
    }

    function childCard(run, child) {
      const article = document.createElement("article"); article.className = "wb-child";
      const heading = document.createElement("div"); heading.className = "wb-child-head";
      const title = document.createElement("strong"); title.textContent = child.display_name;
      heading.append(title, stateBadge(child.state));
      if (child.detonates) { const warning = document.createElement("span"); warning.className = "badge badge--red"; warning.textContent = "detonation"; heading.append(warning); }
      article.append(heading);
      const reason = document.createElement("p"); reason.className = "note"; reason.textContent = child.summary || child.reason || "Waiting for status"; article.append(reason);
      const actions = document.createElement("div"); actions.className = "tw:flex tw:flex-wrap tw:gap-2";
      if (child.result_url) { const link = document.createElement("a"); link.className = "lnk"; link.href = child.result_url; link.textContent = "Open native result →"; actions.append(link); }
      for (const action of ["retry", "cancel"]) {
        if ((action === "retry" && !child.retryable) || (action === "cancel" && !child.cancelable)) continue;
        const button = document.createElement("button"); button.className = "btn btn-sm btn-secondary"; button.type = "button"; button.textContent = action === "retry" ? "Retry child" : "Cancel queued child";
        button.addEventListener("click", async () => { button.disabled = true; try { await api(`/api/payload-workbench/runs/${run.id}/children/${child.analyzer_id}/${action}`, {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"}); await loadRuns(); } catch (error) { say(error.message, true); } finally { button.disabled = false; } });
        actions.append(button);
      }
      article.append(actions);
      return article;
    }

    function renderRuns(runs) {
      runsRoot.replaceChildren();
      if (!runs.length) {
        const empty = document.createElement("div"); empty.className = "card wide"; empty.innerHTML = '<p class="empty">No workbench run exists for this payload yet.</p>'; runsRoot.append(empty);
      } else {
        runs.forEach(run => {
          const section = document.createElement("article"); section.className = "card wide wb-run";
          const head = document.createElement("div"); head.className = "wb-run-head";
          const title = document.createElement("div"), heading = document.createElement("h3"), meta = document.createElement("p");
          heading.textContent = `${run.recipe_name} · r${run.recipe_revision}`; meta.className = "note"; meta.textContent = `${run.id} · ${new Date(run.created_at).toLocaleString()}`;
          title.append(heading, meta); head.append(title, stateBadge(run.state)); section.append(head);
          const children = document.createElement("div"); children.className = "wb-child-grid"; run.children.forEach(child => children.append(childCard(run, child))); section.append(children); runsRoot.append(section);
        });
      }
      runsRoot.setAttribute("aria-busy", "false");
    }

    async function loadRuns() {
      try {
        runsRoot.setAttribute("aria-busy", "true");
        const data = await api(`/api/payload-workbench/runs?sha256=${encodeURIComponent(sha256)}`);
        renderRuns(data.runs || []);
        const active = (data.runs || []).some(run => ["queued", "running"].includes(run.state));
        clearTimeout(pollTimer);
        if (active) pollTimer = setTimeout(loadRuns, 4000);
      } catch (error) {
        renderError(runsRoot, "Correlated runs", error);
      }
    }

    runAll.addEventListener("click", () => {
      root.querySelectorAll('[data-wb-analyzer][data-ready="true"]:not([data-requires-opt-in="true"]) input[type="checkbox"]').forEach(input => { input.checked = true; });
      recipeSelect.value = "";
      say("All currently applicable local analyzers selected.");
    });
    recipeSelect.addEventListener("change", () => {
      const [id, revision] = recipeSelect.value.split("@");
      const recipe = recipes.find(item => item.id === id && item.revision === Number(revision));
      if (recipe) applyRecipe(recipe);
    });

    async function withBusyButton(button, busyLabel, task) {
      const originalLabel = button.textContent;
      button.disabled = true; button.textContent = busyLabel;
      try { await task(); } finally { button.disabled = false; button.textContent = originalLabel; }
    }

    saveButton.addEventListener("click", () => {
      const selected = selections();
      if (!selected.length) return say("Select at least one analyzer.", true);
      const chosen = recipeSelect.value.split("@");
      const payload = {name: root.querySelector("[data-wb-recipe-name]").value, description: root.querySelector("[data-wb-recipe-description]").value, scope: root.querySelector("[data-wb-recipe-scope]").value, analyzers: selected};
      if (chosen[0]) { payload.id = chosen[0]; payload.base_revision = Number(chosen[1]); }
      say("Saving recipe…");
      withBusyButton(saveButton, "Saving…", async () => { try { const recipe = await api("/api/payload-workbench/recipes", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}); await loadRecipes(); recipeSelect.value = `${recipe.id}@${recipe.revision}`; say(`Saved immutable recipe revision ${recipe.revision}.`); } catch (error) { say(error.message, true); } });
    });

    form.addEventListener("submit", event => {
      event.preventDefault();
      const selected = selections();
      if (!selected.length) return say("Select at least one analyzer.", true);
      const [recipeId, recipeRevision] = recipeSelect.value.split("@");
      const payload = recipeId ? {payload_sha256: sha256, recipe_id: recipeId, recipe_revision: Number(recipeRevision)} : {payload_sha256: sha256, recipe_name: root.querySelector("[data-wb-recipe-name]").value, analyzers: selected};
      say("Submitting analysis run…");
      withBusyButton(runButton, "Starting…", async () => { try { const data = await api("/api/payload-workbench/runs", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}); say(data.reused ? "Existing idempotent run loaded. Use the child retry control for a deliberate rerun." : "Analysis run created."); await loadRuns(); } catch (error) { say(error.message, true); } });
    });

    loadRegistry().catch(error => {
      classificationLabel.textContent = "classification unavailable";
      renderError(classificationRoot, "Payload classification", error);
      renderError(analyzersRoot, "Analyzer registry", error);
    });
    loadCorrelation().catch(error => renderError(knownRoot, "Known-elsewhere correlation", error));
    loadModelStatus().catch(error => renderError(modelRoot, "Local-model health", error));
    loadRecipes();
    loadRuns();
  }

  run();
  document.addEventListener("hp-dynamic-nav", run);
})();
