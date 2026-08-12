(() => {
  "use strict";
  const root = document.querySelector("[data-wb-root]");
  if (!root) return;
  const sha256 = root.dataset.payloadSha256;
  const form = root.querySelector("[data-wb-form]");
  const message = root.querySelector("[data-wb-message]");
  const runsRoot = root.querySelector("[data-wb-runs]");
  const recipeSelect = root.querySelector("[data-wb-recipe-select]");
  let recipes = [], pollTimer = 0;
  const say = (value, error = false) => { message.textContent = value; message.classList.toggle("tw:text-red", error); };
  async function api(path, init = {}) { const response = await fetch(path, {cache: "no-store", ...init}); if (!response.ok) throw new Error((await response.text()).trim() || `${response.status} ${response.statusText}`); return response.json(); }
  function selections() {
    return [...root.querySelectorAll("[data-wb-analyzer]")].filter(card => card.querySelector('input[type="checkbox"]').checked).map(card => { const id = card.dataset.analyzerId; return {analyzer_id: id, options: {timeout_seconds: Number(card.querySelector(`[name="${id}-timeout"]`)?.value || 0), max_queue_age_seconds: Number(card.querySelector(`[name="${id}-queue-age"]`)?.value || 0), retry_limit: Number(card.querySelector(`[name="${id}-retry"]`)?.value || 0)}}; });
  }
  function applyRecipe(recipe) {
    const chosen = new Map(recipe.analyzers.map(item => [item.analyzer_id, item.options]));
    root.querySelectorAll("[data-wb-analyzer]").forEach(card => { const id = card.dataset.analyzerId, checkbox = card.querySelector('input[type="checkbox"]'); checkbox.checked = !checkbox.disabled && chosen.has(id); const options = chosen.get(id); if (!options) return; card.querySelector(`[name="${id}-timeout"]`).value = options.timeout_seconds; card.querySelector(`[name="${id}-queue-age"]`).value = options.max_queue_age_seconds; card.querySelector(`[name="${id}-retry"]`).value = options.retry_limit; });
    root.querySelector("[data-wb-recipe-name]").value = recipe.name; root.querySelector("[data-wb-recipe-description]").value = recipe.description || ""; root.querySelector("[data-wb-recipe-scope]").value = recipe.scope;
  }
  async function loadRecipes() { const data = await api("/api/payload-workbench/recipes"); recipes = data.recipes || []; recipeSelect.replaceChildren(new Option("One-off selection", "")); recipes.forEach(recipe => recipeSelect.add(new Option(`${recipe.name} · r${recipe.revision}`, `${recipe.id}@${recipe.revision}`))); }
  function badge(state) { const span = document.createElement("span"); span.className = `badge wb-state wb-state--${state}`; span.textContent = state.replaceAll("_", " "); return span; }
  function childCard(run, child) {
    const article = document.createElement("article"); article.className = "wb-child";
    const heading = document.createElement("div"); heading.className = "wb-child-head"; const title = document.createElement("strong"); title.textContent = child.display_name; heading.append(title, badge(child.state));
    if (child.detonates) { const warning = document.createElement("span"); warning.className = "badge badge--red"; warning.textContent = "detonation"; heading.append(warning); }
    article.append(heading); const reason = document.createElement("p"); reason.className = "note"; reason.textContent = child.summary || child.reason || "Waiting for status"; article.append(reason);
    const actions = document.createElement("div"); actions.className = "tw:flex tw:flex-wrap tw:gap-2";
    if (child.result_url) { const link = document.createElement("a"); link.className = "lnk"; link.href = child.result_url; link.textContent = "Open native result →"; actions.append(link); }
    for (const action of ["retry", "cancel"]) { if ((action === "retry" && !child.retryable) || (action === "cancel" && !child.cancelable)) continue; const button = document.createElement("button"); button.className = "btn btn-sm btn-secondary"; button.type = "button"; button.textContent = action === "retry" ? "Retry child" : "Cancel queued child"; button.addEventListener("click", async () => { button.disabled = true; try { await api(`/api/payload-workbench/runs/${run.id}/children/${child.analyzer_id}/${action}`, {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"}); await loadRuns(); } catch (error) { say(error.message, true); } finally { button.disabled = false; } }); actions.append(button); }
    article.append(actions); return article;
  }
  function renderRuns(runs) {
    runsRoot.replaceChildren(); if (!runs.length) { const empty = document.createElement("div"); empty.className = "card wide"; empty.innerHTML = '<p class="empty">No workbench run exists for this payload yet.</p>'; runsRoot.append(empty); return; }
    runs.forEach(run => { const section = document.createElement("article"); section.className = "card wide wb-run"; const head = document.createElement("div"); head.className = "wb-run-head"; const title = document.createElement("div"), h = document.createElement("h3"), meta = document.createElement("p"); h.textContent = `${run.recipe_name} · r${run.recipe_revision}`; meta.className = "note"; meta.textContent = `${run.id} · ${new Date(run.created_at).toLocaleString()}`; title.append(h, meta); head.append(title, badge(run.state)); section.append(head); const children = document.createElement("div"); children.className = "wb-child-grid"; run.children.forEach(child => children.append(childCard(run, child))); section.append(children); runsRoot.append(section); });
  }
  async function loadRuns() { const data = await api(`/api/payload-workbench/runs?sha256=${encodeURIComponent(sha256)}`); renderRuns(data.runs || []); const active = (data.runs || []).some(run => ["queued", "running"].includes(run.state)); clearTimeout(pollTimer); if (active) pollTimer = setTimeout(() => loadRuns().catch(error => say(error.message, true)), 4000); }
  // #1234: excludes [data-requires-opt-in="true"] (currently just
  // windows-ghosts, the one route with real internet access) -- "Run all
  // applicable" must not be the click that silently opts an operator into
  // real outbound C2/exfiltration connectivity; that route stays opt-in,
  // selected deliberately by its own checkbox, never by this button.
  root.querySelector("[data-wb-run-all]").addEventListener("click", () => { root.querySelectorAll('[data-wb-analyzer][data-ready="true"]:not([data-requires-opt-in="true"]) input[type="checkbox"]').forEach(input => { input.checked = true; }); recipeSelect.value = ""; say("All currently applicable local analyzers selected."); });
  recipeSelect.addEventListener("change", () => { const [id, revision] = recipeSelect.value.split("@"); const recipe = recipes.find(item => item.id === id && item.revision === Number(revision)); if (recipe) applyRecipe(recipe); });
  // #349: disabling the button was the only feedback while a request was in
  // flight -- easy to miss (no visual change beyond a slightly greyed-out
  // button), and indistinguishable from the click not registering at all if
  // the request took more than an instant. Swap the label and post an
  // immediate status message before the fetch even starts, so "something is
  // happening" is unmistakable regardless of how long the request takes.
  async function withBusyButton(button, busyLabel, task) {
    const originalLabel = button.textContent;
    button.disabled = true; button.textContent = busyLabel;
    try { await task(); } finally { button.disabled = false; button.textContent = originalLabel; }
  }
  root.querySelector("[data-wb-save]").addEventListener("click", event => { const button = event.currentTarget, selected = selections(); if (!selected.length) return say("Select at least one analyzer.", true); const chosen = recipeSelect.value.split("@"); const payload = {name: root.querySelector("[data-wb-recipe-name]").value, description: root.querySelector("[data-wb-recipe-description]").value, scope: root.querySelector("[data-wb-recipe-scope]").value, analyzers: selected}; if (chosen[0]) { payload.id = chosen[0]; payload.base_revision = Number(chosen[1]); } say("Saving recipe…"); withBusyButton(button, "Saving…", async () => { try { const recipe = await api("/api/payload-workbench/recipes", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}); await loadRecipes(); recipeSelect.value = `${recipe.id}@${recipe.revision}`; say(`Saved immutable recipe revision ${recipe.revision}.`); } catch (error) { say(error.message, true); } }); });
  form.addEventListener("submit", event => { event.preventDefault(); const selected = selections(); if (!selected.length) return say("Select at least one analyzer.", true); const [recipeId, recipeRevision] = recipeSelect.value.split("@"); const payload = recipeId ? {payload_sha256: sha256, recipe_id: recipeId, recipe_revision: Number(recipeRevision)} : {payload_sha256: sha256, recipe_name: root.querySelector("[data-wb-recipe-name]").value, analyzers: selected}; const button = root.querySelector("[data-wb-run]"); say("Submitting analysis run…"); withBusyButton(button, "Starting…", async () => { try { const data = await api("/api/payload-workbench/runs", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}); say(data.reused ? "Existing idempotent run loaded. Use the child retry control for a deliberate rerun." : "Analysis run created."); await loadRuns(); } catch (error) { say(error.message, true); } }); });
  Promise.all([loadRecipes(), loadRuns()]).catch(error => { say(error.message, true); runsRoot.innerHTML = '<div class="card wide"><p class="empty">Workbench controls require a live administrator session.</p></div>'; form.querySelectorAll("input,select,textarea,button").forEach(control => { control.disabled = true; }); });
})();
