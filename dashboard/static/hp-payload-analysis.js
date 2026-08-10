/* Payload analysis: hydrates the three slow, multi-source cards
   (#1142 -- Isolated dynamic analysis / GitHub analysis / Known elsewhere)
   in after the page itself has already rendered.

   /payload-analysis/<hash> renders from analyzePayloadFast alone now
   (single-file static analysis + YARA, both fast) -- SandboxRuns/
   GitHubAnalysis/Correlation each depend on loadGhidraResults/
   loadSandboxResults/loadGitHubAnalysisResults, which fetch up to 10000
   documents from Elasticsearch regardless of which hash is being asked
   about (see hash_correlation.go's own comment), genuinely slow compared
   to everything else on this page. Fetching them here, after the page has
   already painted, means the operator sees identity/hashes/hex dump/
   strings/YARA findings immediately instead of waiting on three slow
   lookups the vast majority of hashes don't even have results in.

   Markup mirrors payloads.html's own template output exactly (same
   classes, same empty-state copy) so hydration is visually seamless --
   this is a Go template's output re-expressed in JS, not a redesign. */
(() => {
  "use strict";

  const root = document.querySelector("[data-hp-page-content]");
  const hash = root?.dataset.hpPlHash;
  const sha256 = root?.dataset.hpPlSha256;
  const sandboxTarget = document.querySelector("[data-hp-pl-sandbox-runs]");
  const githubTarget = document.querySelector("[data-hp-pl-github-analysis]");
  const knownTarget = document.querySelector("[data-hp-pl-known-elsewhere]");
  const knownHeading = document.getElementById("hp-pl-known-elsewhere-heading");
  if (!root || !hash || !sandboxTarget || !githubTarget || !knownTarget) return;

  const escapeHTML = value => String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function renderSandboxRuns(runs) {
    if (!runs || !runs.length) {
      sandboxTarget.innerHTML = `<p class="empty">No completed KVM sandbox run for this payload. Queue one from the <a class="lnk" href="/payload-workbench/${escapeHTML(hash)}">analysis workbench</a>.</p>`;
      return;
    }
    const rows = runs.map(run => `
      <tr><td>${escapeHTML(run.completed_at)}</td><td class="n">${escapeHTML(run.exit_status)}</td><td class="n">${(run.changed_files || []).length}</td><td><a class="lnk" href="/sandbox/${encodeURIComponent(run.job)}">sandbox report &rarr;</a></td></tr>`).join("");
    sandboxTarget.innerHTML = `<div class="card__scroll"><table class="data-table"><thead><tr><th>completed</th><th>exit</th><th>changed paths</th><th>details</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderGitHubAnalysis(github, family, familyLink) {
    if (!github) {
      githubTarget.innerHTML = `<p class="empty">Not published to Xore/honeypot. Use <strong>Publish to Xore/honeypot</strong> from the payload actions menu above to queue one.</p>`;
      return;
    }
    let html = `<div class="card__row"><span class="card__label">exit status</span><span class="card__value card__value--mono">${escapeHTML(github.exit_status)}</span></div>`;
    if (github.verdict) {
      html += `<div class="card__row"><span class="card__label">detections</span><span class="card__value card__value--mono">${escapeHTML(github.verdict.malicious)} / ${escapeHTML(github.verdict.total)} &bull; ${escapeHTML(github.verdict.level)}</span></div>`;
    }
    if (family) {
      html += `<div class="card__row"><span class="card__label">family</span><span class="card__value"><a class="lnk" href="${escapeHTML(familyLink)}" title="Other sessions that delivered this family">${escapeHTML(family)}</a></span></div>`;
    }
    html += `<a class="lnk" href="/github-analysis/${encodeURIComponent(github.sha256)}">full result &rarr;</a>`;
    githubTarget.innerHTML = html;
  }

  function renderKnownElsewhere(correlation) {
    if (knownHeading) {
      const badge = correlation.known
        ? `<span class="badge badge--green">already analyzed</span>`
        : `<span class="badge badge--muted">not seen elsewhere</span>`;
      knownHeading.innerHTML = `Known elsewhere ${badge}`;
    }
    const ghidraCell = correlation.ghidra
      ? `<span class="badge badge--muted">${escapeHTML(correlation.ghidra.exit_status)}</span> completed ${escapeHTML(correlation.ghidra.completed_at)} &mdash; <a class="lnk" href="/ghidra/${escapeHTML(hash)}">full result &rarr;</a>`
      : `<span class="empty">not yet analyzed</span> &mdash; <a class="lnk" href="/payload-workbench/${escapeHTML(hash)}">queue Ghidra &rarr;</a>`;
    let esCell;
    if (correlation.es_available) {
      esCell = `${correlation.es_sightings} event(s)`;
      if (correlation.es_first_seen) {
        esCell += `, ${correlation.es_truncated ? "on or before " : ""}${escapeHTML(correlation.es_first_seen)} &ndash; ${escapeHTML(correlation.es_last_seen)}`;
      }
      if (correlation.es_truncated) {
        esCell += ` <span class="chip" title="More than 200 sightings; first-seen is the oldest record in the most recent 200, not necessarily the true first sighting.">truncated</span>`;
      }
      for (const sensor of correlation.es_sensors || []) {
        esCell += ` <span class="chip">${escapeHTML(sensor.Key)}: ${escapeHTML(sensor.Count)}</span>`;
      }
    } else {
      esCell = `<span class="empty">Elasticsearch not configured</span>`;
    }
    knownTarget.innerHTML = `
      <div class="card__row"><span class="card__label">Ghidra</span><span class="card__value">${ghidraCell}</span></div>
      <div class="card__row"><span class="card__label">Elasticsearch sightings</span><span class="card__value">${esCell}</span></div>`;
  }

  function renderFailure(message) {
    const errorHTML = `<p class="empty">Could not load &mdash; ${escapeHTML(message)}. <button class="lnk" type="button" data-hp-pl-aggregation-retry>Retry</button></p>`;
    sandboxTarget.innerHTML = errorHTML;
    githubTarget.innerHTML = errorHTML;
    knownTarget.innerHTML = errorHTML;
  }

  async function loadAggregation() {
    try {
      const response = await fetch(`/api/payload-analysis/${encodeURIComponent(hash)}/aggregation?sha256=${encodeURIComponent(sha256 || "")}`, { cache: "no-store" });
      if (!response.ok) throw new Error(`request failed (${response.status})`);
      const agg = await response.json();
      renderSandboxRuns(agg.sandbox_runs);
      renderGitHubAnalysis(agg.github_analysis, agg.family, agg.family_link);
      renderKnownElsewhere(agg.correlation || {});
    } catch (error) {
      renderFailure(error.message);
    }
  }

  document.addEventListener("click", e => {
    if (e.target.closest?.("[data-hp-pl-aggregation-retry]")) loadAggregation();
  });

  loadAggregation();
})();
