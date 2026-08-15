/* Payload analysis: hydrates the page in two independent passes after the
   page shell itself has already rendered.

   /payload-analysis/<hash> used to render from analyzePayloadFast (#1142's
   "fast half": single-file static analysis + YARA) -- fast for a small
   script, but measured at 567ms of pure CPU/disk work (full-file hashing,
   entropy/hex-dump/string/IOC extraction, YARA) against a real 5.26MB
   captured sample, all of it before Go's html/template renderer writes a
   single byte of the response (no streaming -- the whole document is
   buffered first). #1157 pushes that work one level further out: the route
   now renders a bare shell (just the hash from the URL) and this file
   fetches /api/payload-analysis/<hash>/static to hydrate the Identity/
   Findings/Content tabs in afterward.

   The second pass -- SandboxRuns/GitHubAnalysis/Correlation via
   /api/payload-analysis/<hash>/aggregation -- is #1142's original
   hydration, unchanged. The two fetches are independent and unsequenced:
   neither waits on the other. The one exception is sha256, which the
   aggregation fetch needs to scope its ES lookups and which the page shell
   no longer has synchronously -- if the static-analysis fetch resolves a
   sha256 the aggregation fetch didn't have yet, it re-fires loadAggregation()
   once with the now-known value, rather than leaving Known-elsewhere
   permanently scoped to nothing for hashes addressed by MD5 (Dionaea
   captures, see payload_analysis.go's own comment on payloadPathBySHA256).

   Markup mirrors payloads.html's own template output exactly (same
   classes, same empty-state copy) so hydration is visually seamless --
   this is a Go template's output re-expressed in JS, not a redesign.

   /payload-analysis/<hash> is one of hp-dynamic-nav.js's DYNAMIC_ROUTES:
   navigating from one hash's page to another's swaps in a fresh
   [data-hp-page-content] without ever re-fetching this script (already
   loaded from the first visit) -- run() below re-queries the live DOM and
   re-fires both fetches on every "hp-dynamic-nav" event, not just once at
   initial script load, so the second hash's skeleton cards actually
   hydrate instead of sitting there until a full reload. The click
   listeners are registered exactly once, outside run(), and always
   dispatch to whichever page's load functions are current -- registering
   them inside run() would pile up a duplicate listener per navigation. */
(() => {
  "use strict";

  const escapeHTML = value => String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  let loadAggregation = () => {};
  let loadStaticAnalysis = () => {};

  function run() {
    const root = document.querySelector("[data-hp-page-content]");
    const hash = root?.dataset.hpPlHash;
    if (!root || !hash) {
      loadAggregation = () => {};
      loadStaticAnalysis = () => {};
      return;
    }

    // --- Aggregation hydration (#1142, unchanged) ---------------------------

    const sandboxTarget = document.querySelector("[data-hp-pl-sandbox-runs]");
    const githubTarget = document.querySelector("[data-hp-pl-github-analysis]");
    const knownTarget = document.querySelector("[data-hp-pl-known-elsewhere]");
    const knownHeading = document.getElementById("hp-pl-known-elsewhere-heading");

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

    function renderAggregationFailure(message) {
      const errorHTML = `<p class="empty">Could not load &mdash; ${escapeHTML(message)}. <button class="lnk" type="button" data-hp-pl-aggregation-retry>Retry</button></p>`;
      sandboxTarget.innerHTML = errorHTML;
      githubTarget.innerHTML = errorHTML;
      knownTarget.innerHTML = errorHTML;
    }

    loadAggregation = async function () {
      if (!sandboxTarget || !githubTarget || !knownTarget) return;
      try {
        const sha256 = root.dataset.hpPlSha256 || "";
        const response = await fetch(`/api/payload-analysis/${encodeURIComponent(hash)}/aggregation?sha256=${encodeURIComponent(sha256)}`, { cache: "no-store" });
        if (!response.ok) throw new Error(`request failed (${response.status})`);
        const agg = await response.json();
        renderSandboxRuns(agg.sandbox_runs);
        renderGitHubAnalysis(agg.github_analysis, agg.family, agg.family_link);
        renderKnownElsewhere(agg.correlation || {});
      } catch (error) {
        renderAggregationFailure(error.message);
      }
    };

    loadAggregation();

    // --- Static-analysis hydration (#1157) -----------------------------------

    const noteTarget = document.querySelector("[data-hp-pl-classification-note]");
    const riskTarget = document.querySelector("[data-hp-pl-risk]");
    const packedTarget = document.querySelector("[data-hp-pl-packed]");
    const iocsCountTarget = document.querySelector("[data-hp-pl-iocs-count]");
    const identityTarget = document.querySelector("[data-hp-pl-identity]");
    const scriptCard = document.getElementById("hp-pl-script-card");
    const scriptBodyTarget = document.querySelector("[data-hp-pl-script-body]");
    const yaraTarget = document.querySelector("[data-hp-pl-yara]");
    const rulesTarget = document.querySelector("[data-hp-pl-rules]");
    const iocListTarget = document.querySelector("[data-hp-pl-ioc-list]");
    const bytesActionsTarget = document.querySelector("[data-hp-pl-bytes-actions]");
    const textTarget = document.querySelector("[data-hp-pl-text]");
    const decodedTarget = document.querySelector("[data-hp-pl-decoded]");

    function renderClassificationNote(c) {
      if (!noteTarget) return;
      noteTarget.innerHTML = c.dynamic ? "" :
        `<p class="note">${escapeHTML(c.label)} has no dynamic detonation path &mdash; ${escapeHTML(c.analysis_path)}. The evidence below is the whole analysis for this artifact.</p>`;
    }

    function renderKPIs(data) {
      if (riskTarget) riskTarget.textContent = `${data.risk_score} / 100 • ${data.risk_level}`;
      if (packedTarget) packedTarget.textContent = data.packed_likely ? "elevated" : "not indicated";
      if (iocsCountTarget) iocsCountTarget.textContent = String((data.iocs || []).length);
    }

    function renderIdentity(data) {
      const c = data.classification || {};
      if (!identityTarget) return;
      let html = `<div class="card__row"><span class="card__label">identified type</span><span class="card__value"><strong>${escapeHTML(c.label)}</strong> <span class="badge badge--muted">${escapeHTML(c.code)}</span></span></div>`;
      html += `<div class="card__row"><span class="card__label">platform / category</span><span class="card__value card__value--mono">${escapeHTML(c.platform)} / ${escapeHTML(c.category)}</span></div>`;
      html += `<div class="card__row"><span class="card__label">sandbox route</span><span class="card__value card__value--mono">${escapeHTML(c.analysis_path)}</span></div>`;
      html += `<div class="card__row"><span class="card__label">dynamic execution</span><span class="card__value">${c.dynamic ? "supported for this type" : "not automatic; static analysis only"}</span></div>`;
      html += `<div class="card__row"><span class="card__label">magic</span><span class="card__value">${escapeHTML(data.magic)}</span></div>`;
      html += `<div class="card__row"><span class="card__label">MIME</span><span class="card__value card__value--mono">${escapeHTML(data.mime)}</span></div>`;
      html += `<div class="card__row"><span class="card__label">size</span><span class="card__value card__value--mono">${escapeHTML(data.size)}</span></div>`;
      html += `<div class="card__row"><span class="card__label">entropy</span><span class="card__value card__value--mono">${escapeHTML(data.entropy)}</span></div>`;
      html += `<div class="card__row"><span class="card__label">SHA-256</span><span class="card__value card__value--mono">${escapeHTML(data.sha256)}</span></div>`;
      html += `<div class="card__row"><span class="card__label">SHA-1</span><span class="card__value card__value--mono">${escapeHTML(data.sha1)}</span></div>`;
      html += `<div class="card__row"><span class="card__label">MD5</span><span class="card__value card__value--mono">${escapeHTML(data.md5)}</span></div>`;
      if (data.truncated) html += `<p class="note">deep inspection capped at 16 MiB; hashes cover the complete file</p>`;
      identityTarget.innerHTML = html;
    }

    // #1157: was a server-side `{{if or .ScriptType .Indicators}}` that
    // omitted the whole card -- ScriptType/Indicators aren't known until this
    // fetch resolves, so the card always renders (skeleton) and is hidden
    // here instead when it turns out empty. See payloads.html's own comment
    // on why the neighboring sandbox card no longer reflows to "wide" to fill
    // the gap.
    function renderScriptClassification(data) {
      if (!scriptCard) return;
      if (!data.script_type && !(data.indicators || []).length) {
        scriptCard.hidden = true;
        return;
      }
      scriptCard.hidden = false;
      if (!scriptBodyTarget) return;
      let html = "";
      if (data.script_type) html += `<div class="card__row"><span class="card__label">language/type</span><span class="card__value card__value--mono">${escapeHTML(data.script_type)}</span></div>`;
      if ((data.indicators || []).length) {
        html += `<div class="card__row"><span class="card__label">behavior indicators</span><span class="card__value">${data.indicators.map(i => `<span class="chip">${escapeHTML(i)}</span>`).join(" ")}</span></div>`;
      }
      html += `<p class="note">Heuristic static findings only. Captured content is never interpreted or executed.</p>`;
      scriptBodyTarget.innerHTML = html;
    }

    function renderYARA(data) {
      if (!yaraTarget) return;
      let html;
      if ((data.yara_matches || []).length) {
        const rows = data.yara_matches.map(m => `<tr><td><span class="badge badge--red">match</span></td><td class="v">${escapeHTML(m)}</td></tr>`).join("");
        html = `<div class="card__scroll"><table class="data-table"><tbody>${rows}</tbody></table></div>`;
      } else {
        html = `<p class="empty">${data.yara_scanned ? "No YARA rules matched this sample." : "Waiting for the isolated YARA scanner."}</p>`;
      }
      if (data.yara_error) html += `<p class="note tw:text-red">${escapeHTML(data.yara_error)}</p>`;
      if (data.yara_scanned) html += `<p class="note">Scanned ${escapeHTML(data.yara_scanned)} by the networkless YARA sidecar. A match is a triage signal, not attribution.</p>`;
      yaraTarget.innerHTML = html;
    }

    function renderRules(data) {
      if (!rulesTarget) return;
      if ((data.rules || []).length) {
        const rows = data.rules.map(r => `<tr><td><span class="badge badge--muted">${escapeHTML(r.severity)}</span></td><td class="v">${escapeHTML(r.name)}</td><td class="v">${escapeHTML(r.description)}</td></tr>`).join("");
        rulesTarget.innerHTML = `<div class="card__scroll"><table class="data-table"><thead><tr><th>severity</th><th>rule</th><th>reason</th></tr></thead><tbody>${rows}</tbody></table></div>`;
      } else {
        rulesTarget.innerHTML = `<p class="empty">No built-in static rules matched.</p>`;
      }
    }

    function renderIOCList(data) {
      if (!iocListTarget) return;
      if ((data.iocs || []).length) {
        const rows = data.iocs.map(ioc => `<tr><td class="v"><a href="/events?q=${encodeURIComponent(ioc)}" title="search telemetry for this indicator">${escapeHTML(ioc)}</a></td></tr>`).join("");
        iocListTarget.innerHTML = `<div class="card__scroll"><table class="data-table"><tbody>${rows}</tbody></table></div>`;
      } else {
        iocListTarget.innerHTML = `<p class="empty">No URL, domain, or IP indicators found.</p>`;
      }
    }

    function renderSearchableEvidence(target, entries, options) {
      if (!target) return;
      target.replaceChildren();
      if (!entries.length) {
        const empty = document.createElement("p");
        empty.className = "empty";
        empty.textContent = options.empty;
        target.appendChild(empty);
        return;
      }
      const note = document.createElement("p");
      note.className = "note";
      const input = document.createElement("input");
      input.className = "search";
      input.type = "search";
      input.placeholder = options.placeholder;
      input.setAttribute("aria-label", options.placeholder);
      const scroll = document.createElement("div");
      scroll.className = "card__scroll";
      const pre = document.createElement("pre");
      pre.className = "code";
      scroll.appendChild(pre);
      const update = () => {
        const query = input.value.trim().toLowerCase();
        const shown = query ? entries.filter(entry => `${entry.label} ${entry.value}`.toLowerCase().includes(query)) : entries;
        note.textContent = `${shown.length} of ${entries.length} ${options.label}${entries.length === 1 ? "" : "s"} shown${options.note ? ` — ${options.note}` : ""}`;
        pre.textContent = shown.length ? shown.map(entry => entry.label ? `[${entry.label}]\n${entry.value}` : entry.value).join("\n\n") : "No entries match this filter.";
      };
      input.addEventListener("input", update);
      target.append(note, input, scroll);
      update();
    }

    function renderBytesAndMetadata(data) {
      if (!bytesActionsTarget) return;
      bytesActionsTarget.replaceChildren();
      const previewTitle = document.createElement("h3");
      previewTitle.textContent = "Hex / ASCII preview — first 512 bytes";
      const preview = document.createElement("pre");
      preview.className = "code hp-code-results";
      preview.textContent = data.hexdump || "No byte preview is available.";
      bytesActionsTarget.append(previewTitle, preview);
      const formatTitle = document.createElement("h3");
      formatTitle.textContent = "Executable metadata";
      bytesActionsTarget.appendChild(formatTitle);
      if ((data.format_info || []).length) {
        const format = document.createElement("pre");
        format.className = "code hp-code-results";
        format.textContent = data.format_info.join("\n");
        bytesActionsTarget.appendChild(format);
      } else {
        const empty = document.createElement("p");
        empty.className = "empty";
        empty.textContent = "Not a recognized PE or ELF file.";
        bytesActionsTarget.appendChild(empty);
      }
      if (data.truncated) {
        const cap = document.createElement("p");
        cap.className = "note";
        cap.textContent = "Deep inspection is capped at 16 MiB; hashes cover the complete file.";
        bytesActionsTarget.appendChild(cap);
      }
    }

    function renderExtractedText(data) {
      const ascii = (data.ascii || []).map(value => ({label: "ASCII", value}));
      const utf16 = (data.utf16 || []).map(value => ({label: "UTF-16LE", value}));
      renderSearchableEvidence(textTarget, [...ascii, ...utf16], {
        empty: "No printable sequences extracted.",
        placeholder: "Filter printable strings",
        label: "sequence",
        note: "bounded static extraction; sample content is never executed",
      });
    }

    function renderDecoded(data) {
      const entries = (data.decoded || []).map(item => ({
        label: item.kind || "decoded",
        value: `source: ${item.source || "unknown"}\n${item.preview || ""}`,
      }));
      renderSearchableEvidence(decodedTarget, entries, {
        empty: "No bounded Base64, hex, URL or UTF-16 candidates found.",
        placeholder: "Filter decoded candidates",
        label: "candidate",
        note: "bounded decodes only; recovered content is never executed",
      });
    }

    function renderStaticFailure(message) {
      const errorHTML = `<p class="empty">Could not load &mdash; ${escapeHTML(message)}. <button class="lnk" type="button" data-hp-pl-static-retry>Retry</button></p>`;
      if (identityTarget) identityTarget.innerHTML = errorHTML;
      if (yaraTarget) yaraTarget.innerHTML = errorHTML;
      if (rulesTarget) rulesTarget.innerHTML = errorHTML;
      if (iocListTarget) iocListTarget.innerHTML = errorHTML;
      if (bytesActionsTarget) bytesActionsTarget.innerHTML = errorHTML;
      if (textTarget) textTarget.innerHTML = errorHTML;
      if (decodedTarget) decodedTarget.innerHTML = errorHTML;
      if (scriptCard) scriptCard.hidden = true;
    }

    loadStaticAnalysis = async function () {
      try {
        const response = await fetch(`/api/payload-analysis/${encodeURIComponent(hash)}/static`, { cache: "no-store" });
        if (!response.ok) throw new Error(`request failed (${response.status})`);
        const data = await response.json();
        renderClassificationNote(data.classification || {});
        renderKPIs(data);
        renderIdentity(data);
        renderScriptClassification(data);
        renderYARA(data);
        renderRules(data);
        renderIOCList(data);
        renderBytesAndMetadata(data);
        renderExtractedText(data);
        renderDecoded(data);
        // The aggregation fetch above may already have gone out with no
        // sha256 (the page shell doesn't have one) -- now that the real
        // value is known, record it and, if that first aggregation call ran
        // unscoped, re-run it once with the real value.
        if (data.sha256 && root.dataset.hpPlSha256 !== data.sha256) {
          const hadSha256 = !!root.dataset.hpPlSha256;
          root.dataset.hpPlSha256 = data.sha256;
          if (!hadSha256) loadAggregation();
        }
      } catch (error) {
        renderStaticFailure(error.message);
      }
    };

    loadStaticAnalysis();
  }

  document.addEventListener("click", e => {
    if (e.target.closest?.("[data-hp-pl-aggregation-retry]")) loadAggregation();
    if (e.target.closest?.("[data-hp-pl-static-retry]")) loadStaticAnalysis();
  });

  run();
  document.addEventListener("hp-dynamic-nav", run);
})();
