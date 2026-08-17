/* hp-canarytokens.js -- #1487: the standalone /canarytokens page (Tokens /
 * Create bait / Reports / Credentials tabs). The page ships an instant
 * skeleton with no server-side query (routes.go's GET /canarytokens just
 * renders the shell); every tab hydrates itself here, in parallel, on load
 * -- not lazily on tab activation -- so all four are populated in the
 * background regardless of which one the operator lands on first, same
 * convention as the rest of this dashboard's shell+hydrate pages.
 *
 * Reuses the existing #1508 endpoints as-is (/api/settings/canarytokens*)
 * plus the existing generic /api/events?sensor=canarytokens for the Reports
 * tab (classify.go already classifies canarytokens-adapter's fired-token
 * events, #1426) -- no new backend surface for Reports.
 *
 * Credentials tab (items 3/5, #1553's honeyfs-implant primitive) is served
 * by credentials_api.go's /api/settings/credentials* endpoints -- provision/
 * rotate write a live artifact into a honeypot's filesystem, so every
 * mutation here re-fetches the list rather than trying to patch a single
 * row in place (keeps this file's state simple; these are low-frequency,
 * operator-driven actions, not a hot path).
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
      // #1586: a request that never reached this dashboard's own handler at
      // all -- an intermediate proxy 502/504/522 in front of it -- answers
      // with its own branded HTML error page, not plain text from us. Every
      // real error this dashboard's own /api/settings/canarytokens* routes
      // produce is a short plain-text or JSON body (http.Error and friends);
      // surfacing anything under a text/html Content-Type verbatim just
      // dumps that page's full markup into the UI as if it were a message.
      const contentType = response.headers.get("Content-Type") || "";
      const body = await response.text().catch(() => "");
      const message = contentType.includes("text/html")
        ? `the server returned an unexpected response (HTTP ${response.status}) -- it may be temporarily unreachable, try again in a moment`
        : (body || response.statusText);
      const error = new Error(message);
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
  // tokenRecords caches the last-loaded canarytoken list for the
  // Credentials tab's "link a token" select -- populated by loadTokens,
  // read by loadCredentials/renderCredentialRow. Both tabs hydrate in
  // parallel on page load (see this file's header), so
  // ensureTokenRecords() below fetches its own copy if the Tokens tab
  // hasn't finished first, rather than blocking on it.
  let tokenRecords = null;

  async function ensureTokenRecords() {
    if (tokenRecords) return tokenRecords;
    try {
      const body = await api("/api/settings/canarytokens");
      tokenRecords = body.tokens || [];
    } catch (error) {
      tokenRecords = [];
    }
    return tokenRecords;
  }

  // #1575: a gallery card can be clicked before /api/settings/canarytokens/types
  // has resolved (all three tabs hydrate in parallel, per this file's own
  // header comment) -- the chosen type waits here and applies itself the
  // moment the type <select> is populated.
  let pendingGalleryType = null;

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
      tokenRecords = body.tokens || [];
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
      if (pendingGalleryType && typesByKey[pendingGalleryType]) {
        select.value = pendingGalleryType;
        pendingGalleryType = null;
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

  // #1575: the Tokens tab's empty-state gallery -- each card names a
  // specific, actually-supported token type (canarytokens_client.go's
  // canarytokensSupportedTypes; no AWS-key/DNS types exist on this
  // dashboard's scoped subset) and jumps straight into Create bait with
  // that type preselected, the same data-dashboard-tab click mechanism
  // hp-tty-replay.js already uses to switch tabs from other JS.
  function wireTokensGallery() {
    const gallery = q("ct-tokens-gallery");
    if (!gallery) return;
    gallery.addEventListener("click", event => {
      const card = event.target.closest("[data-token-type]");
      if (!card) return;
      const type = card.dataset.tokenType;
      if (typesByKey && typesByKey[type]) {
        q("ct-type").value = type;
        updateCreateFormForType();
      } else {
        pendingGalleryType = type;
      }
      document.querySelector('[data-dashboard-tab="ct-create"]')?.click();
      q("ct-memo")?.focus();
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

  /* ---------------- Credentials tab (#1487 items 3/5) ---------------- */

  // credentialPasswordAlphabet mirrors credentials_manager.go's own
  // generateCredentialPassword alphabet -- ambiguous look-alikes (0/O,
  // 1/l/I) excluded, since this is bait content an operator may need to
  // read back off a screen, not a maximum-entropy secret. Generated
  // client-side purely to prefill the form field for editing before
  // submit; the server generates its own value independently for a
  // password-less rotate call.
  const credentialPasswordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%*";

  function generateClientPassword() {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, b => credentialPasswordAlphabet[b % credentialPasswordAlphabet.length]).join("");
  }

  function linkTokenLabel(record) {
    if (!record.token_type) return record.id;
    return (typesByKey && typesByKey[record.token_type] && typesByKey[record.token_type].label) || record.token_type;
  }

  function buildLinkSelect(record, tokens) {
    const select = document.createElement("select");
    select.className = "btn btn-ghost btn-sm";
    select.setAttribute("aria-label", "Link a canarytoken to this credential");
    const noneOption = document.createElement("option");
    noneOption.value = "";
    noneOption.textContent = "No linked token";
    select.appendChild(noneOption);
    tokens.forEach(tok => {
      const option = document.createElement("option");
      option.value = tok.id;
      option.textContent = linkTokenLabel(tok) + (tok.memo ? " — " + tok.memo : "");
      if (tok.id === record.linked_token_id) option.selected = true;
      select.appendChild(option);
    });
    if (!tokens.some(tok => tok.id === record.linked_token_id) && record.linked_token_id) {
      // The linked token isn't in the current list (deleted upstream, or
      // simply not loaded yet) -- keep it selectable/visible rather than
      // silently falling back to "No linked token" and looking unlinked.
      const staleOption = document.createElement("option");
      staleOption.value = record.linked_token_id;
      staleOption.textContent = record.linked_token_id + " (not found)";
      staleOption.selected = true;
      select.appendChild(staleOption);
    }
    select.addEventListener("change", async () => {
      select.disabled = true;
      try {
        await api("/api/settings/credentials/" + encodeURIComponent(record.id) + "/link-token", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token_id: select.value }),
        });
        await loadCredentials();
      } catch (error) {
        select.disabled = false;
        window.alert("Could not update the link — " + error.message.trim());
      }
    });
    return select;
  }

  function renderCredentialRow(record, tokens) {
    const row = document.createElement("tr");
    const path = document.createElement("td");
    path.className = "mono";
    path.textContent = record.path;
    row.appendChild(path);
    const username = document.createElement("td");
    username.textContent = record.username;
    row.appendChild(username);
    const password = document.createElement("td");
    password.className = "mono";
    password.textContent = record.password;
    row.appendChild(password);
    const memo = document.createElement("td");
    memo.textContent = record.memo || "—";
    row.appendChild(memo);
    const linked = document.createElement("td");
    linked.appendChild(buildLinkSelect(record, tokens));
    row.appendChild(linked);
    const rotated = document.createElement("td");
    rotated.textContent = record.rotated_at ? fmtTime(record.rotated_at) : "never";
    row.appendChild(rotated);
    const manage = document.createElement("td");
    const rotateBtn = document.createElement("button");
    rotateBtn.type = "button";
    rotateBtn.className = "btn btn-ghost btn-sm";
    rotateBtn.textContent = "Rotate";
    rotateBtn.addEventListener("click", async () => {
      rotateBtn.disabled = true;
      try {
        await api("/api/settings/credentials/" + encodeURIComponent(record.id) + "/rotate", { method: "POST" });
        await loadCredentials();
      } catch (error) {
        rotateBtn.disabled = false;
        window.alert("Rotation failed — " + error.message.trim());
      }
    });
    manage.appendChild(rotateBtn);
    row.appendChild(manage);
    return row;
  }

  async function loadCredentials() {
    const tbody = q("ct-credentials-tbody");
    const emptyEl = q("ct-credentials-empty");
    const errorEl = q("ct-credentials-error");
    const unavailable = q("ct-cred-unavailable");
    try {
      const [body, tokens] = await Promise.all([api("/api/settings/credentials"), ensureTokenRecords()]);
      setSkeletonState(tbody, emptyEl, errorEl, body.credentials, record => renderCredentialRow(record, tokens), 7);
      // available here only reflects Elasticsearch (credentials_api.go's
      // serveCredentialsList) -- an unset HONEYFS_IMPLANT_URL isn't visible
      // until a provision/rotate attempt actually fails with 503, same as
      // this dashboard's other "no dedicated availability probe" actions
      // (e.g. ip_block.go's own block/unblock form).
      if (unavailable) unavailable.hidden = body.available !== false;
    } catch (error) {
      showLoadError(tbody, emptyEl, errorEl, error);
    }
  }

  function wireCredentialForm() {
    const form = q("ct-cred-form");
    q("ct-cred-generate").addEventListener("click", () => { q("ct-cred-password").value = generateClientPassword(); });

    form.addEventListener("submit", async event => {
      event.preventDefault();
      const resultEl = q("ct-cred-result");
      const submitBtn = q("ct-cred-submit");
      const payload = {
        path: q("ct-cred-path").value.trim(),
        username: q("ct-cred-username").value.trim(),
        password: q("ct-cred-password").value,
        memo: q("ct-cred-memo").value.trim(),
        content_template: q("ct-cred-template").value,
      };
      submitBtn.disabled = true;
      try {
        await api("/api/settings/credentials/create", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        resultEl.hidden = false;
        resultEl.textContent = "Provisioned. See the table below — the file is live in Cowrie's honeyfs now.";
        form.reset();
        await loadCredentials();
      } catch (error) {
        resultEl.hidden = false;
        resultEl.textContent = "Provisioning failed — " + error.message.trim();
      } finally {
        submitBtn.disabled = false;
      }
    });
  }

  /* ---------------- init ---------------- */

  document.addEventListener("DOMContentLoaded", () => {
    wireCreateForm();
    wireCredentialForm();
    wireTokensGallery();
    // All four tabs hydrate together, in the background, regardless of
    // which one is active on load -- not gated on tab activation.
    loadTokens();
    loadTypesAndWireForm();
    loadReports();
    loadCredentials();
    q("ct-tokens-refresh").addEventListener("click", loadTokens);
    q("ct-reports-refresh").addEventListener("click", loadReports);
    q("ct-credentials-refresh").addEventListener("click", loadCredentials);
  });
})();
