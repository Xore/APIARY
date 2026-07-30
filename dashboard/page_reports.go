package main

// page_reports.go — the Reports studio page (R3). The designer lives in the
// main content area like every other dashboard page; the dynamic behavior is
// in /static/hp-reports.js against the /api/reports/* endpoints. This is the
// single place PDFs are designed, generated, viewed, and downloaded.
const pageReports = `
{{define "reports"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot — Reports studio</title>
{{template "style"}}
<style>
.hp-rp-templates { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 10px; margin: 4px 0 18px; }
.hp-rp-template { text-align: left; background: var(--surface-1); border: 1px solid var(--border-subtle); border-radius: var(--radius-panel); padding: 12px 14px; cursor: pointer; color: var(--text-primary); transition: border-color .15s ease, background .15s ease; }
.hp-rp-template:hover { border-color: var(--border-strong); background: var(--surface-hover); }
.hp-rp-template[aria-pressed="true"] { border-color: var(--accent); background: var(--accent-soft); }
.hp-rp-template strong { display: block; font-size: 13px; margin-bottom: 4px; }
.hp-rp-template span { font-size: 11.5px; color: var(--text-muted); line-height: 1.45; display: block; }
.hp-rp-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px 16px; }
.hp-rp-field label { display: block; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--text-muted); margin-bottom: 5px; }
.hp-rp-field input, .hp-rp-field select { width: 100%; background: var(--surface-0); border: 1px solid var(--border-subtle); border-radius: var(--radius-control); color: var(--text-primary); padding: 8px 10px; font-size: 13px; }
.hp-rp-field input:focus, .hp-rp-field select:focus { outline: none; border-color: var(--border-focus); }
.hp-rp-elements { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 6px 16px; }
.hp-rp-elements label { display: flex; gap: 8px; align-items: baseline; font-size: 12.5px; color: var(--text-secondary); padding: 5px 0; cursor: pointer; }
.hp-rp-elements input { accent-color: var(--accent); margin-top: 2px; }
.hp-rp-elements small { display: block; color: var(--text-muted); font-size: 11px; }
.hp-rp-theme { display: flex; gap: 10px; }
.hp-rp-theme button { flex: 1; max-width: 220px; display: flex; align-items: center; gap: 10px; background: var(--surface-1); border: 1px solid var(--border-subtle); border-radius: var(--radius-panel); padding: 10px 12px; cursor: pointer; color: var(--text-primary); font-size: 13px; }
.hp-rp-theme button[aria-pressed="true"] { border-color: var(--accent); background: var(--accent-soft); }
.hp-rp-swatch { width: 30px; height: 22px; border-radius: var(--radius-xs); border: 1px solid var(--border-strong); flex: none; }
.hp-rp-swatch--dark { background: #20201f; box-shadow: inset 0 -7px 0 #d97757; }
.hp-rp-swatch--light { background: #f7f6f2; box-shadow: inset 0 -7px 0 #c76548; }
.hp-rp-section { margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border-subtle); }
.hp-rp-section > h3 { font-size: 12px; text-transform: uppercase; letter-spacing: .08em; color: var(--text-muted); margin: 0 0 10px; font-weight: 600; }
.hp-rp-actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 18px; }
.hp-rp-status { font-size: 12px; color: var(--text-muted); }
.hp-rp-status[data-state="error"] { color: var(--danger); }
.hp-rp-status[data-state="ok"] { color: var(--success); }
.hp-rp-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.hp-rp-table th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--text-muted); padding: 8px 10px; border-bottom: 1px solid var(--border-strong); }
.hp-rp-table td { padding: 9px 10px; border-bottom: 1px solid var(--border-subtle); vertical-align: middle; }
.hp-rp-table tr:hover td { background: var(--surface-hover); }
.hp-rp-tag { display: inline-block; font-size: 11px; padding: 2px 8px; border-radius: var(--radius-pill); background: var(--surface-2); color: var(--text-secondary); }
.hp-rp-tag--light { background: var(--info-soft); color: var(--info); }
.hp-rp-row-actions { display: flex; gap: 6px; flex-wrap: wrap; }
.hp-rp-viewer { margin-top: 14px; border: 1px solid var(--border-strong); border-radius: var(--radius-panel); overflow: hidden; background: var(--surface-1); }
.hp-rp-viewer header { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 14px; border-bottom: 1px solid var(--border-subtle); font-size: 13px; }
.hp-rp-viewer iframe { display: block; width: 100%; height: 72vh; border: 0; background: var(--surface-0); }
</style>
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap app-content tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="reports-header">
          <div>
            <div class="eyebrow">Reporting</div>
            <h1>Reports studio</h1>
            <p class="subtitle">Design themed, branded PDF reports from live telemetry or sandbox runs &mdash; start from a template or build fully custom, then generate, view, and download here. This is the only place PDFs are produced.</p>
          </div>
          <div class="live-panel">
            <span class="gen">dark &amp; light themes &bull; custom branding &bull; scoped to your search criteria</span>
          </div>
        </header>

        <div data-hp-reports>
          <div class="card wide" id="hp-rp-designer">
            <h2>Designer</h2>
            <p class="note">Pick a template as the starting point, then adjust elements, scope, theme, and branding until the report says exactly what you need.</p>
            <div class="hp-rp-templates" id="hp-rp-templates" role="group" aria-label="Report templates"></div>

            <form id="hp-rp-form" novalidate>
              <div class="hp-rp-grid">
                <div class="hp-rp-field"><label for="hp-rp-name">Report name</label><input id="hp-rp-name" maxlength="60" required placeholder="Weekly board briefing"></div>
                <div class="hp-rp-field"><label for="hp-rp-window">Observation window</label><select id="hp-rp-window"></select></div>
                <div class="hp-rp-field"><label for="hp-rp-appendix">Event appendix limit</label><input id="hp-rp-appendix" type="number" min="0" max="500" step="10" value="120"></div>
                <div class="hp-rp-field"><label>PDF theme</label>
                  <div class="hp-rp-theme" id="hp-rp-theme" role="group" aria-label="PDF theme">
                    <button type="button" data-theme="dark" aria-pressed="true"><span class="hp-rp-swatch hp-rp-swatch--dark"></span>Dark</button>
                    <button type="button" data-theme="light" aria-pressed="false"><span class="hp-rp-swatch hp-rp-swatch--light"></span>Light</button>
                  </div>
                </div>
              </div>

              <div class="hp-rp-section" id="hp-rp-elements-section">
                <h3>Elements</h3>
                <div class="hp-rp-elements" id="hp-rp-elements"></div>
              </div>

              <div class="hp-rp-section" id="hp-rp-scope-section">
                <h3>Scope &amp; search criteria</h3>
                <div class="hp-rp-grid">
                  <div class="hp-rp-field"><label for="hp-rp-scope-ip">Source IP</label><input id="hp-rp-scope-ip" maxlength="64" placeholder="203.0.113.42"></div>
                  <div class="hp-rp-field"><label for="hp-rp-scope-network">Network (CIDR)</label><input id="hp-rp-scope-network" maxlength="64" placeholder="203.0.113.0/24"></div>
                  <div class="hp-rp-field"><label for="hp-rp-scope-sensor">Sensor</label><input id="hp-rp-scope-sensor" maxlength="64" placeholder="cowrie"></div>
                  <div class="hp-rp-field"><label for="hp-rp-scope-port">Destination port</label><input id="hp-rp-scope-port" maxlength="16" placeholder="22"></div>
                  <div class="hp-rp-field"><label for="hp-rp-scope-signature">Signature contains</label><input id="hp-rp-scope-signature" maxlength="120" placeholder="ET SCAN"></div>
                  <div class="hp-rp-field"><label for="hp-rp-scope-country">Country</label><input id="hp-rp-scope-country" maxlength="64" placeholder="Netherlands"></div>
                  <div class="hp-rp-field"><label for="hp-rp-scope-asn">ASN</label><input id="hp-rp-scope-asn" maxlength="32" placeholder="AS64500"></div>
                  <div class="hp-rp-field"><label for="hp-rp-scope-type">Event type</label><select id="hp-rp-scope-type"><option value="">any</option><option value="login">login</option><option value="command">command</option><option value="alert">alert</option><option value="download">download</option></select></div>
                  <div class="hp-rp-field"><label for="hp-rp-scope-session">Session id</label><input id="hp-rp-scope-session" maxlength="128"></div>
                  <div class="hp-rp-field"><label for="hp-rp-scope-text">Free text</label><input id="hp-rp-scope-text" maxlength="200" placeholder="matches across all event fields"></div>
                </div>
              </div>

              <div class="hp-rp-section" id="hp-rp-sandbox-section" hidden>
                <h3>Sandbox run</h3>
                <div class="hp-rp-grid">
                  <div class="hp-rp-field"><label for="hp-rp-sandbox-job">Analysis job</label><select id="hp-rp-sandbox-job"></select></div>
                </div>
                <p class="note">Sandbox reports have a fixed evidence structure; theme and branding still apply.</p>
              </div>

              <div class="hp-rp-section" id="hp-rp-schedule-section">
                <h3>Schedule</h3>
                <div class="hp-rp-grid">
                  <div class="hp-rp-field"><label for="hp-rp-sched-enabled">Recurring generation</label><label style="display:flex;gap:8px;align-items:center;font-size:13px;color:var(--text-secondary);text-transform:none;letter-spacing:0"><input type="checkbox" id="hp-rp-sched-enabled" style="accent-color:var(--accent)"> run this report automatically</label></div>
                  <div class="hp-rp-field"><label for="hp-rp-sched-frequency">Frequency</label><select id="hp-rp-sched-frequency"><option value="daily">daily</option><option value="weekly">weekly</option><option value="monthly">monthly</option></select></div>
                  <div class="hp-rp-field"><label for="hp-rp-sched-hour">Hour (UTC)</label><input id="hp-rp-sched-hour" type="number" min="0" max="23" value="6"></div>
                  <div class="hp-rp-field"><label for="hp-rp-sched-minute">Minute</label><input id="hp-rp-sched-minute" type="number" min="0" max="59" value="30"></div>
                  <div class="hp-rp-field" id="hp-rp-sched-weekday-field" hidden><label for="hp-rp-sched-weekday">Weekday</label><select id="hp-rp-sched-weekday"><option value="1">Monday</option><option value="2">Tuesday</option><option value="3">Wednesday</option><option value="4">Thursday</option><option value="5">Friday</option><option value="6">Saturday</option><option value="0">Sunday</option></select></div>
                  <div class="hp-rp-field" id="hp-rp-sched-monthday-field" hidden><label for="hp-rp-sched-monthday">Day of month</label><input id="hp-rp-sched-monthday" type="number" min="1" max="28" value="1"></div>
                </div>
                <p class="note">Times are UTC. Scheduled reports render through the same pipeline as manual ones and appear in the history with origin <em>schedule</em>; the retention cap prunes the oldest artifacts automatically.</p>
              </div>

              <div class="hp-rp-section">
                <h3>Branding</h3>
                <div class="hp-rp-grid">
                  <div class="hp-rp-field"><label for="hp-rp-brand-title">Report title</label><input id="hp-rp-brand-title" maxlength="80" placeholder="defaults to the template title"></div>
                  <div class="hp-rp-field"><label for="hp-rp-brand-author">Author</label><input id="hp-rp-brand-author" maxlength="60" placeholder="SOC team"></div>
                  <div class="hp-rp-field"><label for="hp-rp-brand-header-left">Header left</label><input id="hp-rp-brand-header-left" maxlength="60" placeholder="XORE//HONEYPOT"></div>
                  <div class="hp-rp-field"><label for="hp-rp-brand-header-right">Header right</label><input id="hp-rp-brand-header-right" maxlength="60" placeholder="DEFENSIVE SECURITY OPERATIONS"></div>
                  <div class="hp-rp-field"><label for="hp-rp-brand-footer">Footer text</label><input id="hp-rp-brand-footer" maxlength="80" placeholder="PRIVATE - XORE//HONEYPOT"></div>
                  <div class="hp-rp-field"><label for="hp-rp-brand-classification">Classification line</label><input id="hp-rp-brand-classification" maxlength="120" placeholder="PRIVATE - contains hostile-source telemetry"></div>
                </div>
              </div>

              <div class="hp-rp-actions">
                <button class="btn btn-primary" type="submit" id="hp-rp-save">Save definition</button>
                <button class="btn btn-secondary" type="button" id="hp-rp-generate">Generate now</button>
                <button class="btn btn-secondary" type="button" id="hp-rp-reset">Reset to template</button>
                <span class="hp-rp-status" id="hp-rp-status" role="status"></span>
              </div>
            </form>
          </div>

          <div class="card wide" id="hp-rp-definitions-card">
            <h2>Saved definitions</h2>
            <p class="note">Saved designs you can re-generate, refine, or schedule.</p>
            <table class="hp-rp-table" id="hp-rp-definitions-table">
              <thead><tr><th>Name</th><th>Template</th><th>Theme</th><th>Window</th><th>Schedule</th><th>Updated</th><th>Actions</th></tr></thead>
              <tbody id="hp-rp-definitions"></tbody>
            </table>
            <p class="empty" id="hp-rp-definitions-empty" hidden>No saved definitions yet &mdash; design one above and save it.</p>
          </div>

          <div class="card wide" id="hp-rp-generated-card">
            <h2>Generated reports</h2>
            <p class="note">Newest first. View inline, download the PDF, or delete stale artifacts.</p>
            <table class="hp-rp-table" id="hp-rp-generated-table">
              <thead><tr><th>Title</th><th>Template</th><th>Theme</th><th>Origin</th><th>Created</th><th>Size</th><th>Actions</th></tr></thead>
              <tbody id="hp-rp-generated"></tbody>
            </table>
            <p class="empty" id="hp-rp-generated-empty" hidden>No reports generated yet.</p>
            <div class="hp-rp-viewer" id="hp-rp-viewer" hidden>
              <header><strong id="hp-rp-viewer-title">Report</strong><button class="btn btn-sm btn-secondary" type="button" id="hp-rp-viewer-close">Close viewer</button></header>
              <iframe id="hp-rp-viewer-frame" title="Generated report preview"></iframe>
            </div>
          </div>

          <p class="note" id="hp-rp-admin-note" hidden>Designing and generating reports requires the administrator role &mdash; sign in with an admin account to use the studio.</p>
        </div>
        <footer id="reports-footer">xore//honeypot &bull; reports studio</footer>
      </div>
    </main>
</div>
<script defer src="/static/hp-reports.js?v=20260730-1"></script>
</body>
</html>
{{end}}
`
