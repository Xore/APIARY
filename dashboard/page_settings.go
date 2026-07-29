package main

// pageSettings is the permanent full-viewport settings dialog from roadmap §7
// (Milestone D), following the Xore theme modal contract (docs/MODALS.md in
// Xore/theme): a native dialog with data-permanent-dialog that owns scrolling
// and cannot close on Escape, with the nested save/reset confirmation as a
// descendant so the browser top-layer invariant holds.
const pageSettings = `
{{define "settings"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Settings — xore//honeypot</title>
<script>(function(){try{var t=localStorage.getItem("hp-theme");if(t==="light"||t==="dark"){document.documentElement.dataset.theme=t;}else if(t){localStorage.removeItem("hp-theme");}}catch(e){}})();</script>
<link rel="stylesheet" href="/static/theme.css?v=20260729-1">
<script defer src="/static/hp-settings.js?v=20260730-1"></script>
<style>
  .hp-settings-page{height:100dvh;overflow:hidden}
  .hp-settings-page .settings-layout__content{height:100dvh}
  .hp-settings-column{width:min(100%,880px)}
  .hp-settings-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:24px}
  .hp-settings-head h1{margin-bottom:6px}
  .hp-settings-head p{margin:0;color:var(--text-secondary);font-size:13px}
  .hp-settings-status{min-height:18px;margin:0 0 18px;font-size:12px;color:var(--text-muted)}
  .hp-settings-status.is-error{color:var(--danger)}
  .hp-settings-status.is-ok{color:var(--success)}
  .hp-settings-pane[hidden],.hp-field[hidden]{display:none}
  .sidebar__item.is-dirty::after{content:"";width:6px;height:6px;margin-left:auto;border-radius:50%;background:var(--accent)}
  .hp-cap-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
  @media(max-width:720px){
    .hp-settings-page{height:auto;overflow:auto}
    .hp-settings-page .settings-layout__content{height:auto}
  }
  @media(prefers-reduced-motion:reduce){
    .hp-settings-page *{animation:none!important;transition:none!important}
  }
</style>
</head>
<body class="hp-settings-page">
<dialog class="modal modal--permanent" id="hp-settings" data-permanent-dialog aria-modal="true" aria-labelledby="hp-settings-title">
  <div class="settings-layout">
  <aside class="settings-layout__sidebar" aria-label="Settings sections">
    <div class="sidebar__search"><span>&#8982;</span><input aria-label="Search settings" placeholder="Search settings" data-hp-settings-search type="search" autocomplete="off"></div>
    <div class="sidebar__section-label">Personal</div>
    <button class="sidebar__item" type="button" data-hp-pane-nav="account">Account</button>
    <button class="sidebar__item" type="button" data-hp-pane-nav="appearance">Appearance</button>
    <button class="sidebar__item" type="button" data-hp-pane-nav="navigation">Navigation &amp; tables</button>
    <button class="sidebar__item" type="button" data-hp-pane-nav="time">Time &amp; live data</button>
    <button class="sidebar__item" type="button" data-hp-pane-nav="map">Map &amp; investigation</button>
    <div class="sidebar__section-label">Dashboard</div>
    <a class="sidebar__item" href="/" data-hp-settings-back>&larr; Back to dashboard</a>
  </aside>

  <main class="settings-layout__content">
    <div class="hp-settings-column">
      <header class="hp-settings-head">
        <div>
          <h1 id="hp-settings-title">Settings</h1>
          <p data-hp-pane-desc>Manage your dashboard identity and preferences.</p>
        </div>
      </header>
      <p class="hp-settings-status" role="status" aria-live="polite" data-hp-settings-status></p>

      <!-- Account: read-only identity plus links into auth-backend. Credential
           mutation never happens on the dashboard origin (roadmap §6). -->
      <section class="hp-settings-pane" data-hp-pane="account" aria-label="Account">
        <section class="card hp-field" data-hp-search="account identity role capabilities profile">
          <div class="card__title">Profile</div>
          <div class="card__desc">Resolved live from the auth backend on every request.</div>
          <div class="card__row">
            <div>
              <div class="card__label" data-hp-acct-name>&hellip;</div>
              <div class="card__value" data-hp-acct-subject></div>
            </div>
            <span class="badge badge--muted" data-hp-acct-role></span>
          </div>
          <div class="hp-cap-list" data-hp-acct-caps></div>
        </section>
        <section class="card hp-field" data-hp-search="account security password passkeys sessions two-factor authentication logout">
          <div class="card__title">Account &amp; security</div>
          <div class="card__desc">Password, passkeys, two-factor authentication, sessions, and recovery email are managed on the auth origin — never through this dashboard.</div>
          <div class="card__row">
            <div><div class="card__label">Security settings</div><div class="card__value">Opens the auth-backend account app in a new tab.</div></div>
            <a class="btn btn-secondary btn-sm" href="#" target="_blank" rel="noopener noreferrer" data-hp-acct-link>Manage account</a>
          </div>
          <div class="card__row">
            <div><div class="card__label">Log out</div><div class="card__value">Ends the current single sign-on session.</div></div>
            <a class="btn btn-ghost btn-sm" href="#" data-hp-acct-logout>Log out</a>
          </div>
        </section>
        <section class="card hp-field" data-hp-search="reset preferences defaults danger">
          <div class="card__title text-danger">Preferences</div>
          <div class="card__row">
            <div><div class="card__label">Reset all preferences</div><div class="card__value">Restores every preference on every pane to the compiled defaults.</div></div>
            <button class="btn btn-danger btn-sm" type="button" data-hp-reset-all>Reset all preferences</button>
          </div>
        </section>
      </section>

      <!-- Appearance -->
      <section class="hp-settings-pane" data-hp-pane="appearance" aria-label="Appearance" hidden>
        <section class="card">
          <div class="card__title">Theme</div>
          <div class="card__desc">Applied immediately and mirrored to this browser for the pre-load bootstrap.</div>
          <div class="hp-field settings-field" data-hp-search="appearance theme dark light system color mode">
            <label class="form-label">Color theme</label>
            <div class="segmented" data-pref="theme" role="group" aria-label="Color theme">
              <button type="button" data-value="system">System</button>
              <button type="button" data-value="dark">Dark</button>
              <button type="button" data-value="light">Light</button>
            </div>
          </div>
          <div class="hp-field settings-field" data-hp-search="appearance density compact comfortable rows spacing">
            <label class="form-label">Density</label>
            <div class="segmented" data-pref="density" role="group" aria-label="Density">
              <button type="button" data-value="comfortable">Comfortable</button>
              <button type="button" data-value="compact">Compact</button>
            </div>
          </div>
          <div class="hp-field settings-field" data-hp-search="appearance motion animation reduced accessibility">
            <label class="form-label">Motion</label>
            <div class="segmented" data-pref="reduced_motion" role="group" aria-label="Motion">
              <button type="button" data-value="system">System</button>
              <button type="button" data-value="on">Reduced</button>
              <button type="button" data-value="off">Full</button>
            </div>
            <div class="settings-field__desc">"Reduced" minimizes non-essential animation.</div>
          </div>
        </section>
        <section class="card">
          <div class="card__title">Readability</div>
          <div class="hp-field card__row" data-hp-search="appearance contrast high accessibility vision">
            <div><div class="card__label">High contrast</div><div class="card__value">Strengthens borders and text separation.</div></div>
            <label class="switch"><input type="checkbox" data-pref="high_contrast" aria-label="High contrast"><span></span></label>
          </div>
          <div class="hp-field card__row" data-hp-search="appearance evidence font size text larger accessibility">
            <div><div class="card__label">Larger evidence text</div><div class="card__value">Increases the font size of raw logs and payload evidence.</div></div>
            <label class="switch"><input type="checkbox" data-pref="large_evidence_text" aria-label="Larger evidence text"><span></span></label>
          </div>
        </section>
        <div class="settings-actions">
          <button class="btn btn-primary" type="button" data-hp-save="appearance" disabled>Save changes</button>
        </div>
      </section>

      <!-- Navigation & tables -->
      <section class="hp-settings-pane" data-hp-pane="navigation" aria-label="Navigation and tables" hidden>
        <section class="card">
          <div class="card__title">Navigation</div>
          <div class="settings-grid">
            <div class="hp-field settings-field" data-hp-search="navigation landing page start home route">
              <label class="form-label" for="hp-pref-landing">Landing page</label>
              <select class="form-input" id="hp-pref-landing" data-pref="landing_page">
                <option value="/">Overview</option>
                <option value="/events">Event explorer</option>
                <option value="/alerts">Alerts</option>
                <option value="/source-health">Sensor &amp; pipeline health</option>
                <option value="/ips">Attack sources</option>
                <option value="/payloads">Captured payloads</option>
                <option value="/sandbox">Sandbox results</option>
                <option value="/campaigns">Campaigns</option>
                <option value="/clusters">Infrastructure clusters</option>
                <option value="/commands">Executed commands</option>
                <option value="/history">Elasticsearch history</option>
                <option value="/dead-letters">Ingest dead letters</option>
              </select>
              <div class="settings-field__desc">First page after sign-in.</div>
            </div>
          </div>
          <div class="hp-field card__row" data-hp-search="navigation sidebar collapse compact layout">
            <div><div class="card__label">Collapsed sidebar</div><div class="card__value">Start with the navigation rail minimized on wide screens.</div></div>
            <label class="switch"><input type="checkbox" data-pref="collapsed_sidebar" aria-label="Collapsed sidebar"><span></span></label>
          </div>
          <div class="hp-field card__row" data-hp-search="navigation filters remember persist">
            <div><div class="card__label">Remember filters</div><div class="card__value">Keep table filters when navigating between pages.</div></div>
            <label class="switch"><input type="checkbox" data-pref="remember_filters" aria-label="Remember filters"><span></span></label>
          </div>
          <div class="hp-field card__row" data-hp-search="navigation details new tab open">
            <div><div class="card__label">Open details in a new tab</div><div class="card__value">Sessions and payload analysis open alongside the current view.</div></div>
            <label class="switch"><input type="checkbox" data-pref="open_details_new_tab" aria-label="Open details in a new tab"><span></span></label>
          </div>
        </section>
        <section class="card">
          <div class="card__title">Tables</div>
          <div class="settings-grid">
            <div class="hp-field settings-field" data-hp-search="tables rows per page size pagination density">
              <label class="form-label" for="hp-pref-rows">Rows per page</label>
              <select class="form-input" id="hp-pref-rows" data-pref="rows_per_page">
                <option value="10">10</option>
                <option value="25">25</option>
                <option value="50">50</option>
                <option value="100">100</option>
              </select>
            </div>
          </div>
          <div class="hp-field card__row" data-hp-search="tables wrap long values text evidence">
            <div><div class="card__label">Wrap long values</div><div class="card__value">Wrap commands and payloads instead of truncating them.</div></div>
            <label class="switch"><input type="checkbox" data-pref="wrap_long_values" aria-label="Wrap long values"><span></span></label>
          </div>
        </section>
        <div class="settings-actions">
          <button class="btn btn-primary" type="button" data-hp-save="navigation" disabled>Save changes</button>
        </div>
      </section>

      <!-- Time & live data -->
      <section class="hp-settings-pane" data-hp-pane="time" aria-label="Time and live data" hidden>
        <section class="card">
          <div class="card__title">Time display</div>
          <div class="settings-grid">
            <div class="hp-field settings-field" data-hp-search="time timezone iana zone clock">
              <label class="form-label" for="hp-pref-timezone">Timezone</label>
              <input class="form-input" id="hp-pref-timezone" data-pref="timezone" autocomplete="off" spellcheck="false" placeholder="browser">
              <div class="settings-field__desc">"browser", "utc", or an IANA zone such as Europe/Berlin.</div>
            </div>
          </div>
          <div class="hp-field settings-field" data-hp-search="time clock 24 12 hour format">
            <label class="form-label">Clock format</label>
            <div class="segmented" data-pref="clock" role="group" aria-label="Clock format">
              <button type="button" data-value="h24">24-hour</button>
              <button type="button" data-value="h12">12-hour</button>
            </div>
          </div>
          <div class="hp-field settings-field" data-hp-search="time timestamps relative absolute date format">
            <label class="form-label">Timestamps</label>
            <div class="segmented" data-pref="timestamps" role="group" aria-label="Timestamps">
              <button type="button" data-value="relative">Relative</button>
              <button type="button" data-value="absolute">Absolute</button>
            </div>
          </div>
        </section>
        <section class="card">
          <div class="card__title">Live data</div>
          <div class="hp-field card__row" data-hp-search="live refresh automatic polling telemetry">
            <div><div class="card__label">Auto-refresh</div><div class="card__value">Keep dashboard pages updating in the background.</div></div>
            <label class="switch"><input type="checkbox" data-pref="auto_refresh" aria-label="Auto-refresh"><span></span></label>
          </div>
          <div class="settings-grid">
            <div class="hp-field settings-field" data-hp-search="live refresh interval seconds polling rate">
              <label class="form-label" for="hp-pref-refresh">Refresh interval</label>
              <select class="form-input" id="hp-pref-refresh" data-pref="refresh_interval_seconds">
                <option value="10">Every 10 seconds</option>
                <option value="15">Every 15 seconds</option>
                <option value="30">Every 30 seconds</option>
                <option value="60">Every minute</option>
                <option value="120">Every 2 minutes</option>
                <option value="300">Every 5 minutes</option>
              </select>
            </div>
          </div>
          <div class="hp-field card__row" data-hp-search="live toast notification popup new events">
            <div><div class="card__label">Live event toasts</div><div class="card__value">Show a toast when new honeypot events arrive.</div></div>
            <label class="switch"><input type="checkbox" data-pref="live_toasts" aria-label="Live event toasts"><span></span></label>
          </div>
        </section>
        <section class="card">
          <div class="card__title">Notifications</div>
          <div class="settings-grid">
            <div class="hp-field settings-field" data-hp-search="notification severity threshold low medium high critical">
              <label class="form-label" for="hp-pref-severity">Minimum severity</label>
              <select class="form-input" id="hp-pref-severity" data-pref="notify_severity">
                <option value="low">Low and above</option>
                <option value="medium">Medium and above</option>
                <option value="high">High and above</option>
                <option value="critical">Critical only</option>
              </select>
            </div>
          </div>
          <div class="hp-field card__row" data-hp-search="notification sound audio alert">
            <div><div class="card__label">Notification sound</div><div class="card__value">Play a short tone for qualifying alerts.</div></div>
            <label class="switch"><input type="checkbox" data-pref="notify_sound" aria-label="Notification sound"><span></span></label>
          </div>
          <div class="hp-field card__row" data-hp-search="notification desktop browser push alert">
            <div><div class="card__label">Desktop notifications</div><div class="card__value">Uses the browser notification permission.</div></div>
            <label class="switch"><input type="checkbox" data-pref="notify_desktop" aria-label="Desktop notifications"><span></span></label>
          </div>
        </section>
        <div class="settings-actions">
          <button class="btn btn-primary" type="button" data-hp-save="time" disabled>Save changes</button>
        </div>
      </section>

      <!-- Map & investigation -->
      <section class="hp-settings-pane" data-hp-pane="map" aria-label="Map and investigation" hidden>
        <section class="card">
          <div class="card__title">Attack map</div>
          <div class="settings-grid">
            <div class="hp-field settings-field" data-hp-search="map basemap tiles openstreetmap offline provider">
              <label class="form-label" for="hp-pref-basemap">Basemap</label>
              <select class="form-input" id="hp-pref-basemap" data-pref="map_basemap">
                <option value="system">Deployment default</option>
                <option value="osm">OpenStreetMap</option>
                <option value="offline">Offline (no tiles)</option>
              </select>
            </div>
          </div>
          <div class="hp-field card__row" data-hp-search="map cluster grouping markers density">
            <div><div class="card__label">Cluster markers</div><div class="card__value">Group nearby attack origins at low zoom levels.</div></div>
            <label class="switch"><input type="checkbox" data-pref="map_clustering" aria-label="Cluster markers"><span></span></label>
          </div>
          <div class="hp-field card__row" data-hp-search="map animation transitions zoom">
            <div><div class="card__label">Map animation</div><div class="card__value">Animate zoom and pan transitions.</div></div>
            <label class="switch"><input type="checkbox" data-pref="map_animation" aria-label="Map animation"><span></span></label>
          </div>
        </section>
        <section class="card">
          <div class="card__title">Investigation defaults</div>
          <div class="settings-grid">
            <div class="hp-field settings-field" data-hp-search="investigation event window default range time 24h">
              <label class="form-label" for="hp-pref-window">Default event window</label>
              <select class="form-input" id="hp-pref-window" data-pref="default_event_window">
                <option value="1h">Last hour</option>
                <option value="6h">Last 6 hours</option>
                <option value="24h">Last 24 hours</option>
                <option value="7d">Last 7 days</option>
                <option value="30d">Last 30 days</option>
              </select>
            </div>
          </div>
          <div class="hp-field card__row" data-hp-search="investigation preserve filters keep drill down">
            <div><div class="card__label">Preserve filters while drilling down</div><div class="card__value">Carry the current filter set into linked investigations.</div></div>
            <label class="switch"><input type="checkbox" data-pref="preserve_filters" aria-label="Preserve filters while drilling down"><span></span></label>
          </div>
        </section>
        <div class="settings-actions">
          <button class="btn btn-primary" type="button" data-hp-save="map" disabled>Save changes</button>
        </div>
      </section>
    </div>
  </main>
  </div>

  <!-- Nested confirmation. It is a descendant of the permanent dialog, per
       the theme modal contract, so the browser top-layer invariant holds. -->
  <div class="edit-dialog-backdrop" id="hp-settings-confirm-backdrop" aria-hidden="true" inert></div>
  <dialog class="edit-dialog" id="hp-settings-confirm" role="alertdialog" aria-modal="true" aria-labelledby="hp-settings-confirm-title" aria-describedby="hp-settings-confirm-desc">
    <h2 class="edit-dialog__title" id="hp-settings-confirm-title">Save preferences?</h2>
    <p class="edit-dialog__desc" id="hp-settings-confirm-desc"></p>
    <div class="danger-dialog__warning" id="hp-settings-confirm-warning" hidden></div>
    <div class="edit-dialog__actions">
      <button class="btn btn-ghost" type="button" data-hp-confirm-cancel>Cancel</button>
      <button class="btn btn-primary" type="button" data-hp-confirm-action>Save preferences</button>
    </div>
  </dialog>
</dialog>
</body>
</html>
{{end}}
`
