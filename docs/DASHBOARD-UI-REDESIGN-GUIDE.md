# Honeystack Dashboard — Claude-Theme UI Redesign Guide

> **Audience:** This document is written for an AI assistant (or developer) that
> will perform the implementation. Read it top-to-bottom before touching any
> file. Every section maps directly to existing source files in
> [`dashboard/`](../dashboard/).

---

## 0. What this guide covers

The honeypot dashboard is a **self-contained Go binary** that renders every
page as a Go `html/template` string inside `page.go` (~106 KB). There is no
external JS framework. The goal is to replace the current dark/custom theme
with an **exact match of the claude.ai desktop UI** (dark, `#1a1a1a` base,
terracotta `#d4764e` accent, Inter font, split-pane layout) — verified from
live screenshots — without changing any backend logic.

### Files you will touch

| File | What changes |
|---|---|
| `dashboard/page.go` | All inline CSS + HTML templates — **primary work** |
| `dashboard/main.go` | HTTP mux, add static-asset route |
| `dashboard/assets.go` | Embed new `static/claude-theme.css` |
| `dashboard/static/claude-theme.css` | **New file** — shared design tokens + components |
| `dashboard/static/` | Existing static dir — add the CSS here |

### Files you must NOT touch

`elastic.go`, `geoip.go`, `intelligence.go`, `investigate.go`, `alerts.go`,
`metrics.go`, `map_api.go`, `payload_analysis.go`, `sandbox.go`,
`sandbox_submit.go`, `script_capture.go`, `stream.go`, `yara.go`,
`persistence.go`, `report_pdf.go`, `worldmap_generated.go`.

---

## 1. Design token reference

Copy these tokens verbatim into `dashboard/static/claude-theme.css`. Every
component in the templates must reference these variables only — no hard-coded
hex values.

```css
:root {
  /* Surfaces */
  --bg:            #1a1a1a;
  --surface-0:     #1e1e1e;
  --surface-1:     #242424;
  --surface-2:     #2a2a2a;
  --surface-3:     #313131;

  /* Borders */
  --border-subtle: #2e2e2e;
  --border-strong: #3d3d3d;
  --border-focus:  rgba(212,118,78,0.55);

  /* Text */
  --text-primary:  #e8e8e8;
  --text-secondary:#a0a0a0;
  --text-muted:    #6b6b6b;
  --text-link:     #d4764e;

  /* Accent (terracotta) */
  --accent:        #d4764e;
  --accent-hover:  #c4673f;
  --accent-subtle: rgba(212,118,78,0.12);

  /* Status */
  --green:         #34d399;
  --green-subtle:  rgba(52,211,153,0.12);
  --blue:          #60a5fa;
  --blue-subtle:   rgba(96,165,250,0.12);
  --orange:        #fb923c;
  --orange-subtle: rgba(251,146,60,0.12);
  --red:           #f87171;
  --red-subtle:    rgba(248,113,113,0.12);

  /* Shape */
  --radius-sm:     8px;
  --radius-md:     12px;
  --radius-lg:     16px;

  /* Shadows */
  --shadow-card:   0 1px 3px rgba(0,0,0,.4), 0 8px 24px rgba(0,0,0,.3);

  /* Motion */
  --transition:    150ms ease;
}
```

---

## 2. Typography

Add to `claude-theme.css`. Inter is loaded from Google Fonts; add the `<link>`
tag to the `<head>` of every page template in `page.go`.

```css
body {
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  font-size: 14px;
  line-height: 1.6;
  color: var(--text-primary);
  background: var(--bg);
  margin: 0;
  -webkit-font-smoothing: antialiased;
}
h1,h2,h3,h4 { font-weight: 600; color: var(--text-primary); margin: 0 0 8px; }
.mono {
  font-family: 'SF Mono','Fira Code','Cascadia Code',monospace;
  font-size: 12px;
}
```

In every page template `<head>` (replace whatever is there now):

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap"
      rel="stylesheet">
<link rel="stylesheet" href="/static/claude-theme.css">
```

---

## 3. App shell layout

The Claude desktop app uses a **fixed left sidebar (160 px)** and a
**scrollable main content area** that fills the rest. Reproduce this structure
as the wrapper for every dashboard page.

### 3.1 HTML shell (add once per page template)

```html
<div class="app">
  <!-- Left sidebar -->
  <aside class="sidebar">
    <!-- Logo / brand -->
    <div class="sidebar__brand">
      <span class="sidebar__logo">&#x2731;</span> <!-- asterisk = Honeypot -->
      <span class="sidebar__name">Honeystack</span>
    </div>

    <!-- Primary nav -->
    <nav class="sidebar__nav">
      <a href="/" class="sidebar__item {{if .ActivePage "overview"}}active{{end}}">
        <!-- SVG icon -->
        Overview
      </a>
      <a href="/events" class="sidebar__item {{if .ActivePage "events"}}active{{end}}">
        Events
      </a>
      <a href="/map" class="sidebar__item">World Map</a>
      <a href="/payloads" class="sidebar__item">Payloads</a>
      <a href="/sandbox" class="sidebar__item">Sandbox</a>
      <a href="/scripts" class="sidebar__item">Scripts</a>
      <a href="/intelligence" class="sidebar__item">Intelligence</a>
      <a href="/investigate" class="sidebar__item">Investigate</a>
      <a href="/alerts" class="sidebar__item">Alerts</a>
    </nav>

    <!-- Bottom items -->
    <div class="sidebar__bottom">
      <a href="/report" class="sidebar__item">Export PDF</a>
    </div>
  </aside>

  <!-- Main content -->
  <main class="main">
    {{block "content" .}}{{end}}
  </main>
</div>
```

### 3.2 Shell CSS (add to `claude-theme.css`)

```css
.app {
  display: flex;
  height: 100dvh;
  overflow: hidden;
}

/* ── Sidebar ───────────────────────────────── */
.sidebar {
  width: 160px;
  flex-shrink: 0;
  background: var(--surface-0);
  border-right: 1px solid var(--border-subtle);
  display: flex;
  flex-direction: column;
  padding: 12px 8px;
  overflow-y: auto;
}
.sidebar__brand {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 8px 16px;
  font-size: 15px;
  font-weight: 600;
  color: var(--text-primary);
}
.sidebar__logo {
  color: var(--accent);
  font-size: 18px;
}
.sidebar__nav {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.sidebar__item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
  text-decoration: none;
  transition: background var(--transition), color var(--transition);
  cursor: pointer;
  white-space: nowrap;
}
.sidebar__item:hover {
  background: var(--surface-2);
  color: var(--text-primary);
}
.sidebar__item.active {
  background: var(--surface-2);
  color: var(--text-primary);
}
.sidebar__item svg { width: 15px; height: 15px; flex-shrink: 0; opacity: 0.7; }
.sidebar__item.active svg { opacity: 1; }
.sidebar__section-label {
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-muted);
  padding: 8px 10px 4px;
}
.sidebar__bottom {
  border-top: 1px solid var(--border-subtle);
  padding-top: 8px;
  margin-top: 8px;
}

/* ── Main area ──────────────────────────────── */
.main {
  flex: 1;
  overflow-y: auto;
  padding: 24px 32px;
  background: var(--bg);
}
.page-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
  margin-bottom: 20px;
}
```

---

## 4. Shared components

All components go in `claude-theme.css`. The templates in `page.go` use these
class names.

### 4.1 Stat card row

Used on Overview and Alerts to show counts (Total attacks, SSH attempts, etc.).

```css
.stats-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  gap: 12px;
  margin-bottom: 24px;
}
.stat-card {
  background: var(--surface-1);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 16px;
}
.stat-card__value {
  font-size: 24px;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1;
  margin-bottom: 6px;
}
.stat-card__label {
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-muted);
}
```

HTML:
```html
<div class="stats-row">
  <div class="stat-card">
    <div class="stat-card__value">{{.TotalEvents}}</div>
    <div class="stat-card__label">Total Events</div>
  </div>
  <!-- repeat for each metric -->
</div>
```

### 4.2 Card

```css
.card {
  background: var(--surface-1);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  padding: 20px 24px;
  margin-bottom: 16px;
}
.card__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}
.card__title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-primary);
}
.card__subtitle {
  font-size: 12px;
  color: var(--text-secondary);
}
```

### 4.3 Data table

```css
.data-table { width: 100%; border-collapse: collapse; }
.data-table thead tr { border-bottom: 1px solid var(--border-subtle); }
.data-table th {
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--text-secondary);
  text-align: left;
  padding: 8px 12px;
}
.data-table td {
  font-size: 13px;
  color: var(--text-primary);
  padding: 10px 12px;
  border-bottom: 1px solid var(--border-subtle);
  vertical-align: middle;
}
.data-table tbody tr:last-child td { border-bottom: none; }
.data-table tbody tr:hover td { background: var(--surface-2); }
```

### 4.4 Badges

```css
.badge {
  display: inline-flex;
  align-items: center;
  font-size: 11px;
  font-weight: 500;
  padding: 2px 8px;
  border-radius: 6px;
  white-space: nowrap;
}
.badge--green  { background: var(--green-subtle);  color: var(--green); }
.badge--blue   { background: var(--blue-subtle);   color: var(--blue); }
.badge--orange { background: var(--orange-subtle); color: var(--orange); }
.badge--red    { background: var(--red-subtle);    color: var(--red); }
.badge--muted  { background: var(--surface-2);     color: var(--text-secondary); }
.badge--accent { background: var(--accent-subtle); color: var(--accent); }
```

### 4.5 Buttons

```css
.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  font-weight: 500;
  padding: 8px 16px;
  border-radius: var(--radius-md);
  cursor: pointer;
  transition: background var(--transition), border-color var(--transition);
  white-space: nowrap;
  border: none;
}
.btn-primary   { background: #fff; color: #111; }
.btn-primary:hover { background: #e8e8e8; }
.btn-secondary {
  background: transparent;
  border: 1px solid var(--border-subtle);
  color: var(--text-primary);
}
.btn-secondary:hover { background: var(--surface-2); }
.btn-danger    { background: var(--red-subtle); color: var(--red);
                 border: 1px solid rgba(248,113,113,.3); }
.btn-danger:hover { background: rgba(248,113,113,.2); }
.btn-sm { font-size: 12px; padding: 5px 10px; }
```

### 4.6 Form inputs

```css
.form-group  { margin-bottom: 14px; }
.form-label  { display: block; font-size: 12px; font-weight: 500;
               color: var(--text-secondary); margin-bottom: 5px; }
.form-input  {
  width: 100%; box-sizing: border-box;
  background: var(--surface-1);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 9px 13px;
  font-size: 13px; color: var(--text-primary);
  outline: none;
  transition: border-color var(--transition), box-shadow var(--transition);
}
.form-input::placeholder { color: var(--text-muted); }
.form-input:focus {
  border-color: var(--border-focus);
  box-shadow: 0 0 0 3px rgba(212,118,78,.15);
}
select.form-input { appearance: none; cursor: pointer; }
```

### 4.7 Alert / flash banner

```css
.alert {
  padding: 12px 16px;
  border-radius: var(--radius-md);
  font-size: 13px;
  margin-bottom: 16px;
  display: flex;
  align-items: flex-start;
  gap: 10px;
}
.alert--red    { background: var(--red-subtle);    color: var(--red);
                 border: 1px solid rgba(248,113,113,.3); }
.alert--orange { background: var(--orange-subtle); color: var(--orange);
                 border: 1px solid rgba(251,146,60,.3); }
.alert--green  { background: var(--green-subtle);  color: var(--green);
                 border: 1px solid rgba(52,211,153,.3); }
```

---

## 5. Page-by-page changes in `page.go`

Every page is a Go `const` string (or `var`) inside `page.go`. Work through
them in order. For each page:
1. Replace the `<head>` section with the Inter font link + `claude-theme.css`.
2. Remove all existing inline `<style>` blocks.
3. Replace structural HTML with the shell from §3.1.
4. Replace custom table/card/badge/button CSS with the class names from §4.
5. Keep all `{{.Field}}` Go template expressions exactly as-is.

### 5.1 Overview page (`overviewPage` / `handleOverview`)

**Current state:** Shows stat counters (total events, by service), a recent
events table, and a world-map SVG.

**Target layout:**
```
app
  sidebar  (§3)
  main
    .page-title  "Overview"
    .stats-row   [Total Events] [SSH] [HTTP] [FTP] [Telnet] [MQTT] ...
    .card        Recent events  →  .data-table  (columns: Time · Service · IP · Country · Event)
    .card        World map SVG  (keep existing inline SVG, just wrap it)
```

**Class mapping:**
- `<div class="counter">` → `<div class="stat-card">`
- `<table class="events">` → `<table class="data-table">`
- Service name strings → `<span class="badge badge--{colour}">` where:
  - `ssh` → `badge--blue`
  - `http` → `badge--green`
  - `ftp` → `badge--orange`
  - `telnet` / `smtp` → `badge--muted`
  - `ics` / `dnp3` / `conpot` → `badge--accent`
  - threat / malware → `badge--red`

### 5.2 Events page (`eventsPage` / `handleEvents`)

**Current state:** Paginated table of all events with filters.

**Target layout:**
```
app
  sidebar
  main
    .page-title  "Events"
    .card  (filter row)
      .form-input  (IP filter)
      .form-input  (Service select)
      .form-input  (Date range)
      .btn.btn-secondary  "Filter"
    .card  (table)
      .data-table  (columns: Time · Service · IP · Country · Port · Event · Actions)
    pagination row  (Prev / Next links styled as .btn.btn-secondary.btn-sm)
```

- Time column: `.mono` class.
- Actions column: link to investigate → `<a class="btn btn-secondary btn-sm">Investigate</a>`.

### 5.3 World Map page (`mapPage` / `handleMap`)

**Current state:** Full-page SVG world map with attack origin pins.

**Target layout:**
```
app
  sidebar
  main  (overflow: hidden; padding: 0)
    .map-toolbar  (top bar: title + time-range buttons)
    .map-container  (flex: 1; contains SVG)
```

```css
.map-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 24px;
  background: var(--surface-0);
  border-bottom: 1px solid var(--border-subtle);
}
.map-container {
  flex: 1;
  overflow: hidden;
  position: relative;
}
.map-container svg { width: 100%; height: 100%; }
/* Attack pin dots */
.map-pin { fill: var(--accent); opacity: 0.8; }
.map-pin--high { fill: var(--red); }
```

### 5.4 Payloads page (`payloadsPage` / `handlePayloads`)

**Current state:** Paginated table of captured payloads with hex dump previews.

**Target layout:**
```
app
  sidebar
  main
    .page-title  "Payloads"
    .card  (filter row: service, type, date)
    .card
      .data-table  (columns: Time · Service · Size · Type · Preview · Actions)
        Preview cell → .mono truncated to 120 chars
        Type cell → .badge per payload kind:
          shellcode → badge--red
          elf/pe    → badge--orange
          script    → badge--blue
          other     → badge--muted
        Actions → [View] [Sandbox] buttons  (.btn.btn-secondary.btn-sm)
```

### 5.5 Payload detail page (`payloadDetailPage` / `handlePayloadDetail`)

**Current state:** Full hex dump + YARA matches + sandbox result for one payload.

**Target layout:**
```
app
  sidebar
  main
    .page-title  "Payload — {hash}"
    .card  Metadata (Time, Service, IP, Size, Type, SHA256)
      .card__row pairs
    .card  Hex dump
      <pre class="mono">  (scrollable, max-height: 400px)
    .card  YARA matches
      .data-table  (Rule · Tags · Description)
      yara hit badge → badge--red
    .card  Sandbox result (if available)
      score bar + behaviour tags
```

```css
.hex-dump {
  font-family: 'SF Mono','Fira Code',monospace;
  font-size: 12px;
  color: var(--text-secondary);
  background: var(--surface-0);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  padding: 16px;
  overflow-x: auto;
  max-height: 420px;
  white-space: pre;
}
```

### 5.6 Alerts page (`alertsPage` / `handleAlerts`)

**Current state:** Shows active threshold-based alerts.

**Target layout:**
```
app
  sidebar
  main
    .page-title  "Alerts"
    .stats-row   [Active] [Resolved] [Critical] [Today]
    .card  Active alerts table
      .data-table  (columns: Severity · Rule · Source IP · Service · Triggered · Status)
        Severity →  badge--red (critical) / badge--orange (high) / badge--blue (medium)
        Status   →  badge--green (active) / badge--muted (resolved)
```

### 5.7 Investigate page (`investigatePage` / `handleInvestigate`)

**Current state:** IP look-up form + threat-intel results (WHOIS, ASN, abuse
score, related events).

**Target layout:**
```
app
  sidebar
  main
    .page-title  "Investigate"
    .card  Search
      .form-group  IP / hash / domain input  + .btn.btn-primary "Investigate"
    (results, shown after POST)
    .card  IP Summary
      .card__row  pairs: Country / ASN / ISP / Abuse score / First seen / Last seen
      Abuse score → colour-coded .badge (green <20, orange 20-60, red >60)
    .card  Related events  →  .data-table
    .card  WHOIS raw  →  <pre class="mono">
    .card  External links  →  Shodan / VirusTotal / AbuseIPDB  (.btn.btn-secondary)
```

### 5.8 Intelligence page (`intelligencePage` / `handleIntelligence`)

**Current state:** Aggregated threat-feed data: top IPs, top countries, top
attack types, timeline chart.

**Target layout:**
```
app
  sidebar
  main
    .page-title  "Intelligence"
    .stats-row   top-level KPIs (Unique IPs, Countries, Attack types)
    two-column grid (gap: 16px)
      .card  Top Source IPs       →  .data-table  (IP · Count · Country · Last seen)
      .card  Top Countries        →  .data-table  (Country · Count · %)
    .card  Attack timeline        →  SVG / canvas chart
    .card  Top Attack Types       →  horizontal bar chart or .data-table
```

For the timeline chart: keep existing chart rendering; just ensure the SVG
background is `var(--bg)` and lines/bars use `var(--accent)` + `var(--blue)`.

### 5.9 Sandbox page (`sandboxPage` / `handleSandbox`)

**Current state:** Submit payload hash for dynamic analysis; list previous sandbox runs.

**Target layout:**
```
app
  sidebar
  main
    .page-title  "Sandbox"
    .card  Submit
      .form-group  Hash / file input  +  .btn.btn-primary  "Analyse"
    .card  Recent runs  →  .data-table
      columns: Submitted · Hash · Status · Score · Verdict
      Status  →  badge--orange (pending) / badge--blue (running) /
                 badge--green (clean) / badge--red (malicious)
      Score   →  numeric, colour-code with badge
      Actions →  .btn.btn-secondary.btn-sm  "View report"
```

### 5.10 Scripts page (`scriptsPage` / `handleScripts`)

**Current state:** Table of captured shell scripts / command sequences from
Cowrie / Multipot, with raw content viewer.

**Target layout:**
```
app
  sidebar
  main
    .page-title  "Scripts"
    .card  table
      .data-table  (columns: Time · Source IP · Length · Preview)
        Preview → <code class="mono"> truncated
        Row click or [View] → expands / links to detail
    .card  Script detail (on separate route or in-page expand)
      <pre class="hex-dump">  full script content
      .badge tags for detected techniques (wget · curl · chmod · rm -rf etc.)
```

### 5.11 PDF Report page (`reportPage` / `handleReport`)

**Current state:** Form to configure and download a PDF threat report.

**Target layout:**
```
app
  sidebar
  main
    .page-title  "Export Report"
    .card  Report options
      .form-group  Date range  (two .form-input date pickers)
      .form-group  Services checkboxes
      .form-group  Include sections (checkboxes: Summary / Events / Map / Payloads)
      .btn.btn-primary  "Generate PDF"
    .card (optional)  Last generated reports list  →  .data-table
```

---

## 6. SSE live-stream indicator

The dashboard has a `stream.go` Server-Sent Events feed (`/stream`). Show a
live indicator in the sidebar when connected:

```css
.live-dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--green);
  box-shadow: 0 0 0 0 rgba(52,211,153,.5);
  animation: pulse 1.5s ease-in-out infinite;
}
@keyframes pulse {
  0%   { box-shadow: 0 0 0 0 rgba(52,211,153,.5); }
  70%  { box-shadow: 0 0 0 6px rgba(52,211,153,0); }
  100% { box-shadow: 0 0 0 0 rgba(52,211,153,0); }
}
```

Add the dot to the sidebar brand area:
```html
<div class="sidebar__brand">
  <span class="sidebar__logo">&#x2731;</span>
  <span class="sidebar__name">Honeystack</span>
  <span class="live-dot" id="live-dot" title="Live" style="margin-left:auto"></span>
</div>
```

In the existing stream JS, toggle `live-dot` visibility on connect/disconnect.

---

## 7. Embed & serve `claude-theme.css`

### 7.1 Create the file

Create `dashboard/static/claude-theme.css` with the contents from §§1–4.

### 7.2 Update `assets.go`

Check `dashboard/assets.go` — it already has a `//go:embed` directive for
`static/`. If it uses `embed.FS`, the file is picked up automatically. If it
embeds specific files, add:

```go
//go:embed static/claude-theme.css
var themeCSS []byte
```

And register the route in `main.go` (or confirm the existing static handler
already serves `dashboard/static/` at `/static/`).

### 7.3 HTTP route

In `main.go`, find the static file handler. The current pattern is likely:
```go
http.Handle("/static/", http.StripPrefix("/static/",
    http.FileServer(http.FS(staticFiles))))
```
No change needed if `assets.go` embeds the whole `static/` directory.

---

## 8. Colour-coding reference for services

Use this consistently across all pages:

| Service | Badge class | Rationale |
|---|---|---|
| `ssh` | `badge--blue` | Calm / informational |
| `http` / `https` | `badge--green` | Web traffic |
| `ftp` / `tftp` | `badge--orange` | File transfer, moderate risk |
| `telnet` / `smtp` | `badge--muted` | Legacy / noisy |
| `ics` / `dnp3` / `conpot` | `badge--accent` | OT/ICS — special interest |
| Malware / shellcode | `badge--red` | High severity |
| Unknown / other | `badge--muted` | Default |

---

## 9. Go integration notes for `page.go`

### 9.1 Active sidebar item

The current pages each render a standalone HTML page. To mark the active
sidebar item without a separate template system, add a small helper to the
template data struct:

```go
// Add to whatever PageData struct each handler uses:
ActivePage string  // e.g. "overview", "events", "map", ...
```

In each handler:
```go
data := OverviewData{
    // ... existing fields ...
    ActivePage: "overview",
}
```

In the template:
```html
<a href="/" class="sidebar__item {{if eq .ActivePage \"overview\"}}active{{end}}">
  Overview
</a>
```

### 9.2 Keeping existing template logic

- All `{{range .Events}}`, `{{.Field}}`, `{{if .Condition}}` expressions stay
  exactly the same — only the surrounding HTML and CSS class names change.
- Do not rename any struct fields or handler function signatures.
- Do not change any route paths.

### 9.3 Inline vs. external CSS

Currently `page.go` has all CSS inline in each page's `<style>` block. The
target state is:
- **Shared styles** → `static/claude-theme.css` (loaded via `<link>`).
- **Page-specific overrides** → small `<style>` block per page, only for things
  that cannot be expressed with the shared components (e.g. SVG map pin styles,
  hex dump max-height tweaks).
- Remove duplicate CSS across pages.

---

## 10. Checklist (per-page)

For each page, tick these off before moving to the next:

- [ ] `<head>` updated: Inter font link + `/static/claude-theme.css`
- [ ] Old inline `<style>` block removed (or reduced to page-specific only)
- [ ] App shell wrapper added (`.app` / `.sidebar` / `.main`)
- [ ] Sidebar nav rendered with correct `.active` class for this page
- [ ] Stat cards use `.stat-card` + `.stats-row`
- [ ] Tables use `.data-table`
- [ ] Badges use `.badge--{colour}` from §8 colour table
- [ ] Buttons use `.btn .btn-{variant}`
- [ ] Form inputs use `.form-input` + `.form-label`
- [ ] No hard-coded hex colours in HTML/template
- [ ] No layout breakage at 1280 × 800 viewport
- [ ] Existing Go template expressions (`{{.}}`) unchanged

## 10.1 Global checklist

- [ ] `dashboard/static/claude-theme.css` created with §§1–4 content
- [ ] `assets.go` confirmed to embed `static/` dir (or updated)
- [ ] Static route `/static/` confirmed in `main.go`
- [ ] Live-stream dot added to sidebar brand (§6)
- [ ] `ActivePage` field added to all page data structs
- [ ] All 10 pages (Overview, Events, Map, Payloads, Payload detail,
      Alerts, Investigate, Intelligence, Sandbox, Scripts, PDF Report)
      pass the per-page checklist
- [ ] `go build ./...` passes with no errors
- [ ] `go test ./...` passes (existing tests must not break)

---

## 11. Reference: current `page.go` structure

The file is ~106 KB. Key const/var names to find and edit:

| Symbol | Page |
|---|---|
| `overviewPageHTML` (or similar) | Overview |
| `eventsPageHTML` | Events |
| `mapPageHTML` | World Map |
| `payloadsPageHTML` | Payloads |
| `payloadDetailHTML` | Payload detail |
| `alertsPageHTML` | Alerts |
| `investigatePageHTML` | Investigate |
| `intelligencePageHTML` | Intelligence |
| `sandboxPageHTML` | Sandbox |
| `scriptsPageHTML` | Scripts |
| `reportPageHTML` | PDF Report |

Use `grep -n 'func.*Page\|const.*Page\|var.*Page' dashboard/page.go` to list
all symbols before starting.

---

## 12. Cross-references

- CSS design tokens: see also
  [`docs/CLAUDE-THEME-GUIDE.md`](CLAUDE-THEME-GUIDE.md) in
  `Xore/auth-backend` (the same token set applies here).
- Admin modal panel: see
  [`docs/ADMIN-UI-GUIDE.md`](ADMIN-UI-GUIDE.md).
- Login page theme: see
  [`docs/UI-REDESIGN-GUIDE.md`](UI-REDESIGN-GUIDE.md).
