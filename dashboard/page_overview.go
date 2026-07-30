package main

const pageOverview = `
{{define "page"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="overview-header">
          <div>
            <div class="eyebrow">Security operations</div>
            <h1>{{presentation.DashboardTitle}}</h1>
            <p class="subtitle">{{if presentation.DashboardSubtitle}}{{presentation.DashboardSubtitle}}{{else}}Live attack telemetry, captured evidence, correlated campaigns, and collection health in one operational view.{{end}}</p>
          </div>
          <div class="live-panel">
            <span class="live-pill"><span class="live-dot"></span>Live telemetry</span>
            <a class="btn btn-sm btn-primary" href="/reports" title="Design and generate a management-ready PDF in the Reports studio"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>Reports studio</a>
            <span class="gen">updated {{.Generated.Format "2006-01-02 15:04:05 MST"}} &bull; refreshes automatically</span>
          </div>
        </header>

        <div class="tw:grid tw:grid-cols-2 tw:sm:grid-cols-3 tw:xl:grid-cols-5 tw:gap-3 tw:mb-6" id="overview-kpis">
          <a class="hp-stat" href="/events" title="Open all normalized events in the current dashboard window"><span class="hp-stat-value">{{.Total}}</span><span class="hp-stat-label">All events</span></a>
          <a class="hp-stat" href="/events?since=24h" title="Open events received during the last 24 hours"><span class="hp-stat-value">{{.Last24h}}</span><span class="hp-stat-label">Events in 24 hours</span><span class="hp-stat-detail" title="Compared with the directly preceding 24-hour period">{{.Change24h}} &bull; {{.ActivityState}}</span></a>
          <a class="hp-stat" href="/ips" title="Distinct attacker source addresses observed by the sensors"><span class="hp-stat-value">{{.UniqueIPs}}</span><span class="hp-stat-label">Attack sources</span></a>
          <a class="hp-stat" href="/events?type=login" title="Authentication attempts captured by interactive honeypots"><span class="hp-stat-value">{{.Logins}}</span><span class="hp-stat-label">Login attempts</span></a>
          <a class="hp-stat" href="/events?type=download" title="Downloads, uploads, and high-confidence script artifacts captured safely"><span class="hp-stat-value">{{.Downloads}}</span><span class="hp-stat-label">Captured payloads</span></a>
        </div>

        <div class="dashboard-tabs" role="tablist" aria-label="Dashboard views">
          <button class="dashboard-tab active" type="button" role="tab" aria-selected="true" aria-controls="panel-live" data-dashboard-tab="live"><span>01</span>Live operations</button>
          <button class="dashboard-tab" type="button" role="tab" aria-selected="false" aria-controls="panel-threats" data-dashboard-tab="threats"><span>02</span>Threat landscape</button>
          <button class="dashboard-tab" type="button" role="tab" aria-selected="false" aria-controls="panel-behavior" data-dashboard-tab="behavior"><span>03</span>Attacker behavior</button>
          <button class="dashboard-tab" type="button" role="tab" aria-selected="false" aria-controls="panel-evidence" data-dashboard-tab="evidence"><span>04</span>Evidence &amp; campaigns</button>
        </div>

        <div class="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" id="panel-live" role="tabpanel" data-dashboard-panel="live">
          <div class="section-heading"><div><h2>Current activity</h2><p>What is happening now, when traffic arrived, and where it originated.</p></div><a class="section-link" href="/events?since=24h">View last 24 hours &rarr;</a></div>
          <div class="card wide chart-card">
            <h2>Activity — last 24h</h2>
            <div class="chart">
              {{range .Timeline}}<div class="col{{if not .Count}} zero{{end}}" data-tip="{{.Label}}:00 — {{.Count}} events" aria-label="{{.Label}}:00, {{.Count}} events" tabindex="0"><div class="bar" style="height:{{.Pct}}%"></div><span>{{.Label}}</span></div>{{end}}
            </div>
            <p class="note">Each bar is one local-time hour. Hover or focus a bar for the exact event count; select the 24-hour KPI above to inspect those events.</p>
          </div>

          {{if .MapPoints}}<div class="card wide map-card" data-attack-map-card><h2>Attack origins &mdash; live geographic view</h2>
            <div class="map-shell" data-map-shell><div id="attack-map" class="leaflet-map" data-tile-url="{{.MapTileURL}}" data-attribution="{{.MapAttribution}}" role="region" aria-label="interactive map of geolocated attack origins"></div><div class="map-status" data-map-status aria-live="polite">Loading attack origins…</div>
            <div class="map-fallback" hidden><div class="map-fallback-note">Interactive map unavailable — offline geographic fallback</div><svg class="world" viewBox="0 0 1000 450" role="img" aria-label="offline world map of geolocated attack origins">
              <rect class="ocean" width="1000" height="450" rx="10"/>
              <g class="graticule">
                <line x1="83" y1="0" x2="83" y2="450"/><line x1="167" y1="0" x2="167" y2="450"/><line x1="250" y1="0" x2="250" y2="450"/><line x1="333" y1="0" x2="333" y2="450"/><line x1="417" y1="0" x2="417" y2="450"/><line x1="500" y1="0" x2="500" y2="450"/><line x1="583" y1="0" x2="583" y2="450"/><line x1="667" y1="0" x2="667" y2="450"/><line x1="750" y1="0" x2="750" y2="450"/><line x1="833" y1="0" x2="833" y2="450"/><line x1="917" y1="0" x2="917" y2="450"/>
                <line x1="0" y1="75" x2="1000" y2="75"/><line x1="0" y1="150" x2="1000" y2="150"/><line x1="0" y1="225" x2="1000" y2="225"/><line x1="0" y1="300" x2="1000" y2="300"/><line x1="0" y1="375" x2="1000" y2="375"/>
              </g>
              {{worldMap}}
              {{range .MapPoints}}<a href="/events?ip={{.IP | urlquery}}"><circle cx="{{printf "%.1f" .X}}" cy="{{printf "%.1f" .Y}}" r="{{.R}}"><title>{{.IP}} — {{.City}} {{.Country}} — AS{{.ASN}} {{.Org}} — {{.Count}} events</title></circle></a>{{end}}
            </svg></div></div><p class="note">Approximate geolocation only. Marker radius is geographic—not fixed-size—so it changes naturally with zoom and is weighted by event count. Hover for IP, city, ASN and provider; select a marker for all related events. Map data © OpenStreetMap contributors.</p></div>{{end}}

          <div class="section-heading"><div><h2>Collection status</h2><p>Sensor activity and the protocols currently attracting traffic.</p></div><a class="section-link" href="/source-health">Open pipeline health &rarr;</a></div>
          <div class="card half sensor-card">
            <h2>Sensor feeds</h2>
            <p class="note">Active = recent traffic, quiet = online with no recent event, stale = its log has stopped updating. A quiet honeypot is not necessarily offline.</p>
            {{if .Sensors}}
            <table><tbody>
              {{range .Sensors}}
              <tr><td class="n">{{.Count}}</td>
                  <td><a class="badge b-{{.Name}}" href="{{.Link}}">{{.Name}}</a></td>
                  <td class="state s-{{.State}}">{{.State}}</td>
                  <td class="ago">{{.Ago}}</td></tr>
              {{end}}
            </tbody></table>
            {{else}}<p class="empty">no sensor logs found under /logs</p>{{end}}
          </div>

          {{template "tbl" dict "t" "Protocols probed" "rows" .Protocols "class" "half"}}

          <div class="section-heading"><div><h2>Live event stream</h2><p>A balanced sample of the newest normalized events across all sensors.</p></div><a class="section-link" href="/events">Open full event explorer &rarr;</a></div>
          <div class="card wide">
            <h2>Recent events</h2>
            {{if .Recent}}
            <table class="recent">
              <thead><tr><th>time</th><th>sensor</th><th>source ip</th><th>port</th><th>detail</th></tr></thead>
              <tbody>
              {{range .Recent}}{{template "everow" .}}{{end}}
            </tbody></table>
            {{else}}<p class="empty">no events yet — waiting for traffic</p>{{end}}
          </div>
        </div>

        <div class="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" id="panel-threats" role="tabpanel" data-dashboard-panel="threats" hidden>
          <div class="section-heading"><div><h2>Threat landscape</h2><p>Highest-volume sources, targets, locations, and network ownership. Select any count or value to open its matching events.</p></div><a class="section-link" href="/ips">Investigate all sources &rarr;</a></div>
          {{template "tbl" dict "t" "Top source IPs" "rows" .TopIPs}}
          {{template "tbl" dict "t" "Top targeted ports" "rows" .TopPorts}}
          {{if .GeoOn}}{{template "tbl" dict "t" "Top countries" "rows" .Countries}}{{else if .Countries}}{{template "tbl" dict "t" "Top countries (cf-ipcountry)" "rows" .Countries}}{{end}}
          {{template "tbl" dict "t" "Top autonomous systems" "rows" .ASNs "class" "half"}}
          {{template "tbl" dict "t" "Network/provider classes" "rows" .Providers "class" "half"}}
        </div>

        <div class="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" id="panel-behavior" role="tabpanel" data-dashboard-panel="behavior" hidden>
          <div class="section-heading"><div><h2>Attacker behavior</h2><p>Authentication attempts, executed commands, client identity, HTTP targets, and reusable fingerprints. Every value opens the related event set.</p></div><a class="section-link" href="/commands">Review all commands &rarr;</a></div>
          {{template "tbl" dict "t" "Top credentials (user / pass)" "rows" .TopCreds
            "hint" "authentication events only; protocol arguments and shell input are excluded"}}
          {{template "tbl" dict "t" "Top commands" "rows" .TopCommands
            "hint" "no shell commands captured yet — fed by cowrie and multipot sessions"}}
          {{template "tbl" dict "t" "SSH/telnet clients" "rows" .Clients
            "hint" "no client banners yet — fed by cowrie"}}
          {{template "tbl" dict "t" "Top fingerprints (HASSH / JA3 / JA4 / User-Agent)" "rows" .Fingerprints "class" "half"
            "hint" "no protocol or client fingerprints captured yet"}}
          {{template "tbl" dict "t" "Top HTTP paths" "rows" .TopPaths "class" "half"
            "hint" "no web probes yet — fed by http-honeypot and tanner"}}
        </div>

        <div class="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" id="panel-evidence" role="tabpanel" data-dashboard-panel="evidence" hidden>
          <div class="section-heading"><div><h2>Detection and evidence</h2><p>IDS findings, captured artifacts, and cross-sensor campaign correlation. Select an item to investigate its evidence.</p></div><a class="section-link" href="/payloads">Open payload analysis &rarr;</a></div>
          {{template "tbl" dict "t" "Suricata alerts" "rows" .Alerts "class" "half"
            "hint" "no alerts — is the VPS eve.json mount at /logs/suricata alive?"}}
          {{template "tbl" dict "t" "Alert categories" "rows" .AlertCats "class" "half"
            "hint" "no suricata alerts yet"}}

          <div class="card wide">
            <h2>Captured payloads</h2>
            <p class="note">Inert copies of malware and high-confidence scripts captured by Dionaea, Cowrie, and command telemetry. Static analysis never executes the payload.</p>
            {{if .Payloads}}
            <table>
              <thead><tr><th>seen</th><th>sha-256</th><th>attacker target path</th><th>lookup</th></tr></thead>
              <tbody>
              {{range .Payloads}}
              <tr>
                <td class="n"><a href="{{.Link}}" title="show events for this payload">{{.Count}}</a></td>
                <td class="v"><a href="{{.Link}}" title="events for this payload">{{.Shasum}}</a></td>
                <td class="v"><a href="{{.Link}}" title="show events for this captured artifact">{{.Download}}</a></td>
                <td class="v"><a class="lnk" href="/payload-analysis/{{.Shasum}}">static analysis &rarr;</a> <a class="lnk" href="{{.VT}}" target="_blank" rel="noopener noreferrer">VirusTotal &rarr;</a></td>
              </tr>
              {{end}}
              </tbody>
            </table>
            {{else}}<p class="empty">no payloads captured yet — cowrie logs downloads/uploads during a shell session</p>{{end}}
          </div>

          <div class="card wide">
            <h2>Correlated campaigns â€” rolling 7 days</h2>
            <p class="note">Groups related source networks across sensors. Score rises with volume, sensor/port spread, reused credentials, payloads, IDS alerts, and matching fingerprints.</p>
            {{if .Campaigns}}
            <table class="recent">
              <thead><tr><th>score</th><th>network</th><th>events</th><th>ips</th><th>sensors</th><th>ports</th><th>creds</th><th>files</th><th>alerts</th><th>ASNs</th><th>provider</th><th>fingerprints</th><th>sequence</th><th>first</th><th>last</th></tr></thead>
              <tbody>{{template "campaignrows" .Campaigns}}</tbody>
            </table>
            {{else}}<p class="empty">waiting for correlatable public source addresses</p>{{end}}
          </div>

        </div>

        <footer id="overview-footer">{{if presentation.FooterText}}{{presentation.FooterText}}{{else}}xore//honeypot &bull; defensive sensor &bull; do not expose without auth{{end}}</footer>
      </div>
    </main>
</div>
<script>
let refreshing=false;
async function refreshDashboard(){
  // The toolbar LIVE control owns every refresh path; while it is paused the
  // overview must keep the snapshot the operator is reading.
  if(window.HoneypotLive&&window.HoneypotLive.paused())return;
  if(refreshing)return;refreshing=true;
  try {
    const r = await fetch(location.pathname, {cache: "no-store"});
    if (!r.ok) return;
    const doc = new DOMParser().parseFromString(await r.text(), "text/html");
    const next = doc.querySelector(".wrap"),current=document.querySelector("[data-hp-page-content]")||document.querySelector(".wrap");
    if (next&&current) {const preserveMap=Boolean(current.querySelector('[data-attack-map-card]')&&next.querySelector('[data-attack-map-card]'));if(window.replaceHoneypotPage)window.replaceHoneypotPage(next,{preserveMap});else current.replaceWith(next);if(window.initDashboardTabs)window.initDashboardTabs();if(window.initHoneypotMaps)window.initHoneypotMaps();}
  } catch {} finally {refreshing=false}
}
if(window.EventSource){const es=new EventSource('/api/stream');es.addEventListener('update',refreshDashboard);es.onerror=()=>{};}
setInterval(refreshDashboard, 60000);
addEventListener('hp-live-resumed',refreshDashboard);
</script>
</body>
</html>
{{end}}

`
