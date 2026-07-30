package main

const pageIPs = `
{{define "iprow"}}<tr>
  <td class="n"><a href="/investigate/ip/{{.IP | urlquery}}" title="attacker profile for {{.IP}}">{{.Count}}</a></td>
  <td class="v"><a href="/investigate/ip/{{.IP | urlquery}}" title="attacker profile for {{.IP}}">{{.IP}}</a></td>
  <td class="v">{{if .Country}}<a class="cc" href="/events?country={{.Country | urlquery}}">{{.Country}}</a>{{end}}</td>
  <td class="n"><a href="/events?ip={{.IP | urlquery}}&amp;type=login" title="login attempts from {{.IP}}">{{.Logins}}</a></td>
  <td class="n"><a href="/events?ip={{.IP | urlquery}}" title="attack chain and sessions for {{.IP}}">{{.Sessions}}</a></td>
  <td class="v"><a href="/events?ip={{.IP | urlquery}}" title="sensor activity for {{.IP}}">{{.Sensors}}</a></td>
  <td>{{.First}}</td>
  <td>{{.Last}}</td>
</tr>{{end}}
{{define "iprows"}}{{range .Rows}}{{template "iprow" .}}{{end}}{{end}}

{{define "ips"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot — source IPs</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="ips-header">
          <div>
            <div class="eyebrow">Attack sources</div>
            <h1>Source IPs</h1>
            <p class="subtitle">Every source address observed by the sensors, with event volume, geolocation, and activity window.</p>
          </div>
          <div class="live-panel">
            <span class="gen">generated {{.Generated.Format "2006-01-02 15:04:05 MST"}}</span>
          </div>
        </header>

        <div class="filters">
          <a class="chip" href="/">&larr; dashboard</a>
          <span class="chip">{{.Total}} unique IPs</span>
        </div>

        <div class="card wide" id="ips-table">
          {{if .Rows}}
          <table class="recent">
            <thead><tr><th>events</th><th>source ip</th><th>cc</th><th>logins</th><th>sessions</th><th>sensors hit</th><th>first seen</th><th>last seen</th></tr></thead>
            <tbody data-hp-page-url="/api/ip-rows" data-hp-total="{{.Total}}" data-hp-offset="0">
            {{template "iprows" .}}
            </tbody>
          </table>
          {{else}}<p class="empty">no source IPs recorded yet</p>{{end}}
        </div>

        <footer id="ips-footer">xore//honeypot &bull; defensive sensor &bull; do not expose without auth</footer>
      </div>
    </main>
</div>
</body>
</html>
{{end}}

{{define "attacker"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>xore//honeypot — attacker {{.IP}}</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap app-content app-content--wide tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="attacker-header">
          <div>
            <div class="eyebrow">Attacker profile</div>
            <h1>{{.IP}}</h1>
            <p class="subtitle">{{.Country}} {{if .ASN}}&bull; AS{{.ASN}}{{end}} {{.Org}} {{if .Provider}}&bull; {{.Provider}}{{end}}</p>
          </div>
          <div class="live-panel">
            <span class="gen">{{.First}} — {{.Last}}</span>
          </div>
        </header>

        <div class="filters">
          <a class="chip" href="/ips">&larr; attack sources</a>
          <a class="chip" href="/events?ip={{.IP | urlquery}}">all matching events</a>
          
        </div>

        <div class="tw:grid tw:grid-cols-2 tw:sm:grid-cols-3 tw:gap-3 tw:mb-6" id="attacker-kpis">
          <div class="hp-stat"><span class="hp-stat-value">{{.Total}}</span><span class="hp-stat-label">Events</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{.Sessions}}</span><span class="hp-stat-label">Sessions</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{.PayloadCount}}</span><span class="hp-stat-label">Payload observations</span></div>
        </div>

        <div class="tw:grid tw:grid-cols-12 tw:gap-3.5" id="attacker-grid">
          {{template "tbl" (dict "t" "Sensors contacted" "rows" .Sensors "class" "half" "hint" "none")}}
          {{template "tbl" (dict "t" "Credentials attempted" "rows" .Creds "class" "half" "hint" "none")}}
          {{template "tbl" (dict "t" "Commands" "rows" .Commands "class" "half" "hint" "none")}}
          {{template "tbl" (dict "t" "HTTP paths" "rows" .Paths "class" "half" "hint" "none")}}
          {{template "tbl" (dict "t" "Payload hashes" "rows" .Payloads "class" "half" "hint" "none")}}
          {{template "tbl" (dict "t" "Alerts" "rows" .Alerts "class" "half" "hint" "none")}}
          {{template "techniques" .Techniques}}
          <div class="card wide"><h2>Attack progression</h2><p class="note">Chronological, oldest to newest; capped to the latest 250 matching records.</p><table class="recent"><thead><tr><th>time</th><th>sensor</th><th>source</th><th>port</th><th>detail</th></tr></thead><tbody>{{range .Events}}{{template "everow" .}}{{end}}</tbody></table></div>
        </div>

        <footer id="attacker-footer">xore//honeypot &bull; attacker investigation</footer>
      </div>
    </main>
</div>
</body>
</html>
{{end}}

`
