package main

const pageSession = `
{{define "session"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot &mdash; session {{.ID}}</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap app-content app-content--wide tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header">
          <div>
            <div class="eyebrow">Session replay</div>
            <h1>{{.ID}}</h1>
            <p class="subtitle">{{.IP}} {{if .Country}}&bull; {{.Country}}{{end}} &bull; {{.First}} &mdash; {{.Last}}</p>
          </div>
          <div class="live-panel">
            <span class="gen">{{.Total}} normalized events</span>
          </div>
        </header>

        <div class="filters"><a class="chip" href="/events">&larr; event explorer</a>{{if .IP}}<a class="chip" href="/investigate/ip/{{.IP | urlquery}}">attacker profile</a>{{end}}<a class="chip" href="/events?session={{.ID | urlquery}}">filtered events</a><a class="btn btn-sm btn-primary" href="/export/report.pdf?session={{.ID | urlquery}}"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>Session PDF</a></div>

        <div class="tw:grid tw:grid-cols-12 tw:gap-3.5">{{template "tbl" (dict "t" "Sensors" "rows" .Sensors "class" "half" "hint" "none")}}{{template "tbl" (dict "t" "Credentials" "rows" .Credentials "class" "half" "hint" "none")}}{{template "tbl" (dict "t" "Commands" "rows" .Commands "class" "half" "hint" "none")}}{{template "tbl" (dict "t" "Payload hashes" "rows" .Payloads "class" "half" "hint" "none")}}{{template "techniques" .Techniques}}
        <div class="card wide"><h2>Chronological replay</h2><p class="note">Oldest to newest. Commands, credentials, downloads, fingerprints, and investigation pivots remain linked.</p><table class="recent"><thead><tr><th>time</th><th>sensor</th><th>source</th><th>port</th><th>detail</th></tr></thead><tbody>{{range .Events}}{{template "everow" .}}{{end}}</tbody></table></div></div>

        <footer>xore//honeypot &bull; session investigation</footer>
      </div>
    </main>
</div>
</body>
</html>
{{end}}

`
