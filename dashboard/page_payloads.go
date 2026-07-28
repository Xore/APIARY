package main

const pagePayloads = `
{{define "payloadrow"}}<tr>
  <td>{{.Mtime}}</td>
  <td>{{range .Sources}}<span class="badge badge--muted">{{.}}</span> {{end}}</td>
  <td class="v">{{.Hash}}</td>
  <td class="v"><strong>{{.Kind}}</strong><br><span class="tw:text-muted">{{.Platform}} &bull; {{.MIME}}</span><br><small title="{{.AnalysisPath}}">{{if .Dynamic}}dynamic route ready{{else}}static-only route{{end}}</small></td>
  <td class="n">{{.SizeH}}</td>
  <td class="n">{{.Copies}}</td>
  <td class="v"><a class="lnk" href="/payload-analysis/{{.Hash}}">static analysis &rarr;</a></td>
  <td class="v"><form method="post" action="/sandbox/submit"><input type="hidden" name="hash" value="{{.Hash}}"><button class="btn btn-sm btn-danger" type="submit" title="{{.AnalysisPath}}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="6 3 20 12 6 21 6 3"/></svg> Analyze</button></form></td>
  <td class="v"><a class="lnk" href="/payload/{{.Hash}}">download &darr;</a></td>
  <td class="v"><a class="lnk" href="/events?shasum={{.Hash}}">related events &rarr;</a></td>
</tr>{{end}}
{{define "payloadrows"}}{{range .Files}}{{template "payloadrow" .}}{{end}}{{end}}

{{define "payloads"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot — captured payloads</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="payloads-header">
          <div>
            <div class="eyebrow">Evidence</div>
            <h1>Captured payloads</h1>
            <p class="subtitle">Unified inventory of Dionaea captures, Cowrie uploads/downloads, and retained script artifacts.</p>
          </div>
          <div class="live-panel">
            <span class="gen">unified payload inventory &bull; generated {{.Generated.Format "2006-01-02 15:04:05 MST"}}</span>
          </div>
        </header>

        <div class="filters" id="payloads-filters">
          <a class="chip" href="/">&larr; dashboard</a>
          {{if .Filter}}<a class="chip" href="/payloads">all sources</a>{{else}}<span class="chip">all sources</span>{{end}}
          {{range .Sources}}{{if .Active}}<span class="chip">{{.Name}} {{.Count}}</span>{{else}}<a class="chip" href="{{.Link}}">{{.Name}} {{.Count}}</a>{{end}}{{end}}
          {{if .Enabled}}<span class="chip">{{len .Files}} loaded of {{.ResultTotal}} matching &bull; {{.UniqueTotal}} unique total &bull; {{.TotalH}}</span>{{end}}
        </div>

        <div class="tw:grid tw:grid-cols-12 tw:gap-3.5" id="payloads-grid">
          <div class="card wide">
            {{if .Notice}}<div class="tw:mb-4 tw:flex tw:items-center tw:gap-2 tw:rounded-lg tw:border tw:border-subtle tw:bg-surface-1 tw:px-4 tw:py-3 tw:text-sm tw:text-green" role="status"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>{{.Notice}} <a class="lnk" href="/sandbox">Open sandbox queue</a></div>{{end}}
            <p class="note">
              &#9888; Unified inventory of Dionaea captures, Cowrie uploads/downloads,
              and retained shell, PowerShell, VBS, Python, JavaScript and other script
              artifacts. Files are inert on disk but <strong>hostile</strong> — handle
              only in an isolated analysis VM.
            </p>
            {{if not .Enabled}}<p class="empty">payload serving is disabled (set PAYLOAD_DIRS and/or SCRIPT_PAYLOAD_DIR)</p>
            {{else if .Loading}}<p class="note" data-payload-warming><span class="live-dot" aria-hidden="true"></span> Preparing the payload inventory. This page will update automatically.</p><script>setTimeout(()=>location.reload(),1500)</script>
            {{else if .Files}}
            <table class="recent">
              <thead><tr><th>captured</th><th>source</th><th>hash</th><th>type</th><th>size</th><th>copies</th><th>static</th><th>dynamic</th><th>download</th><th>events</th></tr></thead>
              <tbody data-hp-page-url="/api/payload-rows?source={{.Filter | urlquery}}" data-hp-total="{{.ResultTotal}}">
              {{template "payloadrows" .}}
              </tbody>
            </table>
            {{else}}<p class="empty">no payloads captured yet</p>{{end}}
          </div>
        </div>

        <footer id="payloads-footer">xore//honeypot &bull; defensive sensor &bull; do not expose without auth</footer>
      </div>
    </main>
</div>
</body>
</html>
{{end}}

{{define "payload-analysis"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>xore//honeypot — payload analysis</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap app-content app-content--wide tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="analysis-header">
          <div>
            <div class="eyebrow">Evidence</div>
            <h1>Payload analysis</h1>
            <p class="subtitle">Bounded static analysis — the sample is never executed.</p>
          </div>
          <div class="live-panel">
            <span class="gen">bounded static analysis &bull; sample is never executed</span>
          </div>
        </header>

        <div class="filters" id="analysis-filters"><a class="chip" href="/payloads">&larr; payloads</a><a class="chip" href="/events?shasum={{.Hash}}">related events</a><a class="chip" href="{{.VT}}" target="_blank" rel="noopener noreferrer">VirusTotal &rarr;</a><a class="chip" href="/payload/{{.Hash}}">download isolated sample &darr;</a><form method="post" action="/sandbox/submit"><input type="hidden" name="hash" value="{{.Hash}}"><button class="btn btn-sm btn-danger" type="submit" title="Execute this payload in the isolated KVM Linux sandbox"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="6 3 20 12 6 21 6 3"/></svg> Analyze in sandbox</button></form></div>

        <div class="tw:grid tw:grid-cols-2 tw:sm:grid-cols-3 tw:gap-3 tw:mb-6" id="analysis-kpis">
          <div class="hp-stat"><span class="hp-stat-value">{{.RiskScore}} / 100 &bull; {{.RiskLevel}}</span><span class="hp-stat-label">Static risk</span></div>
          <div class="hp-stat"><span class="hp-stat-value hp-stat-value--text">{{if .PackedLikely}}elevated{{else}}not indicated{{end}}</span><span class="hp-stat-label">Packing likelihood</span></div>
          <div class="hp-stat"><span class="hp-stat-value">{{len .IOCs}}</span><span class="hp-stat-label">Extracted IOCs</span></div>
        </div>

        <div class="tw:grid tw:grid-cols-12 tw:gap-3.5" id="analysis-grid">
          <div class="card wide"><h2>Identity and selected analysis path</h2><table><tbody><tr><td>identified type</td><td class="v"><strong>{{.Classification.Label}}</strong> <span class="badge badge--muted">{{.Classification.Code}}</span></td></tr><tr><td>platform / category</td><td class="v">{{.Classification.Platform}} / {{.Classification.Category}}</td></tr><tr><td>sandbox route</td><td class="v">{{.Classification.AnalysisPath}}</td></tr><tr><td>dynamic execution</td><td class="v">{{if .Classification.Dynamic}}supported for this type{{else}}not automatic; static analysis only{{end}}</td></tr><tr><td>magic</td><td class="v">{{.Magic}}</td></tr><tr><td>MIME</td><td class="v">{{.MIME}}</td></tr><tr><td>size</td><td class="v">{{.Size}}</td></tr><tr><td>entropy</td><td class="v">{{.Entropy}}</td></tr><tr><td>MD5</td><td class="v">{{.MD5}}</td></tr><tr><td>SHA-1</td><td class="v">{{.SHA1}}</td></tr><tr><td>SHA-256</td><td class="v">{{.SHA256}}</td></tr></tbody></table>{{if .Truncated}}<p class="note">deep inspection capped at 16 MiB; hashes cover the complete file</p>{{end}}</div>
          {{if or .ScriptType .Indicators}}<div class="card wide"><h2>Script classification</h2><table><tbody>{{if .ScriptType}}<tr><td>language/type</td><td class="v">{{.ScriptType}}</td></tr>{{end}}{{if .Indicators}}<tr><td>behavior indicators</td><td class="v">{{range .Indicators}}<span class="chip">{{.}}</span> {{end}}</td></tr>{{end}}</tbody></table><p class="note">Heuristic static findings only. Captured content is never interpreted or executed.</p></div>{{end}}
          <div class="card wide"><h2>YARA static scan</h2>{{if .YARAMatches}}<table><tbody>{{range .YARAMatches}}<tr><td><span class="badge badge--red">match</span></td><td class="v">{{.}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">{{if .YARAScanned}}No YARA rules matched this sample.{{else}}Waiting for the isolated YARA scanner.{{end}}</p>{{end}}{{if .YARAError}}<p class="note tw:text-red">{{.YARAError}}</p>{{end}}{{if .YARAScanned}}<p class="note">Scanned {{.YARAScanned}} by the networkless YARA sidecar. A match is a triage signal, not attribution.</p>{{end}}</div>
          <div class="card wide"><h2>Isolated dynamic analysis</h2>{{if .SandboxRuns}}<table><thead><tr><th>completed</th><th>exit</th><th>changed paths</th><th>details</th></tr></thead><tbody>{{range .SandboxRuns}}<tr><td>{{.CompletedAt}}</td><td class="n">{{.ExitStatus}}</td><td class="n">{{len .ChangedFiles}}</td><td><a class="lnk" href="/sandbox/{{.Job | urlquery}}">sandbox report &rarr;</a></td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No completed KVM sandbox run for this payload. Use <strong>Analyze in sandbox</strong> to queue one.</p>{{end}}</div>
          <div class="card half"><h2>Rule matches</h2>{{if .Rules}}<table><thead><tr><th>severity</th><th>rule</th><th>reason</th></tr></thead><tbody>{{range .Rules}}<tr><td><span class="badge badge--muted">{{.Severity}}</span></td><td class="v">{{.Name}}</td><td class="v">{{.Description}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No built-in static rules matched.</p>{{end}}<p class="note">Deterministic YARA-style heuristics; no sample execution or attribution.</p></div>
          <div class="card half"><h2>Extracted indicators</h2>{{if .IOCs}}<table><tbody>{{range .IOCs}}<tr><td class="v"><a href="/events?q={{. | urlquery}}" title="search telemetry for this indicator">{{.}}</a></td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No URL, domain, or IP indicators found.</p>{{end}}</div>
          <div class="card wide"><h2>Hex / ASCII preview — first 512 bytes</h2><pre class="code">{{.Hexdump}}</pre></div>
          <div class="card"><h2>Executable metadata</h2>{{if .FormatInfo}}<pre class="code">{{range .FormatInfo}}{{.}}
{{end}}</pre>{{else}}<p class="empty">not a recognized PE/ELF file</p>{{end}}</div>
          <div class="card"><h2>Decoded / deobfuscated candidates</h2>{{if .Decoded}}{{range .Decoded}}<p class="note">{{.Kind}} from <code>{{.Source}}</code></p><pre class="code">{{.Preview}}</pre>{{end}}{{else}}<p class="empty">no bounded Base64, hex, URL or UTF-16 candidates found</p>{{end}}</div>
          <div class="card"><h2>Printable strings</h2>{{if .ASCII}}<pre class="code">{{range .ASCII}}{{.}}
{{end}}</pre>{{else}}<p class="empty">none</p>{{end}}</div>
          <div class="card"><h2>UTF-16LE strings</h2>{{if .UTF16}}<pre class="code">{{range .UTF16}}{{.}}
{{end}}</pre>{{else}}<p class="empty">none</p>{{end}}</div>
        </div>

        <footer id="analysis-footer">xore//honeypot &bull; static analysis only &bull; never execute captured samples</footer>
      </div>
    </main>
</div>
</body>
</html>
{{end}}

`
