package main

const pageOps = `
{{define "history"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot — Elasticsearch history</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap app-content tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="history-header">
          <div>
            <div class="eyebrow">Historical data</div>
            <h1>Elasticsearch history</h1>
            <p class="subtitle">Elasticsearch historical explorer &mdash; run query_string searches across every indexed honeypot and Suricata document.</p>
          </div>
          <div class="live-panel">
            <a class="btn btn-sm btn-secondary" id="history-export-top" href="/export/history.json" title="Download the current result set as JSON"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Export JSON</a>
            <span class="gen">long-retention indexed documents</span>
          </div>
        </header>
        <div class="filters" id="history-filters"><a class="chip" href="/">&larr; dashboard</a><input id="history-q" class="search" placeholder="query_string, e.g. honeypot.sensor:cowrie AND honeypot.username:root" aria-label="Elasticsearch query"><button id="history-run" class="copy">search</button><a id="history-export" class="chip" href="/export/history.json">export JSON &darr;</a></div>
        <div class="card wide" id="history-card"><p id="history-meta" class="note">Enter an Elasticsearch query or leave blank for newest documents.</p><pre id="history-results" class="code">waiting</pre></div>
        <footer id="history-footer">xore//honeypot &bull; historical data from Elasticsearch</footer>
      </div>
    </main>
</div>
<script>
const q=document.getElementById('history-q'), out=document.getElementById('history-results'), meta=document.getElementById('history-meta');
q.value=new URLSearchParams(location.search).get('q')||'';
async function run(){const query=q.value.trim(), u='/api/history?limit=200'+(query?'&q='+encodeURIComponent(query):'');document.getElementById('history-export').href='/export/history.json?limit=500'+(query?'&q='+encodeURIComponent(query):'');document.getElementById('history-export-top').href='/export/history.json?limit=500'+(query?'&q='+encodeURIComponent(query):'');meta.textContent='loading…';try{const r=await fetch(u);const j=await r.json();const hits=j.hits?.hits||[];meta.textContent=hits.length+' documents shown';out.textContent=hits.map(h=>JSON.stringify(h._source,null,2)).join('\n\n')}catch(e){meta.textContent='query failed';out.textContent=String(e)}}
document.getElementById('history-run').onclick=run;q.onkeydown=e=>{if(e.key==='Enter')run()};run();
</script>
</body>
</html>
{{end}}

{{define "dead-letters"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot &mdash; ingest dead letters</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap app-content tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="dead-header">
          <div>
            <div class="eyebrow">Pipeline diagnostics</div>
            <h1>Ingest dead letters</h1>
            <p class="subtitle">Documents Elasticsearch rejected, with their original error and field shape for remediation.</p>
          </div>
          <div class="live-panel">
            <span class="gen">{{.ES.RecentDeadLetters}} in 24h &bull; {{.ES.DeadLetters}} retained</span>
          </div>
        </header>
        <div class="filters" id="dead-filters"><a class="chip" href="/source-health">&larr; source health</a><input id="dead-q" class="search" placeholder="optional Elasticsearch query" aria-label="Dead-letter query"><button id="dead-run" class="copy">search</button></div>
        <div class="card wide" id="dead-card"><p id="dead-meta" class="note">Loading rejected documents&hellip;</p><div id="dead-rows" data-hp-lazy-list></div></div>
        <footer id="dead-footer">xore//honeypot &bull; ingestion failure diagnostics</footer>
      </div>
    </main>
</div>
<script>
const deadQ=document.getElementById('dead-q'),deadRows=document.getElementById('dead-rows'),deadMeta=document.getElementById('dead-meta');
async function loadDead(){const q=deadQ.value.trim(),u='/api/dead-letters?limit=200'+(q?'&q='+encodeURIComponent(q):'');deadMeta.textContent='loading';try{const j=await (await fetch(u,{cache:'no-store'})).json(),hits=j.hits?.hits||[];deadMeta.textContent=hits.length+' rejected documents shown';deadRows.innerHTML='';for(const hit of hits){const d=document.createElement('details');d.className='tw:border-b tw:border-subtle tw:py-2';const source=hit._source||{},stamp=source['@timestamp']||'',error=source.error?.message||source.error?.type||'rejected document';const summary=document.createElement('summary');summary.className='v';summary.textContent=stamp+' - '+error;const pre=document.createElement('pre');pre.className='code tw:mt-2';pre.textContent=JSON.stringify(source,null,2);d.append(summary,pre);deadRows.appendChild(d)}if(!hits.length)deadRows.textContent='No matching dead letters.'}catch(e){deadMeta.textContent='query failed';deadRows.textContent=String(e)}}
document.getElementById('dead-run').onclick=loadDead;deadQ.onkeydown=e=>{if(e.key==='Enter')loadDead()};loadDead();
</script>
</body>
</html>
{{end}}

{{define "source-health"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot — source health</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap app-content tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="health-header">
          <div>
            <div class="eyebrow">Pipeline diagnostics</div>
            <h1>Source &amp; pipeline health</h1>
            <p class="subtitle">Dashboard + Filebeat + Elasticsearch ingestion health, from log tail to indexed document.</p>
          </div>
          <div class="live-panel">
            <a class="btn btn-sm btn-secondary" href="/dead-letters" title="Inspect documents Elasticsearch rejected"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Dead letters</a>
            <span class="gen">dashboard + Filebeat + Elasticsearch ingestion health</span>
          </div>
        </header>
        <div class="filters" id="health-filters"><a class="chip" href="/">&larr; dashboard</a><span class="chip">ES {{.ES.State}}</span><a class="chip" href="/history" title="browse all indexed honeypot and Suricata documents">{{.ES.Documents}} indexed documents</a><span class="chip">{{.ES.DeadLetters}} dead letters</span></div>
        <div class="tw:grid tw:grid-cols-2 tw:sm:grid-cols-4 tw:gap-3 tw:mb-6" id="health-kpis">
          <a class="hp-stat" href="#sensor-feeds" title="Jump to the dashboard parser feed table"><span class="hp-stat-value">{{len .Sensors}}</span><span class="hp-stat-label">Configured feeds</span></a>
          <a class="hp-stat" href="/history" title="Browse all indexed documents in Elasticsearch history"><span class="hp-stat-value">{{.ES.Documents}}</span><span class="hp-stat-label">Indexed documents</span></a>
          <a class="hp-stat" href="#pipeline-status" title="Jump to the Filebeat pipeline status table"><span class="hp-stat-value">{{.ES.FilebeatState}}</span><span class="hp-stat-label">Filebeat</span></a>
          <a class="hp-stat" href="/dead-letters" title="Inspect rejected documents"><span class="hp-stat-value">{{.ES.DeadLetters}}</span><span class="hp-stat-label">Dead letters</span></a>
        </div>
        <div class="tw:grid tw:grid-cols-12 tw:gap-3.5" id="health-grid">
          <div class="section-heading"><div><h2>Ingestion pipeline detail</h2><p>Every stage from sensor log tail to indexed document, with freshness and failure counters.</p></div><a class="section-link" href="/dead-letters">Inspect dead letters &rarr;</a></div>
          <div class="card half" id="sensor-feeds"><h2>Dashboard parser feeds</h2><table><thead><tr><th>feed</th><th>tail events</th><th>state</th><th>last</th></tr></thead><tbody>{{range .Sensors}}<tr><td><a class="badge b-{{.Name}}" href="{{.Link}}">{{.Name}}</a></td><td class="n"><a href="{{.Link}}" title="show every related event in the dashboard tail">{{.Count}}</a></td><td class="state s-{{.State}}">{{.State}}</td><td class="ago">{{.Ago}}</td></tr>{{end}}</tbody></table></div>
          <div class="card half"><h2>Elasticsearch indexed totals</h2>{{if .ES.Sources}}<table><thead><tr><th>source</th><th>documents</th></tr></thead><tbody>{{range .ES.Sources}}<tr><td class="v"><a href="{{.Link}}" title="search all indexed documents for this source">{{.Name}}</a></td><td class="n"><a href="{{.Link}}" title="search all indexed documents for this source">{{.Count}}</a></td></tr>{{end}}</tbody></table>{{else}}<p class="empty">{{if .ES.Error}}{{.ES.Error}}{{else}}waiting for Elasticsearch check{{end}}</p>{{end}}</div>
          <div class="card"><h2>Ingestion freshness</h2><table><tbody><tr><td>state</td><td class="state s-{{.ES.IngestState}}">{{.ES.IngestState}}</td></tr><tr><td>latest indexed event</td><td class="v">{{.ES.LastIngest}}</td></tr><tr><td>ingestion age</td><td class="v">{{.ES.LastIngestAge}}</td></tr><tr><td>dead letters in 24h</td><td class="v"><a href="/dead-letters">{{.ES.RecentDeadLetters}}</a></td></tr></tbody></table><p class="note">Delayed means the newest indexed event is over two minutes old; stale means over fifteen minutes.</p></div>
          <div class="card"><h2>YARA scanner</h2><table><tbody><tr><td>enabled</td><td class="v">{{.YARA.Enabled}}</td></tr><tr><td>last report</td><td class="v">{{.YARA.Updated}}</td></tr><tr><td>samples scanned</td><td class="v">{{.YARA.Samples}}</td></tr><tr><td>samples matched</td><td class="v">{{.YARA.Matched}}</td></tr><tr><td>errors</td><td class="v">{{.YARA.Errors}}</td></tr></tbody></table><p class="note">The scanner has no network and receives payload stores read-only.</p></div>
          <div class="card"><h2>Dashboard runtime</h2><table><tbody><tr><td>uptime</td><td class="v">{{.Runtime.Uptime}}</td></tr><tr><td>Go heap</td><td class="v">{{.Runtime.Heap}}</td></tr><tr><td>reserved memory</td><td class="v">{{.Runtime.Reserved}}</td></tr><tr><td>container memory</td><td class="v">{{.Runtime.ContainerUsage}} / {{.Runtime.ContainerLimit}}</td></tr><tr><td>goroutines</td><td class="v">{{.Runtime.Goroutines}}</td></tr></tbody></table><p class="note">Container values come from cgroup v2 when available; the Go heap is the live application allocation. <a href="/metrics">Prometheus metrics</a></p></div>
          <div class="card wide" id="pipeline-status"><h2>Pipeline status</h2><table><tbody><tr><td>Elasticsearch cluster</td><td class="v">{{.ES.State}}</td></tr><tr><td>last indexed</td><td class="v">{{.ES.LastIngest}}</td></tr><tr><td>dead letters</td><td class="v">{{.ES.DeadLetters}}</td></tr><tr><td>Filebeat</td><td class="v">{{.ES.FilebeatState}}</td></tr><tr><td>Filebeat acknowledged</td><td class="v">{{.ES.FilebeatAcked}}</td></tr><tr><td>Filebeat failed / dropped / active</td><td class="v">{{.ES.FilebeatFailed}} / {{.ES.FilebeatDropped}} / {{.ES.FilebeatActive}}</td></tr><tr><td>last checked</td><td class="v">{{.ES.Checked}}</td></tr>{{if .ES.Error}}<tr><td>error</td><td class="v">{{.ES.Error}}</td></tr>{{end}}</tbody></table><p class="note">A quiet dashboard feed with a stable Elasticsearch total means no recent attacks. A growing log with a static ES total indicates Filebeat lag. Dead-letter growth or Filebeat failed/dropped counters indicate a pipeline error.</p></div>
        </div>
        <footer id="health-footer">xore//honeypot &bull; source diagnostics</footer>
      </div>
    </main>
</div>
</body>
</html>
{{end}}

{{define "alerts"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot — alerts</title>
{{template "style"}}
</head>
<body>
<div class="app-shell">
  {{template "topbar" .}}
  {{template "sidebar" .}}
  <main class="app-main">
      <div class="wrap app-content tw:px-6 tw:pt-7 tw:pb-24 tw:lg:px-8" data-hp-page-content>
        <header class="overview-header" id="alerts-header">
          <div>
            <div class="eyebrow">Security operations</div>
            <h1>Alerts</h1>
            <p class="subtitle">Persistent alert state, cooldowns and acknowledgments &mdash; acknowledged alerts stay suppressed until reopened.</p>
          </div>
          <div class="live-panel">
            <a class="btn btn-sm btn-primary" href="/export/report.pdf?type=alert" title="Download a PDF report covering every recorded alert"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>All alerts PDF</a>
            <span class="gen">acknowledged alerts stay suppressed until reopened</span>
          </div>
        </header>
        <div class="filters" id="alerts-filters"><a class="chip" href="/">&larr; dashboard</a><button class="copy" onclick="loadAlerts()">refresh</button></div>
        <div class="card wide" id="alerts-card"><table class="recent"><thead><tr><th>state</th><th>key</th><th>message</th><th>observed</th><th>last seen</th><th>last notified</th><th>action</th></tr></thead><tbody id="alert-rows"></tbody></table><p id="alert-empty" class="empty">loading</p></div>
        <footer id="alerts-footer">xore//honeypot &bull; acknowledged alerts stay suppressed until reopened</footer>
      </div>
    </main>
</div>
<script>
async function setAck(key,ack){await fetch('/api/alerts',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({key,ack:String(ack)})});loadAlerts()}
async function loadAlerts(){const rows=document.getElementById('alert-rows'),empty=document.getElementById('alert-empty');try{const a=await (await fetch('/api/alerts')).json();rows.innerHTML='';for(const r of a){const tr=document.createElement('tr');const vals=[r.Acknowledged?'acknowledged':'open',r.Key,r.Message,r.Count,new Date(r.LastSeen).toLocaleString(),new Date(r.LastNotified).toLocaleString()];for(const v of vals){const td=document.createElement('td');td.className='v';td.textContent=v;tr.appendChild(td)}const td=document.createElement('td'),b=document.createElement('button');b.className='copy';b.textContent=r.Acknowledged?'reopen':'acknowledge';b.onclick=()=>setAck(r.Key,!r.Acknowledged);td.appendChild(b);tr.appendChild(td);rows.appendChild(tr)}empty.textContent=a.length?'':'no alerts recorded'}catch(e){empty.textContent=String(e)}}loadAlerts();
</script>
</body>
</html>
{{end}}
`
