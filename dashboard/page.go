package main

// pageTemplate holds every page of the dashboard as named templates:
//
//	"page"   — the main dashboard (auto-refreshes in place every 15s)
//	"events" — /events drill-down: any KPI / row on the dashboard links here
//	           with a filter; a single-IP view renders as a chronological
//	           attack chain
//	"ips"    — /ips: every source IP with first/last seen and sensors hit
//
// All share the "style" block and the embedded AdminLTE frontend assets.
const pageTemplate = `
{{define "style"}}
<style>
  :root{
    color-scheme:dark;--bg:#070a0f;--panel:#0d131c;--panel2:#111a26;--line:rgba(255,255,255,.08);--line2:rgba(255,255,255,.14);
    --text:#e8edf3;--muted:#8a97a8;--faint:#5c697a;--cyan:#38bdf8;--green:#34d399;
    --amber:#fbbf24;--red:#f87171;--purple:#a78bfa;--shadow:0 18px 50px rgba(0,0,0,.24);--mono:"JetBrains Mono",ui-monospace,monospace;
    --font:"Inter",system-ui,sans-serif;
  }
  :root[data-theme="light"]{color-scheme:light;--bg:#f4f7fb;--panel:#fff;--panel2:#f8fafc;
    --line:rgba(15,23,42,.08);--line2:rgba(15,23,42,.14);--text:#172033;--muted:#526177;
    --faint:#7c899c;--cyan:#0284c7;--green:#059669;--amber:#b45309;--red:#dc2626;--purple:#7c3aed;
    --shadow:0 14px 40px rgba(30,41,59,.08)}
  *{box-sizing:border-box;margin:0;padding:0}
  body{min-height:100vh;font-family:var(--font);color:var(--text);background:var(--bg);padding:30px 32px 40px 264px;transition:background .2s,color .2s}
  body::before{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(900px 500px at 70% -10%,rgba(56,189,248,.08),transparent 65%);z-index:-1}
  .wrap{max-width:1500px;margin:0 auto}
  header{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;margin-bottom:24px;padding-bottom:18px;border-bottom:1px solid var(--line)}
  h1{font-weight:850;letter-spacing:.08em;font-size:1.12rem}
  h1 span{color:var(--cyan)}
  h1 a{color:inherit;text-decoration:none}
  .gen{font-family:var(--mono);font-size:.7rem;color:var(--faint);letter-spacing:.08em}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:22px}
  .kpi{display:block;background:var(--panel);border:1px solid var(--line);box-shadow:var(--shadow);
    border-radius:14px;padding:18px 20px;color:inherit;text-decoration:none;transition:transform .15s,border-color .15s}
  a.kpi:hover{border-color:var(--cyan);transform:translateY(-2px)}
  .kpi .n{font-size:1.7rem;font-weight:700}
  .kpi .l{font-family:var(--mono);font-size:.66rem;letter-spacing:.1em;color:var(--muted);
    text-transform:uppercase;margin-top:4px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
  .card{background:var(--panel);border:1px solid var(--line);box-shadow:var(--shadow);
    border-radius:14px;padding:20px;overflow:hidden}
  .card h2{font-family:var(--mono);font-size:.72rem;letter-spacing:.1em;color:var(--cyan);
    text-transform:uppercase;margin-bottom:12px}
  .card h2::before{content:"> ";color:var(--green)}
  table{width:100%;border-collapse:collapse;font-size:.82rem}
  td{padding:8px 7px;border-bottom:1px solid var(--line);vertical-align:top}
  th{padding:8px 7px;border-bottom:1px solid var(--line2);font-family:var(--mono);
    font-size:.62rem;letter-spacing:.08em;color:var(--faint);text-transform:uppercase;text-align:left}
  tr:last-child td{border-bottom:none}
  tbody tr{transition:background .12s}tbody tr:hover{background:rgba(56,189,248,.045)}
  td.n{color:var(--cyan);font-family:var(--mono);text-align:right;width:64px;white-space:nowrap}
  td.n a{color:inherit;text-decoration:none;border-bottom:1px dotted color-mix(in srgb,var(--cyan) 45%,transparent)}td.n a:hover{color:var(--text);border-color:var(--cyan)}
  td.v{color:var(--muted);font-family:var(--mono);word-break:break-all}
  td.ago{color:var(--faint);font-family:var(--mono);font-size:.72rem;text-align:right;white-space:nowrap}
  td.state{font-family:var(--mono);font-size:.62rem;text-transform:uppercase;text-align:right}
  td.s-active{color:var(--green)} td.s-quiet{color:var(--amber)} td.s-stale{color:var(--red)} td.s-waiting{color:var(--faint)}
  td.v a,td a.lnk{color:inherit;text-decoration:none;border-bottom:1px dotted rgba(138,151,168,.45)}
  td.v a:hover,td a.lnk:hover{color:var(--cyan);border-color:var(--cyan)}
  .wide{grid-column:1/-1}
  .recent td:nth-child(1){color:var(--faint);font-family:var(--mono);font-size:.72rem;white-space:nowrap}
  .badge{font-family:var(--mono);font-size:.6rem;padding:2px 6px;border-radius:5px;letter-spacing:.05em;
    text-decoration:none;display:inline-block}
  .badge{background:rgba(138,151,168,.1);border:1px solid rgba(138,151,168,.25);color:var(--muted)}
  .b-cowrie{background:rgba(56,189,248,.1);border:1px solid rgba(56,189,248,.25);color:var(--cyan)}
  .b-http{background:rgba(52,211,153,.1);border:1px solid rgba(52,211,153,.25);color:var(--green)}
  .b-multipot{background:rgba(251,191,36,.1);border:1px solid rgba(251,191,36,.25);color:var(--amber)}
  .b-dionaea{background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.25);color:var(--red)}
  .b-conpot{background:rgba(192,132,252,.1);border:1px solid rgba(192,132,252,.25);color:#c084fc}
  .b-tanner{background:rgba(244,114,182,.1);border:1px solid rgba(244,114,182,.25);color:#f472b6}
  .b-suricata{background:rgba(148,163,184,.1);border:1px solid rgba(148,163,184,.3);color:#94a3b8}
  .empty{color:var(--faint);font-family:var(--mono);font-size:.78rem}
  .chart{display:flex;align-items:flex-end;gap:3px;height:130px;padding-top:6px}
  .col{position:relative;flex:1;height:100%;display:flex;flex-direction:column;justify-content:flex-end;min-width:0;cursor:help}
  .col::after{content:attr(data-tip);position:absolute;z-index:6;left:50%;top:5px;transform:translate(-50%,-6px);padding:6px 8px;border:1px solid var(--line2);border-radius:7px;background:var(--panel2);box-shadow:var(--shadow);color:var(--text);font:11px var(--mono);white-space:nowrap;opacity:0;pointer-events:none;transition:opacity .12s,transform .12s}
  .col:hover::after,.col:focus-visible::after{opacity:1;transform:translate(-50%,0)}
  .col .bar{background:linear-gradient(180deg,var(--cyan),rgba(56,189,248,.15));
    border-radius:2px 2px 0 0;min-height:2px;opacity:.9}
  .col.zero .bar{background:rgba(255,255,255,.05);min-height:2px}
  .col span{font-family:var(--mono);font-size:.55rem;color:var(--faint);text-align:center;
    margin-top:4px;display:none}
  .col:nth-child(3n+1) span{display:block}
  .filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
  .chip{font-family:var(--mono);font-size:.68rem;padding:4px 10px;border:1px solid var(--line2);
    border-radius:999px;color:var(--muted);text-decoration:none}
  a.chip:hover{color:var(--cyan);border-color:var(--cyan)}
  .note{font-family:var(--mono);font-size:.7rem;color:var(--faint);margin-bottom:12px}
  .cc{font-family:var(--mono);font-size:.6rem;padding:1px 5px;border-radius:4px;text-decoration:none;
    background:rgba(56,189,248,.08);border:1px solid rgba(56,189,248,.2);color:var(--cyan)}
  .lnk.sess{color:var(--green);border-color:rgba(52,211,153,.4)}
  .eventmeta{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}.eventmeta .lnk{display:inline-block;max-width:420px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.66rem;color:var(--cyan)}
  pre.code{white-space:pre-wrap;word-break:break-word;background:#05070a;border:1px solid var(--line);
    border-radius:8px;padding:12px;color:#b8c3d1;font:12px/1.5 var(--mono);max-height:520px;overflow:auto}
  button.copy{background:transparent;border:1px solid var(--line2);color:var(--muted);border-radius:6px;
    padding:3px 8px;font:11px var(--mono);cursor:pointer} button.copy:hover{color:var(--cyan);border-color:var(--cyan)}
  input.search{flex:1;min-width:260px;background:#05070a;border:1px solid var(--line2);border-radius:8px;
    color:var(--text);padding:8px 10px;font:12px var(--mono)}
  .map-shell{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:10px;background:var(--panel2)}
  .leaflet-map{display:block;width:100%;height:clamp(360px,52vw,620px);background:#d8e4ea;z-index:1}
  .map-status{position:absolute;z-index:500;left:10px;bottom:28px;padding:5px 8px;border:1px solid var(--line2);border-radius:7px;background:color-mix(in srgb,var(--panel) 88%,transparent);box-shadow:var(--shadow);color:var(--muted);font:10px var(--mono);pointer-events:none}
  .map-fallback[hidden],.leaflet-map[hidden]{display:none}.map-fallback{padding-top:34px}.map-fallback-note{position:absolute;z-index:2;top:8px;left:10px;color:var(--red);font:11px var(--mono)}
  .leaflet-container{font-family:var(--font);color:#18212c}.leaflet-control-zoom a,.leaflet-control-home{background:var(--panel)!important;color:var(--text)!important;border-color:var(--line2)!important}.leaflet-control-home{width:32px;height:32px;line-height:30px;text-align:center;font:700 11px/30px var(--mono);cursor:pointer}.leaflet-control-attribution{background:color-mix(in srgb,var(--panel) 86%,transparent)!important;color:var(--muted)!important}.leaflet-control-attribution a{color:var(--cyan)!important}.leaflet-tooltip.attack-tooltip{padding:8px 10px;border:1px solid var(--line2);border-radius:7px;background:var(--panel);box-shadow:var(--shadow);color:var(--text);font:11px/1.45 var(--mono)}.leaflet-tooltip.attack-tooltip:before{display:none}.leaflet-interactive{transition:fill-opacity .12s,stroke-opacity .12s}.leaflet-interactive:hover{fill-opacity:.88!important;stroke-opacity:1!important}
  [data-theme="dark"] .leaflet-tile-pane{filter:brightness(.62) invert(1) contrast(1.25) hue-rotate(180deg) saturate(.35)}[data-theme="dark"] .leaflet-map{background:#09111b}
  .world{display:block;width:100%;height:auto;min-height:260px;touch-action:none;cursor:grab;user-select:none}.world.dragging{cursor:grabbing}.world .ocean{fill:transparent}.world .graticule{stroke:color-mix(in srgb,var(--text) 9%,transparent);stroke-width:1;stroke-dasharray:3 5}
  .world .land{fill:color-mix(in srgb,var(--muted) 18%,var(--panel));stroke:color-mix(in srgb,var(--muted) 42%,transparent);stroke-width:1.2;vector-effect:non-scaling-stroke}
  .world .country:hover{fill:color-mix(in srgb,var(--cyan) 16%,var(--panel))}
  .world .country-label{fill:color-mix(in srgb,var(--text) 70%,transparent);font:600 9px var(--mono);letter-spacing:.02em;text-anchor:middle;paint-order:stroke;stroke:var(--panel);stroke-width:2.5px;stroke-linejoin:round;pointer-events:none}
  .world .country-label.rank-3,.world .country-label.rank-4,.world .country-label.rank-5,.world .country-label.rank-6{display:none}
  .world[data-zoom-level="2"] .country-label.rank-3,.world[data-zoom-level="3"] .country-label.rank-3,.world[data-zoom-level="4"] .country-label.rank-3{display:block}
  .world[data-zoom-level="3"] .country-label.rank-4,.world[data-zoom-level="4"] .country-label.rank-4{display:block}
  .world[data-zoom-level="4"] .country-label.rank-5,.world[data-zoom-level="4"] .country-label.rank-6{display:block}
  .world circle{fill:var(--red);fill-opacity:.62;stroke:#fecaca;stroke-width:1.2;filter:drop-shadow(0 0 4px rgba(248,113,113,.55));transition:r .12s,fill-opacity .12s}.world circle:hover{fill-opacity:1;r:8px}
  footer{margin-top:22px;font-family:var(--mono);font-size:.66rem;color:var(--faint);
    letter-spacing:.08em;text-align:center;text-transform:uppercase}
  .appnav{position:fixed;inset:0 auto 0 0;width:232px;background:color-mix(in srgb,var(--panel) 94%,transparent);
    backdrop-filter:blur(18px);border-right:1px solid var(--line);padding:24px 16px;z-index:50;display:flex;flex-direction:column}
  .appbrand{padding:0 10px 20px;font-weight:900;letter-spacing:.12em}.appbrand span{color:var(--cyan)}
  .appsection{font:600 10px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--faint);padding:16px 10px 7px}
  .appnav a{display:flex;align-items:center;gap:10px;color:var(--muted);text-decoration:none;padding:9px 10px;border-radius:8px;font-size:13px}
  .appnav a:hover,.appnav a.active{color:var(--text);background:rgba(56,189,248,.09)}.appnav a.active{box-shadow:inset 2px 0 var(--cyan)}
  .apptheme{margin-top:auto;display:grid;grid-template-columns:repeat(3,1fr);gap:4px;padding:5px;background:var(--panel2);border:1px solid var(--line);border-radius:10px}
  .apptheme button{border:0;background:transparent;color:var(--faint);font:10px var(--mono);padding:7px 3px;border-radius:6px;cursor:pointer}.apptheme button.active{background:var(--panel);color:var(--cyan);box-shadow:0 2px 8px rgba(0,0,0,.12)}
  @media(max-width:800px){body{padding:86px 14px 28px}.appnav{inset:0 0 auto 0;width:auto;height:68px;padding:10px 12px;flex-direction:row;align-items:center;overflow-x:auto}.appbrand{padding:0 14px 0 2px;white-space:nowrap}.appsection{display:none}.appnav a{white-space:nowrap;padding:8px}.apptheme{margin:0 0 0 auto;min-width:146px}.grid{grid-template-columns:1fr}.card{padding:15px}header{align-items:flex-start}}

  /* Operations dashboard layout */
  body{padding:28px 32px 52px 276px;background:
    radial-gradient(900px 520px at 62% -12%,rgba(56,189,248,.075),transparent 68%),var(--bg)}
  .wrap{max-width:1580px}
  header{margin-bottom:18px;padding-bottom:0;border-bottom:0}
  .overview-header{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:end;margin-bottom:20px}
  .eyebrow{margin-bottom:7px;color:var(--cyan);font:700 .66rem var(--mono);letter-spacing:.14em;text-transform:uppercase}
  .overview-header h1{font-size:clamp(1.55rem,2.4vw,2.25rem);letter-spacing:-.035em;line-height:1.05}
  .overview-header h1 span{color:var(--text)}
  .overview-header .subtitle{max-width:720px;margin-top:9px;color:var(--muted);font-size:.9rem;line-height:1.55}
  .live-panel{display:flex;flex-direction:column;align-items:flex-end;gap:7px}
  .live-pill{display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border:1px solid rgba(52,211,153,.22);border-radius:999px;background:rgba(52,211,153,.07);color:var(--green);font:700 .66rem var(--mono);letter-spacing:.08em;text-transform:uppercase}
  .live-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 0 4px rgba(52,211,153,.1),0 0 14px rgba(52,211,153,.55)}
  .kpis{grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:30px}
  .kpi{position:relative;min-height:128px;padding:20px;border-radius:15px;box-shadow:none;overflow:hidden}
  .kpi::before{content:"";position:absolute;inset:0 auto 0 0;width:3px;background:var(--kpi-color,var(--cyan));opacity:.85}
  .kpi:nth-child(2){--kpi-color:var(--green)}.kpi:nth-child(3){--kpi-color:var(--purple)}.kpi:nth-child(4){--kpi-color:var(--amber)}.kpi:nth-child(5){--kpi-color:var(--red)}
  .kpi .n{font-size:2rem;letter-spacing:-.035em;line-height:1}.kpi .l{margin-top:11px;color:var(--text);font:700 .67rem var(--mono)}
  .kpi .d{margin-top:6px;color:var(--faint);font-size:.7rem;line-height:1.35}
  .dashboard-tabs{position:sticky;top:12px;z-index:40;display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin:0 0 18px;padding:6px;border:1px solid var(--line);border-radius:14px;background:color-mix(in srgb,var(--panel) 92%,transparent);backdrop-filter:blur(18px);box-shadow:0 12px 30px rgba(0,0,0,.12)}
  .dashboard-tab{display:flex;align-items:center;justify-content:center;gap:8px;min-height:42px;border:1px solid transparent;border-radius:9px;background:transparent;color:var(--muted);font:700 .72rem var(--font);cursor:pointer;transition:.15s ease}
  .dashboard-tab span{display:grid;place-items:center;width:22px;height:22px;border-radius:6px;background:var(--panel2);color:var(--faint);font:700 8px var(--mono)}
  .dashboard-tab:hover{color:var(--text);background:var(--panel2)}.dashboard-tab.active{border-color:rgba(56,189,248,.25);background:rgba(56,189,248,.1);color:var(--text);box-shadow:inset 0 -2px var(--cyan)}.dashboard-tab.active span{background:var(--cyan);color:#04111a}
  .dashboard-panel[hidden]{display:none}.dashboard-panel{animation:panel-in .16s ease-out}@keyframes panel-in{from{opacity:.35;transform:translateY(4px)}to{opacity:1;transform:none}}
  .grid{grid-template-columns:repeat(12,minmax(0,1fr));gap:14px}
  .card{grid-column:span 4;padding:19px;border-radius:15px;box-shadow:none}
  .card.half{grid-column:span 6}.wide{grid-column:1/-1}
  .card h2{display:flex;align-items:center;gap:8px;margin-bottom:14px;color:var(--text);font-family:var(--font);font-size:.82rem;letter-spacing:0;text-transform:none}
  .card h2::before{content:"";width:7px;height:7px;border-radius:2px;background:var(--cyan);box-shadow:0 0 12px rgba(56,189,248,.35)}
  .section-heading{grid-column:1/-1;display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-top:18px;padding:4px 2px 0}
  .section-heading:first-child{margin-top:0}
  .section-heading h2{font-size:1.02rem;letter-spacing:-.015em}.section-heading p{margin-top:5px;color:var(--muted);font-size:.76rem;line-height:1.45}
  .section-heading .section-link{color:var(--cyan);font:700 .65rem var(--mono);letter-spacing:.05em;text-decoration:none;white-space:nowrap}.section-heading .section-link:hover{text-decoration:underline}
  .chart-card{min-height:240px}.chart{height:150px}.chart-card .note{margin:12px 0 0}
  .map-card{padding:19px}.leaflet-map{height:clamp(390px,42vw,540px)}
  .sensor-card td{padding-top:7px;padding-bottom:7px}
  .card table{min-width:0}.card.wide table{min-width:760px}
  .card:has(table){overflow:auto}
  footer{padding-top:8px}
  .appnav{width:248px;padding:22px 16px 16px;background:color-mix(in srgb,var(--panel) 96%,transparent)}
  .navtop{display:flex;align-items:center;justify-content:space-between}.appbrand{padding:2px 10px 22px;font-size:.98rem}
  .nav-toggle{display:none;border:1px solid var(--line2);border-radius:8px;background:var(--panel2);color:var(--text);padding:7px 10px;font:700 .68rem var(--mono);cursor:pointer}
  .navcontent{display:flex;min-height:0;flex:1;flex-direction:column}
  .appsection{padding:14px 10px 6px;font-size:9px}
  .appnav a{gap:11px;padding:9px 10px;border:1px solid transparent;font-size:12.5px}
  .appnav a.active{border-color:rgba(56,189,248,.12);background:rgba(56,189,248,.09);box-shadow:none}
  .navicon{display:grid;place-items:center;width:25px;height:25px;flex:0 0 25px;border:1px solid var(--line);border-radius:7px;background:var(--panel2);color:var(--faint);font:700 8px var(--mono);letter-spacing:.03em}
  .appnav a.active .navicon,.appnav a:hover .navicon{border-color:rgba(56,189,248,.3);color:var(--cyan)}
  .navmeta{margin:14px 5px 0;padding:12px 7px 0;border-top:1px solid var(--line);color:var(--faint);font:9px/1.5 var(--mono);letter-spacing:.06em;text-transform:uppercase}
  .apptheme{margin-top:auto}
  @media(max-width:1180px){.kpis{grid-template-columns:repeat(3,1fr)}.card{grid-column:span 6}.wide{grid-column:1/-1}}
  @media(max-width:800px){body{padding:84px 14px 30px}.appnav{inset:0 0 auto 0;width:auto;height:64px;padding:10px 13px;overflow:visible;display:block;border-right:0;border-bottom:1px solid var(--line)}.navtop{height:42px}.appbrand{padding:0 4px}.nav-toggle{display:block}.navcontent{display:none;position:absolute;inset:63px 0 auto 0;max-height:calc(100vh - 63px);overflow:auto;padding:10px 14px 18px;background:var(--panel);border-bottom:1px solid var(--line);box-shadow:0 24px 50px rgba(0,0,0,.4)}.appnav.open{height:100vh}.appnav.open .navcontent{display:flex}.appsection{display:block}.appnav a{white-space:normal}.apptheme{margin-top:14px}.navmeta{margin-top:10px}.overview-header{grid-template-columns:1fr;align-items:start}.live-panel{align-items:flex-start}.kpis{grid-template-columns:repeat(2,1fr)}.kpi{min-height:112px}.dashboard-tabs{top:72px;grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.card,.card.half,.wide,.section-heading{grid-column:1}.section-heading{align-items:flex-start;flex-direction:column}.leaflet-map{height:430px}}
  @media(max-width:480px){.kpis{grid-template-columns:1fr}.kpi{min-height:0}.overview-header h1{font-size:1.65rem}.leaflet-map{height:380px}}

  /* Compact admin-console treatment: preserve detail, reduce visual noise. */
  body{padding-top:22px;padding-right:24px;padding-left:254px}
  .appnav{width:226px;padding:18px 13px 14px;background:color-mix(in srgb,var(--panel) 98%,#111936 2%)}
  .appbrand{padding:2px 9px 16px}.appsection{padding:11px 9px 5px}.appnav a{padding:7px 9px}.navicon{width:23px;height:23px;flex-basis:23px}
  .overview-header{margin-bottom:14px}.overview-header .subtitle{margin-top:6px}.live-panel{gap:5px}
  .kpis{gap:9px;margin-bottom:18px}.kpi{min-height:88px;padding:15px 17px;border-radius:11px}.kpi .n{font-size:1.65rem}.kpi .l{margin-top:8px}.kpi .d{display:none}
  .dashboard-tabs{position:relative;top:auto;display:flex;justify-content:flex-start;gap:4px;width:max-content;max-width:100%;margin-bottom:14px;padding:4px;border-radius:10px;overflow-x:auto}
  .dashboard-tab{min-width:150px;min-height:36px;padding:0 12px;font-size:.68rem}.dashboard-tab span{width:19px;height:19px}
  .grid{gap:10px}.card{padding:14px;border-radius:11px}.card h2{margin-bottom:10px}.section-heading{margin-top:10px;padding-top:2px}.section-heading p{margin-top:3px}
  .card:not(.wide) td.v>a{display:block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  td,th{padding-top:6px;padding-bottom:6px}.chart-card{min-height:210px}.chart{height:128px}.leaflet-map{height:clamp(340px,36vw,480px)}
  @media(max-width:800px){body{padding:78px 12px 24px}.appnav{width:auto;padding:9px 12px}.kpi{min-height:84px}.dashboard-tabs{position:sticky;top:68px;width:100%;display:grid;grid-template-columns:repeat(2,1fr)}.dashboard-tab{min-width:0}.leaflet-map{height:390px}}
</style>
<link rel="stylesheet" href="/static/adminlte-4.1.0.min.css">
<link rel="stylesheet" href="/static/bootstrap-icons-1.13.1.min.css">
<link rel="stylesheet" href="/static/hp-tailwind.css?v=20260726-1">
<link rel="stylesheet" href="/static/hp-adminlte.css?v=20260726-3">
<script defer src="/static/hp-api.js?v=20260722-1"></script>
<script defer src="/static/hp-adminlte.js?v=20260726-2"></script>
<script defer src="/static/adminlte-4.1.0.min.js"></script>
<script>
(function(){
 const saved=localStorage.getItem('hp-theme')||'system';
 const apply=t=>{const dark=matchMedia('(prefers-color-scheme: dark)').matches;document.documentElement.dataset.theme=t==='system'?(dark?'dark':'light'):t;document.querySelectorAll('.apptheme button').forEach(b=>b.classList.toggle('active',b.dataset.theme===t));localStorage.setItem('hp-theme',t)};
 apply(saved);addEventListener('DOMContentLoaded',()=>{const nav=document.createElement('aside');nav.className='appnav';nav.setAttribute('aria-label','Primary navigation');nav.innerHTML='<div class="navtop"><div class="appbrand">XORE<span>//</span>HP</div><button class="nav-toggle" type="button" aria-expanded="false" aria-label="Open navigation">Menu</button></div><div class="navcontent"><div class="appsection">Monitor</div><a href="/"><span class="navicon">OV</span>Overview</a><a href="/events"><span class="navicon">EV</span>Event explorer</a><a href="/source-health"><span class="navicon">HL</span>Sensor &amp; pipeline health</a><a href="/alerts"><span class="navicon">AL</span>Alerts</a><div class="appsection">Investigate</div><a href="/ips"><span class="navicon">IP</span>Attack sources</a><a href="/campaigns"><span class="navicon">CP</span>Campaigns</a><a href="/commands"><span class="navicon">CM</span>Executed commands</a><a href="/payloads"><span class="navicon">PL</span>Captured payloads</a><div class="appsection">Archive</div><a href="/history"><span class="navicon">ES</span>Elasticsearch history</a><div class="navmeta">Defensive telemetry<br>Private operations console</div><div class="apptheme" aria-label="Color theme"><button data-theme="light">Light</button><button data-theme="dark">Dark</button><button data-theme="system">Auto</button></div></div>';document.body.prepend(nav);nav.querySelectorAll('a').forEach(a=>{const active=a.pathname===location.pathname;a.classList.toggle('active',active);if(active)a.setAttribute('aria-current','page')});const toggle=nav.querySelector('.nav-toggle');toggle.onclick=()=>{const open=nav.classList.toggle('open');toggle.setAttribute('aria-expanded',String(open));toggle.textContent=open?'Close':'Menu'};addEventListener('keydown',e=>{if(e.key==='Escape'&&nav.classList.contains('open'))toggle.click()});nav.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>{if(nav.classList.contains('open'))toggle.click()}));nav.querySelectorAll('[data-theme]').forEach(b=>b.onclick=()=>apply(b.dataset.theme));apply(localStorage.getItem('hp-theme')||'system');
 const attackRadius=count=>Math.min(350000,35000+Math.sqrt(Math.max(1,count))*8000);
 const attackDetails=p=>{const box=document.createElement('div'),title=document.createElement('strong');title.textContent=p.ip+' — '+p.count+' events';box.append(title);const rows=[p.city&&p.country?[p.city,p.country].join(', '):p.city||p.country,p.asn?'AS'+p.asn+(p.organization?' '+p.organization:''):p.organization,p.intel||p.provider_type].filter(Boolean);rows.forEach(v=>{box.append(document.createElement('br'),document.createTextNode(v))});box.append(document.createElement('br'));const hint=document.createElement('span');hint.textContent='Select marker to show all related events';hint.style.color='var(--cyan)';box.append(hint);return box};
 const showMapFallback=(shell,message)=>{const map=shell.querySelector('.leaflet-map'),fallback=shell.querySelector('.map-fallback'),note=shell.querySelector('[data-map-status]');if(map)map.hidden=true;if(fallback)fallback.hidden=false;if(note)note.textContent=message};
 const initMaps=()=>document.querySelectorAll('.leaflet-map:not([data-map-ready])').forEach(container=>{
  const shell=container.closest('.map-shell'),status=shell.querySelector('[data-map-status]');container.dataset.mapReady='1';
  if(!window.L){showMapFallback(shell,'Interactive map library unavailable — showing offline map');return}
  const savedView=window.honeypotLeafletView||{center:[20,0],zoom:2};
  const map=L.map(container,{minZoom:1,maxZoom:12,maxBounds:[[-85,-180],[85,180]],maxBoundsViscosity:.75,worldCopyJump:false}).setView(savedView.center,savedView.zoom);
  const tileURL=decodeURIComponent(container.dataset.tileUrl),attributionText=container.dataset.attribution||'OpenStreetMap contributors';
  const safeAttribution=document.createElement('span');safeAttribution.textContent=attributionText;
  let tileErrors=0;const tiles=L.tileLayer(tileURL,{maxZoom:19,noWrap:true,attribution:'<a href="https://www.openstreetmap.org/copyright">'+safeAttribution.innerHTML+'</a>'})
   .on('tileerror',()=>{if(++tileErrors>=8)showMapFallback(shell,'Map tiles unavailable — showing offline fallback')})
   .on('load',()=>{tileErrors=0;container.hidden=false;const fallback=shell.querySelector('.map-fallback');if(fallback)fallback.hidden=true})
   .addTo(map);
  const origins=L.layerGroup().addTo(map);
  const saveView=()=>{const c=map.getCenter();window.honeypotLeafletView={center:[c.lat,c.lng],zoom:map.getZoom()}};map.on('moveend zoomend',saveView);
  const Home=L.Control.extend({options:{position:'topright'},onAdd:()=>{const b=L.DomUtil.create('button','leaflet-control-home');b.type='button';b.title='Reset world view';b.setAttribute('aria-label','Reset world view');b.textContent='World';L.DomEvent.disableClickPropagation(b);L.DomEvent.on(b,'click',()=>map.setView([20,0],2));return b}});map.addControl(new Home());
  const update=async()=>{try{const r=await fetch('/api/map-points',{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status);const data=await r.json();origins.clearLayers();L.geoJSON(data,{pointToLayer:(feature,latlng)=>L.circle(latlng,{radius:attackRadius(feature.properties.count),color:'#fecaca',weight:1.2,opacity:.92,fillColor:'#f87171',fillOpacity:.58}),onEachFeature:(feature,layer)=>{const p=feature.properties;layer.bindTooltip(attackDetails(p),{className:'attack-tooltip',sticky:true,direction:'top'});layer.on('click',()=>location.assign(p.events_url));layer.on('add',()=>{const el=layer.getElement();if(!el)return;el.setAttribute('tabindex','0');el.setAttribute('role','link');el.setAttribute('aria-label',p.ip+', '+p.count+' events');el.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();location.assign(p.events_url)}})})}}).addTo(origins);status.textContent=data.features.length+' geolocated sources • zoom '+map.getZoom()}catch(e){status.textContent='Attack origin update failed: '+e.message}};
  map.on('zoomend',()=>{status.textContent=status.textContent.replace(/zoom \d+$/,'zoom '+map.getZoom())});
  window.honeypotLeaflet={map,origins,tiles,container,shell,update};window.updateHoneypotMap=update;update();setTimeout(()=>map.invalidateSize(false),0);
 });window.initHoneypotMaps=initMaps;initMaps();
 const activateDashboardTab=name=>{const valid=['live','threats','behavior','evidence'];if(!valid.includes(name))name='live';window.honeypotDashboardTab=name;document.querySelectorAll('[data-dashboard-panel]').forEach(p=>p.hidden=p.dataset.dashboardPanel!==name);document.querySelectorAll('[data-dashboard-tab]').forEach(b=>{const active=b.dataset.dashboardTab===name;b.classList.toggle('active',active);b.setAttribute('aria-selected',String(active));b.tabIndex=active?0:-1});if(name==='live'&&window.honeypotLeaflet?.map)setTimeout(()=>window.honeypotLeaflet.map.invalidateSize(false),0)};
 window.initDashboardTabs=()=>activateDashboardTab(window.honeypotDashboardTab||location.hash.replace('#','')||'live');window.initDashboardTabs();
 document.addEventListener('click',e=>{const b=e.target.closest('[data-dashboard-tab]');if(!b)return;activateDashboardTab(b.dataset.dashboardTab);history.replaceState(null,'','#'+b.dataset.dashboardTab)});document.addEventListener('keydown',e=>{const b=e.target.closest?.('[data-dashboard-tab]');if(!b||!['ArrowLeft','ArrowRight','Home','End'].includes(e.key))return;const tabs=[...document.querySelectorAll('[data-dashboard-tab]')];let i=tabs.indexOf(b);if(e.key==='Home')i=0;else if(e.key==='End')i=tabs.length-1;else i=(i+(e.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;e.preventDefault();tabs[i].focus();tabs[i].click()});addEventListener('hashchange',()=>activateDashboardTab(location.hash.replace('#','')));
 });
})();
</script>
{{end}}

{{define "tbl"}}
<div class="card {{.class}}">
  <h2>{{.t}}</h2>
  {{if .rows}}
  <table><tbody>
    {{range .rows}}<tr><td class="n">{{if .Link}}<a href="{{.Link}}" title="show all {{.Count}} related events">{{.Count}}</a>{{else}}{{.Count}}{{end}}</td><td class="v">{{if .Link}}<a href="{{.Link}}" title="{{if .Title}}{{.Title}}{{else}}show all related events{{end}}">{{.Key}}</a>{{else}}{{.Key}}{{end}}</td></tr>{{end}}
  </tbody></table>
  {{else}}<p class="empty">{{if .hint}}{{.hint}}{{else}}(none){{end}}</p>{{end}}
</div>
{{end}}

{{define "techniques"}}
{{if .}}<div class="card wide"><h2>MITRE ATT&amp;CK behavior mapping</h2><p class="note">Evidence-based behavioral context only; this does not identify or attribute an actor.</p><table><thead><tr><th>domain</th><th>technique</th><th>observations</th><th>evidence</th></tr></thead><tbody>{{range .}}<tr><td><span class="badge text-bg-secondary">{{.Domain}}</span></td><td class="v"><a href="{{.URL}}" target="_blank" rel="noopener noreferrer">{{.ID}} &mdash; {{.Name}}</a></td><td class="n">{{.Count}}</td><td class="v">{{.Evidence}}</td></tr>{{end}}</tbody></table></div>{{end}}
{{end}}

{{define "everow"}}
<tr>
  <td>{{.Time}}</td>
  <td><a class="badge b-{{.Sensor}}" href="/events?sensor={{.Sensor | urlquery}}">{{.Sensor}}</a></td>
  <td class="v">{{if .SrcIP}}<a href="/events?ip={{.SrcIP | urlquery}}" title="attack chain for {{.SrcIP}}">{{.SrcIP}}</a>{{end}}{{if .Country}} <a class="cc" href="/events?country={{.Country | urlquery}}">{{.Country}}</a>{{end}}</td>
  <td class="v">{{if .Port}}<a href="/events?port={{.Port | urlquery}}">:{{.Port}}</a>{{end}}</td>
  <td class="v">{{.Detail}}<div class="eventmeta">{{if .Persona}}<a class="lnk" href="/events?persona={{.Persona | urlquery}}" title="show events for this honeypot persona">persona {{.Persona}}</a>{{end}}{{if .Site}}<a class="lnk" href="/events?site={{.Site | urlquery}}" title="show events for this fictional site">site {{.Site}}</a>{{end}}{{if .Asset}}<a class="lnk" href="/events?asset={{.Asset | urlquery}}" title="show events for this emulated asset">asset {{.Asset}}</a>{{end}}{{if .Session}}<a class="lnk sess" href="/sessions/{{.Session | urlquery}}" title="replay the complete session">session {{.Session}}</a>{{end}}{{if .Fingerprint}}<a class="lnk" href="/events?fingerprint={{.Fingerprint | urlquery}}" title="show every event with this exact fingerprint">{{if .FingerKind}}{{.FingerKind}}{{else}}fingerprint{{end}}: {{.Fingerprint}}</a>{{end}}{{if .Command}}<a class="lnk" href="/events?cmd={{.Command | urlquery}}" title="show every occurrence of this exact command">command</a>{{end}}{{if .HasCredential}}<a class="lnk" href="/events?cred={{printf "%s / %s" .User .Pass | urlquery}}" title="show every use of these credentials">credentials</a>{{end}}{{if .Path}}<a class="lnk" href="/events?path={{.Path | urlquery}}" title="show every request for this exact path">path {{.Path}}</a>{{end}}{{if .Alert}}<a class="lnk" href="/events?sig={{.Alert | urlquery}}" title="show alerts with this signature">signature</a>{{end}}{{if .Category}}<a class="lnk" href="/events?cat={{.Category | urlquery}}" title="show events in this category">category {{.Category}}</a>{{end}}{{if .ASN}}<a class="lnk" href="/events?asn={{.ASN}}" title="show events from this autonomous system">AS{{.ASN}}</a>{{end}}{{if .Org}}<a class="lnk" href="/events?org={{.Org | urlquery}}" title="show events from this network organization">{{.Org}}</a>{{end}}{{if .Intel}}<a class="lnk" href="/events?provider={{.Intel | urlquery}}" title="show events with this provider classification">{{.Intel}}</a>{{else if .Provider}}<a class="lnk" href="/events?provider={{.Provider | urlquery}}" title="show events from this provider class">{{.Provider}}</a>{{end}}{{if .Shasum}}<a class="lnk" href="/payload-analysis/{{.Shasum}}">static analysis</a><a class="lnk" href="https://www.virustotal.com/gui/file/{{.Shasum}}" target="_blank" rel="noopener noreferrer">VirusTotal</a>{{end}}{{if or .Kibana .EveBox .Arkime}}<details class="hp-open-in"><summary title="Open this event in an external investigation tool"><i class="bi bi-box-arrow-up-right" aria-hidden="true"></i> Open in&hellip;</summary><div class="hp-open-in-menu" role="menu"><div class="hp-open-in-heading">Open in</div>{{if .EveBox}}<a class="hp-open-in-item" href="{{.EveBox}}" target="_blank" rel="noopener noreferrer" role="menuitem"><i class="bi bi-shield-check" aria-hidden="true"></i><span><strong>EveBox</strong><small>Filtered alert inbox</small></span><i class="bi bi-arrow-up-right"></i></a>{{end}}{{if .Kibana}}<a class="hp-open-in-item" href="{{.Kibana}}" target="_blank" rel="noopener noreferrer" role="menuitem"><i class="bi bi-bar-chart" aria-hidden="true"></i><span><strong>Kibana</strong><small>Search historical telemetry</small></span><i class="bi bi-arrow-up-right"></i></a>{{end}}{{if .Arkime}}<a class="hp-open-in-item" href="{{.Arkime}}" target="_blank" rel="noopener noreferrer" role="menuitem"><i class="bi bi-diagram-2" aria-hidden="true"></i><span><strong>Arkime</strong><small>Inspect packets and sessions</small></span><i class="bi bi-arrow-up-right"></i></a>{{end}}</div></details>{{end}}</div></td>
</tr>
{{end}}

{{define "campaignrows"}}
{{range .}}
<tr>
  <td class="n"><a href="{{.Link}}" title="investigate this campaign">{{.Score}}</a></td>
  <td class="v"><a href="{{.Link}}">{{.CIDR}}</a></td>
  <td class="n"><a href="{{.Link}}" title="show campaign events">{{.Events}}</a></td><td class="n"><a href="{{.Link}}" title="show campaign source addresses">{{.UniqueIPs}}</a></td>
  <td class="v"><a href="{{.Link}}" title="show campaign sensor activity">{{.Sensors}}</a></td><td class="v"><a href="{{.Link}}" title="show campaign targeted ports">{{.Ports}}</a></td>
  <td class="n"><a href="{{.Link}}" title="show campaign credentials">{{.Creds}}</a></td><td class="n"><a href="{{.Link}}" title="show campaign payloads">{{.Payloads}}</a></td><td class="n"><a href="{{.Link}}" title="show campaign alerts">{{.Alerts}}</a></td>
  <td class="v"><a href="{{.Link}}" title="show campaign events and ASN details">{{.ASNs}}</a></td><td class="v"><a href="{{.Link}}" title="show campaign events and provider details">{{.Providers}}</a></td><td class="n"><a href="{{.Link}}" title="show campaign events and fingerprints">{{.Fingerprints}}</a></td><td class="v">{{.Sequence}}</td>
  <td class="v" title="why these events were grouped">{{.Explanation}}</td><td>{{.First}}</td><td>{{.Last}}</td>
</tr>
{{end}}
{{end}}

{{define "page"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot</title>
<link rel="stylesheet" href="/static/leaflet.css">
<script src="/static/leaflet.js"></script>
{{template "style"}}
</head>
<body>
<div class="wrap">
  <header class="overview-header">
    <div>
      <div class="eyebrow">Security operations</div>
      <h1>Honeypot command center</h1>
      <p class="subtitle">Live attack telemetry, captured evidence, correlated campaigns, and collection health in one operational view.</p>
    </div>
    <div class="live-panel">
      <span class="live-pill"><span class="live-dot"></span>Live telemetry</span>
      <a class="btn btn-sm btn-primary" href="/export/report.pdf" title="Download a management-ready PDF summarizing the current observation window"><i class="bi bi-file-earmark-pdf me-1"></i>Executive PDF</a>
      <span class="gen">updated {{.Generated.Format "2006-01-02 15:04:05 MST"}} &bull; refreshes automatically</span>
    </div>
  </header>

  <div class="row g-3 mb-4">
    <div class="col-12 col-sm-6 col-xl"><div class="small-box text-bg-primary h-100"><div class="inner"><h3>{{.Total}}</h3><p>All events</p></div><i class="small-box-icon bi bi-activity" aria-hidden="true"></i><a class="small-box-footer link-light link-underline-opacity-0 link-underline-opacity-50-hover" href="/events" title="Open all normalized events in the current dashboard window">Explore <i class="bi bi-arrow-right-circle"></i></a></div></div>
    <div class="col-12 col-sm-6 col-xl"><div class="small-box text-bg-success h-100"><div class="inner"><h3>{{.Last24h}}</h3><p>Events in 24 hours</p><small title="Compared with the directly preceding 24-hour period">{{.Change24h}} &bull; {{.ActivityState}}</small></div><i class="small-box-icon bi bi-clock-history" aria-hidden="true"></i><a class="small-box-footer link-light link-underline-opacity-0 link-underline-opacity-50-hover" href="/events?since=24h" title="Open events received during the last 24 hours">Explore <i class="bi bi-arrow-right-circle"></i></a></div></div>
    <div class="col-12 col-sm-6 col-xl"><div class="small-box text-bg-info h-100"><div class="inner"><h3>{{.UniqueIPs}}</h3><p>Attack sources</p></div><i class="small-box-icon bi bi-globe2" aria-hidden="true"></i><a class="small-box-footer link-dark link-underline-opacity-0 link-underline-opacity-50-hover" href="/ips" title="Distinct attacker source addresses observed by the sensors">Explore <i class="bi bi-arrow-right-circle"></i></a></div></div>
    <div class="col-12 col-sm-6 col-xl"><div class="small-box text-bg-warning h-100"><div class="inner"><h3>{{.Logins}}</h3><p>Login attempts</p></div><i class="small-box-icon bi bi-person-lock" aria-hidden="true"></i><a class="small-box-footer link-dark link-underline-opacity-0 link-underline-opacity-50-hover" href="/events?type=login" title="Authentication attempts captured by interactive honeypots">Explore <i class="bi bi-arrow-right-circle"></i></a></div></div>
    <div class="col-12 col-sm-6 col-xl"><div class="small-box text-bg-danger h-100"><div class="inner"><h3>{{.Downloads}}</h3><p>Captured payloads</p></div><i class="small-box-icon bi bi-file-earmark-binary" aria-hidden="true"></i><a class="small-box-footer link-light link-underline-opacity-0 link-underline-opacity-50-hover" href="/events?type=download" title="Downloads, uploads, and high-confidence script artifacts captured safely">Explore <i class="bi bi-arrow-right-circle"></i></a></div></div>
  </div>

  <div class="dashboard-tabs" role="tablist" aria-label="Dashboard views">
    <button class="dashboard-tab active" type="button" role="tab" aria-selected="true" aria-controls="panel-live" data-dashboard-tab="live"><span>01</span>Live operations</button>
    <button class="dashboard-tab" type="button" role="tab" aria-selected="false" aria-controls="panel-threats" data-dashboard-tab="threats"><span>02</span>Threat landscape</button>
    <button class="dashboard-tab" type="button" role="tab" aria-selected="false" aria-controls="panel-behavior" data-dashboard-tab="behavior"><span>03</span>Attacker behavior</button>
    <button class="dashboard-tab" type="button" role="tab" aria-selected="false" aria-controls="panel-evidence" data-dashboard-tab="evidence"><span>04</span>Evidence &amp; campaigns</button>
  </div>

  <div class="dashboard-panel grid" id="panel-live" role="tabpanel" data-dashboard-panel="live">
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

  <div class="dashboard-panel grid" id="panel-threats" role="tabpanel" data-dashboard-panel="threats" hidden>
    <div class="section-heading"><div><h2>Threat landscape</h2><p>Highest-volume sources, targets, locations, and network ownership. Select any count or value to open its matching events.</p></div><a class="section-link" href="/ips">Investigate all sources &rarr;</a></div>
    {{template "tbl" dict "t" "Top source IPs" "rows" .TopIPs}}
    {{template "tbl" dict "t" "Top targeted ports" "rows" .TopPorts}}
    {{if .GeoOn}}{{template "tbl" dict "t" "Top countries" "rows" .Countries}}{{else if .Countries}}{{template "tbl" dict "t" "Top countries (cf-ipcountry)" "rows" .Countries}}{{end}}
    {{template "tbl" dict "t" "Top autonomous systems" "rows" .ASNs "class" "half"}}
    {{template "tbl" dict "t" "Network/provider classes" "rows" .Providers "class" "half"}}
  </div>

  <div class="dashboard-panel grid" id="panel-behavior" role="tabpanel" data-dashboard-panel="behavior" hidden>
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

  <div class="dashboard-panel grid" id="panel-evidence" role="tabpanel" data-dashboard-panel="evidence" hidden>
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

  <footer>xore//honeypot &bull; defensive sensor &bull; do not expose without auth</footer>
</div>
<script>
let refreshing=false;
async function refreshDashboard(){
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
</script>
</body>
</html>
{{end}}

{{define "eventrows"}}{{range .Events}}{{template "everow" .}}{{end}}{{end}}

{{define "events"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot — {{if .Chain}}attack chain {{.IP}}{{else}}events{{end}}</title>
{{template "style"}}
</head>
<body>
<div class="wrap">
  <header>
    <h1><a href="/">XORE<span>//</span>HONEYPOT</a></h1>
    <span class="gen">{{if .Chain}}attack chain &bull; {{.IP}}{{else}}event explorer{{end}} &bull; generated {{.Generated.Format "2006-01-02 15:04:05 MST"}}</span>
  </header>

  <div class="filters">
    <a class="chip" href="/">&larr; dashboard</a>
    <a class="btn btn-sm btn-primary" href="{{.ReportURL}}" title="Export this exact filtered event scope as a PDF report"><i class="bi bi-file-earmark-pdf me-1"></i>Export filtered PDF</a>
    {{range .Filters}}<span class="chip">{{.}}</span>{{end}}
    <span class="chip">{{.Total}} events</span>
  </div>

  {{if .Chain}}<p class="note">chronological &mdash; the attack reads top to bottom, from first contact to last event</p>{{end}}
  <p class="note">showing events {{.From}}–{{.To}} of {{.Total}} &bull; additional events load in groups of 25 while scrolling</p>

  <div class="card wide">
    {{if .Events}}
    <table class="recent">
      <thead><tr><th>time</th><th>sensor</th><th>source ip</th><th>port</th><th>detail</th></tr></thead>
      <tbody data-hp-page-url="{{.RowsURL}}" data-hp-total="{{.Total}}" data-hp-offset="{{.Offset}}">
      {{template "eventrows" .}}
      </tbody>
    </table>
    {{else}}<p class="empty">no events match this filter</p>{{end}}
  </div>

  {{if gt .Pages 1}}<nav class="mt-3" aria-label="Event pages"><ul class="pagination justify-content-center">
    <li class="page-item{{if not .PrevURL}} disabled{{end}}"><a class="page-link" href="{{if .PrevURL}}{{.PrevURL}}{{else}}#{{end}}">Previous</a></li>
    <li class="page-item disabled"><span class="page-link">Page {{.Page}} / {{.Pages}}</span></li>
    <li class="page-item{{if not .NextURL}} disabled{{end}}"><a class="page-link" href="{{if .NextURL}}{{.NextURL}}{{else}}#{{end}}">Next</a></li>
  </ul></nav>{{end}}

  <footer>xore//honeypot &bull; defensive sensor &bull; do not expose without auth</footer>
</div>
</body>
</html>
{{end}}

{{define "attacker"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>xore//honeypot — attacker {{.IP}}</title>{{template "style"}}</head>
<body><div class="wrap">
<header><div><div class="eyebrow">Attacker profile</div><h1>{{.IP}}</h1><p class="subtitle">{{.Country}} {{if .ASN}}&bull; AS{{.ASN}}{{end}} {{.Org}} {{if .Provider}}&bull; {{.Provider}}{{end}}</p></div><span class="gen">{{.First}} — {{.Last}}</span></header>
<div class="filters"><a class="chip" href="/ips">&larr; attack sources</a><a class="chip" href="/events?ip={{.IP | urlquery}}">all matching events</a><a class="btn btn-sm btn-primary" href="/export/report.pdf?ip={{.IP | urlquery}}"><i class="bi bi-file-earmark-pdf me-1"></i>IP report</a><a class="btn btn-sm btn-outline-danger" href="/export/report.pdf?ip={{.IP | urlquery}}&amp;type=alert"><i class="bi bi-file-earmark-pdf me-1"></i>IP alerts PDF</a></div>
<div class="row g-3 mb-4">
<div class="col-md-4"><div class="info-box"><span class="info-box-icon text-bg-primary"><i class="bi bi-activity"></i></span><div class="info-box-content"><span class="info-box-text">Events</span><span class="info-box-number">{{.Total}}</span></div></div></div>
<div class="col-md-4"><div class="info-box"><span class="info-box-icon text-bg-success"><i class="bi bi-terminal"></i></span><div class="info-box-content"><span class="info-box-text">Sessions</span><span class="info-box-number">{{.Sessions}}</span></div></div></div>
<div class="col-md-4"><div class="info-box"><span class="info-box-icon text-bg-danger"><i class="bi bi-file-earmark-binary"></i></span><div class="info-box-content"><span class="info-box-text">Payload observations</span><span class="info-box-number">{{.PayloadCount}}</span></div></div></div>
</div>
<div class="grid">
{{template "tbl" (dict "t" "Sensors contacted" "rows" .Sensors "class" "half" "hint" "none")}}
{{template "tbl" (dict "t" "Credentials attempted" "rows" .Creds "class" "half" "hint" "none")}}
{{template "tbl" (dict "t" "Commands" "rows" .Commands "class" "half" "hint" "none")}}
{{template "tbl" (dict "t" "HTTP paths" "rows" .Paths "class" "half" "hint" "none")}}
{{template "tbl" (dict "t" "Payload hashes" "rows" .Payloads "class" "half" "hint" "none")}}
{{template "tbl" (dict "t" "Alerts" "rows" .Alerts "class" "half" "hint" "none")}}
{{template "techniques" .Techniques}}
<div class="card wide"><h2>Attack progression</h2><p class="note">Chronological, oldest to newest; capped to the latest 250 matching records.</p><table class="recent"><thead><tr><th>time</th><th>sensor</th><th>source</th><th>port</th><th>detail</th></tr></thead><tbody>{{range .Events}}{{template "everow" .}}{{end}}</tbody></table></div>
</div><footer>xore//honeypot &bull; attacker investigation</footer></div></body></html>{{end}}

{{define "session"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>xore//honeypot &mdash; session {{.ID}}</title>{{template "style"}}</head><body><div class="wrap">
<header><div><div class="eyebrow">Session replay</div><h1>{{.ID}}</h1><p class="subtitle">{{.IP}} {{if .Country}}&bull; {{.Country}}{{end}} &bull; {{.First}} &mdash; {{.Last}}</p></div><span class="gen">{{.Total}} normalized events</span></header>
<div class="filters"><a class="chip" href="/events">&larr; event explorer</a>{{if .IP}}<a class="chip" href="/investigate/ip/{{.IP | urlquery}}">attacker profile</a>{{end}}<a class="chip" href="/events?session={{.ID | urlquery}}">filtered events</a><a class="btn btn-sm btn-primary" href="/export/report.pdf?session={{.ID | urlquery}}"><i class="bi bi-file-earmark-pdf me-1"></i>Session PDF</a></div>
<div class="grid">{{template "tbl" (dict "t" "Sensors" "rows" .Sensors "class" "half" "hint" "none")}}{{template "tbl" (dict "t" "Credentials" "rows" .Credentials "class" "half" "hint" "none")}}{{template "tbl" (dict "t" "Commands" "rows" .Commands "class" "half" "hint" "none")}}{{template "tbl" (dict "t" "Payload hashes" "rows" .Payloads "class" "half" "hint" "none")}}{{template "techniques" .Techniques}}
<div class="card wide"><h2>Chronological replay</h2><p class="note">Oldest to newest. Commands, credentials, downloads, fingerprints, and investigation pivots remain linked.</p><table class="recent"><thead><tr><th>time</th><th>sensor</th><th>source</th><th>port</th><th>detail</th></tr></thead><tbody>{{range .Events}}{{template "everow" .}}{{end}}</tbody></table></div></div>
<footer>xore//honeypot &bull; session investigation</footer></div></body></html>{{end}}

{{define "clusters"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>xore//honeypot &mdash; infrastructure clusters</title>{{template "style"}}</head><body><div class="wrap">
<header><div><div class="eyebrow">Correlation</div><h1>Infrastructure clusters</h1><p class="subtitle">Shared fingerprints, payloads, autonomous systems, and provider classifications across multiple source IPs.</p></div><span class="gen">generated {{.Generated.Format "2006-01-02 15:04:05 MST"}}</span></header>
<div class="filters"><a class="chip" href="/">&larr; dashboard</a><a class="chip" href="/campaigns">network campaigns</a><span class="chip">{{len .Rows}} shared pivots</span></div>
<div class="card wide">{{if .Rows}}<table><thead><tr><th>cluster type</th><th>shared value</th><th>source IPs</th><th>events</th><th>coverage</th><th></th></tr></thead><tbody>{{range .Rows}}<tr><td><span class="badge text-bg-secondary">{{.Kind}}</span></td><td class="v"><a href="{{.Link}}">{{.Value}}</a></td><td class="n"><a href="{{.Link}}">{{.Sources}}</a></td><td class="n"><a href="{{.Link}}">{{.Events}}</a></td><td class="v">{{.Summary}}</td><td><a class="lnk" href="{{.Link}}">investigate &rarr;</a></td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No multi-source pivots are present in the current in-memory window.</p>{{end}}</div>
<footer>xore//honeypot &bull; correlation pivots</footer></div></body></html>{{end}}

{{define "campaigns"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//honeypot â€” campaigns</title>
{{template "style"}}
</head>
<body>
<div class="wrap">
  <header>
    <h1><a href="/">XORE<span>//</span>HONEYPOT</a></h1>
    <span class="gen">correlated campaigns &bull; rolling 7 days &bull; generated {{.Generated.Format "2006-01-02 15:04:05 MST"}}</span>
  </header>
  <div class="filters">
    <a class="chip" href="/">&larr; dashboard</a>
    <a class="btn btn-sm btn-primary" href="/export/report.pdf?since=168h"><i class="bi bi-file-earmark-pdf me-1"></i>7-day executive PDF</a>
    <span class="chip">{{len .Campaigns}} active networks</span>
  </div>
  <p class="note">Score combines volume, unique sources, sensor and port spread, reused credentials, captured payloads, and IDS alerts. Select a network for its complete event chain.</p>
  <div class="card wide">
    {{if .Campaigns}}
    <table class="recent">
      <thead><tr><th>score</th><th>network</th><th>events</th><th>ips</th><th>sensors</th><th>ports</th><th>creds</th><th>files</th><th>alerts</th><th>ASNs</th><th>provider</th><th>fingerprints</th><th>sequence</th><th>why correlated</th><th>first</th><th>last</th></tr></thead>
      <tbody>{{template "campaignrows" .Campaigns}}</tbody>
    </table>
    {{else}}<p class="empty">no active campaigns in the last seven days</p>{{end}}
  </div>
  <footer>xore//honeypot &bull; defensive sensor &bull; do not expose without auth</footer>
</div>
</body>
</html>
{{end}}

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
<div class="wrap">
  <header>
    <h1><a href="/">XORE<span>//</span>HONEYPOT</a></h1>
    <span class="gen">source IPs &bull; generated {{.Generated.Format "2006-01-02 15:04:05 MST"}}</span>
  </header>

  <div class="filters">
    <a class="chip" href="/">&larr; dashboard</a>
    <span class="chip">{{.Total}} unique IPs</span>
  </div>

  <div class="card wide">
    {{if .Rows}}
    <table class="recent">
      <thead><tr><th>events</th><th>source ip</th><th>cc</th><th>logins</th><th>sessions</th><th>sensors hit</th><th>first seen</th><th>last seen</th></tr></thead>
      <tbody data-hp-page-url="/api/ip-rows" data-hp-total="{{.Total}}" data-hp-offset="0">
      {{template "iprows" .}}
      </tbody>
    </table>
    {{else}}<p class="empty">no source IPs recorded yet</p>{{end}}
  </div>

  <footer>xore//honeypot &bull; defensive sensor &bull; do not expose without auth</footer>
</div>
</body>
</html>
{{end}}

{{define "sandbox"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>xore//honeypot &mdash; sandbox results</title>{{template "style"}}</head>
<body><div class="wrap">
<header><div><div class="eyebrow">Dynamic analysis</div><h1>Isolated Linux sandbox</h1><p class="subtitle">Bounded summaries exported from disposable, network-isolated KVM guests.</p></div><span class="gen">generated {{.Generated.Format "2006-01-02 15:04:05 MST"}}</span></header>
{{if .Detail}}
<div class="filters"><a class="chip" href="/sandbox">&larr; all sandbox results</a><a class="chip" href="/payload-analysis/{{.Detail.SHA256}}">static analysis</a><a class="chip" href="/events?shasum={{.Detail.SHA256}}">related events</a><a class="chip" href="/export/sandbox/{{.Detail.Job}}.json">sanitized JSON &darr;</a>{{if .Detail.HostPCAPURL}}<a class="chip" href="{{.Detail.HostPCAPURL}}" title="Raw host-bridge packet capture for Wireshark">host PCAP ({{.Detail.HostPCAPSize}} bytes) &darr;</a>{{end}}{{if .Detail.GuestPCAPURL}}<a class="chip" href="{{.Detail.GuestPCAPURL}}" title="Raw guest capture including loopback DNS for Wireshark">guest PCAP ({{.Detail.GuestPCAPSize}} bytes) &darr;</a>{{end}}</div>
<div class="row g-3 mb-4"><div class="col-md-3"><div class="info-box"><span class="info-box-icon text-bg-danger"><i class="bi bi-shield-exclamation"></i></span><div class="info-box-content"><span class="info-box-text">Dynamic risk</span><span class="info-box-number">{{.Detail.RiskScore}} / 100 &bull; {{.Detail.RiskLevel}}</span></div></div></div><div class="col-md-3"><div class="info-box"><span class="info-box-icon text-bg-primary"><i class="bi bi-stopwatch"></i></span><div class="info-box-content"><span class="info-box-text">Duration</span><span class="info-box-number">{{.Detail.Duration}} seconds</span></div></div></div><div class="col-md-3"><div class="info-box"><span class="info-box-icon text-bg-info"><i class="bi bi-activity"></i></span><div class="info-box-content"><span class="info-box-text">Captured packets</span><span class="info-box-number">{{.Detail.NetworkSummary.Packets}}</span></div></div></div><div class="col-md-3"><div class="info-box"><span class="info-box-icon text-bg-warning"><i class="bi bi-files"></i></span><div class="info-box-content"><span class="info-box-text">Changed paths</span><span class="info-box-number">{{len .Detail.ChangedFiles}}</span></div></div></div></div>
<div class="grid">
<div class="card wide"><h2>Run identity and analysis route</h2><table><tbody><tr><td>job</td><td class="v">{{.Detail.Job}}</td></tr><tr><td>identified payload</td><td class="v"><strong>{{.Detail.Classification.Label}}</strong> {{if .Detail.Classification.Code}}<span class="badge text-bg-secondary">{{.Detail.Classification.Code}}</span>{{end}}</td></tr><tr><td>platform / category</td><td class="v">{{.Detail.Classification.Platform}} / {{.Detail.Classification.Category}}</td></tr><tr><td>selected analysis path</td><td class="v">{{if .Detail.AnalysisPath}}{{.Detail.AnalysisPath}}{{else}}{{.Detail.Classification.AnalysisPath}}{{end}}</td></tr><tr><td>execution mode</td><td class="v">{{.Detail.ExecutionMode}}</td></tr><tr><td>file(1) result</td><td class="v">{{.Detail.FileType}}</td></tr><tr><td>capture source</td><td class="v">{{.Detail.Source}} / {{.Detail.CaptureName}}</td></tr><tr><td>MD5</td><td class="v">{{.Detail.Hashes.MD5}}</td></tr><tr><td>SHA-1</td><td class="v">{{.Detail.Hashes.SHA1}}</td></tr><tr><td>SHA-256</td><td class="v">{{.Detail.SHA256}}</td></tr><tr><td>requested</td><td class="v">{{.Detail.RequestedAt}}</td></tr><tr><td>started</td><td class="v">{{.Detail.StartedAt}}</td></tr><tr><td>completed</td><td class="v">{{.Detail.CompletedAt}}</td></tr><tr><td>exit status</td><td class="v">{{.Detail.ExitStatus}}</td></tr>{{if .Detail.TimeoutReason}}<tr><td>timeout</td><td class="v text-danger">{{.Detail.TimeoutReason}}</td></tr>{{end}}<tr><td>isolation</td><td class="v">fresh transient KVM guest, disposable overlay, no forwarding, strict libvirt NIC filter</td></tr></tbody></table></div>
<div class="card half"><h2>Static versus dynamic</h2><table><tbody><tr><td>static YARA matches</td><td class="n">{{len .StaticYARA}}</td></tr><tr><td>dynamic ATT&amp;CK behaviors</td><td class="n">{{len .Detail.Techniques}}</td></tr><tr><td>system calls recorded</td><td class="n">{{len .Detail.TopSyscalls}}</td></tr><tr><td>filesystem changes</td><td class="n">{{len .Detail.ChangedFiles}}</td></tr><tr><td>network packets</td><td class="n">{{.Detail.NetworkSummary.Packets}}</td></tr></tbody></table>{{if .StaticYARA}}<p class="note">YARA: {{range .StaticYARA}}<span class="chip">{{.}}</span> {{end}}</p>{{end}}<p class="note">Static indicators show what the file contains; dynamic evidence shows what this bounded run actually attempted.</p></div>
<div class="card half"><h2>ATT&amp;CK behavior mapping</h2>{{if .Detail.Techniques}}<table><thead><tr><th>technique</th><th>evidence</th></tr></thead><tbody>{{range .Detail.Techniques}}<tr><td><a href="https://attack.mitre.org/techniques/{{.ID}}/" target="_blank" rel="noopener noreferrer">{{.ID}} {{.Name}}</a></td><td class="v">{{.Evidence}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No mapped behavior in this run.</p>{{end}}<p class="note">Behavior context only; never actor attribution.</p></div>
<div class="card half"><h2>Network and DNS capture</h2><table><tbody><tr><td>host bridge packets</td><td class="n">{{.Detail.NetworkSummary.Packets}}</td></tr><tr><td>host PCAP bytes</td><td class="n">{{.Detail.NetworkSummary.Bytes}}</td></tr><tr><td>guest packets, including loopback DNS</td><td class="n">{{.Detail.NetworkSummary.GuestPackets}}</td></tr><tr><td>guest PCAP bytes</td><td class="n">{{.Detail.NetworkSummary.GuestPCAPBytes}}</td></tr><tr><td>unique DNS queries</td><td class="n">{{len .Detail.NetworkSummary.DNSQueries}}</td></tr>{{range $name,$count := .Detail.NetworkSummary.Protocols}}<tr><td>host {{$name}}</td><td class="n">{{$count}}</td></tr>{{end}}{{range $name,$count := .Detail.NetworkSummary.GuestProtocols}}<tr><td>guest {{$name}}</td><td class="n">{{$count}}</td></tr>{{end}}</tbody></table>{{if .Detail.HostPCAPURL}}<a class="btn btn-sm btn-primary mt-3" href="{{.Detail.HostPCAPURL}}"><i class="bi bi-download"></i> Raw host PCAP</a>{{end}} {{if .Detail.GuestPCAPURL}}<a class="btn btn-sm btn-primary mt-3" href="{{.Detail.GuestPCAPURL}}"><i class="bi bi-download"></i> Raw guest + DNS PCAP</a>{{end}}{{if .Detail.NetworkSummary.DNSQueries}}<details class="mt-3"><summary>Captured DNS names</summary><pre class="code mt-2">{{range .Detail.NetworkSummary.DNSQueries}}{{.}}
{{end}}</pre></details>{{end}}{{if .Detail.NetworkSummary.DNSEvents}}<details class="mt-3"><summary>DNS queries and responses ({{len .Detail.NetworkSummary.DNSEvents}})</summary><pre class="code mt-2">{{range .Detail.NetworkSummary.DNSEvents}}{{.}}
{{end}}</pre></details>{{end}}<p class="note">Raw captures are administrator-only and can be opened directly in Wireshark or tshark. In controlled mode, DNS answers are real and logged while downloads must pass the allowlisted proxy; direct guest routing remains blocked.</p></div>
{{if .Detail.Windows.Detected}}
<div class="card wide"><h2>Windows PE forensics</h2><table><tbody><tr><td>format / machine</td><td class="v">{{.Detail.Windows.PEType}} / {{.Detail.Windows.Machine}}</td></tr><tr><td>DLL</td><td class="v">{{.Detail.Windows.DLL}}</td></tr><tr><td>compile timestamp</td><td class="v">{{.Detail.Windows.CompileTimestamp}}</td></tr><tr><td>entry point</td><td class="v">{{.Detail.Windows.EntryPoint}}</td></tr><tr><td>image base</td><td class="v">{{.Detail.Windows.ImageBase}}</td></tr><tr><td>subsystem</td><td class="v">{{.Detail.Windows.Subsystem}}</td></tr><tr><td>import hash</td><td class="v">{{.Detail.Windows.ImpHash}}</td></tr><tr><td>embedded signature</td><td class="v">{{.Detail.Windows.SignaturePresent}}</td></tr></tbody></table><p class="note">Parsed with pefile inside the powered-off-after-use analysis guest. Wine execution is behavioral emulation, not a perfect replacement for native Windows.</p></div>
<div class="card half"><h2>Suspicious Windows API imports</h2>{{if .Detail.Windows.SuspiciousImports}}<table><thead><tr><th>behavior</th><th>imports</th></tr></thead><tbody>{{range $group,$names := .Detail.Windows.SuspiciousImports}}<tr><td>{{$group}}</td><td class="v">{{range $names}}<span class="chip">{{.}}</span> {{end}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No categorized high-signal imports found.</p>{{end}}</div>
<div class="card half"><h2>PE sections</h2>{{if .Detail.Windows.Sections}}<table><thead><tr><th>name</th><th>virtual</th><th>raw</th><th>entropy</th><th>flags</th></tr></thead><tbody>{{range .Detail.Windows.Sections}}<tr><td class="v">{{.Name}}</td><td class="n">{{.VirtualSize}}</td><td class="n">{{.RawSize}}</td><td class="n">{{.Entropy}}</td><td class="v">{{.Characteristics}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No PE sections parsed.</p>{{end}}</div>
<div class="card wide"><h2>Imported libraries and symbols</h2>{{if .Detail.Windows.Imports}}<table><thead><tr><th>library</th><th>symbols</th></tr></thead><tbody>{{range .Detail.Windows.Imports}}<tr><td class="v">{{.DLL}}</td><td class="v">{{range .Symbols}}<span class="chip">{{.}}</span> {{end}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No imports parsed.</p>{{end}}</div>
<div class="card half"><h2>PE exports and parser warnings</h2>{{if .Detail.Windows.Exports}}<details open><summary>Exports ({{len .Detail.Windows.Exports}})</summary><pre class="code mt-2">{{range .Detail.Windows.Exports}}{{.}}
{{end}}</pre></details>{{else}}<p class="empty">No exported symbols parsed.</p>{{end}}{{if .Detail.Windows.Warnings}}<details class="mt-3" open><summary>Warnings ({{len .Detail.Windows.Warnings}})</summary><pre class="code mt-2">{{range .Detail.Windows.Warnings}}{{.}}
{{end}}</pre></details>{{end}}</div>
<div class="card half"><h2>PE metadata tools</h2><details open><summary>ExifTool</summary><pre class="code mt-2">{{.Detail.Artifacts.ExifTool}}</pre></details><details class="mt-3"><summary>objdump -x</summary><pre class="code mt-2">{{.Detail.Artifacts.PEObjdump}}</pre></details></div>
<div class="card half"><h2>Authenticode inspection</h2><pre class="code">{{.Detail.Windows.Authenticode}}</pre></div>
<div class="card half"><h2>Extracted Windows strings</h2><details><summary>ASCII strings ({{len .Detail.Windows.ASCIIStrings}})</summary><pre class="code mt-2">{{range .Detail.Windows.ASCIIStrings}}{{.}}
{{end}}</pre></details><details class="mt-3"><summary>UTF-16LE strings ({{len .Detail.Windows.UTF16Strings}})</summary><pre class="code mt-2">{{range .Detail.Windows.UTF16Strings}}{{.}}
{{end}}</pre></details></div>
{{end}}
<div class="card half"><h2>Network events</h2>{{if .Detail.NetworkSummary.Events}}<pre class="code">{{range .Detail.NetworkSummary.Events}}{{.}}
{{end}}</pre>{{else}}<p class="empty">No packets were emitted during this run.</p>{{end}}{{if .Detail.NetworkSummary.Attempts}}<p class="note">IPv4/IPv6 connect attempts observed by strace</p><pre class="code">{{range .Detail.NetworkSummary.Attempts}}{{.}}
{{end}}</pre>{{end}}</div>
<div class="card half"><h2>Guest and loopback packet events</h2>{{if .Detail.NetworkSummary.GuestEvents}}<pre class="code">{{range .Detail.NetworkSummary.GuestEvents}}{{.}}
{{end}}</pre>{{else}}<p class="empty">No guest-side packets were decoded.</p>{{end}}</div>
<div class="card half"><h2>Top system calls</h2>{{if .Detail.TopSyscalls}}<table><thead><tr><th>call</th><th>count</th></tr></thead><tbody>{{range .Detail.TopSyscalls}}<tr><td class="v">{{.Name}}</td><td class="n">{{.Count}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No syscall trace was exported.</p>{{end}}</div>
<div class="card half"><h2>Created or changed paths</h2>{{if .Detail.ChangedFiles}}<pre class="code">{{range .Detail.ChangedFiles}}{{.}}
{{end}}</pre>{{else}}<p class="empty">No tracked path changes.</p>{{end}}</div>
<div class="card half"><h2>Standard output</h2><pre class="code">{{.Detail.Stdout}}</pre></div>
<div class="card half"><h2>Standard error</h2><pre class="code">{{.Detail.Stderr}}</pre></div>
<div class="card half"><h2>Sockets before</h2><pre class="code">{{range .Detail.SocketsBefore}}{{.}}
{{end}}</pre></div><div class="card half"><h2>Sockets after</h2><pre class="code">{{range .Detail.SocketsAfter}}{{.}}
{{end}}</pre></div>
<div class="card wide"><h2>Runtime and collection diagnostics</h2><details open><summary>Guest kernel</summary><pre class="code mt-2">{{.Detail.Artifacts.Kernel}}</pre></details><details class="mt-3"><summary>Processes before detonation ({{len .Detail.Artifacts.ProcessesBefore}})</summary><pre class="code mt-2">{{range .Detail.Artifacts.ProcessesBefore}}{{.}}
{{end}}</pre></details><details class="mt-3"><summary>Processes after detonation ({{len .Detail.Artifacts.ProcessesAfter}})</summary><pre class="code mt-2">{{range .Detail.Artifacts.ProcessesAfter}}{{.}}
{{end}}</pre></details><details class="mt-3"><summary>Host tcpdump log</summary><pre class="code mt-2">{{.Detail.Artifacts.HostTCPDumpLog}}</pre></details><details class="mt-3"><summary>Guest tcpdump log</summary><pre class="code mt-2">{{.Detail.Artifacts.GuestTCPDumpLog}}</pre></details>{{if .Detail.Artifacts.ClassificationError}}<details class="mt-3" open><summary>Classifier error</summary><pre class="code mt-2">{{.Detail.Artifacts.ClassificationError}}</pre></details>{{end}}{{if .Detail.Artifacts.PEForensicsError}}<details class="mt-3" open><summary>PE parser error</summary><pre class="code mt-2">{{.Detail.Artifacts.PEForensicsError}}</pre></details>{{end}}</div>
</div><p class="note mt-3">Guest-produced text is untrusted, HTML-escaped, and size-bounded. Raw PCAP downloads require the administrator role; complete raw result directories and syscall traces remain root-only on the homeserver.</p>
{{else}}
<div class="row g-3 mb-4"><div class="col-md"><div class="info-box"><span class="info-box-icon text-bg-primary"><i class="bi bi-cpu"></i></span><div class="info-box-content"><span class="info-box-text">Worker</span><span class="info-box-number">{{.Status.WorkerState}}</span></div></div></div><div class="col-md"><div class="info-box"><span class="info-box-icon {{if .Status.HandoffOld}}text-bg-danger{{else}}text-bg-secondary{{end}}"><i class="bi bi-box-arrow-in-right"></i></span><div class="info-box-content"><span class="info-box-text">Awaiting handoff</span><span class="info-box-number">{{.Status.Handoff}}</span></div></div></div><div class="col-md"><div class="info-box"><span class="info-box-icon text-bg-info"><i class="bi bi-hourglass-split"></i></span><div class="info-box-content"><span class="info-box-text">KVM queued</span><span class="info-box-number">{{.Status.Counts.Queued}}</span></div></div></div><div class="col-md"><div class="info-box"><span class="info-box-icon text-bg-warning"><i class="bi bi-play-circle"></i></span><div class="info-box-content"><span class="info-box-text">Running</span><span class="info-box-number">{{.Status.Counts.Running}}</span></div></div></div><div class="col-md"><div class="info-box"><span class="info-box-icon text-bg-danger"><i class="bi bi-x-octagon"></i></span><div class="info-box-content"><span class="info-box-text">Failed</span><span class="info-box-number">{{.Status.Counts.Failed}}</span></div></div></div></div>
<form class="filters" method="get" action="/sandbox"><a class="chip" href="/payloads">&larr; captured payloads</a><input class="search" name="q" value="{{.Query}}" placeholder="hash, source, file type, risk or job" aria-label="Search sandbox results"><button class="copy" type="submit">search</button>{{if .Query}}<a class="chip" href="/sandbox">clear</a>{{end}}<span class="chip">{{len .Rows}} retained runs</span><span class="chip">status {{.Status.UpdatedAt}}</span></form>
{{if .Status.Jobs}}<div class="card wide"><h2>Active and failed queue jobs</h2><table><thead><tr><th>state</th><th>requested</th><th>source</th><th>SHA-256</th></tr></thead><tbody>{{range .Status.Jobs}}<tr><td><span class="badge text-bg-secondary">{{.State}}</span></td><td>{{.RequestedAt}}</td><td>{{.Source}}</td><td class="v">{{.SHA256}}</td></tr>{{end}}</tbody></table></div>{{end}}
<div class="card wide"><p class="note">Authenticated administrators submit captures with the <strong>Analyze</strong> button. “Awaiting handoff” means the dashboard request has not reached the root-owned host watcher; “KVM queued” means it is staged for the isolated worker. CLI fallback: <code>sudo honeypot-sandbox-submit &lt;hash&gt;</code>.</p>{{if .Status.HandoffOld}}<div class="alert alert-danger"><strong>Sandbox handoff stalled.</strong> Requests have waited over five minutes. Check <code>honeypot-sandbox-web-requests.path</code> and its service.</div>{{end}}{{if .Rows}}<table><thead><tr><th>completed</th><th>source</th><th>SHA-256</th><th>risk</th><th>duration</th><th>packets</th><th>exit</th><th>details</th></tr></thead><tbody>{{range .Rows}}<tr><td>{{.CompletedAt}}</td><td><span class="badge text-bg-secondary">{{.Source}}</span></td><td class="v"><a href="/payload-analysis/{{.SHA256}}">{{.SHA256}}</a></td><td>{{.RiskScore}} / {{.RiskLevel}}</td><td class="n">{{.Duration}}s</td><td class="n">{{.NetworkSummary.Packets}}</td><td class="n">{{.ExitStatus}}</td><td><a class="lnk" href="/sandbox/{{.Job | urlquery}}">investigate &rarr;</a></td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No completed sandbox exports match this view.</p>{{end}}</div>
{{end}}
<footer>xore//honeypot &bull; isolated KVM dynamic analysis &bull; summaries only</footer></div></body></html>{{end}}

{{define "payloadrow"}}<tr>
  <td>{{.Mtime}}</td>
  <td>{{range .Sources}}<span class="badge text-bg-secondary">{{.}}</span> {{end}}</td>
  <td class="v">{{.Hash}}</td>
  <td class="v"><strong>{{.Kind}}</strong><br><span class="text-body-secondary">{{.Platform}} &bull; {{.MIME}}</span><br><small title="{{.AnalysisPath}}">{{if .Dynamic}}dynamic route ready{{else}}static-only route{{end}}</small></td>
  <td class="n">{{.SizeH}}</td>
  <td class="n">{{.Copies}}</td>
  <td class="v"><a class="lnk" href="/payload-analysis/{{.Hash}}">static analysis &rarr;</a></td>
  <td class="v"><form method="post" action="/sandbox/submit"><input type="hidden" name="hash" value="{{.Hash}}"><button class="btn btn-sm btn-danger" type="submit" title="{{.AnalysisPath}}"><i class="bi bi-play-fill"></i> Analyze</button></form></td>
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
<div class="wrap">
  <header>
    <h1><a href="/">XORE<span>//</span>HONEYPOT</a></h1>
    <span class="gen">unified payload inventory &bull; generated {{.Generated.Format "2006-01-02 15:04:05 MST"}}</span>
  </header>

  <div class="filters">
    <a class="chip" href="/">&larr; dashboard</a>
    {{if .Filter}}<a class="chip" href="/payloads">all sources</a>{{else}}<span class="chip">all sources</span>{{end}}
    {{range .Sources}}{{if .Active}}<span class="chip">{{.Name}} {{.Count}}</span>{{else}}<a class="chip" href="{{.Link}}">{{.Name}} {{.Count}}</a>{{end}}{{end}}
    {{if .Enabled}}<span class="chip">{{len .Files}} loaded of {{.ResultTotal}} matching &bull; {{.UniqueTotal}} unique total &bull; {{.TotalH}}</span>{{end}}
  </div>

  <div class="card wide">
	{{if .Notice}}<div class="alert alert-success" role="status"><i class="bi bi-check-circle me-2"></i>{{.Notice}} <a href="/sandbox">Open sandbox queue</a></div>{{end}}
    <p class="empty" style="text-align:left;margin:0 0 14px">
      &#9888; Unified inventory of Dionaea captures, Cowrie uploads/downloads,
      and retained shell, PowerShell, VBS, Python, JavaScript and other script
      artifacts. Files are inert on disk but <strong>hostile</strong> — handle
      only in an isolated analysis VM.
    </p>
    {{if not .Enabled}}<p class="empty">payload serving is disabled (set PAYLOAD_DIRS and/or SCRIPT_PAYLOAD_DIR)</p>
    {{else if .Loading}}<div class="d-flex align-items-center gap-2 py-4 text-body-secondary" data-payload-warming><span class="spinner-border spinner-border-sm" aria-hidden="true"></span><span>Preparing the payload inventory. This page will update automatically.</span></div><script>setTimeout(()=>location.reload(),1500)</script>
    {{else if .Files}}
    <table class="recent">
	  <thead><tr><th>captured</th><th>source</th><th>hash</th><th>type</th><th>size</th><th>copies</th><th>static</th><th>dynamic</th><th>download</th><th>events</th></tr></thead>
      <tbody data-hp-page-url="/api/payload-rows?source={{.Filter | urlquery}}" data-hp-total="{{.ResultTotal}}">
      {{template "payloadrows" .}}
      </tbody>
    </table>
    {{else}}<p class="empty">no payloads captured yet</p>{{end}}
  </div>

  <footer>xore//honeypot &bull; defensive sensor &bull; do not expose without auth</footer>
</div>
</body>
</html>
{{end}}

{{define "commands"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>xore//honeypot — executed commands</title>{{template "style"}}</head>
<body><div class="wrap">
<header><h1><a href="/">XORE<span>//</span>HONEYPOT</a></h1><span class="gen">executed commands &bull; generated {{.Generated.Format "2006-01-02 15:04:05 MST"}}</span></header>
<div class="filters"><a class="chip" href="/">&larr; dashboard</a><a class="chip" href="/export/commands.csv">export CSV &darr;</a><span class="chip">{{len .Rows}} unique commands</span></div>
<div class="card wide">{{if .Rows}}<table class="recent"><thead><tr><th>seen</th><th>sensor</th><th>command</th><th>sources</th><th>sessions</th><th>first</th><th>last</th><th>chain</th></tr></thead><tbody>
{{range .Rows}}<tr><td class="n">{{.Count}}</td><td><span class="badge b-{{.Sensor}}">{{.Sensor}}</span></td>
<td class="v"><code>{{.Command}}</code> <button class="copy" data-copy="{{.Command}}">copy</button></td><td class="v">{{.Sources}}</td><td class="n">{{.Sessions}}</td><td>{{.First}}</td><td>{{.Last}}</td><td><a class="lnk" href="{{.Link}}">events &rarr;</a></td></tr>{{end}}
</tbody></table>{{else}}<p class="empty">no commands captured yet</p>{{end}}</div>
<footer>xore//honeypot &bull; static investigation view</footer></div>
<script>document.querySelectorAll('[data-copy]').forEach(b=>b.onclick=()=>navigator.clipboard.writeText(b.dataset.copy));</script></body></html>{{end}}

{{define "payload-analysis"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>xore//honeypot — payload analysis</title>{{template "style"}}</head>
<body><div class="wrap">
<header><h1><a href="/">XORE<span>//</span>HONEYPOT</a></h1><span class="gen">bounded static analysis &bull; sample is never executed</span></header>
<div class="filters"><a class="chip" href="/payloads">&larr; payloads</a><a class="chip" href="/events?shasum={{.Hash}}">related events</a><a class="chip" href="{{.VT}}" target="_blank" rel="noopener noreferrer">VirusTotal &rarr;</a><a class="chip" href="/payload/{{.Hash}}">download isolated sample &darr;</a><form method="post" action="/sandbox/submit"><input type="hidden" name="hash" value="{{.Hash}}"><button class="btn btn-sm btn-danger" type="submit" title="Execute this payload in the isolated KVM Linux sandbox"><i class="bi bi-play-fill"></i> Analyze in sandbox</button></form></div>
<div class="row g-3 mb-4"><div class="col-md-4"><div class="info-box"><span class="info-box-icon text-bg-danger"><i class="bi bi-shield-exclamation"></i></span><div class="info-box-content"><span class="info-box-text">Static risk</span><span class="info-box-number">{{.RiskScore}} / 100 &bull; {{.RiskLevel}}</span></div></div></div><div class="col-md-4"><div class="info-box"><span class="info-box-icon text-bg-warning"><i class="bi bi-file-zip"></i></span><div class="info-box-content"><span class="info-box-text">Packing likelihood</span><span class="info-box-number">{{if .PackedLikely}}elevated{{else}}not indicated{{end}}</span></div></div></div><div class="col-md-4"><div class="info-box"><span class="info-box-icon text-bg-info"><i class="bi bi-crosshair"></i></span><div class="info-box-content"><span class="info-box-text">Extracted IOCs</span><span class="info-box-number">{{len .IOCs}}</span></div></div></div></div>
<div class="grid">
<div class="card wide"><h2>Identity and selected analysis path</h2><table><tbody><tr><td>identified type</td><td class="v"><strong>{{.Classification.Label}}</strong> <span class="badge text-bg-secondary">{{.Classification.Code}}</span></td></tr><tr><td>platform / category</td><td class="v">{{.Classification.Platform}} / {{.Classification.Category}}</td></tr><tr><td>sandbox route</td><td class="v">{{.Classification.AnalysisPath}}</td></tr><tr><td>dynamic execution</td><td class="v">{{if .Classification.Dynamic}}supported for this type{{else}}not automatic; static analysis only{{end}}</td></tr><tr><td>magic</td><td class="v">{{.Magic}}</td></tr><tr><td>MIME</td><td class="v">{{.MIME}}</td></tr><tr><td>size</td><td class="v">{{.Size}}</td></tr><tr><td>entropy</td><td class="v">{{.Entropy}}</td></tr><tr><td>MD5</td><td class="v">{{.MD5}}</td></tr><tr><td>SHA-1</td><td class="v">{{.SHA1}}</td></tr><tr><td>SHA-256</td><td class="v">{{.SHA256}}</td></tr></tbody></table>{{if .Truncated}}<p class="note">deep inspection capped at 16 MiB; hashes cover the complete file</p>{{end}}</div>
{{if or .ScriptType .Indicators}}<div class="card wide"><h2>Script classification</h2><table><tbody>{{if .ScriptType}}<tr><td>language/type</td><td class="v">{{.ScriptType}}</td></tr>{{end}}{{if .Indicators}}<tr><td>behavior indicators</td><td class="v">{{range .Indicators}}<span class="chip">{{.}}</span> {{end}}</td></tr>{{end}}</tbody></table><p class="note">Heuristic static findings only. Captured content is never interpreted or executed.</p></div>{{end}}
<div class="card wide"><h2>YARA static scan</h2>{{if .YARAMatches}}<table><tbody>{{range .YARAMatches}}<tr><td><span class="badge text-bg-danger">match</span></td><td class="v">{{.}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">{{if .YARAScanned}}No YARA rules matched this sample.{{else}}Waiting for the isolated YARA scanner.{{end}}</p>{{end}}{{if .YARAError}}<p class="note text-danger">{{.YARAError}}</p>{{end}}{{if .YARAScanned}}<p class="note">Scanned {{.YARAScanned}} by the networkless YARA sidecar. A match is a triage signal, not attribution.</p>{{end}}</div>
<div class="card wide"><h2>Isolated dynamic analysis</h2>{{if .SandboxRuns}}<table><thead><tr><th>completed</th><th>exit</th><th>changed paths</th><th>details</th></tr></thead><tbody>{{range .SandboxRuns}}<tr><td>{{.CompletedAt}}</td><td class="n">{{.ExitStatus}}</td><td class="n">{{len .ChangedFiles}}</td><td><a class="lnk" href="/sandbox/{{.Job | urlquery}}">sandbox report &rarr;</a></td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No completed KVM sandbox run for this payload. Use <strong>Analyze in sandbox</strong> to queue one.</p>{{end}}</div>
<div class="card half"><h2>Rule matches</h2>{{if .Rules}}<table><thead><tr><th>severity</th><th>rule</th><th>reason</th></tr></thead><tbody>{{range .Rules}}<tr><td><span class="badge text-bg-secondary">{{.Severity}}</span></td><td class="v">{{.Name}}</td><td class="v">{{.Description}}</td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No built-in static rules matched.</p>{{end}}<p class="note">Deterministic YARA-style heuristics; no sample execution or attribution.</p></div>
<div class="card half"><h2>Extracted indicators</h2>{{if .IOCs}}<table><tbody>{{range .IOCs}}<tr><td class="v"><a href="/events?q={{. | urlquery}}" title="search telemetry for this indicator">{{.}}</a></td></tr>{{end}}</tbody></table>{{else}}<p class="empty">No URL, domain, or IP indicators found.</p>{{end}}</div>
<div class="card wide"><h2>Hex / ASCII preview — first 512 bytes</h2><pre class="code">{{.Hexdump}}</pre></div>
<div class="card"><h2>Executable metadata</h2>{{if .FormatInfo}}<pre class="code">{{range .FormatInfo}}{{.}}
{{end}}</pre>{{else}}<p class="empty">not a recognized PE/ELF file</p>{{end}}</div>
<div class="card"><h2>Decoded / deobfuscated candidates</h2>{{if .Decoded}}{{range .Decoded}}<p class="note">{{.Kind}} from <code>{{.Source}}</code></p><pre class="code">{{.Preview}}</pre>{{end}}{{else}}<p class="empty">no bounded Base64, hex, URL or UTF-16 candidates found</p>{{end}}</div>
<div class="card"><h2>Printable strings</h2>{{if .ASCII}}<pre class="code">{{range .ASCII}}{{.}}
{{end}}</pre>{{else}}<p class="empty">none</p>{{end}}</div>
<div class="card"><h2>UTF-16LE strings</h2>{{if .UTF16}}<pre class="code">{{range .UTF16}}{{.}}
{{end}}</pre>{{else}}<p class="empty">none</p>{{end}}</div>
</div><footer>xore//honeypot &bull; static analysis only &bull; never execute captured samples</footer></div></body></html>{{end}}

{{define "history"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>xore//honeypot — Elasticsearch history</title>{{template "style"}}</head><body><div class="wrap">
<header><h1><a href="/">XORE<span>//</span>HONEYPOT</a></h1><span class="gen">Elasticsearch historical explorer</span></header>
<div class="filters"><a class="chip" href="/">&larr; dashboard</a><input id="history-q" class="search" placeholder="query_string, e.g. honeypot.sensor:cowrie AND honeypot.username:root" aria-label="Elasticsearch query"><button id="history-run" class="copy">search</button><a id="history-export" class="chip" href="/export/history.json">export JSON &darr;</a></div>
<div class="card wide"><p id="history-meta" class="note">Enter an Elasticsearch query or leave blank for newest documents.</p><pre id="history-results" class="code">waiting</pre></div>
<footer>xore//honeypot &bull; historical data from Elasticsearch</footer></div>
<script>
const q=document.getElementById('history-q'), out=document.getElementById('history-results'), meta=document.getElementById('history-meta');
q.value=new URLSearchParams(location.search).get('q')||'';
async function run(){const query=q.value.trim(), u='/api/history?limit=200'+(query?'&q='+encodeURIComponent(query):'');document.getElementById('history-export').href='/export/history.json?limit=500'+(query?'&q='+encodeURIComponent(query):'');meta.textContent='loading…';try{const r=await fetch(u);const j=await r.json();const hits=j.hits?.hits||[];meta.textContent=hits.length+' documents shown';out.textContent=hits.map(h=>JSON.stringify(h._source,null,2)).join('\n\n')}catch(e){meta.textContent='query failed';out.textContent=String(e)}}
document.getElementById('history-run').onclick=run;q.onkeydown=e=>{if(e.key==='Enter')run()};run();
</script></body></html>{{end}}

{{define "dead-letters"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>xore//honeypot &mdash; ingest dead letters</title>{{template "style"}}</head><body><div class="wrap">
<header><div><div class="eyebrow">Pipeline diagnostics</div><h1>Ingest dead letters</h1><p class="subtitle">Documents Elasticsearch rejected, with their original error and field shape for remediation.</p></div><span class="gen">{{.ES.RecentDeadLetters}} in 24h &bull; {{.ES.DeadLetters}} retained</span></header>
<div class="filters"><a class="chip" href="/source-health">&larr; source health</a><input id="dead-q" class="search" placeholder="optional Elasticsearch query" aria-label="Dead-letter query"><button id="dead-run" class="copy">search</button></div>
<div class="card wide"><p id="dead-meta" class="note">Loading rejected documents&hellip;</p><div id="dead-rows" data-hp-lazy-list></div></div>
<footer>xore//honeypot &bull; ingestion failure diagnostics</footer></div><script>
const deadQ=document.getElementById('dead-q'),deadRows=document.getElementById('dead-rows'),deadMeta=document.getElementById('dead-meta');
async function loadDead(){const q=deadQ.value.trim(),u='/api/dead-letters?limit=200'+(q?'&q='+encodeURIComponent(q):'');deadMeta.textContent='loading';try{const j=await (await fetch(u,{cache:'no-store'})).json(),hits=j.hits?.hits||[];deadMeta.textContent=hits.length+' rejected documents shown';deadRows.innerHTML='';for(const hit of hits){const d=document.createElement('details');d.className='border-bottom py-2';const source=hit._source||{},stamp=source['@timestamp']||'',error=source.error?.message||source.error?.type||'rejected document';const summary=document.createElement('summary');summary.className='v';summary.textContent=stamp+' - '+error;const pre=document.createElement('pre');pre.className='code mt-2';pre.textContent=JSON.stringify(source,null,2);d.append(summary,pre);deadRows.appendChild(d)}if(!hits.length)deadRows.textContent='No matching dead letters.'}catch(e){deadMeta.textContent='query failed';deadRows.textContent=String(e)}}
document.getElementById('dead-run').onclick=loadDead;deadQ.onkeydown=e=>{if(e.key==='Enter')loadDead()};loadDead();
</script></body></html>{{end}}

{{define "source-health"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>xore//honeypot — source health</title>{{template "style"}}</head><body><div class="wrap">
<header><h1><a href="/">XORE<span>//</span>HONEYPOT</a></h1><span class="gen">dashboard + Filebeat + Elasticsearch ingestion health</span></header><div class="filters"><a class="chip" href="/">&larr; dashboard</a><span class="chip">ES {{.ES.State}}</span><a class="chip" href="/history" title="browse all indexed honeypot and Suricata documents">{{.ES.Documents}} indexed documents</a><span class="chip">{{.ES.DeadLetters}} dead letters</span></div>
<div class="row g-3 mb-4"><div class="col-md-3"><div class="info-box"><span class="info-box-icon text-bg-primary"><i class="bi bi-hdd-network"></i></span><div class="info-box-content"><span class="info-box-text">Configured feeds</span><span class="info-box-number">{{len .Sensors}}</span></div></div></div><div class="col-md-3"><div class="info-box"><span class="info-box-icon text-bg-success"><i class="bi bi-database-check"></i></span><div class="info-box-content"><span class="info-box-text">Indexed documents</span><span class="info-box-number">{{.ES.Documents}}</span></div></div></div><div class="col-md-3"><div class="info-box"><span class="info-box-icon text-bg-info"><i class="bi bi-arrow-repeat"></i></span><div class="info-box-content"><span class="info-box-text">Filebeat</span><span class="info-box-number">{{.ES.FilebeatState}}</span></div></div></div><div class="col-md-3"><div class="info-box"><span class="info-box-icon text-bg-danger"><i class="bi bi-exclamation-triangle"></i></span><div class="info-box-content"><span class="info-box-text">Dead letters</span><span class="info-box-number">{{.ES.DeadLetters}}</span></div></div></div></div>
<div class="grid"><div class="card"><h2>Dashboard parser feeds</h2><table><thead><tr><th>feed</th><th>tail events</th><th>state</th><th>last</th></tr></thead><tbody>{{range .Sensors}}<tr><td><a class="badge b-{{.Name}}" href="{{.Link}}">{{.Name}}</a></td><td class="n"><a href="{{.Link}}" title="show every related event in the dashboard tail">{{.Count}}</a></td><td class="state s-{{.State}}">{{.State}}</td><td class="ago">{{.Ago}}</td></tr>{{end}}</tbody></table></div>
<div class="card"><h2>Elasticsearch indexed totals</h2>{{if .ES.Sources}}<table><thead><tr><th>source</th><th>documents</th></tr></thead><tbody>{{range .ES.Sources}}<tr><td class="v"><a href="{{.Link}}" title="search all indexed documents for this source">{{.Name}}</a></td><td class="n"><a href="{{.Link}}" title="search all indexed documents for this source">{{.Count}}</a></td></tr>{{end}}</tbody></table>{{else}}<p class="empty">{{if .ES.Error}}{{.ES.Error}}{{else}}waiting for Elasticsearch check{{end}}</p>{{end}}</div>
<div class="card"><h2>Ingestion freshness</h2><table><tbody><tr><td>state</td><td class="state s-{{.ES.IngestState}}">{{.ES.IngestState}}</td></tr><tr><td>latest indexed event</td><td class="v">{{.ES.LastIngest}}</td></tr><tr><td>ingestion age</td><td class="v">{{.ES.LastIngestAge}}</td></tr><tr><td>dead letters in 24h</td><td class="v"><a href="/dead-letters">{{.ES.RecentDeadLetters}}</a></td></tr></tbody></table><p class="note">Delayed means the newest indexed event is over two minutes old; stale means over fifteen minutes.</p></div>
<div class="card"><h2>YARA scanner</h2><table><tbody><tr><td>enabled</td><td class="v">{{.YARA.Enabled}}</td></tr><tr><td>last report</td><td class="v">{{.YARA.Updated}}</td></tr><tr><td>samples scanned</td><td class="v">{{.YARA.Samples}}</td></tr><tr><td>samples matched</td><td class="v">{{.YARA.Matched}}</td></tr><tr><td>errors</td><td class="v">{{.YARA.Errors}}</td></tr></tbody></table><p class="note">The scanner has no network and receives payload stores read-only.</p></div>
<div class="card"><h2>Dashboard runtime</h2><table><tbody><tr><td>uptime</td><td class="v">{{.Runtime.Uptime}}</td></tr><tr><td>Go heap</td><td class="v">{{.Runtime.Heap}}</td></tr><tr><td>reserved memory</td><td class="v">{{.Runtime.Reserved}}</td></tr><tr><td>container memory</td><td class="v">{{.Runtime.ContainerUsage}} / {{.Runtime.ContainerLimit}}</td></tr><tr><td>goroutines</td><td class="v">{{.Runtime.Goroutines}}</td></tr></tbody></table><p class="note">Container values come from cgroup v2 when available; the Go heap is the live application allocation. <a href="/metrics">Prometheus metrics</a></p></div>
<div class="card wide"><h2>Pipeline status</h2><table><tbody><tr><td>Elasticsearch cluster</td><td class="v">{{.ES.State}}</td></tr><tr><td>last indexed</td><td class="v">{{.ES.LastIngest}}</td></tr><tr><td>dead letters</td><td class="v">{{.ES.DeadLetters}}</td></tr><tr><td>Filebeat</td><td class="v">{{.ES.FilebeatState}}</td></tr><tr><td>Filebeat acknowledged</td><td class="v">{{.ES.FilebeatAcked}}</td></tr><tr><td>Filebeat failed / dropped / active</td><td class="v">{{.ES.FilebeatFailed}} / {{.ES.FilebeatDropped}} / {{.ES.FilebeatActive}}</td></tr><tr><td>last checked</td><td class="v">{{.ES.Checked}}</td></tr>{{if .ES.Error}}<tr><td>error</td><td class="v">{{.ES.Error}}</td></tr>{{end}}</tbody></table><p class="note">A quiet dashboard feed with a stable Elasticsearch total means no recent attacks. A growing log with a static ES total indicates Filebeat lag. Dead-letter growth or Filebeat failed/dropped counters indicate a pipeline error.</p></div></div>
<footer>xore//honeypot &bull; source diagnostics</footer></div></body></html>{{end}}

{{define "alerts"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>xore//honeypot — alerts</title>{{template "style"}}</head><body><div class="wrap">
<header><h1><a href="/">XORE<span>//</span>HONEYPOT</a></h1><span class="gen">persistent alert state, cooldowns and acknowledgments</span></header><div class="filters"><a class="chip" href="/">&larr; dashboard</a><a class="btn btn-sm btn-primary" href="/export/report.pdf?type=alert"><i class="bi bi-file-earmark-pdf me-1"></i>All alerts PDF</a><button class="copy" onclick="loadAlerts()">refresh</button></div>
<div class="card wide"><table class="recent"><thead><tr><th>state</th><th>key</th><th>message</th><th>observed</th><th>last seen</th><th>last notified</th><th>action</th></tr></thead><tbody id="alert-rows"></tbody></table><p id="alert-empty" class="empty">loading</p></div>
<footer>xore//honeypot &bull; acknowledged alerts stay suppressed until reopened</footer></div><script>
async function setAck(key,ack){await fetch('/api/alerts',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({key,ack:String(ack)})});loadAlerts()}
async function loadAlerts(){const rows=document.getElementById('alert-rows'),empty=document.getElementById('alert-empty');try{const a=await (await fetch('/api/alerts')).json();rows.innerHTML='';for(const r of a){const tr=document.createElement('tr');const vals=[r.Acknowledged?'acknowledged':'open',r.Key,r.Message,r.Count,new Date(r.LastSeen).toLocaleString(),new Date(r.LastNotified).toLocaleString()];for(const v of vals){const td=document.createElement('td');td.className='v';td.textContent=v;tr.appendChild(td)}const td=document.createElement('td'),b=document.createElement('button');b.className='copy';b.textContent=r.Acknowledged?'reopen':'acknowledge';b.onclick=()=>setAck(r.Key,!r.Acknowledged);td.appendChild(b);tr.appendChild(td);rows.appendChild(tr)}empty.textContent=a.length?'':'no alerts recorded'}catch(e){empty.textContent=String(e)}}loadAlerts();
</script></body></html>{{end}}
`
