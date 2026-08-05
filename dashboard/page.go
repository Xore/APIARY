package main

// pageTemplate holds every page of the dashboard as named templates:
//
//	"page"   — the main dashboard (auto-refreshes in place every 15s)
//	"events" — /events drill-down: any KPI / row on the dashboard links here
//	           with a filter; a single-IP view renders as a chronological
//	           attack chain
//	"ips"    — /ips: every source IP with first/last seen and sensors hit
//	"search" — /search: grouped matches across every source, for a command-dock
//	           query that does not name one specific entity
//
// All share the "style" block and the embedded Tailwind/Leaflet frontend assets.
var pageTemplate = pageStyle + settingsModal + pageOverview + pageEvents + pageIPs + pageSession + pageIntel + pagePayloads + pageWorkbench + pageSandbox + pageGhidra + pageRevdeck + pageGitHubAnalysis + pageOps + pageReports + pageSearch + pageMLAnomalies + pageLLMAnalysis + pageTTYReplay
