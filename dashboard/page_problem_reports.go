package main

// pageProblemReports is /admin/problem-reports: the "Report a problem"
// review queue (#1147). Markup lives in ui/problem_reports.html, not here --
// see page_ghidra.go's own comment for why.
//
// #1157 follow-up: this var was missing from pageTemplate's own
// concatenation (page.go) entirely -- the "problem-reports" template name
// serveProblemReportsPage renders was never registered, so
// tmpl.ExecuteTemplate silently failed (render.go's renderPage discards
// ExecuteTemplate's error) and the page served an empty body on every
// request, pre-dating and independent of this sweep's Loading/skeleton
// work. Fixed alongside that work since a skeleton is moot on a page that
// never rendered anything at all.
var pageProblemReports = mustReadUI("problem_reports.html")
