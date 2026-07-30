package main

// page_reports.go — the Reports studio page (R3). The designer lives in the
// main content area like every other dashboard page; the dynamic behavior is
// in /static/hp-reports.js against the /api/reports/* endpoints. This is the
// single place PDFs are designed, generated, viewed, and downloaded.
//
// The markup itself lives in the embedded ui tree; see
// docs/DASHBOARD-RENDER-ENGINE-GUIDE.md §6 step 3.
var pageReports = mustReadUI("reports.html")
