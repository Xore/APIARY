package main

import (
	"html/template"
	"testing"
)

// TestRoutesRegisterWithoutConflict (#1323) is the regression guard #1317
// didn't have: net/http.ServeMux panics at registration time when two
// patterns overlap without one being a strict subset of the other, and
// that class of bug is invisible to go build/go vet/go test unless
// something actually calls Handle/HandleFunc for the COMPLETE real route
// set at once. #1317 converted a handful of routes to method-scoped
// wildcards and broke a sibling registration elsewhere in main.go --
// undetected locally, only caught once CI started the real binary. This
// test builds the exact route table main() itself builds and would panic
// on any ambiguous pattern the way the real process would at startup.
//
// dashboardOIDC (package-level, nil in a bare test binary) is fine here:
// routes() only ever takes method VALUES off it (dashboardOIDC.serveLogin
// etc.), never calls them or dereferences fields during registration --
// evaluating a method value on a nil pointer receiver doesn't itself
// panic in Go, only calling the resulting function would.
func TestRoutesRegisterWithoutConflict(t *testing.T) {
	s := &store{}
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(s, "")).Parse(pageTemplate))
	mux := s.routes(tmpl)
	if mux == nil {
		t.Fatal("routes() returned a nil mux")
	}
}
