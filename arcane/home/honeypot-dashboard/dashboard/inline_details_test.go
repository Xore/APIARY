package main

import (
	"html/template"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProblemReportsRenderBoundedInlineDetailShell(t *testing.T) {
	tmpl := template.Must(template.New("t").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	data := problemReportsPageData{Reports: []problemReport{{
		ID:              "report-inline",
		SubmittedAt:     time.Date(2026, 8, 15, 10, 30, 0, 0, time.UTC),
		SubmittedBy:     "subject-inline",
		SubmittedByName: "Inline Operator",
		Page:            "/events",
		Expected:        "expected inline",
		Actual:          "actual inline",
		Status:          "open",
	}}}
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "problem-reports", &data); err != nil {
		t.Fatalf("problem reports page does not render: %v", err)
	}
	html := out.String()
	for _, want := range []string{`id="hp-pr-detail-panel"`, `data-hp-pr-detail-body`, `aria-busy="true"`, `aria-controls="hp-pr-detail-panel"`, `class="hp-table-wrap card__scroll"`} {
		if !strings.Contains(html, want) {
			t.Fatalf("inline problem-report shell is missing %q", want)
		}
	}
	for _, forbidden := range []string{`hp-pr-detail-modal`, `hp-pr-detail-backdrop`} {
		if strings.Contains(html, forbidden) {
			t.Fatalf("problem-report context is still modal-only: %q", forbidden)
		}
	}
}

func TestProblemReportControllerRendersEveryCapturedFieldInline(t *testing.T) {
	data, err := os.ReadFile("static/hp-problem-reports-admin.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		"Report identity", "submitted_at", "submitted_by", "submitted_by_name", "report.page",
		"report.expected", "report.actual", "report.action_trail", "report.console_errors",
		"report.network_failures", "report.api_calls", "call.request_body", "call.response_body",
		"report.dom_snapshot", "report.user_agent", "card__scroll", "replaceChildren",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("inline problem-report renderer is missing %q", want)
		}
	}
	for _, forbidden := range []string{"createFocusTrap", "hp-pr-detail-modal", "modal.hidden", "backdrop"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("problem-report controller still depends on a modal: %q", forbidden)
		}
	}
}
