package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// problem_reports.go (#1147): an admin-toggleable "Report a problem" button,
// present on every page, that lets an operator submit a bug report carrying
// the technical context needed to actually reproduce it -- a click/nav
// trail, recent console errors and failed network requests, a DOM snapshot
// at submit time, and the request/response bodies of recent dashboard API
// calls. Reports are stored in Elasticsearch (this dashboard's own
// ES-only-reads posture, see #1103) and reviewed by an admin in a new
// /admin/problem-reports page; nothing here files a GitHub issue directly
// -- an admin decides which reports become real issues, same as any other
// internal bug queue.
//
// Redaction: captured DOM/API content can easily carry real operational
// data (attacker IPs, event details, other operators' actions) or literal
// secrets if a page ever rendered one into the DOM or an API body. Every
// captured string passed to submitProblemReport is redacted server-side
// (redactCapturedText) before it is ever written to Elasticsearch --
// belt-and-suspenders on top of whatever the client itself elects to trim.
// This is a deliberately conservative pattern match (see #1147's own design
// note flagging this as the riskiest part of the feature); broadening or
// narrowing it is expected to need real review, not a one-line tweak.

const problemReportsIndex = "dashboard-problem-reports-v1"

// Hard ceilings on captured payload size, independent of docIndexMaxBytes:
// a DOM snapshot or an API body can be large, and this endpoint accepts
// unauthenticated-shaped (any logged-in user, not just admin) input, so it
// needs its own bound rather than trusting docIndexSized alone to reject
// an oversized document after the fact.
const (
	maxDOMSnapshotBytes   = 200_000
	maxCapturedTextBytes  = 20_000
	maxActionTrailEntries = 200
	maxConsoleErrors      = 50
	maxNetworkFailures    = 50
	maxAPICalls           = 30
)

// redactPatterns matches key=value-shaped or JSON-field-shaped occurrences
// of common secret/credential field names, case-insensitively, regardless
// of which of the several capture types (DOM text, API JSON body, header
// line) they appear in. Deliberately broad rather than trying to enumerate
// every real field name this dashboard or a browser could ever render.
//
// Order matters: the two-word "Authorization: Bearer <token>" and
// "Cookie: <value>" header forms must run BEFORE the generic single-token
// key/value pattern below. Confirmed live by this file's own test
// (TestRedactCapturedTextStripsCommonSecretFields): the generic pattern's
// \S+ value capture only grabs one word, so against "Authorization: Bearer
// <token>" it matched "authorization" as the field and "Bearer" alone as
// the value -- redacting the literal word "Bearer" and leaving the real
// token in place, immediately downstream of a `[redacted]` marker that
// looked like the whole thing had been handled.
var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)(\S+)`),
	regexp.MustCompile(`(?i)(Cookie:\s*)(.+)`),
	regexp.MustCompile(`(?i)("?(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization|cookie|session[_-]?id|bearer)"?\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)`),
}

func redactCapturedText(s string) string {
	if len(s) > maxCapturedTextBytes {
		s = s[:maxCapturedTextBytes] + "...[truncated]"
	}
	for _, re := range redactPatterns {
		s = re.ReplaceAllString(s, "${1}[redacted]")
	}
	return s
}

type problemReportActionEntry struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"` // "click" | "navigation"
	Detail string    `json:"detail"`
}

type problemReportAPICall struct {
	At           time.Time `json:"at"`
	Method       string    `json:"method"`
	URL          string    `json:"url"`
	Status       int       `json:"status"`
	RequestBody  string    `json:"request_body,omitempty"`
	ResponseBody string    `json:"response_body,omitempty"`
}

type problemReport struct {
	ID              string                     `json:"id"`
	SubmittedAt     time.Time                  `json:"submitted_at"`
	SubmittedBy     string                     `json:"submitted_by"`
	SubmittedByName string                     `json:"submitted_by_name,omitempty"`
	Page            string                     `json:"page"`
	Expected        string                     `json:"expected"`
	Actual          string                     `json:"actual,omitempty"`
	ActionTrail     []problemReportActionEntry `json:"action_trail,omitempty"`
	ConsoleErrors   []string                   `json:"console_errors,omitempty"`
	NetworkFailures []string                   `json:"network_failures,omitempty"`
	APICalls        []problemReportAPICall     `json:"api_calls,omitempty"`
	DOMSnapshot     string                     `json:"dom_snapshot,omitempty"`
	UserAgent       string                     `json:"user_agent,omitempty"`
	Status          string                     `json:"status"` // "open" | "triaged" | "closed"
}

// problemReportSubmission is the client-facing wire shape -- narrower than
// problemReport (no ID/SubmittedAt/SubmittedBy/Status, which the server
// assigns) and the only shape submitProblemReport ever trusts as input.
type problemReportSubmission struct {
	Page            string                     `json:"page"`
	Expected        string                     `json:"expected"`
	Actual          string                     `json:"actual"`
	ActionTrail     []problemReportActionEntry `json:"action_trail"`
	ConsoleErrors   []string                   `json:"console_errors"`
	NetworkFailures []string                   `json:"network_failures"`
	APICalls        []problemReportAPICall     `json:"api_calls"`
	DOMSnapshot     string                     `json:"dom_snapshot"`
	UserAgent       string                     `json:"user_agent"`
}

func newProblemReportID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return time.Now().UTC().Format("20060102T150405Z0700")
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(raw[:])
}

func clampStrings(in []string, maxN int) []string {
	out := make([]string, 0, min(len(in), maxN))
	for i, s := range in {
		if i >= maxN {
			break
		}
		out = append(out, redactCapturedText(s))
	}
	return out
}

// (*store).serveProblemReports handles both submitting a new report (POST,
// any authenticated user -- reporting a problem should never itself require
// the role that might be missing because of the problem being reported) and
// listing existing reports (GET, admin only).
func (s *store) serveProblemReports(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.es == nil {
		http.Error(w, "problem reports unavailable: Elasticsearch not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.submitProblemReport(w, r)
	case http.MethodGet:
		if !requireAdmin(w, r) {
			return
		}
		s.listProblemReports(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *store) submitProblemReport(w http.ResponseWriter, r *http.Request) {
	if !s.problemReportButtonEnabled() {
		http.Error(w, "the report-a-problem feature is disabled on this dashboard", http.StatusNotFound)
		return
	}
	identity, err := resolveIdentity(r)
	if err != nil {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	var in problemReportSubmission
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDOMSnapshotBytes+2_000_000))
	if err := dec.Decode(&in); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.Expected) == "" {
		http.Error(w, "expected behavior is required", http.StatusBadRequest)
		return
	}

	domSnapshot := in.DOMSnapshot
	if len(domSnapshot) > maxDOMSnapshotBytes {
		domSnapshot = domSnapshot[:maxDOMSnapshotBytes] + "...[truncated]"
	}
	domSnapshot = redactCapturedText(domSnapshot)

	trail := in.ActionTrail
	if len(trail) > maxActionTrailEntries {
		trail = trail[len(trail)-maxActionTrailEntries:]
	}
	for i := range trail {
		trail[i].Detail = redactCapturedText(trail[i].Detail)
	}

	apiCalls := in.APICalls
	if len(apiCalls) > maxAPICalls {
		apiCalls = apiCalls[len(apiCalls)-maxAPICalls:]
	}
	for i := range apiCalls {
		apiCalls[i].RequestBody = redactCapturedText(apiCalls[i].RequestBody)
		apiCalls[i].ResponseBody = redactCapturedText(apiCalls[i].ResponseBody)
	}

	report := problemReport{
		ID:              newProblemReportID(),
		SubmittedAt:     time.Now().UTC(),
		SubmittedBy:     identity.Subject,
		SubmittedByName: identity.DisplayName,
		Page:            redactCapturedText(in.Page),
		Expected:        redactCapturedText(in.Expected),
		Actual:          redactCapturedText(in.Actual),
		ActionTrail:     trail,
		ConsoleErrors:   clampStrings(in.ConsoleErrors, maxConsoleErrors),
		NetworkFailures: clampStrings(in.NetworkFailures, maxNetworkFailures),
		APICalls:        apiCalls,
		DOMSnapshot:     domSnapshot,
		UserAgent:       redactCapturedText(in.UserAgent),
		Status:          "open",
	}

	doc, err := json.Marshal(report)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.es.docIndexSized(problemReportsIndex, report.ID, doc, maxDOMSnapshotBytes+2_000_000, true, 0, 0); err != nil {
		http.Error(w, "failed to store report", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": report.ID})
}

func (s *store) listProblemReports(w http.ResponseWriter, r *http.Request) {
	hits, err := s.es.docSearchAll(problemReportsIndex, 500)
	if err != nil {
		http.Error(w, "failed to list reports", http.StatusBadGateway)
		return
	}
	reports := make([]problemReport, 0, len(hits))
	for _, h := range hits {
		var rep problemReport
		if err := json.Unmarshal(h.Source, &rep); err != nil {
			continue
		}
		reports = append(reports, rep)
	}
	sortProblemReportsNewestFirst(reports)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reports)
}

func sortProblemReportsNewestFirst(reports []problemReport) {
	for i := 1; i < len(reports); i++ {
		for j := i; j > 0 && reports[j].SubmittedAt.After(reports[j-1].SubmittedAt); j-- {
			reports[j], reports[j-1] = reports[j-1], reports[j]
		}
	}
}

// serveProblemReportItem handles PATCH /api/problem-reports/{id} (admin
// only) -- the only mutation an existing report ever gets is a status
// change (open -> triaged -> closed); the captured content itself is never
// edited after submission, so this stays a single-field patch rather than a
// general update endpoint.
func (s *store) serveProblemReportItem(w http.ResponseWriter, r *http.Request) {
	if s == nil || s.es == nil {
		http.Error(w, "problem reports unavailable: Elasticsearch not configured", http.StatusServiceUnavailable)
		return
	}
	if !requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPatch {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/problem-reports/")
	if id == "" {
		http.Error(w, "missing report id", http.StatusBadRequest)
		return
	}
	var patch struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	switch patch.Status {
	case "open", "triaged", "closed":
	default:
		http.Error(w, `status must be "open", "triaged", or "closed"`, http.StatusBadRequest)
		return
	}

	hit, found, err := s.es.docGet(problemReportsIndex, id)
	if err != nil {
		http.Error(w, "failed to load report", http.StatusBadGateway)
		return
	}
	if !found {
		http.Error(w, "report not found", http.StatusNotFound)
		return
	}
	var rep problemReport
	if err := json.Unmarshal(hit.Source, &rep); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rep.Status = patch.Status
	doc, err := json.Marshal(rep)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.es.docIndex(problemReportsIndex, id, doc, false, hit.SeqNo, hit.PrimaryTerm); err != nil {
		if err == errESConflict {
			http.Error(w, "report was updated concurrently, reload and try again", http.StatusConflict)
			return
		}
		http.Error(w, "failed to update report", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *store) problemReportButtonEnabled() bool {
	if s == nil || s.settings == nil {
		return defaultDashboardConfig().Behavior.ShowProblemReportButton
	}
	cfg, _ := s.settings.config.Get()
	return cfg.Behavior.ShowProblemReportButton
}

type problemReportsPageData struct {
	pageMeta
	Reports []problemReport
}

func (s *store) serveProblemReportsPage(w http.ResponseWriter, r *http.Request, tmpl *template.Template) {
	if !requireAdmin(w, r) {
		return
	}
	hits, err := s.es.docSearchAll(problemReportsIndex, 500)
	reports := make([]problemReport, 0, len(hits))
	if err == nil {
		for _, h := range hits {
			var rep problemReport
			if json.Unmarshal(h.Source, &rep) == nil {
				reports = append(reports, rep)
			}
		}
		sortProblemReportsNewestFirst(reports)
	}
	data := problemReportsPageData{Reports: reports}
	renderPage(w, tmpl, "problem-reports", &data)
}
