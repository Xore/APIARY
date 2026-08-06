package main

// reports_store.go — report definitions, the template catalog, and
// generated-report persistence for the Reports studio (R2).
//
// A report definition is the operator-designed recipe for a PDF: a template
// preset (or a custom element list), a dark/light theme, brandable header /
// footer / author / classification copy, a telemetry scope (window plus the
// same search criteria the Event Explorer understands), and — for the sandbox
// template — a sandbox job reference. Definitions live in one atomic,
// revisioned JSON document (the same store primitive as the typed settings);
// generated PDFs are files under the reports directory referenced by
// generated-report metadata entries in that document, pruned to a bounded
// retention count.
//
// All report endpoints are administrator-only. PDF generation is
// consolidated here: dashboard pages no longer export PDFs directly — the
// Reports studio is the single place that produces them.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Bounds for the reports document. Definitions and generated metadata are
// small records; the caps keep the single-document store healthy.
const (
	maxReportDefinitions       = 200
	maxGeneratedReportsDefault = 100
	maxReportAppendix          = 500
	maxReportName              = 60
)

// Report element identifiers. A definition lists the elements to render in
// order; "cover" always renders first and "parameters" last when selected.
const (
	elementCover            = "cover"
	elementMetrics          = "metrics"
	elementAssessment       = "assessment"
	elementFindings         = "findings"
	elementRecommendations  = "recommendations"
	elementTopSensors       = "top_sensors"
	elementTopSources       = "top_sources"
	elementTopSignatures    = "top_signatures"
	elementTopASNs          = "top_asns"
	elementTopCountries     = "top_countries"
	elementTopPorts         = "top_ports"
	elementOperationalAlert = "operational_alerts"
	elementEventAppendix    = "event_appendix"
	elementParameters       = "parameters"
)

// reportElementCatalog documents every selectable element for the designer UI.
var reportElementCatalog = []struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}{
	{elementCover, "Cover", "Title, scope, author, observed window, and classification line"},
	{elementMetrics, "Metric grid", "Headline counts: events, sources, alerts, logins, payloads, sessions, risk rating"},
	{elementAssessment, "Assessment", "Deterministic triage score explanation and rating"},
	{elementFindings, "Key findings", "Derived findings from the matching telemetry"},
	{elementRecommendations, "Recommended actions", "Derived defensive next steps"},
	{elementTopSensors, "Top sensors", "Sensor volume ranking"},
	{elementTopSources, "Top source addresses", "Source IP volume ranking"},
	{elementTopSignatures, "Top alert signatures", "IDS / honeypot signature ranking"},
	{elementTopASNs, "Top autonomous systems", "ASN / organization ranking"},
	{elementTopCountries, "Top countries", "Country ranking (contextual GeoIP lead only)"},
	{elementTopPorts, "Top destination ports", "Targeted port ranking"},
	{elementOperationalAlert, "Operational alerts", "Dashboard operational alert state matching the scope"},
	{elementEventAppendix, "Event appendix", "Representative newest matching event records (bounded)"},
	{elementParameters, "Parameters and limitations", "Applied filters, data source, and evidentiary limitations"},
}

func knownReportElement(id string) bool {
	for _, element := range reportElementCatalog {
		if element.ID == id {
			return true
		}
	}
	return false
}

// reportTemplate is a designer preset: a named starting point with a default
// theme, window, title, and element selection the operator can then adjust.
type reportTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Title       string   `json:"title"`
	Theme       string   `json:"theme"`
	Window      string   `json:"window,omitempty"`
	Elements    []string `json:"elements,omitempty"`
	Sandbox     bool     `json:"sandbox,omitempty"`
	// Payload marks the #474 per-payload report: like Sandbox, this template
	// renders from one referenced artifact (Scope.Hash) rather than a
	// telemetry window, and is never exercised through the designer's saved-
	// definition flow -- see generatePayloadReport in reports_api.go.
	Payload bool `json:"payload,omitempty"`
	// Ghidra marks the #814 per-sample static-analysis report: same
	// Scope.Hash-referenced-artifact shape as Payload (the picker UI is
	// shared with it client-side, see hp-reports.js), rendered by
	// ghidra_pdf.go instead of payload_pdf.go. This is deliberately a
	// second first-class Reports-studio template rather than folding
	// Ghidra detail into the payload report's existing "any GitHub-analysis
	// verdict" summary section -- a payload's Ghidra result (functions,
	// strings, imports, capa capabilities, floss deobfuscation, fuzzy
	// hashes) is its own substantial evidence set an operator may want
	// themed/branded/scheduled on its own, the same way a sandbox run gets
	// its own template instead of being a payload-report subsection.
	Ghidra bool `json:"ghidra,omitempty"`
}

// reportTemplateCatalog presets cover every PDF function the dashboard pages
// previously offered directly (executive overview, filtered scope, IP and
// session investigations, alert digests, weekly summaries, sandbox runs).
func reportTemplateCatalog() []reportTemplate {
	return []reportTemplate{
		{
			ID: "executive", Name: "Executive report",
			Description: "Management-ready summary of the observation window: headline metrics, assessment, findings, and recommendations.",
			Title:       "Honeypot Executive Security Report",
			Theme:       "dark", Window: "24h",
			Elements: []string{elementCover, elementMetrics, elementAssessment, elementFindings, elementRecommendations, elementTopSources, elementTopCountries, elementParameters},
		},
		{
			ID: "security", Name: "Full security report",
			Description: "Complete defensive picture: every metric, ranking, operational alert, and a bounded evidence appendix.",
			Title:       "Honeypot Security Operations Report",
			Theme:       "dark", Window: "24h",
			Elements: []string{elementCover, elementMetrics, elementAssessment, elementFindings, elementRecommendations, elementTopSensors, elementTopSources, elementTopSignatures, elementTopASNs, elementTopCountries, elementTopPorts, elementOperationalAlert, elementEventAppendix, elementParameters},
		},
		{
			ID: "threat", Name: "Threat landscape",
			Description: "Who and what is attacking: signatures, autonomous systems, countries, and targeted ports over a longer window.",
			Title:       "Honeypot Threat Landscape Report",
			Theme:       "dark", Window: "7d",
			Elements: []string{elementCover, elementMetrics, elementTopSignatures, elementTopASNs, elementTopCountries, elementTopPorts, elementFindings, elementParameters},
		},
		{
			ID: "incident", Name: "Incident investigation",
			Description: "Scoped deep-dive for one IP, session, network, or signature with operational alerts and an extended event appendix.",
			Title:       "Honeypot Incident Investigation Report",
			Theme:       "dark", Window: "24h",
			Elements: []string{elementCover, elementMetrics, elementAssessment, elementFindings, elementRecommendations, elementOperationalAlert, elementEventAppendix, elementParameters},
		},
		{
			ID: "sensors", Name: "Sensor and collection health",
			Description: "Collection coverage and operational state: sensor volumes plus open operational alerts.",
			Title:       "Honeypot Sensor and Collection Health Report",
			Theme:       "dark", Window: "24h",
			Elements: []string{elementCover, elementMetrics, elementTopSensors, elementOperationalAlert, elementParameters},
		},
		{
			ID: "sandbox", Name: "Sandbox analysis",
			Description: "Dynamic-analysis report for one sandbox job: assessment, process / socket / network evidence, and ATT&CK mapping.",
			Title:       "Sandbox Dynamic Analysis Report",
			Theme:       "dark",
			Sandbox:     true,
		},
		{
			ID: "payload", Name: "Payload analysis",
			Description: "Static/dynamic analysis report for one captured payload: classification, IOCs, YARA, sandbox runs, and any GitHub-analysis verdict.",
			Title:       "Payload Analysis Report",
			Theme:       "dark",
			Payload:     true,
		},
		{
			ID: "ghidra", Name: "Ghidra static analysis",
			Description: "Headless-decompilation report for one captured payload: functions, strings, imports, capa capabilities, FLOSS-deobfuscated strings, fuzzy hashes, and structural (lief) info.",
			Title:       "Ghidra Static Analysis Report",
			Theme:       "dark",
			Ghidra:      true,
		},
		{
			ID: "custom", Name: "Custom report",
			Description: "Blank canvas: pick every element, the scope, the theme, and the branding yourself.",
			Title:       "Honeypot Custom Report",
			Theme:       "dark",
			Elements:    []string{elementCover, elementMetrics, elementParameters},
		},
	}
}

// reportTemplateCatalogWithOverrides (#477) applies an administrator's
// Name/Description overrides on top of the compiled catalog for display --
// the structural fields (theme, window, elements, Sandbox/Payload) always
// stay compiled, since those are report logic, not editable chrome. An
// override for an id that no longer exists in the compiled catalog (a
// preset renamed/removed in a later release) is silently ignored here
// rather than erroring: the config that produced it was valid when saved,
// and a stale leftover key should never break the templates listing.
func reportTemplateCatalogWithOverrides(overrides map[string]reportPresetOverride) []reportTemplate {
	catalog := reportTemplateCatalog()
	if len(overrides) == 0 {
		return catalog
	}
	for i := range catalog {
		override, ok := overrides[catalog[i].ID]
		if !ok {
			continue
		}
		if override.Name != "" {
			catalog[i].Name = override.Name
		}
		if override.Description != "" {
			catalog[i].Description = override.Description
		}
	}
	return catalog
}

// reportPresetRow (#477) is one row of the settings modal's "Report Studio
// presets" pane: a template's fixed id and compiled-default copy (shown as
// placeholder text -- the operator sees exactly what an empty override
// falls back to) alongside its current override, if any.
type reportPresetRow struct {
	ID                  string
	DefaultName         string
	DefaultDescription  string
	OverrideName        string
	OverrideDescription string
}

func reportPresetRowsFor(overrides map[string]reportPresetOverride) []reportPresetRow {
	catalog := reportTemplateCatalog()
	rows := make([]reportPresetRow, 0, len(catalog))
	for _, template := range catalog {
		override := overrides[template.ID]
		rows = append(rows, reportPresetRow{
			ID:                  template.ID,
			DefaultName:         template.Name,
			DefaultDescription:  template.Description,
			OverrideName:        override.Name,
			OverrideDescription: override.Description,
		})
	}
	return rows
}

func reportTemplateByID(id string) (reportTemplate, bool) {
	for _, template := range reportTemplateCatalog() {
		if template.ID == id {
			return template, true
		}
	}
	return reportTemplate{}, false
}

// reportWindowDuration maps the designer's window options to durations. An
// empty window means "no time restriction" (the full observation window).
func reportWindowDuration(window string) (time.Duration, bool) {
	switch window {
	case "1h":
		return time.Hour, true
	case "6h":
		return 6 * time.Hour, true
	case "24h":
		return 24 * time.Hour, true
	case "7d":
		return 7 * 24 * time.Hour, true
	case "30d":
		return 30 * 24 * time.Hour, true
	}
	return 0, false
}

// reportBranding is the operator-configurable identity of a generated report.
// Empty fields fall back to the deployment defaults at render time.
type reportBranding struct {
	Title          string `json:"title,omitempty"`
	Author         string `json:"author,omitempty"`
	HeaderLeft     string `json:"header_left,omitempty"`
	HeaderRight    string `json:"header_right,omitempty"`
	FooterLeft     string `json:"footer_left,omitempty"`
	Classification string `json:"classification,omitempty"`
}

func (b reportBranding) pdf() pdfBranding {
	return pdfBranding{
		HeaderLeft:     b.HeaderLeft,
		HeaderRight:    b.HeaderRight,
		FooterLeft:     b.FooterLeft,
		Classification: b.Classification,
		Author:         b.Author,
	}
}

// reportScope carries the designer's search criteria. The fields mirror the
// Event Explorer filters; all set fields must match (AND). Job selects a
// sandbox analysis run and is only valid for the sandbox template.
type reportScope struct {
	Window    string `json:"window,omitempty"`
	IP        string `json:"ip,omitempty"`
	Network   string `json:"network,omitempty"`
	Sensor    string `json:"sensor,omitempty"`
	Port      string `json:"port,omitempty"`
	Signature string `json:"signature,omitempty"`
	Country   string `json:"country,omitempty"`
	ASN       string `json:"asn,omitempty"`
	Text      string `json:"text,omitempty"`
	Type      string `json:"type,omitempty"`
	Session   string `json:"session,omitempty"`
	Job       string `json:"job,omitempty"`  // sandbox template
	Hash      string `json:"hash,omitempty"` // payload template (#474)
}

// filter converts the scope into the shared telemetry filter at generation
// time, so the window is always relative to when the report is produced.
func (sc reportScope) filter(now time.Time) filter {
	f := filter{
		ip: sc.IP, cidr: sc.Network, sensor: sc.Sensor, port: sc.Port,
		sig: sc.Signature, country: sc.Country, asn: sc.ASN,
		q: sc.Text, typ: sc.Type, session: sc.Session,
	}
	if d, ok := reportWindowDuration(sc.Window); ok {
		f.since = now.Add(-d)
		f.sinceStr = sc.Window
	}
	return f
}

// reportSchedule is the optional recurrence of a definition (R4). Times are
// UTC; monthly schedules are bounded to days 1–28 so every month has a run.
type reportSchedule struct {
	Enabled   bool      `json:"enabled"`
	Frequency string    `json:"frequency,omitempty"` // daily | weekly | monthly
	Hour      int       `json:"hour"`
	Minute    int       `json:"minute"`
	Weekday   int       `json:"weekday,omitempty"`   // 0 = Sunday … 6 = Saturday (weekly)
	MonthDay  int       `json:"month_day,omitempty"` // 1 … 28 (monthly)
	LastRunAt time.Time `json:"last_run_at,omitempty"`
	NextRunAt time.Time `json:"next_run_at,omitempty"`
}

// validateReportSchedule enforces the schedule contract whenever scheduling
// is enabled; a disabled schedule carries no constraints.
func validateReportSchedule(schedule *reportSchedule) error {
	if schedule == nil || !schedule.Enabled {
		return nil
	}
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errSettingsValidation, fmt.Sprintf(format, args...))
	}
	switch schedule.Frequency {
	case "daily":
	case "weekly":
		if schedule.Weekday < 0 || schedule.Weekday > 6 {
			return invalid("schedule.weekday must be between 0 (Sunday) and 6 (Saturday)")
		}
	case "monthly":
		if schedule.MonthDay < 1 || schedule.MonthDay > 28 {
			return invalid("schedule.month_day must be between 1 and 28")
		}
	default:
		return invalid("schedule.frequency must be one of daily, weekly, monthly")
	}
	if schedule.Hour < 0 || schedule.Hour > 23 {
		return invalid("schedule.hour must be between 0 and 23 (UTC)")
	}
	if schedule.Minute < 0 || schedule.Minute > 59 {
		return invalid("schedule.minute must be between 0 and 59")
	}
	return nil
}

// nextScheduleRun computes the first fire time strictly after from.
func nextScheduleRun(schedule *reportSchedule, from time.Time) time.Time {
	from = from.UTC()
	candidate := time.Date(from.Year(), from.Month(), from.Day(), schedule.Hour, schedule.Minute, 0, 0, time.UTC)
	switch schedule.Frequency {
	case "daily":
		if !candidate.After(from) {
			candidate = candidate.AddDate(0, 0, 1)
		}
	case "weekly":
		for i := 0; i < 8; i++ {
			if int(candidate.Weekday()) == schedule.Weekday && candidate.After(from) {
				break
			}
			candidate = candidate.AddDate(0, 0, 1)
		}
	case "monthly":
		for i := 0; i < 62; i++ {
			if candidate.Day() == schedule.MonthDay && candidate.After(from) {
				break
			}
			candidate = candidate.AddDate(0, 0, 1)
		}
	}
	return candidate
}

// reportDefinition is one saved report design.
type reportDefinition struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Template      string          `json:"template"`
	Theme         string          `json:"theme"`
	Branding      reportBranding  `json:"branding,omitempty"`
	Scope         reportScope     `json:"scope,omitempty"`
	Elements      []string        `json:"elements,omitempty"`
	AppendixLimit int             `json:"appendix_limit,omitempty"`
	Schedule      *reportSchedule `json:"schedule,omitempty"`
	Created       time.Time       `json:"created"`
	Updated       time.Time       `json:"updated"`
}

// generatedReport is the metadata for one produced PDF. The definition
// fields are snapshots, so a generated report stays meaningful after its
// definition is changed or deleted.
//
// #475: metadata and PDF bytes both live in Elasticsearch
// (generatedReportIndex), not this struct's own document -- generatedReport
// itself is still the shape served over the API and rendered by the
// designer's generated-history list; storedGeneratedReport (reports_es.go)
// is the ES-side wrapper that adds the base64 PDF payload.
type generatedReport struct {
	ID           string    `json:"id"`
	DefinitionID string    `json:"definition_id,omitempty"`
	Name         string    `json:"name"`
	Template     string    `json:"template"`
	Theme        string    `json:"theme"`
	Title        string    `json:"title"`
	SizeBytes    int64     `json:"size_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	Origin       string    `json:"origin"` // manual | schedule
}

// reportsDocument is the persisted state of the Reports studio's saved
// definitions. Generated reports (#475) live in Elasticsearch instead, not
// this document -- see generatedReportIndex.
type reportsDocument struct {
	Definitions []reportDefinition `json:"definitions"`
}

func newReportID(prefix string) string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(fmt.Sprintf("generate report id: %v", err))
	}
	return prefix + hex.EncodeToString(raw[:])
}

func validReportID(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+16 {
		return false
	}
	for _, char := range id[len(prefix):] {
		if char >= '0' && char <= '9' || char >= 'a' && char <= 'f' {
			continue
		}
		return false
	}
	return true
}

// validateDefinitionFields enforces the definition contract shared by the API
// and the store loader. Messages name fields and bounds, never values.
func validateDefinitionFields(def reportDefinition) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", errSettingsValidation, fmt.Sprintf(format, args...))
	}
	name := strings.TrimSpace(def.Name)
	if name == "" || len(def.Name) > maxReportName {
		return invalid("name is required and must be at most %d characters", maxReportName)
	}
	template, ok := reportTemplateByID(def.Template)
	if !ok {
		return invalid("template must be one of the published report templates")
	}
	if def.Theme != "dark" && def.Theme != "light" {
		return invalid("theme must be dark or light")
	}
	switch {
	case template.Sandbox:
		if strings.TrimSpace(def.Scope.Job) == "" {
			return invalid("scope.job selects the sandbox analysis run for the sandbox template")
		}
		if def.Scope.Hash != "" {
			return invalid("scope.hash is only valid for the payload and ghidra templates")
		}
		if len(def.Elements) != 0 {
			return invalid("elements are fixed for the sandbox template; only theme and branding apply")
		}
	case template.Payload, template.Ghidra:
		if !hashName.MatchString(def.Scope.Hash) {
			return invalid("scope.hash selects the captured payload for the payload and ghidra templates")
		}
		if def.Scope.Job != "" {
			return invalid("scope.job is only valid for the sandbox template")
		}
		if len(def.Elements) != 0 {
			return invalid("elements are fixed for the payload and ghidra templates; only theme and branding apply")
		}
	default:
		if def.Scope.Job != "" {
			return invalid("scope.job is only valid for the sandbox template")
		}
		if def.Scope.Hash != "" {
			return invalid("scope.hash is only valid for the payload and ghidra templates")
		}
		if len(def.Elements) == 0 || len(def.Elements) > len(reportElementCatalog) {
			return invalid("elements must select between 1 and %d report elements", len(reportElementCatalog))
		}
		seen := map[string]bool{}
		for _, element := range def.Elements {
			if !knownReportElement(element) {
				return invalid("elements contains an unknown report element")
			}
			if seen[element] {
				return invalid("elements must not repeat a report element")
			}
			seen[element] = true
		}
	}
	if def.AppendixLimit < 0 || def.AppendixLimit > maxReportAppendix {
		return invalid("appendix_limit must be between 0 and %d", maxReportAppendix)
	}
	if def.Scope.Window != "" {
		if _, ok := reportWindowDuration(def.Scope.Window); !ok {
			return invalid("scope.window must be one of 1h, 6h, 24h, 7d, 30d")
		}
	}
	switch def.Scope.Type {
	case "", "login", "command", "alert", "download":
	default:
		return invalid("scope.type must be one of login, command, alert, download")
	}
	scopeCaps := []struct {
		value string
		field string
		max   int
	}{
		{def.Scope.IP, "scope.ip", 64},
		{def.Scope.Network, "scope.network", 64},
		{def.Scope.Sensor, "scope.sensor", 64},
		{def.Scope.Port, "scope.port", 16},
		{def.Scope.Signature, "scope.signature", 120},
		{def.Scope.Country, "scope.country", 64},
		{def.Scope.ASN, "scope.asn", 32},
		{def.Scope.Text, "scope.text", 200},
		{def.Scope.Session, "scope.session", 128},
		{def.Scope.Job, "scope.job", 128},
	}
	for _, cap := range scopeCaps {
		if len(cap.value) > cap.max {
			return invalid("%s must be at most %d characters", cap.field, cap.max)
		}
	}
	brandingCaps := []struct {
		value string
		field string
		max   int
	}{
		{def.Branding.Title, "branding.title", 80},
		{def.Branding.Author, "branding.author", 60},
		{def.Branding.HeaderLeft, "branding.header_left", 60},
		{def.Branding.HeaderRight, "branding.header_right", 60},
		{def.Branding.FooterLeft, "branding.footer_left", 80},
		{def.Branding.Classification, "branding.classification", 120},
	}
	for _, cap := range brandingCaps {
		if len(cap.value) > cap.max {
			return invalid("%s must be at most %d characters", cap.field, cap.max)
		}
	}
	if err := validateReportSchedule(def.Schedule); err != nil {
		return err
	}
	return nil
}

// validateReportsDocument is the store loader's guard: a corrupt or
// out-of-contract document triggers backup recovery instead of being served.
func validateReportsDocument(doc reportsDocument) error {
	if len(doc.Definitions) > maxReportDefinitions {
		return fmt.Errorf("too many report definitions (max %d)", maxReportDefinitions)
	}
	ids := map[string]bool{}
	for _, def := range doc.Definitions {
		if !validReportID(def.ID, "rep_") || def.Created.IsZero() || def.Updated.IsZero() {
			return errors.New("report definition has an invalid id or timestamps")
		}
		if ids[def.ID] {
			return errors.New("duplicate report definition id")
		}
		ids[def.ID] = true
		if err := validateDefinitionFields(def); err != nil {
			return err
		}
	}
	return nil
}

// reportStore owns the definitions document (local, unchanged) and generated
// PDF reports (#475: Elasticsearch, via es -- see reports_es.go). es may be
// nil (Elasticsearch not configured): definitions CRUD keeps working, but
// every generated-report method returns errReportsStorageUnavailable rather
// than falling back to local disk -- no local fallback, by design, the same
// as #494's alert state.
type reportStore struct {
	inner        *atomicSettingsStore[reportsDocument]
	es           *esClient
	maxGenerated int
}

func newReportStore(path string, es *esClient) *reportStore {
	store := &reportStore{es: es, maxGenerated: maxGeneratedReportsDefault}
	store.inner = newAtomicSettingsStore(path, reportsDocument{}, validateReportsDocument)
	if store.inner.Degraded() {
		fmt.Printf("dashboard: reports store at %s unreadable — serving defaults read-only\n", path)
	} else if store.inner.Recovered() {
		fmt.Printf("dashboard: reports store recovered from backup generation at %s\n", path)
	}
	return store
}

func (rs *reportStore) document() (reportsDocument, string) {
	return rs.inner.Get()
}

func (rs *reportStore) definition(id string) (reportDefinition, bool) {
	doc, _ := rs.inner.Get()
	for _, def := range doc.Definitions {
		if def.ID == id {
			return def, true
		}
	}
	return reportDefinition{}, false
}

// putDefinition creates or replaces a definition. An empty def.ID creates a
// new record with a server-assigned id; an existing id replaces that record.
func (rs *reportStore) putDefinition(ifMatch string, def reportDefinition) (reportDefinition, string, error) {
	now := time.Now().UTC()
	if def.ID == "" {
		def.ID = newReportID("rep_")
		def.Created = now
	} else if !validReportID(def.ID, "rep_") {
		return reportDefinition{}, "", fmt.Errorf("%w: id must be a server-assigned report id", errSettingsValidation)
	}
	def.Name = strings.TrimSpace(def.Name)
	def.Updated = now
	if def.Schedule != nil && def.Schedule.Enabled {
		// Recompute the fire time on every save: the schedule parameters or
		// the clock may have moved since the last save.
		def.Schedule.NextRunAt = nextScheduleRun(def.Schedule, now)
	} else if def.Schedule != nil {
		def.Schedule.NextRunAt = time.Time{}
	}
	if err := validateDefinitionFields(def); err != nil {
		return reportDefinition{}, "", err
	}
	etag, _, err := rs.inner.Update(ifMatch, func(doc *reportsDocument) error {
		for index, existing := range doc.Definitions {
			if existing.ID == def.ID {
				def.Created = existing.Created
				doc.Definitions[index] = def
				return nil
			}
		}
		if def.Created.IsZero() {
			return fmt.Errorf("%w: no report definition with this id", errUnknownRecord)
		}
		doc.Definitions = append(doc.Definitions, def)
		return nil
	})
	if err != nil {
		return reportDefinition{}, "", err
	}
	return def, etag, nil
}

func (rs *reportStore) deleteDefinition(ifMatch, id string) error {
	_, _, err := rs.inner.Update(ifMatch, func(doc *reportsDocument) error {
		for index, existing := range doc.Definitions {
			if existing.ID == id {
				doc.Definitions = append(doc.Definitions[:index], doc.Definitions[index+1:]...)
				return nil
			}
		}
		return fmt.Errorf("%w: no report definition with this id", errUnknownRecord)
	})
	return err
}

// dueReports returns enabled schedules whose fire time has arrived. The
// returned definitions are copies; the scheduler marks runs afterwards.
func (rs *reportStore) dueReports(now time.Time) []reportDefinition {
	doc, _ := rs.inner.Get()
	var due []reportDefinition
	for _, def := range doc.Definitions {
		if def.Schedule == nil || !def.Schedule.Enabled || def.Schedule.NextRunAt.IsZero() {
			continue
		}
		if !def.Schedule.NextRunAt.After(now) {
			due = append(due, def)
		}
	}
	return due
}

// markScheduledRun records the outcome of a scheduled run: the next fire time
// always advances (a failing definition must not hot-loop), and LastRunAt
// moves only on success.
func (rs *reportStore) markScheduledRun(id string, ranAt time.Time, success bool) {
	_, _, _ = rs.inner.Update("", func(doc *reportsDocument) error {
		for index, def := range doc.Definitions {
			if def.ID == id && def.Schedule != nil {
				if success {
					doc.Definitions[index].Schedule.LastRunAt = ranAt
				}
				doc.Definitions[index].Schedule.NextRunAt = nextScheduleRun(def.Schedule, ranAt)
				return nil
			}
		}
		return nil
	})
}

// Generated-report storage (metadata + PDF bytes) moved to Elasticsearch --
// see reports_es.go for addGenerated/generated/generatedPDF/deleteGenerated/
// listGenerated and the #475 design comment on generatedReportIndex.
