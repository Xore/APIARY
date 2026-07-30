package main

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	pdfPageWidth  = 595.0
	pdfPageHeight = 842.0
)

type pdfPage struct {
	content bytes.Buffer
}

// pdfRGB is a PDF device color (0–1 per channel).
type pdfRGB struct{ r, g, b float64 }

// pdfTheme carries every palette decision of the rendered report, so a
// definition can render dark (screen-style) or light (print-style) PDFs.
// Both palettes are snapshots of the canonical Xore/theme tokens — the light
// set matches the Xore/Honeypot scan-report design, the dark set is its
// canonical dark counterpart.
type pdfTheme struct {
	Page        pdfRGB // app-bg
	HeaderBand  pdfRGB // top band background (sidebar-bg / surface-1)
	HeaderRule  pdfRGB // band separator and section rules (border-strong)
	BrandText   pdfRGB // headings, metric values, brand marks (text-primary)
	MutedText   pdfRGB // subtitles, metadata, footer (text-muted)
	BodyText    pdfRGB // paragraphs and table rows
	Accent      pdfRGB // section bars, labels, bullet dashes (accent)
	Card        pdfRGB // metric card background (surface-1 / surface-0)
	CardBorder  pdfRGB // metric card outline (border-subtle)
	AltRow      pdfRGB // zebra striping
	TableHeader pdfRGB // table header band (surface-raised / surface-2)
	Bar         pdfRGB // count bars (text-link)
	FaintText   pdfRGB // appendix detail lines
	Success     pdfRGB // clean / low-risk semantics
	Warning     pdfRGB // elevated-risk semantics
	Danger      pdfRGB // detected / high-risk semantics
	Link        pdfRGB // link and information accents
}

// pdfThemeDark is the canonical Xore/theme dark palette (theme.css :root).
func pdfThemeDark() pdfTheme {
	return pdfTheme{
		Page:        pdfRGB{0.125, 0.125, 0.122}, // #20201f
		HeaderBand:  pdfRGB{0.118, 0.118, 0.110}, // #1e1e1c
		HeaderRule:  pdfRGB{0.204, 0.204, 0.196}, // #343432
		BrandText:   pdfRGB{0.914, 0.902, 0.875}, // #e9e6df
		MutedText:   pdfRGB{0.549, 0.561, 0.553}, // #8c8f8d
		BodyText:    pdfRGB{0.740, 0.740, 0.710},
		Accent:      pdfRGB{0.851, 0.467, 0.341}, // #d97757
		Card:        pdfRGB{0.173, 0.173, 0.165}, // #2c2c2a
		CardBorder:  pdfRGB{0.239, 0.239, 0.231}, // #3d3d3b
		AltRow:      pdfRGB{0.151, 0.151, 0.145},
		TableHeader: pdfRGB{0.220, 0.220, 0.208}, // #383835
		Bar:         pdfRGB{0.427, 0.655, 0.925}, // #6da7ec
		FaintText:   pdfRGB{0.660, 0.670, 0.650},
		Success:     pdfRGB{0.475, 0.788, 0.620}, // #79c99e
		Warning:     pdfRGB{0.871, 0.702, 0.416}, // #deb36a
		Danger:      pdfRGB{0.863, 0.467, 0.455}, // #dc7774
		Link:        pdfRGB{0.427, 0.655, 0.925}, // #6da7ec
	}
}

// pdfThemeLight is the canonical Xore/theme light palette — the print-safe
// token snapshot from the Xore/Honeypot scan-report design (report.py).
func pdfThemeLight() pdfTheme {
	return pdfTheme{
		Page:        pdfRGB{0.969, 0.965, 0.949}, // #f7f6f2
		HeaderBand:  pdfRGB{0.957, 0.949, 0.929}, // #f4f2ed
		HeaderRule:  pdfRGB{0.819, 0.813, 0.798}, // border-strong composite
		BrandText:   pdfRGB{0.184, 0.169, 0.153}, // #2f2b27
		MutedText:   pdfRGB{0.569, 0.541, 0.510}, // #918a82
		BodyText:    pdfRGB{0.300, 0.280, 0.250}, // primary/secondary blend
		Accent:      pdfRGB{0.780, 0.396, 0.282}, // #c76548
		Card:        pdfRGB{0.984, 0.980, 0.969}, // #fbfaf7
		CardBorder:  pdfRGB{0.908, 0.903, 0.891}, // border-subtle composite
		AltRow:      pdfRGB{0.961, 0.955, 0.937}, // rgba(#f4f2ed, 0.65) on app-bg
		TableHeader: pdfRGB{0.922, 0.914, 0.890}, // #ebe9e3
		Bar:         pdfRGB{0.165, 0.471, 0.839}, // #2a78d6
		FaintText:   pdfRGB{0.569, 0.541, 0.510},
		Success:     pdfRGB{0.247, 0.529, 0.392}, // #3f8764
		Warning:     pdfRGB{0.608, 0.420, 0.145}, // #9b6b25
		Danger:      pdfRGB{0.702, 0.310, 0.298}, // #b34f4c
		Link:        pdfRGB{0.165, 0.471, 0.839}, // #2a78d6
	}
}

func pdfThemeNamed(name string) pdfTheme {
	if name == "light" {
		return pdfThemeLight()
	}
	return pdfThemeDark()
}

// pdfBranding carries the operator-configurable identity of a report:
// header/footer copy, classification line, and author. Empty fields fall
// back to the deployment defaults so existing output stays byte-identical.
type pdfBranding struct {
	HeaderLeft     string
	HeaderRight    string
	FooterLeft     string
	Classification string
	Author         string
}

func defaultPDFBranding() pdfBranding {
	return pdfBranding{
		HeaderLeft:     "XORE//HONEYPOT",
		HeaderRight:    "DEFENSIVE SECURITY OPERATIONS",
		FooterLeft:     "PRIVATE - XORE//HONEYPOT",
		Classification: "PRIVATE - contains hostile-source telemetry and forensic indicators",
	}
}

func (b pdfBranding) withDefaults() pdfBranding {
	defaults := defaultPDFBranding()
	if b.HeaderLeft == "" {
		b.HeaderLeft = defaults.HeaderLeft
	}
	if b.HeaderRight == "" {
		b.HeaderRight = defaults.HeaderRight
	}
	if b.FooterLeft == "" {
		b.FooterLeft = defaults.FooterLeft
	}
	if b.Classification == "" {
		b.Classification = defaults.Classification
	}
	return b
}

type pdfDocument struct {
	pages      []*pdfPage
	theme      pdfTheme
	footerLeft string
}

type pdfReportWriter struct {
	doc      *pdfDocument
	page     *pdfPage
	y        float64
	title    string
	scope    string
	branding pdfBranding
}

type reportSummary struct {
	Events          int
	Alerts          int
	HighSeverity    int
	UniqueSources   int
	Logins          int
	Payloads        int
	Sessions        int
	Commands        int
	Sensors         int
	OpenOperational int
	FirstSeen       string
	LastSeen        string
	RiskScore       int
	RiskLevel       string
}

type reportData struct {
	Generated         time.Time
	Title             string
	Scope             string
	Filters           []string
	Summary           reportSummary
	Events            []storedEvent
	TopSensors        []kv
	TopSources        []kv
	TopSignatures     []kv
	TopASNs           []kv
	TopCountries      []kv
	TopPorts          []kv
	OperationalAlerts []alertRecord
	Findings          []string
	Recommendations   []string
}

// reportDataFor builds the report dataset for a telemetry filter. The
// Reports studio constructs the filter from a definition's scope; the
// dashboard's page-level direct PDF exports were removed in R2 — the
// generator is the single place that produces PDFs.
func (s *store) reportDataFor(f filter) reportData {
	events := f.filtered(s.getEvents())
	data := reportData{
		Generated: time.Now(),
		Title:     "Honeypot Executive Security Report",
		Filters:   f.describe(),
		Events:    events,
	}
	if len(data.Filters) == 0 {
		data.Scope = "All normalized telemetry in the current dashboard observation window"
	} else {
		data.Scope = strings.Join(data.Filters, " AND ")
	}

	sensors, sources, signatures := map[string]int{}, map[string]int{}, map[string]int{}
	asns, countries, ports := map[string]int{}, map[string]int{}, map[string]int{}
	sessions := map[string]bool{}
	var first, last time.Time
	for _, event := range events {
		sensors[firstNonEmpty(event.Sensor, "unknown")]++
		if event.SrcIP != "" {
			sources[event.SrcIP]++
		}
		if event.Alert != "" {
			signatures[event.Alert]++
			data.Summary.Alerts++
		}
		if event.Severity > 0 && event.Severity <= 2 {
			data.Summary.HighSeverity++
		}
		if event.ASN != 0 {
			label := "AS" + strconv.FormatUint(uint64(event.ASN), 10)
			if event.Org != "" {
				label += " " + event.Org
			}
			asns[label]++
		}
		if event.Country != "" {
			countries[event.Country]++
		}
		if event.Port != "" {
			ports[event.Port]++
		}
		if event.IsLogin {
			data.Summary.Logins++
		}
		if event.Shasum != "" {
			data.Summary.Payloads++
		}
		if event.Command != "" {
			data.Summary.Commands++
		}
		if event.Session != "" {
			sessions[event.Session] = true
		}
		if !event.when.IsZero() {
			if first.IsZero() || event.when.Before(first) {
				first = event.when
			}
			if last.IsZero() || event.when.After(last) {
				last = event.when
			}
		}
	}
	data.Summary.Events = len(events)
	data.Summary.UniqueSources = len(sources)
	data.Summary.Sessions = len(sessions)
	data.Summary.Sensors = len(sensors)
	if !first.IsZero() {
		data.Summary.FirstSeen = first.Format("2006-01-02 15:04:05 MST")
	}
	if !last.IsZero() {
		data.Summary.LastSeen = last.Format("2006-01-02 15:04:05 MST")
	}
	data.TopSensors = topN(sensors, 10)
	data.TopSources = topN(sources, 12)
	data.TopSignatures = topN(signatures, 12)
	data.TopASNs = topN(asns, 10)
	data.TopCountries = topN(countries, 10)
	data.TopPorts = topN(ports, 10)

	if s.alerts != nil {
		for _, alert := range s.alerts.list() {
			if reportAlertMatches(alert, f) {
				data.OperationalAlerts = append(data.OperationalAlerts, alert)
				if !alert.Acknowledged {
					data.Summary.OpenOperational++
				}
			}
		}
	}

	score := 5
	score += min(30, data.Summary.Alerts/5)
	score += min(25, data.Summary.HighSeverity*5)
	score += min(15, data.Summary.Payloads*3)
	score += min(10, max(0, data.Summary.Sensors-1)*2)
	score += min(10, data.Summary.OpenOperational*2)
	score += min(5, data.Summary.Commands)
	data.Summary.RiskScore = min(100, score)
	data.Summary.RiskLevel = riskLevel(data.Summary.RiskScore)

	data.Findings = reportFindings(data)
	data.Recommendations = reportRecommendations(data)
	return data
}

func reportAlertMatches(alert alertRecord, f filter) bool {
	needles := []string{f.ip, f.cidr, f.sensor, f.sig, f.cat, f.country, f.provider, f.org, f.asn}
	blob := alert.Key + " " + alert.Message
	for _, needle := range needles {
		if needle != "" && !containsFold(blob, needle) {
			return false
		}
	}
	return true
}

func reportFindings(data reportData) []string {
	s := data.Summary
	findings := []string{
		fmt.Sprintf("%d matching events from %d unique source addresses reached %d sensors.", s.Events, s.UniqueSources, s.Sensors),
	}
	if s.Alerts > 0 {
		findings = append(findings, fmt.Sprintf("%d IDS or honeypot alert signatures were observed; %d records carried high-severity classifications.", s.Alerts, s.HighSeverity))
	}
	if s.Logins > 0 {
		findings = append(findings, fmt.Sprintf("%d authentication attempts were recorded across the selected scope.", s.Logins))
	}
	if s.Payloads > 0 {
		findings = append(findings, fmt.Sprintf("%d payload observations require static and isolated sandbox triage.", s.Payloads))
	}
	if s.Commands > 0 {
		findings = append(findings, fmt.Sprintf("%d command-execution records provide behavioral evidence.", s.Commands))
	}
	if s.OpenOperational > 0 {
		findings = append(findings, fmt.Sprintf("%d operational dashboard alerts remain open or unacknowledged.", s.OpenOperational))
	}
	if s.Events == 0 {
		findings = append(findings, "No telemetry matched the selected report filters in the current in-memory observation window.")
	}
	return findings
}

func reportRecommendations(data reportData) []string {
	s := data.Summary
	var recommendations []string
	if s.HighSeverity > 0 || s.Alerts > 20 {
		recommendations = append(recommendations, "Prioritize the highest-volume signatures and pivot to EveBox and Arkime for packet and session confirmation.")
	}
	if s.Payloads > 0 {
		recommendations = append(recommendations, "Complete static analysis and disposable-VM sandbox runs for every unique payload hash before handling samples elsewhere.")
	}
	if s.Logins > 0 {
		recommendations = append(recommendations, "Review repeated credentials, source reuse, and cross-sensor authentication patterns for campaign correlation.")
	}
	if s.UniqueSources > 0 {
		recommendations = append(recommendations, "Use ASN, provider, country, fingerprint, and network pivots before considering network-level blocking.")
	}
	if s.OpenOperational > 0 {
		recommendations = append(recommendations, "Resolve collection or correlation problems represented by open operational alerts, then acknowledge them with an audit note.")
	}
	recommendations = append(recommendations, "Treat all attribution and GeoIP results as contextual leads, not proof of actor identity or physical location.")
	return recommendations
}

// allReportElements is the historical full-report layout order, kept as the
// security-template default and for the legacy render entry points.
var allReportElements = []string{
	elementCover, elementMetrics, elementAssessment, elementFindings, elementRecommendations,
	elementTopSensors, elementTopSources, elementTopSignatures, elementTopASNs, elementTopCountries,
	elementTopPorts, elementOperationalAlert, elementEventAppendix, elementParameters,
}

// renderSecurityReportPDF keeps the historical executive layout with the
// dark theme and default branding.
func renderSecurityReportPDF(data reportData) []byte {
	return renderThemedReportPDF(data, pdfThemeDark(), defaultPDFBranding())
}

func renderThemedReportPDF(data reportData, theme pdfTheme, branding pdfBranding) []byte {
	return renderReportElements(data, theme, branding, allReportElements, 120)
}

// renderDefinitionPDF renders a Reports studio definition: its theme,
// branding, element selection, and appendix bound.
func renderDefinitionPDF(data reportData, def reportDefinition) []byte {
	limit := def.AppendixLimit
	if limit <= 0 {
		limit = 120
	}
	return renderReportElements(data, pdfThemeNamed(def.Theme), def.Branding.pdf(), def.Elements, limit)
}

// normalizeReportElements keeps the designer's ordering but anchors the cover
// at the start and the parameters section at the end when selected.
func normalizeReportElements(elements []string) []string {
	var body []string
	hasCover, hasParameters := false, false
	for _, element := range elements {
		switch element {
		case elementCover:
			hasCover = true
		case elementParameters:
			hasParameters = true
		default:
			body = append(body, element)
		}
	}
	out := body
	if hasCover {
		out = append([]string{elementCover}, out...)
	}
	if hasParameters {
		out = append(out, elementParameters)
	}
	return out
}

// renderReportElements drives the writer from an element list, so a
// definition renders exactly the sections the operator selected.
func renderReportElements(data reportData, theme pdfTheme, branding pdfBranding, elements []string, appendixLimit int) []byte {
	writer := &pdfReportWriter{
		doc:      &pdfDocument{theme: theme, footerLeft: branding.withDefaults().FooterLeft},
		title:    data.Title,
		scope:    data.Scope,
		branding: branding.withDefaults(),
	}
	writer.newPage()
	for _, element := range normalizeReportElements(elements) {
		switch element {
		case elementCover:
			writer.cover(data)
		case elementMetrics:
			writer.section("Executive summary")
			writer.metricGrid(data.Summary)
		case elementAssessment:
			writer.section("Assessment")
			writer.paragraph(fmt.Sprintf("Overall triage score: %d/100 (%s). This deterministic score prioritizes alert volume, severity, payload observations, sensor spread, commands, and open operational alerts; it is not an attribution or compromise verdict.", data.Summary.RiskScore, strings.ToUpper(data.Summary.RiskLevel)))
		case elementFindings:
			writer.bullets("Key findings", data.Findings)
		case elementRecommendations:
			writer.bullets("Recommended actions", data.Recommendations)
		case elementTopSensors:
			writer.topTable("Top sensors", "Sensor", data.TopSensors)
		case elementTopSources:
			writer.topTable("Top source addresses", "Source IP", data.TopSources)
		case elementTopSignatures:
			writer.topTable("Top alert signatures", "Signature", data.TopSignatures)
		case elementTopASNs:
			writer.topTable("Top autonomous systems", "ASN / organization", data.TopASNs)
		case elementTopCountries:
			writer.topTable("Top countries", "Country", data.TopCountries)
		case elementTopPorts:
			writer.topTable("Top destination ports", "Port", data.TopPorts)
		case elementOperationalAlert:
			writer.operationalAlerts(data.OperationalAlerts)
		case elementEventAppendix:
			writer.eventAppendix(data.Events, appendixLimit)
		case elementParameters:
			writer.parameters(data)
		}
	}
	return writer.doc.bytes()
}

func (w *pdfReportWriter) theme() pdfTheme { return w.doc.theme }

func (w *pdfReportWriter) newPage() {
	t := w.theme()
	w.page = &pdfPage{}
	w.doc.pages = append(w.doc.pages, w.page)
	w.y = pdfPageHeight - 68
	w.rect(0, 0, pdfPageWidth, pdfPageHeight, t.Page)
	w.rect(0, pdfPageHeight-48, pdfPageWidth, 48, t.HeaderBand)
	w.line(0, pdfPageHeight-48, pdfPageWidth, pdfPageHeight-48, t.HeaderRule)
	w.text(32, pdfPageHeight-29, 12, true, t.BrandText, w.branding.HeaderLeft)
	w.text(pdfPageWidth-188, pdfPageHeight-29, 7.5, false, t.MutedText, w.branding.HeaderRight)
}

func (w *pdfReportWriter) ensure(height float64) {
	if w.y-height < 55 {
		w.newPage()
	}
}

func (w *pdfReportWriter) cover(data reportData) {
	t := w.theme()
	w.displayText(32, w.y, 25, t.BrandText, data.Title)
	w.y -= 29
	w.text(32, w.y, 9, true, t.Accent, "REPORT SCOPE")
	w.y -= 17
	for _, line := range wrapPDFText(data.Scope, 88) {
		w.text(32, w.y, 10, false, t.BrandText, line)
		w.y -= 14
	}
	w.y -= 4
	if w.branding.Author != "" {
		w.text(32, w.y, 8.5, false, t.MutedText, "Author: "+w.branding.Author)
		w.y -= 13
	}
	w.text(32, w.y, 8.5, false, t.MutedText, "Generated: "+data.Generated.Format("2006-01-02 15:04:05 MST"))
	w.y -= 13
	window := firstNonEmpty(data.Summary.FirstSeen, "not available") + " to " + firstNonEmpty(data.Summary.LastSeen, "not available")
	w.text(32, w.y, 8.5, false, t.MutedText, "Observed window: "+window)
	w.y -= 13
	w.text(32, w.y, 8.5, false, t.Accent, "Classification: "+w.branding.Classification)
	w.y -= 28
}

func (w *pdfReportWriter) section(title string) {
	t := w.theme()
	// Keep a section heading with at least one useful row or paragraph beneath it.
	w.ensure(70)
	w.y -= 8
	w.rect(32, w.y-5, 4, 18, t.Accent)
	w.displayText(44, w.y, 15, t.BrandText, title)
	w.y -= 25
	w.line(32, w.y+7, pdfPageWidth-32, w.y+7, t.HeaderRule)
}

func (w *pdfReportWriter) paragraph(value string) {
	t := w.theme()
	lines := wrapPDFText(value, 100)
	w.ensure(float64(len(lines))*13 + 10)
	for _, line := range lines {
		w.text(36, w.y, 9, false, t.BodyText, line)
		w.y -= 13
	}
	w.y -= 6
}

// riskColor maps a triage level to the theme's semantic color, mirroring the
// badge system of the canonical scan-report design.
func (t pdfTheme) riskColor(level string) pdfRGB {
	switch strings.ToLower(level) {
	case "low", "clean", "minimal":
		return t.Success
	case "medium", "elevated", "guard":
		return t.Warning
	case "high", "critical", "severe":
		return t.Danger
	default:
		return t.BrandText
	}
}

func (w *pdfReportWriter) metricGrid(summary reportSummary) {
	t := w.theme()
	metrics := []struct {
		label string
		value string
		color pdfRGB
	}{
		{"Matching events", strconv.Itoa(summary.Events), t.BrandText},
		{"Unique sources", strconv.Itoa(summary.UniqueSources), t.BrandText},
		{"Alert records", strconv.Itoa(summary.Alerts), t.BrandText},
		{"High severity", strconv.Itoa(summary.HighSeverity), t.BrandText},
		{"Login attempts", strconv.Itoa(summary.Logins), t.BrandText},
		{"Payload observations", strconv.Itoa(summary.Payloads), t.BrandText},
		{"Sessions", strconv.Itoa(summary.Sessions), t.BrandText},
		{"Risk rating", fmt.Sprintf("%d - %s", summary.RiskScore, strings.ToUpper(summary.RiskLevel)), t.riskColor(summary.RiskLevel)},
	}
	cellW, cellH := 126.5, 54.0
	for i, metric := range metrics {
		if i%4 == 0 {
			w.ensure(cellH + 8)
		}
		x := 32 + float64(i%4)*(cellW+7)
		y := w.y - cellH
		w.rect(x, y, cellW, cellH, t.Card)
		w.strokeRect(x, y, cellW, cellH, t.CardBorder)
		w.text(x+10, y+31, 15, true, metric.color, metric.value)
		w.text(x+10, y+14, 7.5, true, t.MutedText, strings.ToUpper(metric.label))
		if i%4 == 3 {
			w.y -= cellH + 8
		}
	}
	w.y -= 6
}

func (w *pdfReportWriter) bullets(title string, items []string) {
	t := w.theme()
	if len(items) == 0 {
		return
	}
	w.ensure(28)
	w.text(36, w.y, 10.5, true, t.BrandText, title)
	w.y -= 17
	for _, item := range items {
		lines := wrapPDFText(item, 92)
		w.ensure(float64(len(lines))*12 + 5)
		w.text(39, w.y, 9, true, t.Accent, "-")
		for index, line := range lines {
			x := 50.0
			if index > 0 {
				x = 50
			}
			w.text(x, w.y, 8.7, false, t.BodyText, line)
			w.y -= 12
		}
		w.y -= 3
	}
	w.y -= 3
}

func (w *pdfReportWriter) topTable(title, label string, rows []kv) {
	t := w.theme()
	if len(rows) == 0 {
		return
	}
	firstLines := wrapPDFText(firstNonEmpty(rows[0].Title, rows[0].Key), 78)
	firstHeight := math.Max(25, float64(len(firstLines))*11+9)
	w.ensure(33 + 24 + firstHeight)
	w.section(title)
	maxCount := max(1, rows[0].Count)
	w.tableHeader(label, "Events")
	for index, row := range rows {
		lines := wrapPDFText(firstNonEmpty(row.Title, row.Key), 78)
		height := math.Max(25, float64(len(lines))*11+9)
		w.ensure(height)
		if index%2 == 1 {
			w.rect(32, w.y-height+5, pdfPageWidth-64, height, t.AltRow)
		}
		barWidth := 115 * float64(row.Count) / float64(maxCount)
		w.rect(pdfPageWidth-184, w.y-12, barWidth, 5, t.Bar)
		for _, line := range lines {
			w.text(38, w.y-7, 8.3, false, t.BodyText, line)
			w.y -= 11
		}
		w.text(pdfPageWidth-55, w.y+float64(len(lines))*11-7, 8.5, true, t.BrandText, strconv.Itoa(row.Count))
		w.y -= 8
	}
	w.y -= 4
}

func (w *pdfReportWriter) tableHeader(left, right string) {
	t := w.theme()
	w.ensure(23)
	w.rect(32, w.y-17, pdfPageWidth-64, 22, t.TableHeader)
	w.text(38, w.y-10, 8, true, t.BrandText, strings.ToUpper(left))
	w.text(pdfPageWidth-68, w.y-10, 8, true, t.BrandText, strings.ToUpper(right))
	w.y -= 24
}

func (w *pdfReportWriter) operationalAlerts(alerts []alertRecord) {
	t := w.theme()
	if len(alerts) == 0 {
		return
	}
	firstLines := wrapPDFText("OPEN - "+alerts[0].Message, 82)
	firstHeight := math.Max(25, float64(len(firstLines))*11+9)
	w.ensure(33 + 24 + firstHeight)
	w.section("Operational dashboard alerts")
	w.tableHeader("State / message", "Count")
	for index, alert := range alerts[:min(40, len(alerts))] {
		state := "OPEN"
		if alert.Acknowledged {
			state = "ACKNOWLEDGED"
		}
		lines := wrapPDFText(state+" - "+alert.Message, 82)
		height := math.Max(25, float64(len(lines))*11+9)
		w.ensure(height)
		if index%2 == 1 {
			w.rect(32, w.y-height+5, pdfPageWidth-64, height, t.AltRow)
		}
		for _, line := range lines {
			w.text(38, w.y-7, 8.2, false, t.BodyText, line)
			w.y -= 11
		}
		w.text(pdfPageWidth-55, w.y+float64(len(lines))*11-7, 8.5, true, t.BrandText, strconv.Itoa(alert.Count))
		w.y -= 8
	}
}

func (w *pdfReportWriter) eventAppendix(events []storedEvent, appendixLimit int) {
	t := w.theme()
	w.section("Evidence appendix - representative events")
	if len(events) == 0 || appendixLimit <= 0 {
		w.paragraph("No matching event records were available.")
		return
	}
	limit := min(appendixLimit, len(events))
	w.paragraph(fmt.Sprintf("Showing the newest %d of %d matching records. Use the dashboard Event Explorer or Elasticsearch export for the complete machine-readable dataset.", limit, len(events)))
	for index, event := range events[:limit] {
		detail := firstNonEmpty(event.Alert, event.Detail, event.Command, event.Path, "event")
		head := strings.Join([]string{event.Time, event.Sensor, event.SrcIP, event.Port}, "  |  ")
		lines := wrapPDFText(detail, 88)
		height := 25 + float64(len(lines))*10
		w.ensure(height)
		if index%2 == 0 {
			w.rect(32, w.y-height+7, pdfPageWidth-64, height, t.AltRow)
		}
		w.text(38, w.y-6, 7.8, true, t.BrandText, head)
		w.y -= 14
		for _, line := range lines {
			w.text(38, w.y-5, 7.8, false, t.FaintText, line)
			w.y -= 10
		}
		w.y -= 6
	}
}

func (w *pdfReportWriter) parameters(data reportData) {
	w.section("Report parameters and limitations")
	filters := "none - executive overview"
	if len(data.Filters) > 0 {
		filters = strings.Join(data.Filters, "; ")
	}
	w.paragraph("Applied filters: " + filters)
	w.paragraph("Data source: normalized in-memory dashboard telemetry and persistent operational alert state. Counts reflect the dashboard observation window, not an assertion that every historical Elasticsearch document is present.")
	w.paragraph("Limitations: honeypot interactions show hostile or suspicious activity directed at decoy services. GeoIP, ASN, provider, behavioral mappings, and risk scoring are contextual triage aids. They do not prove attribution, physical location, successful compromise, or impact to production systems.")
}

func (w *pdfReportWriter) text(x, y, size float64, bold bool, color pdfRGB, value string) {
	font := "F1"
	if bold {
		font = "F2"
	}
	fmt.Fprintf(&w.page.content, "BT /%s %.2f Tf %.3f %.3f %.3f rg %.2f %.2f Td (%s) Tj ET\n",
		font, size, color.r, color.g, color.b, x, y, escapePDFText(value))
}

func (w *pdfReportWriter) displayText(x, y, size float64, color pdfRGB, value string) {
	fmt.Fprintf(&w.page.content, "BT /F3 %.2f Tf %.3f %.3f %.3f rg %.2f %.2f Td (%s) Tj ET\n",
		size, color.r, color.g, color.b, x, y, escapePDFText(value))
}

func (w *pdfReportWriter) rect(x, y, width, height float64, color pdfRGB) {
	fmt.Fprintf(&w.page.content, "%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f\n", color.r, color.g, color.b, x, y, width, height)
}

func (w *pdfReportWriter) strokeRect(x, y, width, height float64, color pdfRGB) {
	fmt.Fprintf(&w.page.content, "%.3f %.3f %.3f RG 0.6 w %.2f %.2f %.2f %.2f re S\n", color.r, color.g, color.b, x, y, width, height)
}

func (w *pdfReportWriter) line(x1, y1, x2, y2 float64, color pdfRGB) {
	fmt.Fprintf(&w.page.content, "%.3f %.3f %.3f RG 0.6 w %.2f %.2f m %.2f %.2f l S\n", color.r, color.g, color.b, x1, y1, x2, y2)
}

func escapePDFText(value string) string {
	var out strings.Builder
	for _, char := range value {
		switch {
		case char == '\\' || char == '(' || char == ')':
			out.WriteByte('\\')
			out.WriteRune(char)
		case char == '\n' || char == '\r' || char == '\t':
			out.WriteByte(' ')
		case char >= 0x20 && char <= 0x7e:
			out.WriteRune(char)
		default:
			out.WriteByte('?')
		}
	}
	return out.String()
}

func wrapPDFText(value string, width int) []string {
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return []string{""}
	}
	var lines []string
	for len(value) > width {
		cut := strings.LastIndex(value[:width+1], " ")
		if cut < width/2 {
			cut = width
		}
		lines = append(lines, strings.TrimSpace(value[:cut]))
		value = strings.TrimSpace(value[cut:])
	}
	if value != "" {
		lines = append(lines, value)
	}
	return lines
}

func (d *pdfDocument) bytes() []byte {
	if len(d.pages) == 0 {
		d.pages = append(d.pages, &pdfPage{})
	}
	muted := d.theme.MutedText
	footerLeft := d.footerLeft
	if footerLeft == "" {
		footerLeft = defaultPDFBranding().FooterLeft
	}
	objects := make([][]byte, 5+len(d.pages)*2)
	objects[0] = []byte("<< /Type /Catalog /Pages 2 0 R >>")
	var kids strings.Builder
	for index := range d.pages {
		fmt.Fprintf(&kids, "%d 0 R ", 6+index*2)
	}
	objects[1] = []byte(fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", len(d.pages), kids.String()))
	objects[2] = []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	objects[3] = []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	objects[4] = []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman /Encoding /WinAnsiEncoding >>")
	for index, page := range d.pages {
		pageNumber := 6 + index*2
		contentNumber := pageNumber + 1
		footer := fmt.Sprintf("BT /F1 7.5 Tf %.3f %.3f %.3f rg 32 27 Td (%s) Tj ET\nBT /F1 7.5 Tf %.3f %.3f %.3f rg 516 27 Td (Page %d of %d) Tj ET\n",
			muted.r, muted.g, muted.b, escapePDFText(footerLeft), muted.r, muted.g, muted.b, index+1, len(d.pages))
		stream := append(append([]byte(nil), page.content.Bytes()...), []byte(footer)...)
		objects[pageNumber-1] = []byte(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>", pdfPageWidth, pdfPageHeight, contentNumber))
		objects[contentNumber-1] = append([]byte(fmt.Sprintf("<< /Length %d >>\nstream\n", len(stream))), append(stream, []byte("endstream")...)...)
	}

	var output bytes.Buffer
	output.WriteString("%PDF-1.4\n%\xd3\xf4\xcc\xe1\n")
	offsets := make([]int, len(objects)+1)
	for index, object := range objects {
		offsets[index+1] = output.Len()
		fmt.Fprintf(&output, "%d 0 obj\n", index+1)
		output.Write(object)
		output.WriteString("\nendobj\n")
	}
	xref := output.Len()
	fmt.Fprintf(&output, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&output, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&output, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return output.Bytes()
}
