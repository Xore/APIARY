package main

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"net/url"
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

type pdfDocument struct {
	pages []*pdfPage
}

type pdfReportWriter struct {
	doc        *pdfDocument
	page       *pdfPage
	y          float64
	pageNumber int
	title      string
	scope      string
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

func (s *store) servePDFReport(w http.ResponseWriter, r *http.Request) {
	if !requireAdmin(w, r) {
		return
	}
	data := s.reportData(r)
	body := renderSecurityReportPDF(data)
	filename := reportFilename(parseFilter(r))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(body)
}

func reportURL(values url.Values) string {
	query := make(url.Values, len(values))
	for key, entries := range values {
		if key == "page" || key == "per_page" || key == "offset" {
			continue
		}
		query[key] = append([]string(nil), entries...)
	}
	if encoded := query.Encode(); encoded != "" {
		return "/export/report.pdf?" + encoded
	}
	return "/export/report.pdf"
}

func reportFilename(f filter) string {
	scope := "executive"
	switch {
	case f.ip != "":
		scope = "ip-" + f.ip
	case f.asn != "":
		scope = "asn-" + strings.TrimPrefix(strings.ToUpper(f.asn), "AS")
	case f.cidr != "":
		scope = "network-" + f.cidr
	case f.sig != "":
		scope = "signature-" + f.sig
	case f.typ == "alert":
		scope = "all-alerts"
	case f.sensor != "":
		scope = "sensor-" + f.sensor
	case f.country != "":
		scope = "country-" + f.country
	}
	var clean strings.Builder
	for _, char := range strings.ToLower(scope) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '.' {
			clean.WriteRune(char)
		} else {
			clean.WriteByte('-')
		}
	}
	return "honeypot-" + strings.Trim(clean.String(), "-") + "-report.pdf"
}

func (s *store) reportData(r *http.Request) reportData {
	f := parseFilter(r)
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

func renderSecurityReportPDF(data reportData) []byte {
	writer := &pdfReportWriter{doc: &pdfDocument{}, title: data.Title, scope: data.Scope}
	writer.newPage()
	writer.cover(data)
	writer.section("Executive summary")
	writer.metricGrid(data.Summary)
	writer.section("Assessment")
	writer.paragraph(fmt.Sprintf("Overall triage score: %d/100 (%s). This deterministic score prioritizes alert volume, severity, payload observations, sensor spread, commands, and open operational alerts; it is not an attribution or compromise verdict.", data.Summary.RiskScore, strings.ToUpper(data.Summary.RiskLevel)))
	writer.bullets("Key findings", data.Findings)
	writer.bullets("Recommended actions", data.Recommendations)
	writer.topTable("Top sensors", "Sensor", data.TopSensors)
	writer.topTable("Top source addresses", "Source IP", data.TopSources)
	writer.topTable("Top alert signatures", "Signature", data.TopSignatures)
	writer.topTable("Top autonomous systems", "ASN / organization", data.TopASNs)
	writer.topTable("Top countries", "Country", data.TopCountries)
	writer.topTable("Top destination ports", "Port", data.TopPorts)
	writer.operationalAlerts(data.OperationalAlerts)
	writer.eventAppendix(data.Events)
	writer.parameters(data)
	return writer.doc.bytes()
}

func (w *pdfReportWriter) newPage() {
	w.pageNumber++
	w.page = &pdfPage{}
	w.doc.pages = append(w.doc.pages, w.page)
	w.y = pdfPageHeight - 68
	w.rect(0, pdfPageHeight-48, pdfPageWidth, 48, 0.055, 0.102, 0.180)
	w.text(32, pdfPageHeight-29, 12, true, 1, 1, 1, "XORE//HONEYPOT")
	w.text(pdfPageWidth-188, pdfPageHeight-29, 7.5, false, 0.76, 0.82, 0.90, "DEFENSIVE SECURITY OPERATIONS")
}

func (w *pdfReportWriter) ensure(height float64) {
	if w.y-height < 55 {
		w.newPage()
	}
}

func (w *pdfReportWriter) cover(data reportData) {
	w.text(32, w.y, 24, true, 0.055, 0.102, 0.180, data.Title)
	w.y -= 29
	w.text(32, w.y, 11, true, 0.04, 0.45, 0.75, "REPORT SCOPE")
	w.y -= 17
	for _, line := range wrapPDFText(data.Scope, 88) {
		w.text(32, w.y, 10, false, 0.18, 0.23, 0.30, line)
		w.y -= 14
	}
	w.y -= 4
	w.text(32, w.y, 8.5, false, 0.35, 0.40, 0.47, "Generated: "+data.Generated.Format("2006-01-02 15:04:05 MST"))
	w.y -= 13
	window := firstNonEmpty(data.Summary.FirstSeen, "not available") + " to " + firstNonEmpty(data.Summary.LastSeen, "not available")
	w.text(32, w.y, 8.5, false, 0.35, 0.40, 0.47, "Observed window: "+window)
	w.y -= 13
	w.text(32, w.y, 8.5, false, 0.55, 0.16, 0.16, "Classification: PRIVATE - contains hostile-source telemetry and forensic indicators")
	w.y -= 28
}

func (w *pdfReportWriter) section(title string) {
	w.ensure(38)
	w.y -= 8
	w.rect(32, w.y-5, 4, 18, 0.04, 0.45, 0.75)
	w.text(44, w.y, 14, true, 0.055, 0.102, 0.180, title)
	w.y -= 25
	w.line(32, w.y+7, pdfPageWidth-32, w.y+7, 0.82, 0.85, 0.89)
}

func (w *pdfReportWriter) paragraph(value string) {
	lines := wrapPDFText(value, 100)
	w.ensure(float64(len(lines))*13 + 10)
	for _, line := range lines {
		w.text(36, w.y, 9, false, 0.18, 0.23, 0.30, line)
		w.y -= 13
	}
	w.y -= 6
}

func (w *pdfReportWriter) metricGrid(summary reportSummary) {
	metrics := []struct {
		label string
		value string
	}{
		{"Matching events", strconv.Itoa(summary.Events)},
		{"Unique sources", strconv.Itoa(summary.UniqueSources)},
		{"Alert records", strconv.Itoa(summary.Alerts)},
		{"High severity", strconv.Itoa(summary.HighSeverity)},
		{"Login attempts", strconv.Itoa(summary.Logins)},
		{"Payload observations", strconv.Itoa(summary.Payloads)},
		{"Sessions", strconv.Itoa(summary.Sessions)},
		{"Risk rating", fmt.Sprintf("%d - %s", summary.RiskScore, strings.ToUpper(summary.RiskLevel))},
	}
	cellW, cellH := 126.5, 54.0
	for i, metric := range metrics {
		if i%4 == 0 {
			w.ensure(cellH + 8)
		}
		x := 32 + float64(i%4)*(cellW+7)
		y := w.y - cellH
		w.rect(x, y, cellW, cellH, 0.95, 0.97, 0.99)
		w.strokeRect(x, y, cellW, cellH, 0.82, 0.86, 0.91)
		w.text(x+10, y+31, 15, true, 0.055, 0.102, 0.180, metric.value)
		w.text(x+10, y+14, 7.5, true, 0.35, 0.40, 0.47, strings.ToUpper(metric.label))
		if i%4 == 3 {
			w.y -= cellH + 8
		}
	}
	w.y -= 6
}

func (w *pdfReportWriter) bullets(title string, items []string) {
	if len(items) == 0 {
		return
	}
	w.ensure(28)
	w.text(36, w.y, 10.5, true, 0.055, 0.102, 0.180, title)
	w.y -= 17
	for _, item := range items {
		lines := wrapPDFText(item, 92)
		w.ensure(float64(len(lines))*12 + 5)
		w.text(39, w.y, 9, true, 0.04, 0.45, 0.75, "-")
		for index, line := range lines {
			x := 50.0
			if index > 0 {
				x = 50
			}
			w.text(x, w.y, 8.7, false, 0.18, 0.23, 0.30, line)
			w.y -= 12
		}
		w.y -= 3
	}
	w.y -= 3
}

func (w *pdfReportWriter) topTable(title, label string, rows []kv) {
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
			w.rect(32, w.y-height+5, pdfPageWidth-64, height, 0.975, 0.982, 0.99)
		}
		barWidth := 115 * float64(row.Count) / float64(maxCount)
		w.rect(pdfPageWidth-184, w.y-12, barWidth, 5, 0.20, 0.64, 0.88)
		for _, line := range lines {
			w.text(38, w.y-7, 8.3, false, 0.18, 0.23, 0.30, line)
			w.y -= 11
		}
		w.text(pdfPageWidth-55, w.y+float64(len(lines))*11-7, 8.5, true, 0.055, 0.102, 0.180, strconv.Itoa(row.Count))
		w.y -= 8
	}
	w.y -= 4
}

func (w *pdfReportWriter) tableHeader(left, right string) {
	w.ensure(23)
	w.rect(32, w.y-17, pdfPageWidth-64, 22, 0.055, 0.102, 0.180)
	w.text(38, w.y-10, 8, true, 1, 1, 1, strings.ToUpper(left))
	w.text(pdfPageWidth-68, w.y-10, 8, true, 1, 1, 1, strings.ToUpper(right))
	w.y -= 24
}

func (w *pdfReportWriter) operationalAlerts(alerts []alertRecord) {
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
			w.rect(32, w.y-height+5, pdfPageWidth-64, height, 0.975, 0.982, 0.99)
		}
		for _, line := range lines {
			w.text(38, w.y-7, 8.2, false, 0.18, 0.23, 0.30, line)
			w.y -= 11
		}
		w.text(pdfPageWidth-55, w.y+float64(len(lines))*11-7, 8.5, true, 0.055, 0.102, 0.180, strconv.Itoa(alert.Count))
		w.y -= 8
	}
}

func (w *pdfReportWriter) eventAppendix(events []storedEvent) {
	w.section("Evidence appendix - representative events")
	if len(events) == 0 {
		w.paragraph("No matching event records were available.")
		return
	}
	limit := min(120, len(events))
	w.paragraph(fmt.Sprintf("Showing the newest %d of %d matching records. Use the dashboard Event Explorer or Elasticsearch export for the complete machine-readable dataset.", limit, len(events)))
	for index, event := range events[:limit] {
		detail := firstNonEmpty(event.Alert, event.Detail, event.Command, event.Path, "event")
		head := strings.Join([]string{event.Time, event.Sensor, event.SrcIP, event.Port}, "  |  ")
		lines := wrapPDFText(detail, 88)
		height := 25 + float64(len(lines))*10
		w.ensure(height)
		if index%2 == 0 {
			w.rect(32, w.y-height+7, pdfPageWidth-64, height, 0.975, 0.982, 0.99)
		}
		w.text(38, w.y-6, 7.8, true, 0.055, 0.102, 0.180, head)
		w.y -= 14
		for _, line := range lines {
			w.text(38, w.y-5, 7.8, false, 0.25, 0.30, 0.37, line)
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

func (w *pdfReportWriter) text(x, y, size float64, bold bool, r, g, b float64, value string) {
	font := "F1"
	if bold {
		font = "F2"
	}
	fmt.Fprintf(&w.page.content, "BT /%s %.2f Tf %.3f %.3f %.3f rg %.2f %.2f Td (%s) Tj ET\n",
		font, size, r, g, b, x, y, escapePDFText(value))
}

func (w *pdfReportWriter) rect(x, y, width, height, r, g, b float64) {
	fmt.Fprintf(&w.page.content, "%.3f %.3f %.3f rg %.2f %.2f %.2f %.2f re f\n", r, g, b, x, y, width, height)
}

func (w *pdfReportWriter) strokeRect(x, y, width, height, r, g, b float64) {
	fmt.Fprintf(&w.page.content, "%.3f %.3f %.3f RG 0.6 w %.2f %.2f %.2f %.2f re S\n", r, g, b, x, y, width, height)
}

func (w *pdfReportWriter) line(x1, y1, x2, y2, r, g, b float64) {
	fmt.Fprintf(&w.page.content, "%.3f %.3f %.3f RG 0.6 w %.2f %.2f m %.2f %.2f l S\n", r, g, b, x1, y1, x2, y2)
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
	objects := make([][]byte, 4+len(d.pages)*2)
	objects[0] = []byte("<< /Type /Catalog /Pages 2 0 R >>")
	var kids strings.Builder
	for index := range d.pages {
		fmt.Fprintf(&kids, "%d 0 R ", 5+index*2)
	}
	objects[1] = []byte(fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", len(d.pages), kids.String()))
	objects[2] = []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	objects[3] = []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	for index, page := range d.pages {
		pageNumber := 5 + index*2
		contentNumber := pageNumber + 1
		footer := fmt.Sprintf("BT /F1 7.5 Tf 0.35 0.40 0.47 rg 32 27 Td (PRIVATE - XORE//HONEYPOT) Tj ET\nBT /F1 7.5 Tf 0.35 0.40 0.47 rg 516 27 Td (Page %d of %d) Tj ET\n", index+1, len(d.pages))
		stream := append(append([]byte(nil), page.content.Bytes()...), []byte(footer)...)
		objects[pageNumber-1] = []byte(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>", pdfPageWidth, pdfPageHeight, contentNumber))
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
