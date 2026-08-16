package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type sandboxPDFMetric struct {
	Label string
	Value string
}

// renderThemedSandboxReportPDF renders a sandbox analysis run with the
// definition's theme and branding.
func renderThemedSandboxReportPDF(result sandboxResult, generated time.Time, theme pdfTheme, branding pdfBranding) []byte {
	writer := &pdfReportWriter{
		doc:      &pdfDocument{theme: theme, footerLeft: branding.withDefaults().FooterLeft},
		title:    "Sandbox Dynamic Analysis Report",
		scope:    result.Job,
		branding: branding.withDefaults(),
	}
	writer.newPage()
	writer.cover(reportData{
		Generated: generated,
		Title:     writer.title,
		Scope:     result.Job + " | SHA-256 " + result.SHA256,
		Summary: reportSummary{
			FirstSeen: firstNonEmpty(result.StartedAt, result.RequestedAt),
			LastSeen:  result.CompletedAt,
		},
	})

	writer.section("Run assessment")
	writer.sandboxMetricGrid([]sandboxPDFMetric{
		{Label: "Dynamic risk", Value: fmt.Sprintf("%d - %s", result.RiskScore, strings.ToUpper(firstNonEmpty(result.RiskLevel, "not rated")))},
		{Label: "Run status", Value: strings.ToUpper(firstNonEmpty(result.RunStatus, "unknown"))},
		{Label: "Duration", Value: fmt.Sprintf("%.1f seconds", result.Duration)},
		{Label: "Guest started", Value: strconv.FormatBool(result.GuestStarted)},
		{Label: "Processes added", Value: strconv.Itoa(len(result.ProcessDiff.Added))},
		{Label: "Sockets added", Value: strconv.Itoa(len(result.SocketDiff.Added))},
		{Label: "DNS names", Value: strconv.Itoa(len(result.NetworkSummary.DNSQueries))},
		{Label: "Changed files", Value: strconv.Itoa(len(result.ChangedFiles))},
	})
	writer.paragraph(sandboxAssessment(result))

	writer.sandboxKeyValues("Sample and execution identity", [][2]string{
		{"SHA-256", result.SHA256},
		{"SHA-1", result.Hashes.SHA1},
		{"MD5", result.Hashes.MD5},
		{"Capture name", result.CaptureName},
		{"Source", result.Source},
		{"File type", result.FileType},
		{"Classification", joinNonEmpty(" / ", result.Classification.Label, result.Classification.Code)},
		{"Platform / category", joinNonEmpty(" / ", result.Platform, result.Classification.Category)},
		{"Selected analysis path", firstNonEmpty(result.AnalysisPath, result.Classification.AnalysisPath)},
		{"Execution mode", firstNonEmpty(result.ExecutionMode, result.Windows.ExecutionMode)},
		{"Exit status", result.ExitStatus},
	})
	if result.FailureReason != "" || result.TimeoutReason != "" {
		writer.bullets("Infrastructure failure evidence", nonEmptyStrings(result.FailureReason, result.TimeoutReason))
	}

	writer.sandboxDifference("Process difference", result.ProcessDiff,
		"Userspace commands added or removed between pre- and post-execution snapshots. Volatile PID and resource columns plus kernel-worker churn are normalized.")
	writer.sandboxDifference("Sockets difference", result.SocketDiff,
		"Socket rows added or removed between pre- and post-execution snapshots.")

	writer.section("Network and DNS evidence")
	writer.sandboxMetricGrid([]sandboxPDFMetric{
		{Label: "Host packets", Value: strconv.Itoa(result.NetworkSummary.Packets)},
		{Label: "Host bytes", Value: strconv.FormatInt(result.NetworkSummary.Bytes, 10)},
		{Label: "Guest packets", Value: strconv.Itoa(result.NetworkSummary.GuestPackets)},
		{Label: "Guest PCAP bytes", Value: strconv.FormatInt(result.NetworkSummary.GuestPCAPBytes, 10)},
	})
	writer.bullets("Captured DNS names", limitStrings(result.NetworkSummary.DNSQueries, 80))
	writer.bullets("Network attempts", limitStrings(result.NetworkSummary.Attempts, 80))
	writer.bullets("Host capture events", limitStrings(result.NetworkSummary.Events, 60))
	writer.bullets("Guest capture events", limitStrings(result.NetworkSummary.GuestEvents, 60))

	if len(result.Techniques) > 0 {
		items := make([]string, 0, len(result.Techniques))
		for _, technique := range result.Techniques {
			items = append(items, strings.TrimSpace(technique.ID+" "+technique.Name+" - "+technique.Evidence))
		}
		writer.bullets("ATT&CK behavior mapping", limitStrings(items, 60))
	}
	writer.bullets("Changed files", limitStrings(result.ChangedFiles, 100))
	if len(result.TopSyscalls) > 0 {
		items := make([]string, 0, len(result.TopSyscalls))
		for _, syscall := range result.TopSyscalls {
			items = append(items, fmt.Sprintf("%s - %d calls", syscall.Name, syscall.Count))
		}
		writer.bullets("Top system calls", limitStrings(items, 50))
	}

	if result.Windows.Detected {
		writer.sandboxWindowsForensics(result.Windows)
	}

	writer.ensure(150)
	writer.section("Evidence access and limitations")
	writer.paragraph("The administrator dashboard provides the sanitized JSON result and, when retained, host PCAP, guest PCAP, and a bounded diagnostics bundle. Use the SHA-256 on the result page to open the corresponding VirusTotal file record.")
	writer.paragraph("Dynamic analysis records what this bounded isolated run observed. Missing evidence is not proof of benign behavior. Emulation, guest time limits, environment checks, unsupported formats, encrypted traffic, and delayed execution can reduce visibility. Risk scoring and ATT&CK mappings are deterministic triage aids, not attribution or a compromise verdict.")
	return writer.doc.bytes()
}

func sandboxAssessment(result sandboxResult) string {
	if result.Incomplete || result.RunStatus != "completed" {
		return "Analysis did not run to completion. Empty evidence sections indicate an infrastructure or execution failure and must not be interpreted as a clean payload result."
	}
	return fmt.Sprintf("The isolated guest completed the selected %s path. The deterministic dynamic risk score is %d/100 (%s); review the evidence sections before drawing a verdict.",
		firstNonEmpty(result.AnalysisPath, result.Classification.AnalysisPath, "sandbox analysis"),
		result.RiskScore, strings.ToUpper(firstNonEmpty(result.RiskLevel, "not rated")))
}

func (w *pdfReportWriter) sandboxMetricGrid(metrics []sandboxPDFMetric) {
	t := w.theme()
	cellW, cellH := 126.5, 54.0
	for index, metric := range metrics {
		if index%4 == 0 {
			w.ensure(cellH + 8)
		}
		x := 32 + float64(index%4)*(cellW+7)
		y := w.y - cellH
		w.rect(x, y, cellW, cellH, t.Card)
		w.strokeRect(x, y, cellW, cellH, t.CardBorder)
		value := firstNonEmpty(metric.Value, "not available")
		if len(value) > 22 {
			value = value[:19] + "..."
		}
		w.text(x+10, y+31, 13, true, t.BrandText, value)
		w.text(x+10, y+14, 7.5, true, t.MutedText, strings.ToUpper(metric.Label))
		if index%4 == 3 || index == len(metrics)-1 {
			w.y -= cellH + 8
		}
	}
	w.y -= 6
}

func (w *pdfReportWriter) sandboxKeyValues(title string, rows [][2]string) {
	t := w.theme()
	w.section(title)
	for index, row := range rows {
		if strings.TrimSpace(row[1]) == "" {
			continue
		}
		lines := wrapPDFText(row[1], 70)
		height := max(24.0, float64(len(lines))*11+10)
		w.ensure(height)
		if index%2 == 0 {
			w.rect(32, w.y-height+5, pdfPageWidth-64, height, t.AltRow)
		}
		w.text(38, w.y-7, 8, true, t.MutedText, strings.ToUpper(row[0]))
		for lineIndex, line := range lines {
			w.text(176, w.y-7-float64(lineIndex)*11, 8.2, false, t.BrandText, line)
		}
		w.y -= height
	}
	w.y -= 5
}

func (w *pdfReportWriter) sandboxDifference(title string, diff sandboxDifference, note string) {
	w.section(title)
	w.paragraph(note)
	if len(diff.Added) == 0 && len(diff.Removed) == 0 {
		w.paragraph("No added or removed entries were observed.")
		return
	}
	w.bullets(fmt.Sprintf("Added (%d)", len(diff.Added)), limitStrings(diff.Added, 100))
	w.bullets(fmt.Sprintf("Removed (%d)", len(diff.Removed)), limitStrings(diff.Removed, 100))
}

func (w *pdfReportWriter) sandboxWindowsForensics(result sandboxWindows) {
	w.sandboxKeyValues("Windows PE forensics", [][2]string{
		{"Format / machine", joinNonEmpty(" / ", result.PEType, result.Machine)},
		{"Execution mode", result.ExecutionMode},
		{"Compile timestamp", result.CompileTimestamp},
		{"Entry point", strconv.FormatInt(result.EntryPoint, 10)},
		{"Image base", strconv.FormatInt(result.ImageBase, 10)},
		{"Import hash", result.ImpHash},
		{"Embedded signature", strconv.FormatBool(result.SignaturePresent)},
	})
	var imports []string
	for _, item := range result.Imports {
		imports = append(imports, item.DLL+": "+strings.Join(limitStrings(item.Symbols, 30), ", "))
	}
	w.bullets("Imported libraries and symbols", limitStrings(imports, 80))
	keys := make([]string, 0, len(result.SuspiciousImports))
	for key := range result.SuspiciousImports {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var suspicious []string
	for _, key := range keys {
		suspicious = append(suspicious, key+": "+strings.Join(result.SuspiciousImports[key], ", "))
	}
	w.bullets("Suspicious Windows API imports", limitStrings(suspicious, 60))
	w.bullets("Parser warnings", limitStrings(result.Warnings, 40))
}

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	out := append([]string(nil), values[:limit]...)
	return append(out, fmt.Sprintf("... %d additional entries omitted from this bounded report", len(values)-limit))
}

func nonEmptyStrings(values ...string) []string {
	var out []string
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func joinNonEmpty(separator string, values ...string) string {
	return strings.Join(nonEmptyStrings(values...), separator)
}
