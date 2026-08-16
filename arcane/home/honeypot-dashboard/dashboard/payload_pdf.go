package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// renderThemedPayloadReportPDF renders one captured payload's static/dynamic
// analysis as a PDF, in the same reportData/pdfReportWriter shape
// renderThemedSandboxReportPDF (sandbox_pdf.go) already established for a
// non-telemetry, single-artifact report type. #474.
func renderThemedPayloadReportPDF(a binaryAnalysis, generated time.Time, theme pdfTheme, branding pdfBranding) []byte {
	writer := &pdfReportWriter{
		doc:      &pdfDocument{theme: theme, footerLeft: branding.withDefaults().FooterLeft},
		title:    "Payload Analysis Report",
		scope:    a.Hash,
		branding: branding.withDefaults(),
	}
	writer.newPage()
	writer.cover(reportData{
		Generated: generated,
		Title:     writer.title,
		Scope:     "SHA-256 " + a.SHA256,
		Summary: reportSummary{
			FirstSeen: a.OriginLabel,
		},
	})

	writer.section("Assessment")
	writer.sandboxMetricGrid([]sandboxPDFMetric{
		{Label: "Static risk", Value: fmt.Sprintf("%d - %s", a.RiskScore, strings.ToUpper(firstNonEmpty(a.RiskLevel, "not rated")))},
		{Label: "Classification", Value: joinNonEmpty(" / ", a.Classification.Label, a.Classification.Code)},
		{Label: "Entropy", Value: fmt.Sprintf("%.3f (%s)", a.EntropyValue, boolLabel(a.PackedLikely, "packed likely", "not packed-like"))},
		{Label: "Size", Value: a.Size},
		{Label: "YARA matches", Value: strconv.Itoa(len(a.YARAMatches))},
		{Label: "IOCs extracted", Value: strconv.Itoa(len(a.IOCs))},
		{Label: "Sandbox runs", Value: strconv.Itoa(len(a.SandboxRuns))},
		{Label: "GitHub verdict", Value: githubVerdictLabel(a.GitHubAnalysis)},
	})
	writer.paragraph(payloadAssessment(a))

	writer.sandboxKeyValues("Sample identity", [][2]string{
		{"Capture id", a.Hash},
		{"SHA-256", a.SHA256},
		{"SHA-1", a.SHA1},
		{"MD5", a.MD5},
		{"MIME / magic", joinNonEmpty(" / ", a.MIME, a.Magic)},
		{"Platform", a.Classification.Platform},
		{"Suggested analysis path", a.Classification.AnalysisPath},
		{"Script type", a.ScriptType},
		{"Family attribution", a.Family},
		{"First observed", a.OriginLabel},
	})

	if len(a.FormatInfo) > 0 {
		writer.bullets("Executable format details", limitStrings(a.FormatInfo, 60))
	}
	if len(a.Indicators) > 0 {
		writer.bullets("Script indicators", limitStrings(a.Indicators, 60))
	}
	writer.bullets("Indicators of compromise", limitStrings(a.IOCs, 80))
	if len(a.Rules) > 0 {
		items := make([]string, 0, len(a.Rules))
		for _, rule := range a.Rules {
			items = append(items, fmt.Sprintf("%s [%s] - %s", rule.Name, strings.ToUpper(rule.Severity), rule.Description))
		}
		writer.bullets("Static rule matches", limitStrings(items, 60))
	}

	writer.section("YARA and dynamic analysis")
	if a.YARAError != "" {
		writer.paragraph("YARA scan error: " + a.YARAError)
	} else if len(a.YARAMatches) == 0 {
		writer.paragraph("No YARA rule matched this sample as of " + firstNonEmpty(a.YARAScanned, "the last scan") + ".")
	} else {
		writer.bullets(fmt.Sprintf("YARA matches (scanned %s)", firstNonEmpty(a.YARAScanned, "unknown time")), limitStrings(a.YARAMatches, 60))
	}
	if len(a.SandboxRuns) == 0 {
		writer.paragraph("No isolated dynamic-analysis run has been queued for this sample yet.")
	} else {
		items := make([]string, 0, len(a.SandboxRuns))
		for _, run := range a.SandboxRuns {
			items = append(items, fmt.Sprintf("%s - %s - risk %d (%s)", run.CompletedAt, strings.ToUpper(firstNonEmpty(run.RunStatus, "unknown")), run.RiskScore, strings.ToUpper(firstNonEmpty(run.RiskLevel, "not rated"))))
		}
		writer.bullets("Sandbox runs", limitStrings(items, 40))
	}
	if a.GitHubAnalysis != nil {
		writer.sandboxKeyValues("GitHub-analysis verdict", [][2]string{
			{"Exit status", a.GitHubAnalysis.ExitStatus},
			{"Family", a.GitHubAnalysis.Family},
		})
	}

	writer.ensure(150)
	writer.section("Evidence access and limitations")
	writer.paragraph("The administrator dashboard provides the raw sample (read-only, sandboxed access), the full static analysis, and links to any queued Ghidra/sandbox/GitHub-analysis results. Use the SHA-256 above to open the corresponding VirusTotal file record.")
	writer.paragraph("Static analysis characterizes the file as captured; it does not execute it. Missing evidence (no YARA match, no sandbox run yet) is not proof of benign behavior. Risk scoring is a deterministic triage aid, not attribution or a compromise verdict.")
	return writer.doc.bytes()
}

func payloadAssessment(a binaryAnalysis) string {
	return fmt.Sprintf("Static analysis classifies this sample as %s (%s/100, %s). Review the evidence sections below, and any linked dynamic-analysis run, before drawing a verdict.",
		firstNonEmpty(a.Classification.Label, "an unclassified file"),
		strconv.Itoa(a.RiskScore), strings.ToUpper(firstNonEmpty(a.RiskLevel, "not rated")))
}

func githubVerdictLabel(result *githubAnalysisResult) string {
	if result == nil {
		return "not queued"
	}
	if result.Verdict != nil {
		return fmt.Sprintf("%d/%d %s", result.Verdict.Malicious, result.Verdict.Total, result.Verdict.Level)
	}
	return firstNonEmpty(result.ExitStatus, "queued")
}

func boolLabel(value bool, whenTrue, whenFalse string) string {
	if value {
		return whenTrue
	}
	return whenFalse
}
