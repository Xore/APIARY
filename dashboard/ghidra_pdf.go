package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// renderThemedGhidraReportPDF renders one Ghidra static-analysis result with
// the definition's theme and branding (#814). Same shape as
// renderThemedSandboxReportPDF/renderThemedPayloadReportPDF -- this file
// exists because a payload's Ghidra evidence (functions, strings, imports,
// capa capabilities, FLOSS deobfuscation, fuzzy hashes) is substantial
// enough to want its own themed/branded/scheduled report, the same way a
// sandbox run gets its own template instead of being a payload-report
// subsection (see reports_store.go's Ghidra template entry for the full
// reasoning).
func renderThemedGhidraReportPDF(result ghidraResult, generated time.Time, theme pdfTheme, branding pdfBranding) []byte {
	writer := &pdfReportWriter{
		doc:      &pdfDocument{theme: theme, footerLeft: branding.withDefaults().FooterLeft},
		title:    "Ghidra Static Analysis Report",
		scope:    "SHA-256 " + result.SHA256,
		branding: branding.withDefaults(),
	}
	writer.newPage()
	writer.cover(reportData{
		Generated: generated,
		Title:     writer.title,
		Scope:     "SHA-256 " + result.SHA256,
		Summary: reportSummary{
			FirstSeen: firstNonEmpty(result.RequestedAt, result.StartedAt),
			LastSeen:  result.CompletedAt,
		},
	})

	writer.section("Analysis assessment")
	writer.paragraph(ghidraAssessment(result))
	if result.AITriage != nil {
		writer.sandboxKeyValues("AI triage", [][2]string{
			{"Family guess", result.AITriage.FamilyGuess},
			{"Risk level", strings.ToUpper(firstNonEmpty(result.AITriage.RiskLevel, "not rated"))},
			{"Model", result.AITriage.Model},
			{"Evidence shown to model", result.AITriage.EvidenceShown},
		})
		writer.bullets("Behaviors noted", limitStrings(result.AITriage.Behaviors, 40))
	}

	writer.sandboxKeyValues("Sample identity", [][2]string{
		{"SHA-256", result.SHA256},
		{"Exit status", result.ExitStatus},
		{"Requested", result.RequestedAt},
		{"Completed", result.CompletedAt},
	})
	if result.Error != "" {
		writer.bullets("Failure evidence", []string{result.Error})
	}

	if result.Lief != nil {
		l := result.Lief
		writer.sandboxKeyValues("Structural info (lief)", [][2]string{
			{"Format", l.Format},
			{"Architecture", l.Architecture},
			{"Entry point", l.Entrypoint},
			{"Position-independent", strconv.FormatBool(l.IsPIE)},
			{"Sections", strconv.Itoa(l.SectionCount)},
			{"Stripped", formatBoolPtr(l.Stripped)},
			{"Is DLL", formatBoolPtr(l.IsDLL)},
			{"Compile timestamp", formatInt64Ptr(l.CompileTimestamp)},
		})
		writer.bullets("Linked libraries", limitStrings(l.Libraries, 60))
	}

	writer.section("Functions, strings, and imports")
	writer.sandboxMetricGrid([]sandboxPDFMetric{
		{Label: "Functions", Value: strconv.Itoa(len(result.Functions))},
		{Label: "Strings", Value: strconv.Itoa(len(result.Strings))},
		{Label: "Imports", Value: strconv.Itoa(len(result.Imports))},
		{Label: "Crypto constants", Value: strconv.Itoa(len(result.FindCrypt))},
	})
	writer.bullets(fmt.Sprintf("Functions (%d)", len(result.Functions)), limitStrings(ghidraFunctionLines(result.Functions), 80))
	writer.bullets(fmt.Sprintf("Strings (%d)", len(result.Strings)), limitStrings(result.Strings, 100))
	writer.bullets(fmt.Sprintf("Imports (%d)", len(result.Imports)), limitStrings(result.Imports, 100))
	if len(result.FindCrypt) > 0 {
		items := make([]string, 0, len(result.FindCrypt))
		for _, c := range result.FindCrypt {
			items = append(items, fmt.Sprintf("%s: %s (%s)", c.Address, c.Algorithm, c.Constant))
		}
		writer.bullets("Cryptographic constants", limitStrings(items, 60))
	}

	if result.Capa != nil {
		writer.section("Capabilities (capa)")
		if result.Capa.Unsupported != "" {
			writer.paragraph("capa declined this sample: " + result.Capa.Unsupported)
		} else if len(result.Capa.Capabilities) == 0 {
			writer.paragraph("No capabilities observed.")
		} else {
			items := make([]string, 0, len(result.Capa.Capabilities))
			for _, cap := range result.Capa.Capabilities {
				items = append(items, fmt.Sprintf("%s (%s) - %d match(es)", cap.Name, cap.Namespace, cap.Matches))
			}
			writer.bullets(fmt.Sprintf("Capabilities (%d)", len(result.Capa.Capabilities)), limitStrings(items, 80))
			var attack []string
			for _, a := range result.Capa.Attack {
				attack = append(attack, strings.TrimSpace(a.ID+" "+a.Tactic+" - "+a.Technique+" "+a.Subtechnique))
			}
			writer.bullets("ATT&CK mapping", limitStrings(attack, 60))
			var mbc []string
			for _, m := range result.Capa.MBC {
				mbc = append(mbc, strings.TrimSpace(m.ID+" "+m.Objective+" - "+m.Behavior+" "+m.Method))
			}
			writer.bullets("Malware Behavior Catalog mapping", limitStrings(mbc, 60))
		}
	}

	if result.Floss != nil {
		writer.section("Deobfuscated strings (FLOSS)")
		if result.Floss.Unsupported != "" {
			writer.paragraph("FLOSS declined this sample: " + result.Floss.Unsupported)
		} else {
			writer.bullets(fmt.Sprintf("Static strings (%d of %d)", len(result.Floss.StaticStrings), result.Floss.StaticStringsTotal), limitStrings(result.Floss.StaticStrings, 60))
			writer.bullets(fmt.Sprintf("Stack strings (%d of %d)", len(result.Floss.StackStrings), result.Floss.StackStringsTotal), limitStrings(result.Floss.StackStrings, 60))
			writer.bullets(fmt.Sprintf("Tight strings (%d of %d)", len(result.Floss.TightStrings), result.Floss.TightStringsTotal), limitStrings(result.Floss.TightStrings, 60))
			writer.bullets(fmt.Sprintf("Decoded strings (%d of %d)", len(result.Floss.DecodedStrings), result.Floss.DecodedStringsTotal), limitStrings(result.Floss.DecodedStrings, 60))
		}
	}

	if result.FuzzyHashes != nil {
		writer.sandboxKeyValues("Fuzzy hashes", [][2]string{
			{"ssdeep", firstNonEmpty(result.FuzzyHashes.SSDeep, result.FuzzyHashes.SSDeepError)},
			{"TLSH", firstNonEmpty(result.FuzzyHashes.TLSH, result.FuzzyHashes.TLSHError)},
		})
	}

	if result.RevDeck != nil && result.RevDeck.Answer != "" {
		writer.section("Rev·Deck assisted analysis")
		writer.sandboxKeyValues("Run", [][2]string{
			{"Workflow", result.RevDeck.Workflow},
			{"Status", result.RevDeck.Status},
			{"Tool calls", strconv.Itoa(result.RevDeck.ToolCalls)},
		})
		writer.paragraph(result.RevDeck.Answer)
		writer.bullets("Warnings", limitStrings(result.RevDeck.Warnings, 20))
	}

	if result.IOCCorrelation != nil && !result.IOCCorrelation.Empty() {
		writer.section("Correlation against Windows-sandbox runs")
		writer.paragraph("FLOSS-decoded strings above cross-referenced against any Windows-sandbox execution of this same SHA-256, by IP/URL/domain/UNC pattern. \"Confirmed at runtime\" is the strongest signal: a value FLOSS decoded from the binary that a sandbox run also actually observed happening.")
		writer.sandboxKeyValues("Confirmed at runtime", [][2]string{
			{"IP addresses", strconv.Itoa(len(result.IOCCorrelation.IPs.ConfirmedAtRuntime))},
			{"Domains", strconv.Itoa(len(result.IOCCorrelation.Domains.ConfirmedAtRuntime))},
			{"URLs", strconv.Itoa(len(result.IOCCorrelation.URLs.ConfirmedAtRuntime))},
		})
		writer.bullets("Confirmed IP addresses", limitStrings(result.IOCCorrelation.IPs.ConfirmedAtRuntime, 40))
		writer.bullets("Confirmed domains", limitStrings(result.IOCCorrelation.Domains.ConfirmedAtRuntime, 40))
		writer.bullets("Confirmed URLs", limitStrings(result.IOCCorrelation.URLs.ConfirmedAtRuntime, 40))
	}

	writer.ensure(150)
	writer.section("Evidence access and limitations")
	writer.paragraph("The administrator dashboard provides the sanitized JSON result, the rendered call graph (when graphviz is installed on the analysis host), and the raw sample. Use the SHA-256 above to open the corresponding VirusTotal file record.")
	writer.paragraph("This is a static analysis: it describes what the sample contains, not what it does when run. capa and FLOSS each cover a bounded set of formats/architectures -- \"unsupported\" above means the tool declined this sample's format, not that it found nothing. AI triage and Rev·Deck answers are model output over attacker-influenced content and must be reviewed, not trusted as fact.")
	return writer.doc.bytes()
}

func ghidraAssessment(result ghidraResult) string {
	if result.ExitStatus == "error" || result.CompletedAt == "" {
		return "Analysis did not complete successfully. Empty evidence sections indicate an infrastructure or execution failure and must not be interpreted as a clean payload result."
	}
	return fmt.Sprintf("Headless decompilation completed: %d function(s), %d string(s), and %d import(s) recovered. Review the evidence sections below before drawing a verdict.",
		len(result.Functions), len(result.Strings), len(result.Imports))
}

func ghidraFunctionLines(functions []ghidraFunction) []string {
	items := make([]string, 0, len(functions))
	for _, f := range functions {
		name := firstNonEmpty(f.Name, "(unnamed)")
		items = append(items, fmt.Sprintf("%s %s - %s (%d bytes)", f.Address, name, f.Signature, f.Size))
	}
	return items
}

func formatBoolPtr(value *bool) string {
	if value == nil {
		return ""
	}
	return strconv.FormatBool(*value)
}

func formatInt64Ptr(value *int64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(*value, 10)
}
