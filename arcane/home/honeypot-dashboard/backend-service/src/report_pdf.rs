//! Hand-rolled, dependency-free PDF report composer, ported from
//! dashboard/report_pdf.go + report_pdf_brandmark.go + report_pdf_watermark.go
//! (#1612 phase 4a). No external PDF library on either side of the port —
//! this emits raw PDF 1.4 syntax directly: uncompressed per-page content
//! streams of plain operators (BT/ET text, rg/RG color, re rectangles, m/l
//! lines, cm/Do/gs for the two embedded image masks), a fixed small set of
//! indirect objects (Catalog, Pages, 3 Type1 fonts, the watermark image +
//! its ExtGState, the header-mark image, then one Page+Contents pair per
//! page), and a plain xref table + trailer. Object numbers 1-8 are fixed
//! (see `bytes()` below); page objects start at 9.
//!
//! This module is pure: given an already-assembled [`ReportData`] plus a
//! theme/branding/element selection, it returns PDF bytes. It does not
//! touch Elasticsearch or HTTP — gathering `ReportData` from live telemetry
//! (the Go tier's `reportDataFor`) is a later phase's job.
//!
//! No route calls `render_report_pdf` yet — the definitions API, generate
//! endpoint, and `ReportData` assembly land in #1612 phase 4b.

use std::fmt::Write as _;

const PDF_PAGE_WIDTH: f64 = 595.0;
const PDF_PAGE_HEIGHT: f64 = 842.0;

/// Bounds how much of a single event's alert/detail/command/path field
/// `event_appendix` renders — mirrors eventAppendixDetailCap (#885).
const EVENT_APPENDIX_DETAIL_CAP: usize = 2000;

/// Cuts `s` to at most `max` bytes without splitting a multi-byte UTF-8
/// character in half.
fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[derive(Clone, Copy, Debug)]
pub struct PdfRgb {
    pub r: f64,
    pub g: f64,
    pub b: f64,
}

/// Carries every palette decision of the rendered report, so a definition
/// can render dark (screen-style) or light (print-style) PDFs. Both
/// palettes are snapshots of the canonical Xore/theme tokens.
#[derive(Clone, Copy, Debug)]
pub struct PdfTheme {
    pub page: PdfRgb,
    pub header_band: PdfRgb,
    pub header_rule: PdfRgb,
    pub brand_text: PdfRgb,
    pub muted_text: PdfRgb,
    pub body_text: PdfRgb,
    pub accent: PdfRgb,
    pub card: PdfRgb,
    pub card_border: PdfRgb,
    pub alt_row: PdfRgb,
    pub table_header: PdfRgb,
    pub bar: PdfRgb,
    pub faint_text: PdfRgb,
    pub success: PdfRgb,
    pub warning: PdfRgb,
    pub danger: PdfRgb,
    #[allow(dead_code)] // ported 1:1 with the Go palette; not read by any element yet
    pub link: PdfRgb,
}

#[rustfmt::skip]
/// The canonical Xore/theme dark palette (theme.css :root). Kept as compact
/// one-liners (rustfmt disabled locally) so this stays a legible diff
/// against report_pdf.go's own pdfThemeDark table.
pub fn pdf_theme_dark() -> PdfTheme {
    PdfTheme {
        page:        PdfRgb { r: 0.125, g: 0.125, b: 0.122 }, // #20201f
        header_band: PdfRgb { r: 0.118, g: 0.118, b: 0.110 }, // #1e1e1c
        header_rule: PdfRgb { r: 0.204, g: 0.204, b: 0.196 }, // #343432
        brand_text:  PdfRgb { r: 0.914, g: 0.902, b: 0.875 }, // #e9e6df
        muted_text:  PdfRgb { r: 0.549, g: 0.561, b: 0.553 }, // #8c8f8d
        body_text:   PdfRgb { r: 0.740, g: 0.740, b: 0.710 },
        accent:      PdfRgb { r: 0.851, g: 0.467, b: 0.341 }, // #d97757
        card:        PdfRgb { r: 0.173, g: 0.173, b: 0.165 }, // #2c2c2a
        card_border: PdfRgb { r: 0.239, g: 0.239, b: 0.231 }, // #3d3d3b
        alt_row:     PdfRgb { r: 0.151, g: 0.151, b: 0.145 },
        table_header:PdfRgb { r: 0.220, g: 0.220, b: 0.208 }, // #383835
        bar:         PdfRgb { r: 0.427, g: 0.655, b: 0.925 }, // #6da7ec
        faint_text:  PdfRgb { r: 0.660, g: 0.670, b: 0.650 },
        success:     PdfRgb { r: 0.475, g: 0.788, b: 0.620 }, // #79c99e
        warning:     PdfRgb { r: 0.871, g: 0.702, b: 0.416 }, // #deb36a
        danger:      PdfRgb { r: 0.863, g: 0.467, b: 0.455 }, // #dc7774
        link:        PdfRgb { r: 0.427, g: 0.655, b: 0.925 }, // #6da7ec
    }
}

#[rustfmt::skip]
/// The canonical Xore/theme light palette — the print-safe token snapshot
/// from the Xore/Honeypot scan-report design (report.py).
pub fn pdf_theme_light() -> PdfTheme {
    PdfTheme {
        page:        PdfRgb { r: 0.969, g: 0.965, b: 0.949 }, // #f7f6f2
        header_band: PdfRgb { r: 0.957, g: 0.949, b: 0.929 }, // #f4f2ed
        header_rule: PdfRgb { r: 0.819, g: 0.813, b: 0.798 }, // border-strong composite
        brand_text:  PdfRgb { r: 0.184, g: 0.169, b: 0.153 }, // #2f2b27
        muted_text:  PdfRgb { r: 0.569, g: 0.541, b: 0.510 }, // #918a82
        body_text:   PdfRgb { r: 0.300, g: 0.280, b: 0.250 }, // primary/secondary blend
        accent:      PdfRgb { r: 0.780, g: 0.396, b: 0.282 }, // #c76548
        card:        PdfRgb { r: 0.984, g: 0.980, b: 0.969 }, // #fbfaf7
        card_border: PdfRgb { r: 0.908, g: 0.903, b: 0.891 }, // border-subtle composite
        alt_row:     PdfRgb { r: 0.961, g: 0.955, b: 0.937 }, // rgba(#f4f2ed, 0.65) on app-bg
        table_header:PdfRgb { r: 0.922, g: 0.914, b: 0.890 }, // #ebe9e3
        bar:         PdfRgb { r: 0.165, g: 0.471, b: 0.839 }, // #2a78d6
        faint_text:  PdfRgb { r: 0.569, g: 0.541, b: 0.510 },
        success:     PdfRgb { r: 0.247, g: 0.529, b: 0.392 }, // #3f8764
        warning:     PdfRgb { r: 0.608, g: 0.420, b: 0.145 }, // #9b6b25
        danger:      PdfRgb { r: 0.702, g: 0.310, b: 0.298 }, // #b34f4c
        link:        PdfRgb { r: 0.165, g: 0.471, b: 0.839 }, // #2a78d6
    }
}

pub fn pdf_theme_named(name: &str) -> PdfTheme {
    if name == "light" {
        pdf_theme_light()
    } else {
        pdf_theme_dark()
    }
}

impl PdfTheme {
    /// Maps a triage level to the theme's semantic color, mirroring the
    /// badge system of the canonical scan-report design.
    fn risk_color(&self, level: &str) -> PdfRgb {
        match level.to_lowercase().as_str() {
            "low" | "clean" | "minimal" => self.success,
            "medium" | "elevated" | "guard" => self.warning,
            "high" | "critical" | "severe" => self.danger,
            _ => self.brand_text,
        }
    }
}

/// The operator-configurable identity of a report: header/footer copy,
/// classification line, and author. Empty fields fall back to the
/// deployment defaults so existing output stays byte-identical.
#[derive(Clone, Debug, Default)]
pub struct PdfBranding {
    pub header_left: String,
    pub header_right: String,
    pub footer_left: String,
    pub classification: String,
    pub author: String,
}

pub fn default_pdf_branding() -> PdfBranding {
    PdfBranding {
        header_left: "APIARY".into(),
        header_right: "DEFENSIVE SECURITY OPERATIONS".into(),
        footer_left: "PRIVATE - APIARY".into(),
        classification: "PRIVATE - contains hostile-source telemetry and forensic indicators".into(),
        author: String::new(),
    }
}

impl PdfBranding {
    pub fn with_defaults(mut self) -> Self {
        let defaults = default_pdf_branding();
        if self.header_left.is_empty() {
            self.header_left = defaults.header_left;
        }
        if self.header_right.is_empty() {
            self.header_right = defaults.header_right;
        }
        if self.footer_left.is_empty() {
            self.footer_left = defaults.footer_left;
        }
        if self.classification.is_empty() {
            self.classification = defaults.classification;
        }
        self
    }
}

/// Element ID strings a report definition selects, in Reports studio order.
/// These exact string literals are also the wire values Phase 4b's
/// definitions API stores/accepts — keep them in sync with
/// dashboard/reports_store.go's elementCover/etc. constants.
pub const ELEMENT_COVER: &str = "cover";
pub const ELEMENT_METRICS: &str = "metrics";
pub const ELEMENT_ASSESSMENT: &str = "assessment";
pub const ELEMENT_FINDINGS: &str = "findings";
pub const ELEMENT_RECOMMENDATIONS: &str = "recommendations";
pub const ELEMENT_TOP_SENSORS: &str = "top_sensors";
pub const ELEMENT_TOP_SOURCES: &str = "top_sources";
pub const ELEMENT_TOP_SIGNATURES: &str = "top_signatures";
pub const ELEMENT_TOP_ASNS: &str = "top_asns";
pub const ELEMENT_TOP_COUNTRIES: &str = "top_countries";
pub const ELEMENT_TOP_PORTS: &str = "top_ports";
pub const ELEMENT_OPERATIONAL_ALERTS: &str = "operational_alerts";
pub const ELEMENT_EVENT_APPENDIX: &str = "event_appendix";
pub const ELEMENT_PARAMETERS: &str = "parameters";

/// One ranked key/count row (mirrors dashboard/pages_data.go's `kv`).
#[derive(Clone, Debug, Default)]
pub struct Kv {
    pub key: String,
    pub count: i64,
    #[allow(dead_code)] // ported for parity; no report element reads it yet
    pub link: String,
    /// Full value when `key` is shortened for display; falls back to `key`.
    pub title: String,
}

/// One operational dashboard alert record (dashboard-alert-state-v1 shape —
/// see src/worker.rs's Notifier::observe for the field names already in use
/// in this crate: Key/Message/Link/FirstSeen/LastSeen/Count/Acknowledged).
/// Only the fields `operational_alerts()` actually renders are kept here.
#[derive(Clone, Debug, Default)]
pub struct AlertRecord {
    pub message: String,
    pub count: i64,
    pub acknowledged: bool,
}

/// One representative event row for the evidence appendix. A local,
/// report-specific shape rather than this crate's ECS-oriented EventRow
/// (src/events.rs) — the appendix wants alert/detail/command/path as
/// distinct fallback fields, which EventRow doesn't carry.
#[derive(Clone, Debug, Default)]
pub struct ReportEventRow {
    pub time: String,
    pub sensor: String,
    pub src_ip: String,
    pub port: String,
    pub alert: String,
    pub detail: String,
    pub command: String,
    pub path: String,
}

#[derive(Clone, Debug, Default)]
pub struct ReportSummary {
    pub events: i64,
    pub alerts: i64,
    pub high_severity: i64,
    pub unique_sources: i64,
    pub logins: i64,
    pub payloads: i64,
    pub sessions: i64,
    pub commands: i64,
    pub sensors: i64,
    pub open_operational: i64,
    pub first_seen: String,
    pub last_seen: String,
    pub risk_score: i64,
    pub risk_level: String,
}

#[derive(Clone, Debug, Default)]
pub struct ReportData {
    pub generated: chrono::DateTime<chrono::Utc>,
    pub title: String,
    pub scope: String,
    pub filters: Vec<String>,
    pub summary: ReportSummary,
    pub events: Vec<ReportEventRow>,
    pub top_sensors: Vec<Kv>,
    pub top_sources: Vec<Kv>,
    pub top_signatures: Vec<Kv>,
    pub top_asns: Vec<Kv>,
    pub top_countries: Vec<Kv>,
    pub top_ports: Vec<Kv>,
    pub operational_alerts: Vec<AlertRecord>,
    pub findings: Vec<String>,
    pub recommendations: Vec<String>,
}

struct PdfPage {
    content: String,
}

struct PdfDocument {
    pages: Vec<PdfPage>,
    theme: PdfTheme,
    footer_left: String,
}

struct PdfReportWriter {
    doc: PdfDocument,
    y: f64,
    branding: PdfBranding,
}

impl PdfReportWriter {
    fn theme(&self) -> PdfTheme {
        self.doc.theme
    }

    fn page_mut(&mut self) -> &mut PdfPage {
        self.doc.pages.last_mut().expect("new_page always pushes a page before returning")
    }

    fn new_page(&mut self) {
        let t = self.theme();
        self.doc.pages.push(PdfPage { content: String::new() });
        self.y = PDF_PAGE_HEIGHT - 68.0;
        self.rect(0.0, 0.0, PDF_PAGE_WIDTH, PDF_PAGE_HEIGHT, t.page);
        // Drawn immediately after the solid background and before anything
        // else -- content streams paint in the order they're written, so
        // everything below ends up visually on top of this, never the
        // reverse.
        self.draw_watermark();
        self.rect(0.0, PDF_PAGE_HEIGHT - 48.0, PDF_PAGE_WIDTH, 48.0, t.header_band);
        self.line(0.0, PDF_PAGE_HEIGHT - 48.0, PDF_PAGE_WIDTH, PDF_PAGE_HEIGHT - 48.0, t.header_rule);
        self.draw_header_mark();
        let header_left = self.branding.header_left.clone();
        let header_right = self.branding.header_right.clone();
        self.text(62.0, PDF_PAGE_HEIGHT - 29.0, 12.0, true, t.brand_text, &header_left);
        self.text(PDF_PAGE_WIDTH - 188.0, PDF_PAGE_HEIGHT - 29.0, 7.5, false, t.muted_text, &header_right);
    }

    fn ensure(&mut self, height: f64) {
        if self.y - height < 55.0 {
            self.new_page();
        }
    }

    fn cover(&mut self, data: &ReportData) {
        let t = self.theme();
        self.display_text(32.0, self.y, 25.0, t.brand_text, &data.title);
        self.y -= 29.0;
        self.text(32.0, self.y, 9.0, true, t.accent, "REPORT SCOPE");
        self.y -= 17.0;
        for line in wrap_pdf_text(&data.scope, 88) {
            self.text(32.0, self.y, 10.0, false, t.brand_text, &line);
            self.y -= 14.0;
        }
        self.y -= 4.0;
        if !self.branding.author.is_empty() {
            let line = format!("Author: {}", self.branding.author);
            self.text(32.0, self.y, 8.5, false, t.muted_text, &line);
            self.y -= 13.0;
        }
        let generated = format!("Generated: {}", data.generated.format("%Y-%m-%d %H:%M:%S UTC"));
        self.text(32.0, self.y, 8.5, false, t.muted_text, &generated);
        self.y -= 13.0;
        // #1567: "not available to not available" read as a copy bug --
        // when neither bound is known, say so once.
        let window = if !data.summary.first_seen.is_empty() || !data.summary.last_seen.is_empty() {
            format!(
                "{} to {}",
                first_non_empty(&[&data.summary.first_seen], "unknown"),
                first_non_empty(&[&data.summary.last_seen], "unknown"),
            )
        } else {
            "not available".to_string()
        };
        let observed = format!("Observed window: {window}");
        self.text(32.0, self.y, 8.5, false, t.muted_text, &observed);
        self.y -= 13.0;
        let classification = format!("Classification: {}", self.branding.classification);
        self.text(32.0, self.y, 8.5, false, t.accent, &classification);
        self.y -= 28.0;
    }

    fn section(&mut self, title: &str) {
        let t = self.theme();
        // Keep a section heading with at least one useful row or paragraph
        // beneath it.
        self.ensure(70.0);
        self.y -= 8.0;
        self.rect(32.0, self.y - 5.0, 4.0, 18.0, t.accent);
        self.display_text(44.0, self.y, 15.0, t.brand_text, title);
        self.y -= 25.0;
        self.line(32.0, self.y + 7.0, PDF_PAGE_WIDTH - 32.0, self.y + 7.0, t.header_rule);
    }

    fn paragraph(&mut self, value: &str) {
        let t = self.theme();
        let lines = wrap_pdf_text(value, 100);
        self.ensure(lines.len() as f64 * 13.0 + 10.0);
        for line in &lines {
            self.text(36.0, self.y, 9.0, false, t.body_text, line);
            self.y -= 13.0;
        }
        self.y -= 6.0;
    }

    fn metric_grid(&mut self, summary: &ReportSummary) {
        let t = self.theme();
        let risk_color = t.risk_color(&summary.risk_level);
        let metrics: [(&str, String, PdfRgb); 8] = [
            ("Matching events", summary.events.to_string(), t.brand_text),
            ("Unique sources", summary.unique_sources.to_string(), t.brand_text),
            ("Alert records", summary.alerts.to_string(), t.brand_text),
            ("High severity", summary.high_severity.to_string(), t.brand_text),
            ("Login attempts", summary.logins.to_string(), t.brand_text),
            ("Payload observations", summary.payloads.to_string(), t.brand_text),
            ("Sessions", summary.sessions.to_string(), t.brand_text),
            ("Risk rating", format!("{} - {}", summary.risk_score, summary.risk_level.to_uppercase()), risk_color),
        ];
        let (cell_w, cell_h) = (126.5, 54.0);
        for (i, (label, value, color)) in metrics.iter().enumerate() {
            if i % 4 == 0 {
                self.ensure(cell_h + 8.0);
            }
            let x = 32.0 + (i % 4) as f64 * (cell_w + 7.0);
            let y = self.y - cell_h;
            self.rect(x, y, cell_w, cell_h, t.card);
            self.stroke_rect(x, y, cell_w, cell_h, t.card_border);
            self.text(x + 10.0, y + 31.0, 15.0, true, *color, value);
            self.text(x + 10.0, y + 14.0, 7.5, true, t.muted_text, &label.to_uppercase());
            if i % 4 == 3 {
                self.y -= cell_h + 8.0;
            }
        }
        self.y -= 6.0;
    }

    fn bullets(&mut self, title: &str, items: &[String]) {
        let t = self.theme();
        if items.is_empty() {
            return;
        }
        self.ensure(28.0);
        self.text(36.0, self.y, 10.5, true, t.brand_text, title);
        self.y -= 17.0;
        for item in items {
            let lines = wrap_pdf_text(item, 92);
            self.ensure(lines.len() as f64 * 12.0 + 5.0);
            self.text(39.0, self.y, 9.0, true, t.accent, "-");
            for line in &lines {
                self.text(50.0, self.y, 8.7, false, t.body_text, line);
                self.y -= 12.0;
            }
            self.y -= 3.0;
        }
        self.y -= 3.0;
    }

    fn top_table(&mut self, title: &str, label: &str, rows: &[Kv]) {
        let t = self.theme();
        if rows.is_empty() {
            return;
        }
        let first_label = first_non_empty(&[&rows[0].title, &rows[0].key], "");
        let first_lines = wrap_pdf_text(first_label, 78);
        let first_height = (first_lines.len() as f64 * 11.0 + 9.0).max(25.0);
        self.ensure(33.0 + 24.0 + first_height);
        self.section(title);
        let max_count = rows[0].count.max(1);
        self.table_header(label, "Events");
        for (index, row) in rows.iter().enumerate() {
            let row_label = first_non_empty(&[&row.title, &row.key], "");
            let lines = wrap_pdf_text(row_label, 78);
            let height = (lines.len() as f64 * 11.0 + 9.0).max(25.0);
            self.ensure(height);
            if index % 2 == 1 {
                self.rect(32.0, self.y - height + 5.0, PDF_PAGE_WIDTH - 64.0, height, t.alt_row);
            }
            let bar_width = 115.0 * row.count as f64 / max_count as f64;
            self.rect(PDF_PAGE_WIDTH - 184.0, self.y - 12.0, bar_width, 5.0, t.bar);
            let line_count = lines.len();
            for line in &lines {
                self.text(38.0, self.y - 7.0, 8.3, false, t.body_text, line);
                self.y -= 11.0;
            }
            let count_str = row.count.to_string();
            self.text(PDF_PAGE_WIDTH - 55.0, self.y + line_count as f64 * 11.0 - 7.0, 8.5, true, t.brand_text, &count_str);
            self.y -= 8.0;
        }
        self.y -= 4.0;
    }

    fn table_header(&mut self, left: &str, right: &str) {
        let t = self.theme();
        self.ensure(23.0);
        self.rect(32.0, self.y - 17.0, PDF_PAGE_WIDTH - 64.0, 22.0, t.table_header);
        let left = left.to_uppercase();
        let right = right.to_uppercase();
        self.text(38.0, self.y - 10.0, 8.0, true, t.brand_text, &left);
        self.text(PDF_PAGE_WIDTH - 68.0, self.y - 10.0, 8.0, true, t.brand_text, &right);
        self.y -= 24.0;
    }

    fn operational_alerts(&mut self, alerts: &[AlertRecord]) {
        let t = self.theme();
        if alerts.is_empty() {
            return;
        }
        let first_lines = wrap_pdf_text(&format!("OPEN - {}", alerts[0].message), 82);
        let first_height = (first_lines.len() as f64 * 11.0 + 9.0).max(25.0);
        self.ensure(33.0 + 24.0 + first_height);
        self.section("Operational dashboard alerts");
        self.table_header("State / message", "Count");
        for (index, alert) in alerts.iter().take(40).enumerate() {
            let state = if alert.acknowledged { "ACKNOWLEDGED" } else { "OPEN" };
            let lines = wrap_pdf_text(&format!("{state} - {}", alert.message), 82);
            let height = (lines.len() as f64 * 11.0 + 9.0).max(25.0);
            self.ensure(height);
            if index % 2 == 1 {
                self.rect(32.0, self.y - height + 5.0, PDF_PAGE_WIDTH - 64.0, height, t.alt_row);
            }
            let line_count = lines.len();
            for line in &lines {
                self.text(38.0, self.y - 7.0, 8.2, false, t.body_text, line);
                self.y -= 11.0;
            }
            let count_str = alert.count.to_string();
            self.text(PDF_PAGE_WIDTH - 55.0, self.y + line_count as f64 * 11.0 - 7.0, 8.5, true, t.brand_text, &count_str);
            self.y -= 8.0;
        }
    }

    fn event_appendix(&mut self, events: &[ReportEventRow], appendix_limit: i64) {
        let t = self.theme();
        self.section("Evidence appendix - representative events");
        if events.is_empty() || appendix_limit <= 0 {
            self.paragraph("No matching event records were available.");
            return;
        }
        let limit = (appendix_limit as usize).min(events.len());
        let summary =
            format!("Showing the newest {limit} of {} matching records. Use the dashboard Event Explorer or Elasticsearch export for the complete machine-readable dataset.", events.len());
        self.paragraph(&summary);
        for (index, event) in events[..limit].iter().enumerate() {
            let mut detail = first_non_empty(&[&event.alert, &event.detail, &event.command, &event.path], "event").to_string();
            if detail.len() > EVENT_APPENDIX_DETAIL_CAP {
                detail = format!("{} …(truncated)", truncate_utf8(&detail, EVENT_APPENDIX_DETAIL_CAP));
            }
            let head = [event.time.as_str(), event.sensor.as_str(), event.src_ip.as_str(), event.port.as_str()].join("  |  ");
            let lines = wrap_pdf_text(&detail, 88);
            let height = 25.0 + lines.len() as f64 * 10.0;
            self.ensure(height);
            if index % 2 == 0 {
                self.rect(32.0, self.y - height + 7.0, PDF_PAGE_WIDTH - 64.0, height, t.alt_row);
            }
            self.text(38.0, self.y - 6.0, 7.8, true, t.brand_text, &head);
            self.y -= 14.0;
            for line in &lines {
                self.text(38.0, self.y - 5.0, 7.8, false, t.faint_text, line);
                self.y -= 10.0;
            }
            self.y -= 6.0;
        }
    }

    fn parameters(&mut self, data: &ReportData) {
        self.section("Report parameters and limitations");
        let filters =
            if data.filters.is_empty() { "none - executive overview".to_string() } else { data.filters.join("; ") };
        self.paragraph(&format!("Applied filters: {filters}"));
        self.paragraph("Data source: normalized in-memory dashboard telemetry and persistent operational alert state. Counts reflect the dashboard observation window, not an assertion that every historical Elasticsearch document is present.");
        self.paragraph("Limitations: honeypot interactions show hostile or suspicious activity directed at decoy services. GeoIP, ASN, provider, behavioral mappings, and risk scoring are contextual triage aids. They do not prove attribution, physical location, successful compromise, or impact to production systems.");
    }

    fn text(&mut self, x: f64, y: f64, size: f64, bold: bool, color: PdfRgb, value: &str) {
        let font = if bold { "F2" } else { "F1" };
        let escaped = escape_pdf_text(value);
        let _ = writeln!(
            self.page_mut().content,
            "BT /{font} {size:.2} Tf {:.3} {:.3} {:.3} rg {x:.2} {y:.2} Td ({escaped}) Tj ET",
            color.r, color.g, color.b
        );
    }

    fn display_text(&mut self, x: f64, y: f64, size: f64, color: PdfRgb, value: &str) {
        let escaped = escape_pdf_text(value);
        let _ = writeln!(
            self.page_mut().content,
            "BT /F3 {size:.2} Tf {:.3} {:.3} {:.3} rg {x:.2} {y:.2} Td ({escaped}) Tj ET",
            color.r, color.g, color.b
        );
    }

    fn rect(&mut self, x: f64, y: f64, width: f64, height: f64, color: PdfRgb) {
        let _ = writeln!(
            self.page_mut().content,
            "{:.3} {:.3} {:.3} rg {x:.2} {y:.2} {width:.2} {height:.2} re f",
            color.r, color.g, color.b
        );
    }

    fn stroke_rect(&mut self, x: f64, y: f64, width: f64, height: f64, color: PdfRgb) {
        let _ = writeln!(
            self.page_mut().content,
            "{:.3} {:.3} {:.3} RG 0.6 w {x:.2} {y:.2} {width:.2} {height:.2} re S",
            color.r, color.g, color.b
        );
    }

    fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, color: PdfRgb) {
        let _ = writeln!(
            self.page_mut().content,
            "{:.3} {:.3} {:.3} RG 0.6 w {x1:.2} {y1:.2} m {x2:.2} {y2:.2} l S",
            color.r, color.g, color.b
        );
    }

    // -- watermark / header-mark (report_pdf_watermark.go / report_pdf_brandmark.go) --

    fn draw_watermark(&mut self) {
        let x = (PDF_PAGE_WIDTH - WATERMARK_SIZE) / 2.0;
        let y = (PDF_PAGE_HEIGHT - WATERMARK_SIZE) / 2.0;
        let t = self.theme();
        let _ = writeln!(
            self.page_mut().content,
            "q /GS1 gs {:.3} {:.3} {:.3} rg {WATERMARK_SIZE:.2} 0 0 {WATERMARK_SIZE:.2} {x:.2} {y:.2} cm /Wm Do Q",
            t.accent.r, t.accent.g, t.accent.b
        );
    }

    fn draw_header_mark(&mut self) {
        let t = self.theme();
        let y = PDF_PAGE_HEIGHT - 35.0;
        let _ = writeln!(
            self.page_mut().content,
            "q {:.3} {:.3} {:.3} rg {PDF_HEADER_MARK_SIZE:.2} 0 0 {PDF_HEADER_MARK_SIZE:.2} 32 {y:.2} cm /HMark Do Q",
            t.accent.r, t.accent.g, t.accent.b
        );
    }
}

fn first_non_empty<'a>(values: &[&'a str], fallback: &'a str) -> &'a str {
    values.iter().copied().find(|v| !v.is_empty()).unwrap_or(fallback)
}

fn escape_pdf_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' | '(' | ')' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' | '\r' | '\t' => out.push(' '),
            c if (0x20 as u32..=0x7e).contains(&(c as u32)) => out.push(c),
            _ => out.push('?'),
        }
    }
    out
}

fn wrap_pdf_text(value: &str, width: usize) -> Vec<String> {
    let joined = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.is_empty() {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut remaining = joined.as_str();
    while remaining.len() > width {
        // Mirrors Go's strings.LastIndex(value[:width+1], " "): search for
        // the last space within the first width+1 bytes (byte-indexed, like
        // the Go source — this text is ASCII-only after escape_pdf_text, so
        // byte and char boundaries coincide for the values this ever wraps).
        let probe_end = (width + 1).min(remaining.len());
        let probe = &remaining[..probe_end];
        let mut cut = probe.rfind(' ').unwrap_or(usize::MAX);
        if cut == usize::MAX || cut < width / 2 {
            cut = width.min(remaining.len());
        }
        lines.push(remaining[..cut].trim().to_string());
        remaining = remaining[cut..].trim_start();
    }
    if !remaining.is_empty() {
        lines.push(remaining.to_string());
    }
    lines
}

// -- watermark / header-mark assets (report_pdf_watermark.go / report_pdf_brandmark.go) --

const WATERMARK_IMAGE_WIDTH: u32 = 360;
const WATERMARK_IMAGE_HEIGHT: u32 = 360;
/// Intentionally very low — this sits behind every other element on the
/// page, so it must never compete with the report's own text.
const WATERMARK_OPACITY: f64 = 0.05;
/// On-page footprint in points, centered, larger than the printable column
/// so it reads as a background mark rather than a bounded illustration.
const WATERMARK_SIZE: f64 = 380.0;

const PDF_HEADER_MARK_WIDTH: u32 = 64;
const PDF_HEADER_MARK_HEIGHT: u32 = 64;
const PDF_HEADER_MARK_SIZE: f64 = 22.0;

/// Fixed object numbers shared with `PdfDocument::bytes()`'s own layout —
/// not computed there.
const PDF_WATERMARK_OBJECT_NUMBER: usize = 6;
const PDF_WATERMARK_GSTATE_OBJECT_NUMBER: usize = 7;
const PDF_HEADER_MARK_OBJECT_NUMBER: usize = 8;

/// The detailed APIARY emblem, a transparent 360x360 one-bit image mask.
/// Its color comes from the active report theme at draw time.
static WATERMARK_MASK_DATA: &[u8] = include_bytes!("../assets_pdf/watermark.maskdata");

/// The compact APIARY emblem, a 64x64 one-bit image mask for the header band.
static PDF_HEADER_MARK_DATA: &[u8] = include_bytes!("../assets_pdf/apiary-header-mark.maskdata");

fn pdf_watermark_image_object() -> Vec<u8> {
    format!(
        "<< /Type /XObject /Subtype /Image /Width {WATERMARK_IMAGE_WIDTH} /Height {WATERMARK_IMAGE_HEIGHT} /ImageMask true /BitsPerComponent 1 /Decode [1 0] /Filter /FlateDecode /Length {} >>\nstream\n",
        WATERMARK_MASK_DATA.len()
    )
    .into_bytes()
}

fn pdf_watermark_gstate_object() -> Vec<u8> {
    format!("<< /Type /ExtGState /ca {WATERMARK_OPACITY:.3} >>").into_bytes()
}

fn pdf_header_mark_image_object() -> Vec<u8> {
    format!(
        "<< /Type /XObject /Subtype /Image /Width {PDF_HEADER_MARK_WIDTH} /Height {PDF_HEADER_MARK_HEIGHT} /ImageMask true /BitsPerComponent 1 /Decode [1 0] /Filter /FlateDecode /Length {} >>\nstream\n",
        PDF_HEADER_MARK_DATA.len()
    )
    .into_bytes()
}

// -- document assembly (report_pdf.go's (*pdfDocument).bytes()) --

impl PdfDocument {
    fn bytes(mut self) -> Vec<u8> {
        if self.pages.is_empty() {
            self.pages.push(PdfPage { content: String::new() });
        }
        let muted = self.theme.muted_text;
        let footer_left =
            if self.footer_left.is_empty() { default_pdf_branding().footer_left } else { self.footer_left.clone() };

        // Objects 1-5 are the catalog/pages/fonts every build has always
        // had; 6-7 are the watermark's shared Image XObject and ExtGState;
        // object 8 is the compact header-mark image mask. Page objects
        // start at 9.
        let mut objects: Vec<Vec<u8>> = vec![Vec::new(); 8 + self.pages.len() * 2];
        objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>".to_vec();
        let mut kids = String::new();
        for index in 0..self.pages.len() {
            let _ = write!(kids, "{} 0 R ", 9 + index * 2);
        }
        objects[1] = format!("<< /Type /Pages /Count {} /Kids [{kids}] >>", self.pages.len()).into_bytes();
        objects[2] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".to_vec();
        objects[3] =
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>".to_vec();
        // Portable sans display fallback for APIARY's Space Grotesk heading role.
        objects[4] =
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>".to_vec();

        let mut watermark_object = pdf_watermark_image_object();
        watermark_object.extend_from_slice(WATERMARK_MASK_DATA);
        watermark_object.extend_from_slice(b"\nendstream");
        objects[PDF_WATERMARK_OBJECT_NUMBER - 1] = watermark_object;
        objects[PDF_WATERMARK_GSTATE_OBJECT_NUMBER - 1] = pdf_watermark_gstate_object();

        let mut header_mark_object = pdf_header_mark_image_object();
        header_mark_object.extend_from_slice(PDF_HEADER_MARK_DATA);
        header_mark_object.extend_from_slice(b"\nendstream");
        objects[PDF_HEADER_MARK_OBJECT_NUMBER - 1] = header_mark_object;

        let page_count = self.pages.len();
        for (index, page) in self.pages.iter().enumerate() {
            let page_number = 9 + index * 2;
            let content_number = page_number + 1;
            let footer = format!(
                "BT /F1 7.5 Tf {:.3} {:.3} {:.3} rg 32 27 Td ({}) Tj ET\nBT /F1 7.5 Tf {:.3} {:.3} {:.3} rg 516 27 Td (Page {} of {page_count}) Tj ET\n",
                muted.r, muted.g, muted.b, escape_pdf_text(&footer_left), muted.r, muted.g, muted.b, index + 1
            );
            let mut stream = page.content.clone().into_bytes();
            stream.extend_from_slice(footer.as_bytes());
            objects[page_number - 1] = format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PDF_PAGE_WIDTH:.0} {PDF_PAGE_HEIGHT:.0}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> /XObject << /Wm {PDF_WATERMARK_OBJECT_NUMBER} 0 R /HMark {PDF_HEADER_MARK_OBJECT_NUMBER} 0 R >> /ExtGState << /GS1 {PDF_WATERMARK_GSTATE_OBJECT_NUMBER} 0 R >> >> /Contents {content_number} 0 R >>"
            )
            .into_bytes();
            let mut content_object = format!("<< /Length {} >>\nstream\n", stream.len()).into_bytes();
            content_object.extend_from_slice(&stream);
            content_object.extend_from_slice(b"endstream");
            objects[content_number - 1] = content_object;
        }

        let mut output: Vec<u8> = Vec::new();
        output.extend_from_slice(b"%PDF-1.4\n%\xd3\xf4\xcc\xe1\n");
        let mut offsets = vec![0usize; objects.len() + 1];
        for (index, object) in objects.iter().enumerate() {
            offsets[index + 1] = output.len();
            output.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
            output.extend_from_slice(object);
            output.extend_from_slice(b"\nendobj\n");
        }
        let xref = output.len();
        output.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
        for offset in &offsets[1..] {
            output.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        output.extend_from_slice(
            format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objects.len() + 1).as_bytes(),
        );
        output
    }
}

/// Keeps the designer's ordering but anchors the cover at the start and the
/// parameters section at the end when selected.
fn normalize_report_elements(elements: &[String]) -> Vec<String> {
    let mut body = Vec::new();
    let (mut has_cover, mut has_parameters) = (false, false);
    for element in elements {
        match element.as_str() {
            ELEMENT_COVER => has_cover = true,
            ELEMENT_PARAMETERS => has_parameters = true,
            _ => body.push(element.clone()),
        }
    }
    let mut out = Vec::new();
    if has_cover {
        out.push(ELEMENT_COVER.to_string());
    }
    out.extend(body);
    if has_parameters {
        out.push(ELEMENT_PARAMETERS.to_string());
    }
    out
}

/// Renders a report from an already-assembled dataset: the public entry
/// point every caller (Reports studio definitions, the one-click
/// payload/sandbox/ghidra reports once those land) drives the writer
/// through, exactly the sections the operator selected.
pub fn render_report_pdf(
    data: &ReportData,
    theme: PdfTheme,
    branding: PdfBranding,
    elements: &[String],
    appendix_limit: i64,
) -> Vec<u8> {
    let branding = branding.with_defaults();
    let mut writer = PdfReportWriter {
        doc: PdfDocument { pages: Vec::new(), theme, footer_left: branding.footer_left.clone() },
        y: 0.0,
        branding,
    };
    writer.new_page();
    for element in normalize_report_elements(elements) {
        match element.as_str() {
            ELEMENT_COVER => writer.cover(data),
            ELEMENT_METRICS => {
                writer.section("Executive summary");
                writer.metric_grid(&data.summary);
            }
            ELEMENT_ASSESSMENT => {
                writer.section("Assessment");
                let text = format!(
                    "Overall triage score: {}/100 ({}). This deterministic score prioritizes alert volume, severity, payload observations, sensor spread, commands, and open operational alerts; it is not an attribution or compromise verdict.",
                    data.summary.risk_score,
                    data.summary.risk_level.to_uppercase()
                );
                writer.paragraph(&text);
            }
            ELEMENT_FINDINGS => writer.bullets("Key findings", &data.findings),
            ELEMENT_RECOMMENDATIONS => writer.bullets("Recommended actions", &data.recommendations),
            ELEMENT_TOP_SENSORS => writer.top_table("Top sensors", "Sensor", &data.top_sensors),
            ELEMENT_TOP_SOURCES => writer.top_table("Top source addresses", "Source IP", &data.top_sources),
            ELEMENT_TOP_SIGNATURES => writer.top_table("Top alert signatures", "Signature", &data.top_signatures),
            ELEMENT_TOP_ASNS => writer.top_table("Top autonomous systems", "ASN / organization", &data.top_asns),
            ELEMENT_TOP_COUNTRIES => writer.top_table("Top countries", "Country", &data.top_countries),
            ELEMENT_TOP_PORTS => writer.top_table("Top destination ports", "Port", &data.top_ports),
            ELEMENT_OPERATIONAL_ALERTS => writer.operational_alerts(&data.operational_alerts),
            ELEMENT_EVENT_APPENDIX => writer.event_appendix(&data.events, appendix_limit),
            ELEMENT_PARAMETERS => writer.parameters(data),
            _ => {}
        }
    }
    writer.doc.bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_minimal_valid_looking_pdf() {
        let data = ReportData {
            generated: chrono::Utc::now(),
            title: "Test Report".into(),
            scope: "All normalized telemetry".into(),
            summary: ReportSummary { events: 3, risk_score: 12, risk_level: "low".into(), ..Default::default() },
            top_sources: vec![Kv { key: "1.2.3.4".into(), count: 5, title: "1.2.3.4".into(), ..Default::default() }],
            findings: vec!["3 matching events.".into()],
            ..Default::default()
        };
        let elements = vec![
            ELEMENT_COVER.to_string(),
            ELEMENT_METRICS.to_string(),
            ELEMENT_FINDINGS.to_string(),
            ELEMENT_TOP_SOURCES.to_string(),
            ELEMENT_PARAMETERS.to_string(),
        ];
        let bytes = render_report_pdf(&data, pdf_theme_dark(), PdfBranding::default(), &elements, 120);
        assert!(bytes.starts_with(b"%PDF-1.4"));
        assert!(bytes.ends_with(b"%%EOF\n"));
        assert!(bytes.len() > 1000);
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("/Type /Catalog"));
        assert!(text.contains("trailer"));
    }

    #[test]
    #[ignore = "scratch: dumps a multi-page PDF to /tmp for manual xref inspection"]
    fn scratch_dump_multi_page_pdf() {
        let mut top_sources = Vec::new();
        for i in 0..300 {
            top_sources.push(Kv { key: format!("10.0.0.{i}"), count: 300 - i, title: format!("10.0.0.{i}"), ..Default::default() });
        }
        let mut events = Vec::new();
        for i in 0..300 {
            events.push(ReportEventRow {
                time: format!("2026-01-01T00:00:{i:02}Z"),
                sensor: "cowrie".into(),
                src_ip: format!("10.0.0.{i}"),
                port: "22".into(),
                detail: "login attempt with a moderately long detail string to force wrapping".into(),
                ..Default::default()
            });
        }
        let data = ReportData {
            generated: chrono::Utc::now(),
            title: "Scratch Multi-Page Report".into(),
            scope: "test".into(),
            summary: ReportSummary { events: 300, risk_score: 80, risk_level: "high".into(), ..Default::default() },
            top_sources,
            events,
            findings: vec!["finding one".into(), "finding two".into()],
            recommendations: vec!["do the thing".into()],
            ..Default::default()
        };
        let elements = vec![
            ELEMENT_COVER.to_string(),
            ELEMENT_METRICS.to_string(),
            ELEMENT_ASSESSMENT.to_string(),
            ELEMENT_FINDINGS.to_string(),
            ELEMENT_RECOMMENDATIONS.to_string(),
            ELEMENT_TOP_SOURCES.to_string(),
            ELEMENT_EVENT_APPENDIX.to_string(),
            ELEMENT_PARAMETERS.to_string(),
        ];
        let bytes = render_report_pdf(&data, pdf_theme_dark(), PdfBranding::default(), &elements, 300);
        std::fs::write("/tmp/report_pdf_scratch.pdf", &bytes).unwrap();
        eprintln!("wrote {} bytes", bytes.len());
    }

    #[test]
    fn wraps_text_without_splitting_words() {
        let lines = wrap_pdf_text("the quick brown fox jumps over the lazy dog", 10);
        assert!(lines.iter().all(|l| l.len() <= 10 || !l.contains(' ')));
        assert_eq!(lines.join(" ").split_whitespace().collect::<Vec<_>>(), vec![
            "the", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog"
        ]);
    }
}
