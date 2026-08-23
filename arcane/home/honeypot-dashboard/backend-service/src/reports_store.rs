//! Report definitions (dashboard-reports-definitions-v1, one singleton
//! document — same read-modify-write pattern as config.rs/preferences.rs,
//! not Go's generic esSettingsStore[T]) and generated-report storage
//! (dashboard-generated-reports-v1, one document per produced PDF), ported
//! from dashboard/reports_store.go + reports_es.go.
//!
//! Scope decision (#1612): the "sandbox"/"payload"/"ghidra" templates
//! render one referenced artifact through their own dedicated renderers
//! (sandbox_pdf.go/ghidra_pdf.go/a payload equivalent) that this pass does
//! not port — those three templates are still accepted here (so saving and
//! listing a definition for them works), but generating one returns a
//! clear "not yet implemented" error instead of attempting to render. See
//! reports_api.rs's generate handler.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AppState;

pub const DEFINITIONS_INDEX: &str = "dashboard-reports-definitions-v1";
const DEFINITIONS_DOC_ID: &str = "definitions";
pub const GENERATED_INDEX: &str = "dashboard-generated-reports-v1";

const MAX_REPORT_DEFINITIONS: usize = 200;
const MAX_GENERATED_REPORTS_DEFAULT: usize = 100;
const MAX_REPORT_APPENDIX: i64 = 500;
const MAX_REPORT_NAME: usize = 60;

// ---------------------------------------------------------------------------
// Element catalog — string literals MUST match report_pdf.rs's ELEMENT_*.
// ---------------------------------------------------------------------------

pub struct ElementInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
}

pub const REPORT_ELEMENT_CATALOG: &[ElementInfo] = &[
    ElementInfo {
        id: crate::report_pdf::ELEMENT_COVER,
        label: "Cover",
        description: "Title, scope, author, observed window, and classification line",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_METRICS,
        label: "Metric grid",
        description:
            "Headline counts: events, sources, alerts, logins, payloads, sessions, risk rating",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_ASSESSMENT,
        label: "Assessment",
        description: "Deterministic triage score explanation and rating",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_FINDINGS,
        label: "Key findings",
        description: "Derived findings from the matching telemetry",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_RECOMMENDATIONS,
        label: "Recommended actions",
        description: "Derived defensive next steps",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_TOP_SENSORS,
        label: "Top sensors",
        description: "Sensor volume ranking",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_TOP_SOURCES,
        label: "Top source addresses",
        description: "Source IP volume ranking",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_TOP_SIGNATURES,
        label: "Top alert signatures",
        description: "IDS / honeypot signature ranking",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_TOP_ASNS,
        label: "Top autonomous systems",
        description: "ASN / organization ranking",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_TOP_COUNTRIES,
        label: "Top countries",
        description: "Country ranking (contextual GeoIP lead only)",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_TOP_PORTS,
        label: "Top destination ports",
        description: "Targeted port ranking",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_OPERATIONAL_ALERTS,
        label: "Operational alerts",
        description: "Dashboard operational alert state matching the scope",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_EVENT_APPENDIX,
        label: "Event appendix",
        description: "Representative newest matching event records (bounded)",
    },
    ElementInfo {
        id: crate::report_pdf::ELEMENT_PARAMETERS,
        label: "Parameters and limitations",
        description: "Applied filters, data source, and evidentiary limitations",
    },
];

fn known_report_element(id: &str) -> bool {
    REPORT_ELEMENT_CATALOG
        .iter()
        .any(|element| element.id == id)
}

// ---------------------------------------------------------------------------
// Template catalog
// ---------------------------------------------------------------------------

/// Which artifact-referenced renderer (if any) a template dispatches to.
/// A template is exactly one of these — the prior three independent bools
/// allowed representing an invalid "two true" template that no renderer
/// actually handles.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReportTemplateKind {
    Generic,
    Sandbox,
    Payload,
    Ghidra,
}

pub struct ReportTemplate {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub title: &'static str,
    pub theme: &'static str,
    pub window: &'static str,
    pub elements: &'static [&'static str],
    pub kind: ReportTemplateKind,
}

pub fn report_template_catalog() -> Vec<ReportTemplate> {
    use crate::report_pdf::*;
    vec![
        ReportTemplate {
            id: "executive", name: "Executive report",
            description: "Management-ready summary of the observation window: headline metrics, assessment, findings, and recommendations.",
            title: "Honeypot Executive Security Report", theme: "dark", window: "24h",
            elements: &[ELEMENT_COVER, ELEMENT_METRICS, ELEMENT_ASSESSMENT, ELEMENT_FINDINGS, ELEMENT_RECOMMENDATIONS, ELEMENT_TOP_SOURCES, ELEMENT_TOP_COUNTRIES, ELEMENT_PARAMETERS],
            kind: ReportTemplateKind::Generic,
        },
        ReportTemplate {
            id: "security", name: "Full security report",
            description: "Complete defensive picture: every metric, ranking, operational alert, and a bounded evidence appendix.",
            title: "Honeypot Security Operations Report", theme: "dark", window: "24h",
            elements: &[ELEMENT_COVER, ELEMENT_METRICS, ELEMENT_ASSESSMENT, ELEMENT_FINDINGS, ELEMENT_RECOMMENDATIONS, ELEMENT_TOP_SENSORS, ELEMENT_TOP_SOURCES, ELEMENT_TOP_SIGNATURES, ELEMENT_TOP_ASNS, ELEMENT_TOP_COUNTRIES, ELEMENT_TOP_PORTS, ELEMENT_OPERATIONAL_ALERTS, ELEMENT_EVENT_APPENDIX, ELEMENT_PARAMETERS],
            kind: ReportTemplateKind::Generic,
        },
        ReportTemplate {
            id: "threat", name: "Threat landscape",
            description: "Who and what is attacking: signatures, autonomous systems, countries, and targeted ports over a longer window.",
            title: "Honeypot Threat Landscape Report", theme: "dark", window: "7d",
            elements: &[ELEMENT_COVER, ELEMENT_METRICS, ELEMENT_TOP_SIGNATURES, ELEMENT_TOP_ASNS, ELEMENT_TOP_COUNTRIES, ELEMENT_TOP_PORTS, ELEMENT_FINDINGS, ELEMENT_PARAMETERS],
            kind: ReportTemplateKind::Generic,
        },
        ReportTemplate {
            id: "incident", name: "Incident investigation",
            description: "Scoped deep-dive for one IP, session, network, or signature with operational alerts and an extended event appendix.",
            title: "Honeypot Incident Investigation Report", theme: "dark", window: "24h",
            elements: &[ELEMENT_COVER, ELEMENT_METRICS, ELEMENT_ASSESSMENT, ELEMENT_FINDINGS, ELEMENT_RECOMMENDATIONS, ELEMENT_OPERATIONAL_ALERTS, ELEMENT_EVENT_APPENDIX, ELEMENT_PARAMETERS],
            kind: ReportTemplateKind::Generic,
        },
        ReportTemplate {
            id: "sensors", name: "Sensor and collection health",
            description: "Collection coverage and operational state: sensor volumes plus open operational alerts.",
            title: "Honeypot Sensor and Collection Health Report", theme: "dark", window: "24h",
            elements: &[ELEMENT_COVER, ELEMENT_METRICS, ELEMENT_TOP_SENSORS, ELEMENT_OPERATIONAL_ALERTS, ELEMENT_PARAMETERS],
            kind: ReportTemplateKind::Generic,
        },
        ReportTemplate {
            id: "sandbox", name: "Sandbox analysis",
            description: "Dynamic-analysis report for one sandbox job: assessment, process / socket / network evidence, and ATT&CK mapping.",
            title: "Sandbox Dynamic Analysis Report", theme: "dark", window: "",
            elements: &[], kind: ReportTemplateKind::Sandbox,
        },
        ReportTemplate {
            id: "payload", name: "Payload analysis",
            description: "Static/dynamic analysis report for one captured payload: classification, IOCs, YARA, sandbox runs, and any GitHub-analysis verdict.",
            title: "Payload Analysis Report", theme: "dark", window: "",
            elements: &[], kind: ReportTemplateKind::Payload,
        },
        ReportTemplate {
            id: "ghidra", name: "Ghidra static analysis",
            description: "Headless-decompilation report for one captured payload: functions, strings, imports, capa capabilities, FLOSS-deobfuscated strings, fuzzy hashes, and structural (lief) info.",
            title: "Ghidra Static Analysis Report", theme: "dark", window: "",
            elements: &[], kind: ReportTemplateKind::Ghidra,
        },
        ReportTemplate {
            id: "custom", name: "Custom report",
            description: "Blank canvas: pick every element, the scope, the theme, and the branding yourself.",
            title: "Honeypot Custom Report", theme: "dark", window: "",
            elements: &[ELEMENT_COVER, ELEMENT_METRICS, ELEMENT_PARAMETERS],
            kind: ReportTemplateKind::Generic,
        },
    ]
}

fn report_template_by_id(id: &str) -> Option<ReportTemplate> {
    report_template_catalog().into_iter().find(|t| t.id == id)
}

pub fn report_window_duration(window: &str) -> Option<chrono::Duration> {
    match window {
        "1h" => Some(chrono::Duration::hours(1)),
        "6h" => Some(chrono::Duration::hours(6)),
        "24h" => Some(chrono::Duration::hours(24)),
        "7d" => Some(chrono::Duration::days(7)),
        "30d" => Some(chrono::Duration::days(30)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Definition types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct ReportBranding {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub author: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub header_left: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub header_right: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub footer_left: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub classification: String,
}

impl ReportBranding {
    pub fn to_pdf_branding(&self) -> crate::report_pdf::PdfBranding {
        crate::report_pdf::PdfBranding {
            header_left: self.header_left.clone(),
            header_right: self.header_right.clone(),
            footer_left: self.footer_left.clone(),
            classification: self.classification.clone(),
            author: self.author.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct ReportScope {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub window: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub network: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sensor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub port: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub asn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub job: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hash: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct ReportSchedule {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub frequency: String,
    #[serde(default)]
    pub hour: i64,
    #[serde(default)]
    pub minute: i64,
    #[serde(default)]
    pub weekday: i64,
    #[serde(default)]
    pub month_day: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub last_run_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub next_run_at: String,
}

/// Computes the first fire time strictly after `from`, mirroring
/// nextScheduleRun's daily/weekly/monthly walk exactly.
pub fn next_schedule_run(
    schedule: &ReportSchedule,
    from: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    let mut candidate = from
        .date_naive()
        .and_hms_opt(
            schedule.hour.clamp(0, 23) as u32,
            schedule.minute.clamp(0, 59) as u32,
            0,
        )
        .unwrap()
        .and_utc();
    match schedule.frequency.as_str() {
        "daily" => {
            if candidate <= from {
                candidate += chrono::Duration::days(1);
            }
        }
        "weekly" => {
            for _ in 0..8 {
                // chrono weekday: Mon=0..Sun=6; Go's time.Weekday: Sun=0..Sat=6.
                let go_weekday = (candidate.weekday().num_days_from_sunday()) as i64;
                if go_weekday == schedule.weekday && candidate > from {
                    break;
                }
                candidate += chrono::Duration::days(1);
            }
        }
        "monthly" => {
            for _ in 0..62 {
                if candidate.day() as i64 == schedule.month_day && candidate > from {
                    break;
                }
                candidate += chrono::Duration::days(1);
            }
        }
        _ => {}
    }
    candidate
}

use chrono::Datelike;

fn validate_report_schedule(schedule: &Option<ReportSchedule>) -> Result<(), String> {
    let Some(schedule) = schedule else {
        return Ok(());
    };
    if !schedule.enabled {
        return Ok(());
    }
    match schedule.frequency.as_str() {
        "daily" => {}
        "weekly" => {
            if !(0..=6).contains(&schedule.weekday) {
                return Err("schedule.weekday must be between 0 (Sunday) and 6 (Saturday)".into());
            }
        }
        "monthly" => {
            if !(1..=28).contains(&schedule.month_day) {
                return Err("schedule.month_day must be between 1 and 28".into());
            }
        }
        _ => return Err("schedule.frequency must be one of daily, weekly, monthly".into()),
    }
    if !(0..=23).contains(&schedule.hour) {
        return Err("schedule.hour must be between 0 and 23 (UTC)".into());
    }
    if !(0..=59).contains(&schedule.minute) {
        return Err("schedule.minute must be between 0 and 59".into());
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct ReportDefinition {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub template: String,
    #[serde(default)]
    pub theme: String,
    #[serde(default)]
    pub branding: ReportBranding,
    #[serde(default)]
    pub scope: ReportScope,
    #[serde(default)]
    pub elements: Vec<String>,
    #[serde(default)]
    pub appendix_limit: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<ReportSchedule>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub updated: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct GeneratedReportMeta {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub definition_id: String,
    pub name: String,
    pub template: String,
    pub theme: String,
    pub title: String,
    pub size_bytes: i64,
    pub created_at: String,
    pub origin: String,
}

/// Validates a definition against Go's validateDefinitionFields, field for
/// field. Returns a human-readable message (mapped to 400/422 by the
/// caller), never panics on out-of-range input.
pub fn validate_definition_fields(def: &ReportDefinition) -> Result<(), String> {
    let name = def.name.trim();
    if name.is_empty() || def.name.chars().count() > MAX_REPORT_NAME {
        return Err(format!(
            "name is required and must be at most {MAX_REPORT_NAME} characters"
        ));
    }
    let Some(template) = report_template_by_id(&def.template) else {
        return Err("template must be one of the published report templates".into());
    };
    if def.theme != "dark" && def.theme != "light" {
        return Err("theme must be dark or light".into());
    }
    match template.kind {
        ReportTemplateKind::Sandbox => {
            if def.scope.job.trim().is_empty() {
                return Err(
                    "scope.job selects the sandbox analysis run for the sandbox template".into(),
                );
            }
            if !def.scope.hash.is_empty() {
                return Err("scope.hash is only valid for the payload and ghidra templates".into());
            }
            if !def.elements.is_empty() {
                return Err(
                    "elements are fixed for the sandbox template; only theme and branding apply".into(),
                );
            }
        }
        ReportTemplateKind::Payload | ReportTemplateKind::Ghidra => {
            if !hash_name(&def.scope.hash) {
                return Err(
                    "scope.hash selects the captured payload for the payload and ghidra templates"
                        .into(),
                );
            }
            if !def.scope.job.is_empty() {
                return Err("scope.job is only valid for the sandbox template".into());
            }
            if !def.elements.is_empty() {
                return Err("elements are fixed for the payload and ghidra templates; only theme and branding apply".into());
            }
        }
        ReportTemplateKind::Generic => {
            if !def.scope.job.is_empty() {
                return Err("scope.job is only valid for the sandbox template".into());
            }
            if !def.scope.hash.is_empty() {
                return Err("scope.hash is only valid for the payload and ghidra templates".into());
            }
            if def.elements.is_empty() || def.elements.len() > REPORT_ELEMENT_CATALOG.len() {
                return Err(format!(
                    "elements must select between 1 and {} report elements",
                    REPORT_ELEMENT_CATALOG.len()
                ));
            }
            let mut seen = std::collections::HashSet::new();
            for element in &def.elements {
                if !known_report_element(element) {
                    return Err("elements contains an unknown report element".into());
                }
                if !seen.insert(element.clone()) {
                    return Err("elements must not repeat a report element".into());
                }
            }
        }
    }
    if !(0..=MAX_REPORT_APPENDIX).contains(&def.appendix_limit) {
        return Err(format!(
            "appendix_limit must be between 0 and {MAX_REPORT_APPENDIX}"
        ));
    }
    if !def.scope.window.is_empty() && report_window_duration(&def.scope.window).is_none() {
        return Err("scope.window must be one of 1h, 6h, 24h, 7d, 30d".into());
    }
    match def.scope.kind.as_str() {
        "" | "login" | "command" | "alert" | "download" => {}
        _ => return Err("scope.type must be one of login, command, alert, download".into()),
    }
    let scope_caps: &[(&str, &str, usize)] = &[
        (&def.scope.ip, "scope.ip", 64),
        (&def.scope.network, "scope.network", 64),
        (&def.scope.sensor, "scope.sensor", 64),
        (&def.scope.port, "scope.port", 16),
        (&def.scope.signature, "scope.signature", 120),
        (&def.scope.country, "scope.country", 64),
        (&def.scope.asn, "scope.asn", 32),
        (&def.scope.text, "scope.text", 200),
        (&def.scope.session, "scope.session", 128),
        (&def.scope.job, "scope.job", 128),
    ];
    for (value, field, max) in scope_caps {
        if value.len() > *max {
            return Err(format!("{field} must be at most {max} characters"));
        }
    }
    let branding_caps: &[(&str, &str, usize)] = &[
        (&def.branding.title, "branding.title", 80),
        (&def.branding.author, "branding.author", 60),
        (&def.branding.header_left, "branding.header_left", 60),
        (&def.branding.header_right, "branding.header_right", 60),
        (&def.branding.footer_left, "branding.footer_left", 80),
        (&def.branding.classification, "branding.classification", 120),
    ];
    for (value, field, max) in branding_caps {
        if value.len() > *max {
            return Err(format!("{field} must be at most {max} characters"));
        }
    }
    validate_report_schedule(&def.schedule)?;
    Ok(())
}

fn hash_name(value: &str) -> bool {
    (value.len() == 64 || value.len() == 32) && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn new_report_id(prefix: &str) -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!(
        "{prefix}{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn valid_report_id(id: &str, prefix: &str) -> bool {
    id.strip_prefix(prefix)
        .is_some_and(|rest| rest.len() == 32 && rest.chars().all(|c| c.is_ascii_hexdigit()))
}

// ---------------------------------------------------------------------------
// Singleton document CRUD (dashboard-reports-definitions-v1)
// ---------------------------------------------------------------------------

async fn load_definitions_doc(state: &AppState) -> anyhow::Result<Value> {
    Ok(state
        .es
        .get_doc(DEFINITIONS_INDEX, DEFINITIONS_DOC_ID)
        .await?
        .unwrap_or_else(
            || json!({"schema_version": 1, "revision": 0, "payload": {"definitions": []}}),
        ))
}

async fn save_definitions_doc(state: &AppState, mut doc: Value) -> anyhow::Result<()> {
    doc["revision"] = json!(doc["revision"].as_u64().unwrap_or(0) + 1);
    doc["updated"] = json!(chrono::Utc::now().to_rfc3339());
    state
        .es
        .index_doc(DEFINITIONS_INDEX, DEFINITIONS_DOC_ID, doc)
        .await
}

pub async fn list_definitions(state: &AppState) -> anyhow::Result<Vec<ReportDefinition>> {
    let doc = load_definitions_doc(state).await?;
    let list = doc["payload"]["definitions"].clone();
    Ok(serde_json::from_value(list).unwrap_or_default())
}

pub async fn get_definition(
    state: &AppState,
    id: &str,
) -> anyhow::Result<Option<ReportDefinition>> {
    Ok(list_definitions(state)
        .await?
        .into_iter()
        .find(|d| d.id == id))
}

/// Creates (empty id) or replaces (existing id) a definition. Recomputes
/// next_run_at on every save, matching Go's putDefinition.
pub async fn put_definition(
    state: &AppState,
    mut def: ReportDefinition,
) -> Result<ReportDefinition, String> {
    let now = chrono::Utc::now();
    if def.id.is_empty() {
        def.id = new_report_id("rep_");
        def.created = now.to_rfc3339();
    } else if !valid_report_id(&def.id, "rep_") {
        return Err("id must be a server-assigned report id".into());
    }
    def.name = def.name.trim().to_string();
    def.updated = now.to_rfc3339();
    if let Some(schedule) = def.schedule.as_mut() {
        if schedule.enabled {
            schedule.next_run_at = next_schedule_run(schedule, now).to_rfc3339();
        } else {
            schedule.next_run_at.clear();
        }
    }
    validate_definition_fields(&def)?;

    let mut doc = load_definitions_doc(state)
        .await
        .map_err(|e| e.to_string())?;
    let list = doc["payload"]["definitions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut definitions: Vec<ReportDefinition> =
        serde_json::from_value(Value::Array(list)).unwrap_or_default();
    match definitions.iter_mut().find(|existing| existing.id == def.id) {
        Some(existing) => {
            if def.created.is_empty() {
                def.created = existing.created.clone();
            }
            *existing = def.clone();
        }
        None => {
            if def.created.is_empty() {
                return Err("no report definition with this id".into());
            }
            if definitions.len() >= MAX_REPORT_DEFINITIONS {
                return Err(format!(
                    "report definition limit reached ({MAX_REPORT_DEFINITIONS})"
                ));
            }
            definitions.push(def.clone());
        }
    }
    doc["payload"]["definitions"] = json!(definitions);
    save_definitions_doc(state, doc)
        .await
        .map_err(|e| e.to_string())?;
    Ok(def)
}

pub async fn delete_definition(state: &AppState, id: &str) -> Result<(), String> {
    let mut doc = load_definitions_doc(state)
        .await
        .map_err(|e| e.to_string())?;
    let list = doc["payload"]["definitions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut definitions: Vec<ReportDefinition> =
        serde_json::from_value(Value::Array(list)).unwrap_or_default();
    let before = definitions.len();
    definitions.retain(|d| d.id != id);
    if definitions.len() == before {
        return Err("no report definition with this id".into());
    }
    doc["payload"]["definitions"] = json!(definitions);
    save_definitions_doc(state, doc)
        .await
        .map_err(|e| e.to_string())
}

/// Definitions whose schedule is enabled and due (next_run_at <= now).
pub async fn due_definitions(state: &AppState) -> anyhow::Result<Vec<ReportDefinition>> {
    let now = chrono::Utc::now();
    Ok(list_definitions(state)
        .await?
        .into_iter()
        .filter(|d| {
            d.schedule.as_ref().is_some_and(|s| {
                s.enabled
                    && !s.next_run_at.is_empty()
                    && chrono::DateTime::parse_from_rfc3339(&s.next_run_at)
                        .map(|at| at.with_timezone(&chrono::Utc) <= now)
                        .unwrap_or(false)
            })
        })
        .collect())
}

/// Records one scheduled run's outcome: next_run_at always advances (a
/// failing definition must not hot-loop); last_run_at only on success.
pub async fn mark_scheduled_run(
    state: &AppState,
    id: &str,
    ran_at: chrono::DateTime<chrono::Utc>,
    success: bool,
) {
    let Ok(mut doc) = load_definitions_doc(state).await else {
        return;
    };
    let list = doc["payload"]["definitions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut definitions: Vec<ReportDefinition> =
        serde_json::from_value(Value::Array(list)).unwrap_or_default();
    let mut changed = false;
    for def in definitions.iter_mut() {
        if def.id == id {
            if let Some(schedule) = def.schedule.as_mut() {
                if success {
                    schedule.last_run_at = ran_at.to_rfc3339();
                }
                schedule.next_run_at = next_schedule_run(schedule, ran_at).to_rfc3339();
                changed = true;
            }
            break;
        }
    }
    if !changed {
        return;
    }
    doc["payload"]["definitions"] = json!(definitions);
    let _ = save_definitions_doc(state, doc).await;
}

// ---------------------------------------------------------------------------
// Generated-report storage (dashboard-generated-reports-v1)
// ---------------------------------------------------------------------------

const GENERATED_MAX_BYTES: usize = 24 << 20;

/// Renders-then-stores in one step: assigns a server-side id, base64-
/// encodes the PDF, writes metadata+PDF as one document, and prunes the
/// oldest records past the retention cap. Mirrors reports_es.go's
/// addGenerated/pruneGenerated.
pub async fn add_generated(
    state: &AppState,
    mut meta: GeneratedReportMeta,
    pdf: Vec<u8>,
) -> anyhow::Result<GeneratedReportMeta> {
    if pdf.is_empty() {
        anyhow::bail!("refusing to record an empty report PDF");
    }
    meta.id = new_report_id("gen_");
    meta.size_bytes = pdf.len() as i64;
    meta.created_at = chrono::Utc::now().to_rfc3339();
    if meta.origin.is_empty() {
        meta.origin = "manual".into();
    }
    let pdf_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pdf);
    let mut doc = serde_json::to_value(&meta)?;
    doc["pdf_base64"] = json!(pdf_base64);
    let approx_bytes = serde_json::to_vec(&doc)?.len();
    if approx_bytes > GENERATED_MAX_BYTES {
        anyhow::bail!("generated report exceeds the {GENERATED_MAX_BYTES}-byte storage cap");
    }
    state.es.index_doc(GENERATED_INDEX, &meta.id, doc).await?;
    prune_generated(state).await;
    Ok(meta)
}

/// Deletes one generated-report artifact by its own `id` (the ES `_id`,
/// per `add_generated`'s `index_doc(GENERATED_INDEX, &meta.id, doc)`) —
/// the per-report delete reports.html's Library grid had (#1682) and the
/// port dropped. `delete_doc` is already idempotent on a missing id.
pub async fn delete_generated(state: &AppState, id: &str) -> anyhow::Result<()> {
    state.es.delete_doc(GENERATED_INDEX, id).await
}

async fn prune_generated(state: &AppState) {
    let Ok(all) = list_generated(state).await else {
        return;
    };
    if all.len() <= MAX_GENERATED_REPORTS_DEFAULT {
        return;
    }
    for meta in &all[..all.len() - MAX_GENERATED_REPORTS_DEFAULT] {
        let _ = state.es.delete_doc(GENERATED_INDEX, &meta.id).await;
    }
}

/// Every generated report's metadata (never the PDF bytes), oldest first —
/// mirrors listGenerated's own ordering.
pub async fn list_generated(state: &AppState) -> anyhow::Result<Vec<GeneratedReportMeta>> {
    let result = state
        .es
        .search_index(
            &[GENERATED_INDEX],
            json!({"size": 10000, "_source": {"excludes": ["pdf_base64"]}, "sort": [{"created_at": {"order": "asc", "unmapped_type": "date"}}]}),
        )
        .await?;
    Ok(result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| serde_json::from_value(hit["_source"].clone()).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom_definition() -> ReportDefinition {
        ReportDefinition {
            id: String::new(),
            name: "Weekly overview".into(),
            template: "custom".into(),
            theme: "dark".into(),
            branding: ReportBranding::default(),
            scope: ReportScope {
                window: "24h".into(),
                ..Default::default()
            },
            elements: vec![
                crate::report_pdf::ELEMENT_COVER.into(),
                crate::report_pdf::ELEMENT_METRICS.into(),
            ],
            appendix_limit: 0,
            schedule: None,
            created: String::new(),
            updated: String::new(),
        }
    }

    #[test]
    fn validates_a_well_formed_custom_definition() {
        assert!(validate_definition_fields(&custom_definition()).is_ok());
    }

    #[test]
    fn rejects_unknown_template() {
        let mut def = custom_definition();
        def.template = "not-a-template".into();
        assert!(validate_definition_fields(&def).is_err());
    }

    #[test]
    fn rejects_empty_elements_for_generic_template() {
        let mut def = custom_definition();
        def.elements.clear();
        assert!(validate_definition_fields(&def).is_err());
    }

    #[test]
    fn rejects_scope_hash_on_generic_template() {
        let mut def = custom_definition();
        def.scope.hash = "a".repeat(64);
        assert!(validate_definition_fields(&def).is_err());
    }

    #[test]
    fn accepts_sandbox_template_with_job_and_no_elements() {
        let mut def = custom_definition();
        def.template = "sandbox".into();
        def.elements.clear();
        def.scope = ReportScope {
            job: "job-123".into(),
            ..Default::default()
        };
        assert!(validate_definition_fields(&def).is_ok());
    }

    #[test]
    fn next_schedule_run_daily_moves_forward() {
        let schedule = ReportSchedule {
            enabled: true,
            frequency: "daily".into(),
            hour: 3,
            minute: 30,
            ..Default::default()
        };
        let from = chrono::Utc::now();
        let next = next_schedule_run(&schedule, from);
        assert!(next > from);
        assert!(next - from <= chrono::Duration::days(1));
    }

    #[test]
    fn next_schedule_run_weekly_lands_on_requested_weekday() {
        let schedule = ReportSchedule {
            enabled: true,
            frequency: "weekly".into(),
            hour: 9,
            minute: 0,
            weekday: 3,
            ..Default::default()
        };
        let from = chrono::Utc::now();
        let next = next_schedule_run(&schedule, from);
        assert!(next > from);
        assert_eq!(next.weekday().num_days_from_sunday() as i64, 3);
    }
}
