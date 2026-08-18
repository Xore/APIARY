//! /api/v1/sensors — the per-sensor detail view (#1538), ported from
//! sensor_detail.go 1:1: mailoney SMTP conversations grouped by
//! session_id, http-honeypot and tanner raw per-request fields (the data
//! classify.go deliberately collapses into one-line summaries). Same
//! caps and 48h window as the Go loaders.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

use crate::AppState;

const RAW_EVENT_CAP: u64 = 3000;
const MAILONEY_SESSION_CAP: usize = 150;
const REQUEST_CAP: usize = 300;
const WINDOW: &str = "now-48h";

#[derive(Serialize, Default, Clone)]
pub struct MailoneySession {
    pub session_id: String,
    pub when: String,
    pub ip: String,
    pub port: u64,
    pub logged_in: bool,
    pub user: String,
    pub pass: String,
    pub mail_from: Vec<String>,
    pub rcpt_to: Vec<String>,
    pub body_size: u64,
    pub truncated: bool,
    pub body_path: String,
    pub body_preview: String,
}

#[derive(Serialize, Default)]
pub struct HttpRequest {
    pub when: String,
    pub ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub user_agent: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub username: String,
    pub password: String,
    pub auth_type: String,
    pub status: u64,
    pub category: String,
    pub tarpitted: bool,
    pub tarpit_bytes: u64,
    pub tarpit_ms: u64,
}

#[derive(Serialize, Default)]
pub struct TannerRequest {
    pub when: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub user_agent: String,
    pub headers: HashMap<String, String>,
    pub username: String,
    pub password: String,
    pub tarpitted: bool,
    pub tarpit_bytes: u64,
    pub tarpit_ms: u64,
    pub post_data: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub detection_name: String,
    pub detection_payload: String,
}

#[derive(Serialize)]
pub struct SensorDetail {
    pub mailoney: Vec<MailoneySession>,
    pub http_requests: Vec<HttpRequest>,
    pub tanner: Vec<TannerRequest>,
}

fn s(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

fn n(value: &Value) -> u64 {
    value.as_u64().unwrap_or_else(|| value.as_f64().unwrap_or(0.0).max(0.0) as u64)
}

/// Headers object → lowercase-keyed string map (headerMap in Go).
fn header_map(value: &Value) -> HashMap<String, String> {
    value
        .as_object()
        .map(|object| object.iter().map(|(k, v)| (k.to_lowercase(), s(v))).collect())
        .unwrap_or_default()
}

/// Plain string map, key case preserved (stringMap in Go — tanner
/// post_data/cookies keys are attacker-controlled and case-significant).
fn string_map(value: &Value) -> HashMap<String, String> {
    value
        .as_object()
        .map(|object| object.iter().map(|(k, v)| (k.clone(), s(v))).collect())
        .unwrap_or_default()
}

async fn query_sensor_raw(state: &AppState, sensor: &str, desc: bool) -> anyhow::Result<Vec<Value>> {
    let body = json!({
        "size": RAW_EVENT_CAP,
        "sort": [{"@timestamp": {"order": if desc { "desc" } else { "asc" }}}],
        "query": {"bool": {"filter": [
            {"term": {"event.sensor": sensor}},
            {"range": {"@timestamp": {"gte": WINDOW}}}
        ]}}
    });
    let result = state.es.search_index(&["honeypot-v2-*"], body).await?;
    Ok(result["hits"]["hits"].as_array().cloned().unwrap_or_default())
}

fn mailoney_sessions(hits: &[Value]) -> Vec<MailoneySession> {
    let empty = Map::new();
    let mut order: Vec<String> = Vec::new();
    let mut by_session: HashMap<String, MailoneySession> = HashMap::new();
    for hit in hits {
        let source = &hit["_source"];
        let event = source["honeypot"].as_object().unwrap_or(&empty);
        let sid = s(&event.get("session_id").cloned().unwrap_or(Value::Null));
        if sid.is_empty() {
            continue;
        }
        let session = by_session.entry(sid.clone()).or_insert_with(|| {
            order.push(sid.clone());
            MailoneySession {
                session_id: sid.clone(),
                ip: s(&event.get("src_ip").cloned().unwrap_or(Value::Null)),
                port: n(&event.get("src_port").cloned().unwrap_or(Value::Null)),
                ..Default::default()
            }
        });
        session.when = s(&source["@timestamp"]);
        let get = |key: &str| event.get(key).cloned().unwrap_or(Value::Null);
        match s(&get("event")).as_str() {
            "login" => {
                session.logged_in = true;
                session.user = s(&get("username"));
                session.pass = s(&get("password"));
            }
            "envelope" => {
                let command = s(&get("command")).trim().to_string();
                let lower = command.to_lowercase();
                if lower.starts_with("mail from") {
                    session.mail_from.push(command);
                } else if lower.starts_with("rcpt to") {
                    session.rcpt_to.push(command);
                }
            }
            "mail-body" => {
                session.body_size = n(&get("size"));
                session.truncated = get("truncated").as_bool().unwrap_or(false);
                session.body_path = s(&get("body_path"));
                session.body_preview = s(&get("body_preview"));
            }
            _ => {}
        }
    }
    let mut sessions: Vec<MailoneySession> =
        order.into_iter().filter_map(|sid| by_session.remove(&sid)).collect();
    sessions.sort_by(|a, b| b.when.cmp(&a.when));
    sessions.truncate(MAILONEY_SESSION_CAP);
    sessions
}

fn http_requests(hits: &[Value]) -> Vec<HttpRequest> {
    let mut out = Vec::new();
    for hit in hits {
        let source = &hit["_source"];
        let event = &source["honeypot"];
        if !event.is_object() {
            continue;
        }
        out.push(HttpRequest {
            when: s(&source["@timestamp"]),
            ip: s(&event["src_ip"]),
            method: s(&event["method"]),
            host: s(&event["host"]),
            path: s(&event["path"]),
            query: s(&event["query"]),
            user_agent: s(&event["user_agent"]),
            headers: header_map(&event["headers"]),
            body: s(&event["body"]),
            username: s(&event["username"]),
            password: s(&event["password"]),
            auth_type: s(&event["auth_type"]),
            status: n(&event["status"]),
            category: s(&event["category"]),
            tarpitted: event["tarpitted"].as_bool().unwrap_or(false),
            tarpit_bytes: n(&event["tarpit_bytes"]),
            tarpit_ms: n(&event["tarpit_ms"]),
        });
        if out.len() >= REQUEST_CAP {
            break;
        }
    }
    out
}

fn tanner_requests(hits: &[Value]) -> Vec<TannerRequest> {
    let mut out = Vec::new();
    for hit in hits {
        let source = &hit["_source"];
        let event = &source["honeypot"];
        if !event.is_object() {
            continue;
        }
        // Legacy "peer" session-report shape has no per-request fields;
        // startup markers are operational noise. Same skips as Go.
        if s(&event["method"]).is_empty() && s(&event["category"]).is_empty() {
            continue;
        }
        if s(&event["category"]) == "startup" {
            continue;
        }
        let headers = header_map(&event["headers"]);
        let header = |key: &str| headers.get(key).cloned().unwrap_or_default();
        // Real client IP from CF/proxy headers when fronted by Cloudflare,
        // same preference order as classify.go.
        let ip = [
            header("cf-connecting-ip"),
            header("x-real-ip"),
            header("x-forwarded-for").split(',').next().unwrap_or("").trim().to_string(),
            s(&event["src_ip"]),
        ]
        .into_iter()
        .find(|candidate| !candidate.is_empty())
        .unwrap_or_default();
        let detection = &event["response_msg"]["response"]["message"]["detection"];
        let mut payload = s(&detection["payload"]["value"]);
        if payload.len() > 1000 {
            let mut cut = 1000;
            while !payload.is_char_boundary(cut) {
                cut -= 1;
            }
            payload.truncate(cut);
            payload.push_str("(...)");
        }
        out.push(TannerRequest {
            when: s(&source["@timestamp"]),
            ip,
            method: s(&event["method"]),
            path: s(&event["path"]),
            user_agent: header("user-agent"),
            headers,
            username: s(&event["username"]),
            password: s(&event["password"]),
            tarpitted: event["tarpitted"].as_bool().unwrap_or(false),
            tarpit_bytes: n(&event["tarpit_bytes"]),
            tarpit_ms: n(&event["tarpit_ms"]),
            post_data: string_map(&event["post_data"]),
            cookies: string_map(&event["cookies"]),
            detection_name: s(&detection["name"]),
            detection_payload: payload,
        });
        if out.len() >= REQUEST_CAP {
            break;
        }
    }
    out
}

pub async fn detail(State(state): State<AppState>) -> Result<Json<SensorDetail>, (StatusCode, String)> {
    let (mailoney, http, tanner) = tokio::try_join!(
        query_sensor_raw(&state, "mailoney", false),
        query_sensor_raw(&state, "http-honeypot", true),
        query_sensor_raw(&state, "tanner", true),
    )
    .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(Json(SensorDetail {
        mailoney: mailoney_sessions(&mailoney),
        http_requests: http_requests(&http),
        tanner: tanner_requests(&tanner),
    }))
}
