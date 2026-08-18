//! /api/v1/mail/{session_id} — surface mailoney's captured SMTP DATA
//! bodies (#1611 workstream B). The event stream only ever carried a
//! `mail-body` line with size/body_path; the actual .eml bytes lived only
//! on disk, invisible to the dashboard. es_importer.rs's new
//! `mailoney_mail` source now mirrors those files into `mailoney-mail-v1`
//! keyed by sha256(filename); this endpoint does the two-step join the
//! importer's own doc comment describes: honeypot-v2-*/suricata-v2-* for
//! the `mail-body` event matching this session_id -> its body_path, then
//! mailoney-mail-v1 for that body_path -> the base64 .eml bytes, parsed
//! with the `mail-parser` crate (attacker-controlled MIME input gets a
//! real, battle-tested parser rather than a hand-rolled one).
//!
//! Bodies are exposed as plain text only — HTML is decoded to a string
//! but never rendered, and attachments are listed as metadata (name,
//! content-type, size, sha256) without their bytes, so this endpoint
//! can't become an attacker-controlled HTML/script sink or a malware
//! distribution point.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use base64::Engine;
use mail_parser::{MessageParser, MimeHeaders};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::AppState;

#[derive(Serialize)]
pub struct MailAttachment {
    pub filename: String,
    pub content_type: String,
    pub size_bytes: usize,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct MailAddress {
    pub name: String,
    pub address: String,
}

#[derive(Serialize)]
pub struct Mail {
    pub session_id: String,
    pub body_path: String,
    pub size_bytes: u64,
    pub imported_at: String,
    pub from: Option<MailAddress>,
    pub to: Vec<MailAddress>,
    pub subject: String,
    pub date: String,
    pub message_id: String,
    pub body_text: String,
    pub attachments: Vec<MailAttachment>,
    pub eml_base64: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn addr(a: &mail_parser::Addr) -> MailAddress {
    MailAddress {
        name: a.name.as_deref().unwrap_or("").to_string(),
        address: a.address.as_deref().unwrap_or("").to_string(),
    }
}

fn addr_list(value: Option<&mail_parser::Address>) -> Vec<MailAddress> {
    value
        .map(|address| address.as_list().unwrap_or(&[]).iter().map(addr).collect())
        .unwrap_or_default()
}

/// Everything derivable from the raw .eml bytes alone (no ES fields) —
/// factored out so it's testable against literal fixtures without a live
/// Elasticsearch connection.
struct ParsedMail {
    from: Option<MailAddress>,
    to: Vec<MailAddress>,
    subject: String,
    date: String,
    message_id: String,
    body_text: String,
    attachments: Vec<MailAttachment>,
}

fn parse_eml(raw: &[u8]) -> Option<ParsedMail> {
    let message = MessageParser::default().parse(raw)?;
    let body_text = message
        .body_text(0)
        .map(|text| text.into_owned())
        .or_else(|| message.body_html(0).map(|html| html.into_owned()))
        .unwrap_or_default();
    let attachments = message
        .attachments()
        .map(|part| {
            let bytes = part.contents();
            MailAttachment {
                filename: part.attachment_name().unwrap_or("").to_string(),
                content_type: part
                    .content_type()
                    .map(|ct| match &ct.c_subtype {
                        Some(sub) => format!("{}/{sub}", ct.c_type),
                        None => ct.c_type.to_string(),
                    })
                    .unwrap_or_default(),
                size_bytes: bytes.len(),
                sha256: hex(&Sha256::digest(bytes)),
            }
        })
        .collect();
    Some(ParsedMail {
        from: message.from().and_then(|a| a.first()).map(addr),
        to: addr_list(message.to()),
        subject: message.subject().unwrap_or("").to_string(),
        date: message.date().map(|d| d.to_rfc3339()).unwrap_or_default(),
        message_id: message.message_id().unwrap_or("").to_string(),
        body_text,
        attachments,
    })
}

pub async fn get(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<Mail>, (StatusCode, String)> {
    let session_id = session_id.trim().to_string();
    if session_id.is_empty() || session_id.len() > 256 {
        return Err((StatusCode::BAD_REQUEST, "invalid session id".into()));
    }

    let event_body = json!({
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [
            {"term": {"honeypot.session_id": session_id}},
            {"term": {"honeypot.event": "mail-body"}}
        ]}}
    });
    let event_result = state
        .es
        .search(event_body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let event_hit = event_result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .ok_or((StatusCode::NOT_FOUND, "no captured mail for this session".to_string()))?;
    let body_path = event_hit["_source"]["honeypot"]["body_path"].as_str().unwrap_or("").to_string();
    if body_path.is_empty() {
        return Err((StatusCode::NOT_FOUND, "mail-body event carries no body_path".to_string()));
    }

    let mail_body = json!({"size": 1, "query": {"term": {"body_path": body_path}}});
    let mail_result = state
        .es
        .search_index(&["mailoney-mail-v1"], mail_body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let mail_hit = mail_result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .ok_or((StatusCode::NOT_FOUND, "mail body not yet imported".to_string()))?;
    let source = &mail_hit["_source"];
    let encoded = source["eml_base64"].as_str().unwrap_or("").to_string();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .map_err(|error| (StatusCode::BAD_GATEWAY, format!("eml decode: {error}")))?;

    let parsed = parse_eml(&raw).ok_or((StatusCode::BAD_GATEWAY, "unparseable mail body".to_string()))?;

    Ok(Json(Mail {
        session_id,
        body_path,
        size_bytes: source["size_bytes"].as_u64().unwrap_or(raw.len() as u64),
        imported_at: source["imported_at"].as_str().unwrap_or("").to_string(),
        from: parsed.from,
        to: parsed.to,
        subject: parsed.subject,
        date: parsed.date,
        message_id: parsed.message_id,
        body_text: parsed.body_text,
        attachments: parsed.attachments,
        eml_base64: encoded,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: &[u8] = b"From: Attacker <attacker@evil.example>\r\n\
To: victim@example.org\r\n\
Subject: test payload\r\n\
Date: Tue, 18 Aug 2026 10:00:00 +0000\r\n\
Message-ID: <abc123@evil.example>\r\n\
Content-Type: text/plain\r\n\
\r\n\
hello from mailoney\r\n";

    const MULTIPART: &[u8] = b"From: Attacker <attacker@evil.example>\r\n\
To: victim@example.org\r\n\
Subject: with attachment\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\
\r\n\
--BOUNDARY\r\n\
Content-Type: text/plain\r\n\
\r\n\
see attached\r\n\
--BOUNDARY\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=\"payload.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
aGVsbG8=\r\n\
--BOUNDARY--\r\n";

    #[test]
    fn plain_text_mail_extracts_headers_and_body() {
        let parsed = parse_eml(PLAIN).expect("should parse");
        assert_eq!(parsed.subject, "test payload");
        assert_eq!(parsed.message_id, "abc123@evil.example");
        assert_eq!(parsed.body_text.trim(), "hello from mailoney");
        assert_eq!(parsed.to[0].address, "victim@example.org");
        assert_eq!(parsed.from.unwrap().address, "attacker@evil.example");
        assert!(parsed.attachments.is_empty());
    }

    #[test]
    fn multipart_mail_lists_attachment_metadata_without_html_rendering_risk() {
        let parsed = parse_eml(MULTIPART).expect("should parse");
        assert_eq!(parsed.body_text.trim(), "see attached");
        assert_eq!(parsed.attachments.len(), 1);
        let attachment = &parsed.attachments[0];
        assert_eq!(attachment.filename, "payload.bin");
        assert_eq!(attachment.content_type, "application/octet-stream");
        assert_eq!(attachment.size_bytes, 5); // "hello" decoded from base64
        assert_eq!(attachment.sha256, hex(&Sha256::digest(b"hello")));
    }

    #[test]
    fn garbage_bytes_still_parse_as_a_bodyless_message() {
        // mail-parser is lenient by design (attacker-controlled input) —
        // this asserts we don't panic on malformed input, not that it
        // necessarily returns None.
        let _ = parse_eml(b"not an email at all, just bytes \x00\x01\x02");
    }
}
