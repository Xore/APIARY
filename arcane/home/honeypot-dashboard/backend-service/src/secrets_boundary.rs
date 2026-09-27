//! The API's side of #3213's secret-handling rule.
//!
//! The two decoys this issue is about -- http-honeypot and
//! cisco-asa-honeypot -- now decide a request's credential status in the
//! sensor and never store the secret, and each carries its own tests
//! proving it. This module is the SECOND half of the same boundary, and it
//! exists for a reason the sensor-side tests cannot cover: Elasticsearch
//! keeps everything it was ever given.
//!
//! A fleet that has been running these decoys has documents in the index
//! from before the sensor fix, with the password in `password` and in an
//! unredacted `body`/`data`. Redacting at the sensor fixes tomorrow's
//! events; it does nothing at all for the events already stored, and those
//! are exactly the ones an analyst opens the event page for. So the read
//! path scrubs, and the sensor's own redaction is the first line rather
//! than the only one.
//!
//! ## Why one choke point
//!
//! The alternative is threading a guard through every read of
//! `honeypot.password` -- and there are a dozen of them across
//! event_detail.rs, session.rs, exports.rs, events.rs and event_page.rs,
//! plus the raw `record` passthrough that returns a whole `_source` and
//! would need its own argument. Each one added is a place the next
//! contributor does not think about. So the rule is applied to the document
//! once, on the way in, at the top of the function that is already deciding
//! what to render. A read site that forgets to think about this cannot leak,
//! because by the time it runs the field is gone.
//!
//! ## What is deliberately NOT scrubbed
//!
//! Only the two decoys. cowrie, tanner, multipot, beelzebub, mailoney,
//! wordpot and the rest still return their passwords, exactly as before,
//! and this is the remaining exposure #3213's PR body declares rather than
//! hides. Those sensors were out of scope for the issue, and quietly
//! changing ten sensors' API responses inside a fix for two would be a
//! much larger breaking change than the one this PR already documents.
//! `is_credential_bearing` is the single place that scoping lives, so
//! widening it later is a one-line change with a test already waiting.
//!
//! What IS preserved for those sensors, and for these two, is the account
//! identifier: a username is the analytic value (a spray is a spray of
//! accounts) and it is not a secret. Only the secret half is removed.
//!
//! One aggregate is named here rather than left for a reader to trip over,
//! because it is the obvious next question: attacker identity's `Entity`
//! persists a `"{user} / {pass}"` signal per IP into `attackers-v1`, and the
//! attackers page renders it. That signal is built from every sensor at once
//! and stored as one merged string, so there is no way to tell which sensor
//! contributed a given pair -- dropping the two decoys from it would mean
//! either deleting the feature's central output for all twenty-odd sensors or
//! inventing a join the data does not have. It is left alone for the same
//! reason cowrie is. What this change does do is stop feeding it: the two
//! decoys no longer write `password`, so `canonical_pass` is never promoted
//! for them again and the residual is historical documents only.

use serde_json::{Map, Value};

/// The sensors whose events carry credentials under the #3213 schema.
///
/// Matched on the sensor name as the ingest pipeline recorded it, which is
/// also what covers documents indexed before the schema existed -- the
/// historical ones carry a `password` field this fleet's own UI used to
/// read and render, and the sensor name is the only thing they have in
/// common with the fixed events.
pub const CREDENTIAL_SENSORS: &[&str] = &["http-honeypot", "cisco-asa-honeypot"];

/// The fields a scrubbed document's free-text bodies can live in.
///
/// `data` is the ASA's field (its posted logon form) and `body` is the
/// HTTP decoy's; `query` and `post_data` are the other two channels either
/// sensor can be reached on. They are all strings of attacker-controlled
/// bytes that may hold a credential, so they all get the same pass.
const BODY_FIELDS: &[&str] = &["body", "data", "query", "post_data"];

/// Header names whose entire value is a credential or a session token.
/// Matched case-insensitively as substrings, so X-Api-Key and
/// Proxy-Authorization are covered by the same list -- the same list the
/// sensors use, kept in step deliberately.
const SECRET_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "api-key",
    "apikey",
    "auth-token",
];

/// What replaces a credential-shaped value. The same literal the sensors
/// use, so a reader looking at a scrubbed body and a reader looking at a
/// freshly-captured one recognise the same marker.
pub const REDACT_MARKER: &str = "[redacted]";

/// Envelope fields the scrubber must leave alone, whatever their name
/// matches.
///
/// Every one of these is #3213 metadata whose NAME contains a substring the
/// redaction key list matches -- "credential" and "auth" both do -- so
/// without this list the scrubber overwrites the values of the very fields
/// that describe the redaction: "extracted" becomes "[redacted]", "simulated"
/// becomes "[redacted]", and the API's answer to "was there a credential, and
/// was the auth real" becomes silence. `username` is here for the other
/// reason: the account half is deliberately kept.
///
/// Honoured on the ENVELOPE ONLY, never inside attacker-controlled data, and
/// that restriction is the security property rather than a detail. Matching
/// the list at any depth would hand anyone a bypass: POST a form field called
/// `auth_type` and its value would walk straight through the pass. The depth
/// is therefore carried down the recursion rather than inferred.
const ENVELOPE_FIELDS: &[&str] = &[
    "credential_status",
    "credential_present",
    "credential_indicator_match",
    "credential_indicator",
    "auth_type",
    "auth_outcome",
    "decoy_session_present",
    "username",
];

/// Field names the scrubber replaces values under. Wider than the set that
/// sets `credential_status` on purpose: a false redaction costs one
/// scanner's junk parameter, while a missed one is the failure this whole
/// boundary exists to prevent. `csrf` and `cookie` are in it because they
/// are session secrets an attacker will replay, even though neither is a
/// login credential.
const REDACT_KEYS: &[&str] = &[
    "pass",
    "pwd",
    "secret",
    "token",
    "jwt",
    "auth",
    "credential",
    "session",
    "csrf",
    "xsrf",
    "otp",
    "pin",
    "cookie",
    "sig",
    "signature",
    "nonce",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "secret_key",
    "private_key",
];

/// Reports whether a document is one of the decoys this boundary covers.
///
/// Two ways in, and both are needed. A document that declares
/// `credential_status` is on the new schema whatever its sensor field
/// says -- that catches a sensor added to the fleet later, and a document
/// whose sensor label has been rewritten in between. The sensor-name list
/// catches everything else, and specifically the historical documents from
/// before the field existed, which is the entire reason this module is not
/// redundant with the sensors' own redaction.
pub fn is_credential_bearing(sensor: &str, doc: &Value) -> bool {
    doc.get("credential_status").is_some() || CREDENTIAL_SENSORS.contains(&sensor)
}

/// Returns a scrubbed copy of one `honeypot.*` document, or `None` when
/// the sensor is out of scope.
///
/// `None` rather than an unchanged copy is deliberate: an out-of-scope
/// sensor's events are by far the common case in this service, and
/// cloning every one of them to hand back the same bytes would be a
/// measurable cost on the hottest read paths for no benefit. Callers write
/// `let hp = scrub_event(sensor, hp).as_ref().unwrap_or(hp);` and get the
/// borrow checker to do the rest.
pub fn scrub_event(sensor: &str, doc: &Value) -> Option<Value> {
    if !is_credential_bearing(sensor, doc) {
        return None;
    }
    let mut out = doc.clone();
    scrub_in_place(&mut out);
    Some(out)
}

/// Removes every secret from a document that has already been accepted as
/// credential-bearing, in place.
///
/// The `password` field goes rather than being blanked: an always-empty
/// field is still a field a consumer can be told to read, and #3213's
/// acceptance criteria are about what the API returns, not about what it
/// declines to fill in. Everything else is redacted rather than dropped,
/// because a body with the credential values replaced is still a payload an
/// analyst can classify, and a body removed is a blind spot.
fn scrub_in_place(doc: &mut Value) {
    let Some(map) = doc.as_object_mut() else {
        return;
    };
    map.remove("password");

    for field in BODY_FIELDS {
        if let Some(Value::String(raw)) = map.get_mut(*field) {
            *raw = redact_values(raw);
        }
    }

    if let Some(Value::Object(headers)) = map.get_mut("headers") {
        for (name, value) in headers.iter_mut() {
            // Only the headers that ARE a credential, and only by value.
            // The name survives so "did this request attempt to
            // authenticate at all" stays answerable, and every other
            // header survives untouched -- blanking the whole map would
            // be a far larger regression than the leak it prevents.
            if !is_secret_header(name) {
                continue;
            }
            if let Value::String(text) = value {
                *text = REDACT_MARKER.to_string();
            }
        }
    }
    // The ASA's posted form and the HTTP decoy's body are also reachable
    // through a nested object in some historical documents, so the same
    // pass runs over anything nested under one of the body fields rather
    // than assuming a flat string. Depth 0 is the envelope.
    scrub_nested(map, 0);
}

/// Whether a header's entire value is a credential or a session token.
/// Substring match, so X-Api-Key and Proxy-Authorization are covered by
/// the same list.
fn is_secret_header(name: &str) -> bool {
    let lower = name.to_lowercase();
    SECRET_HEADERS.iter().any(|s| lower.contains(s))
}

/// Recurses into nested objects and arrays replacing credential-shaped
/// values, for documents whose body is not a flat string.
///
/// `depth` is 0 on the event envelope and grows with the recursion, and it
/// is the only thing standing between `ENVELOPE_FIELDS` and being a bypass --
/// see that constant's note.
fn scrub_nested(node: &mut Map<String, Value>, depth: usize) {
    for (key, child) in node.iter_mut() {
        if depth == 0 && ENVELOPE_FIELDS.contains(&key.as_str()) {
            continue;
        }
        if REDACT_KEYS.iter().any(|k| key.to_lowercase().contains(k)) {
            if child.is_string() {
                *child = Value::String(REDACT_MARKER.to_string());
            }
            continue;
        }
        match child {
            Value::Object(obj) => scrub_nested(obj, depth + 1),
            Value::Array(items) => {
                for item in items.iter_mut() {
                    if let Value::Object(obj) = item {
                        scrub_nested(obj, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Replaces the value of every credential-shaped field in a free-text
/// body, query string, or data payload.
///
/// A value scrubber rather than a parser, and the same shape as the Go
/// sensors' `redactOpaque`: find a field name, look at the separator that
/// follows it, and replace the value that belongs to that separator's own
/// structural delimiter. Stopping at the first space would leave the tail
/// of "correct horse battery staple" behind, and a password is exactly
/// where someone puts a space.
///
/// It over-redacts on purpose. A field called "monkey" loses its value; a
/// prose body that mentions "password" may lose the rest of its line.
pub fn redact_values(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let lower = raw.to_lowercase();
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0usize;

    while i < bytes.len() {
        let Some(name_len) = match_field_name(&lower, bytes, i) else {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        };
        out.push_str(&raw[i..i + name_len]);
        i += name_len;
        // Step over the rest of the name and WRITE it. "password=" matched
        // the key "pass" with the cursor on "word=", so the matched prefix
        // alone is not the field name -- emitting only that would turn
        // "password=x" into "pass[redacted]" and lose the very field whose
        // value was being redacted.
        let name_end = i + bytes[i..].iter().take_while(|b| is_name_byte(**b)).count();
        out.push_str(&raw[i..name_end]);
        i = name_end;
        // A QUOTED field name closes before its separator: JSON puts a
        // quote there, and a quote is also one of the value separators, so
        // without this the scrubber would read the key's own closing quote
        // as "a quoted value starts here" and redact through the colon.
        if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
            out.push(bytes[i] as char);
            i += 1;
        }
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
            out.push(bytes[i] as char);
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        if !is_value_separator(bytes[i]) {
            continue;
        }
        // The separator is part of the field's shape, not part of its
        // value, so it is written back around the marker. Without that
        // "password=x" would come out as "password[redacted]" -- which
        // both loses the field name an analyst is reading and stops
        // being re-parseable, so the next read of the same body would
        // not recognise the field at all.
        out.push(bytes[i] as char);

        // A quoted value ends at its own closing quote, whichever
        // separator introduced it. This is the JSON case: the value after
        // ':' is a quoted string, and the ':' rule (scan to , } ]) would
        // run straight past the closing quote and write the secret back
        // into the response.
        if i + 1 < bytes.len() && (bytes[i + 1] == b'"' || bytes[i + 1] == b'\'') {
            let quote = bytes[i + 1] as char;
            out.push(quote);
            out.push_str(REDACT_MARKER);
            out.push(quote);
            i = scan_quoted(bytes, i + 1);
            continue;
        }
        out.push_str(REDACT_MARKER);
        let end = value_end(bytes, i + 1);
        if end > i + 1 {
            i = end;
        }
    }
    out
}

/// Whether a byte can introduce a value after a field name. The shapes
/// `redact_values` knows how to bound.
fn is_value_separator(b: u8) -> bool {
    matches!(b, b'=' | b':' | b'>' | b'"' | b'\'')
}

/// The index just past the closing quote of the quoted run starting at `i`,
/// or `bytes.len()` when the run is unterminated.
fn scan_quoted(bytes: &[u8], i: usize) -> usize {
    let quote = bytes[i];
    for (j, b) in bytes.iter().enumerate().skip(i + 1) {
        if *b == quote {
            return j + 1;
        }
    }
    bytes.len()
}

/// The end of an unquoted value that starts at `from`, by the separator
/// that introduced it: `bytes[from-1]` is the `=`, `:` or `>` that started
/// it, and the rules differ per separator. Returns `from` when there is
/// nothing to replace, so a bare mention of a field name costs nothing.
///
/// The separator is passed in rather than found here because `redact_values`
/// has already written it back around the marker by the time this runs;
/// finding it again would mean walking back over bytes already emitted.
fn value_end(bytes: &[u8], from: usize) -> usize {
    if from == 0 || from > bytes.len() {
        return from;
    }
    match bytes[from - 1] {
        b'=' => scan_to(bytes, from, b"&\n"),
        b':' => scan_to(bytes, from, b",}]\n"),
        b'>' => scan_to(bytes, from, b"<\n"),
        b'"' | b'\'' => scan_quoted(bytes, from - 1),
        _ => from,
    }
}

fn scan_to(bytes: &[u8], from: usize, stops: &[u8]) -> usize {
    for (j, b) in bytes.iter().enumerate().skip(from) {
        if stops.contains(b) {
            return j;
        }
    }
    bytes.len()
}

/// The longest credential field name starting at `i`, if one starts there.
///
/// A name only counts at the start of a token, or at a camelCase boundary.
/// "compass=1" must not lose its value to the "pass" inside it, so a match
/// mid-word needs an uppercase letter to start it -- which is exactly what a
/// camelCase field name has and a lowercase word does not. Both strings are
/// needed for that test: the lowercased form cannot tell `loginPassword`
/// from `loginpassword`, and only the first is a field name anyone writes.
fn match_field_name(lower: &str, bytes: &[u8], i: usize) -> Option<usize> {
    if i > 0 && !is_name_start(bytes, i) {
        return None;
    }
    let rest = &lower[i..];
    REDACT_KEYS
        .iter()
        .filter(|k| rest.starts_with(**k))
        .map(|k| k.len())
        .max()
}

/// Whether position `i` begins a field name rather than sitting in the
/// middle of one.
fn is_name_start(bytes: &[u8], i: usize) -> bool {
    if matches!(
        bytes[i - 1],
        b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'=' | b':' | b'<' | b'[' | b'{' | b',' | b';' | b'&' | b'?'
    ) {
        return true;
    }
    // A camelCase boundary: the character here is a letter and it is
    // capitalised. A lowercase match inside a word is still a word.
    bytes[i].is_ascii_uppercase()
}

/// Whether a byte can continue a field name. Narrower than the set that may
/// START one, and narrower than alphanumeric: a value that ran on without a
/// separator is not a name, and treating it as one would swallow the rest
/// of the payload looking for an `=` that never comes.
fn is_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'
}

/// Scrubs a full `_source` document -- the shape `event_page.rs` returns as
/// its raw `record` and `events.rs::row_from_source` hands to the explorer.
///
/// The whole point of this function is that these two show an analyst the
/// document as stored. Returning it unscrubbed is how a stored password
/// reaches a browser, so the record is scrubbed in the same place and the
/// same way as every derived field, rather than being trusted to a per-field
/// guard that a new field would not know about.
///
/// `None` for an out-of-scope sensor, for the same reason as `scrub_event`:
/// this runs once per row of the explorer and once per event page, and the
/// overwhelming majority of documents belong to sensors this issue does not
/// cover. Callers write `.unwrap_or(src)` and the borrow checker holds the
/// rest.
pub fn scrub_source(sensor: &str, src: &Value) -> Option<Value> {
    if !is_credential_bearing(sensor, &src["honeypot"]) {
        return None;
    }
    let mut out = src.clone();
    if let Some(hp) = out.get_mut("honeypot") {
        scrub_in_place(hp);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "correct-horse-battery-staple-9f2c";

    fn scrubbed(sensor: &str, doc: &Value) -> Value {
        scrub_event(sensor, doc).expect("a boundary sensor must always be scrubbed")
    }

    #[test]
    fn out_of_scope_sensors_are_returned_unchanged_and_uncloned() {
        // None, not a clone: this is the common case on the hot read paths
        // and must not cost an allocation per event.
        assert!(scrub_event("cowrie", &json!({"password": SECRET})).is_none());
        assert!(scrub_event("tanner", &json!({"password": SECRET})).is_none());
        assert!(scrub_event("suricata", &json!({"password": SECRET})).is_none());
    }

    #[test]
    fn the_password_field_is_removed_not_blanked() {
        let out = scrubbed("http-honeypot", &json!({"password": SECRET, "username": "root"}));
        assert!(out.get("password").is_none(), "an always-empty field is still a field a consumer can read");
        assert_eq!(out["username"], json!("root"), "the account identifier is the analytic value and survives");
    }

    #[test]
    fn a_form_body_loses_its_secret_and_keeps_its_shape() {
        let out = scrubbed(
            "http-honeypot",
            &json!({"body": format!("username=admin&password={SECRET}&next=%2Fwp-admin")}),
        );
        assert!(!out["body"].as_str().unwrap().contains(SECRET));
        assert!(out["body"].as_str().unwrap().contains(&format!("password={REDACT_MARKER}")));
        assert!(out["body"].as_str().unwrap().contains("next=%2Fwp-admin"));
    }

    #[test]
    fn the_asa_data_field_is_scrubbed_too() {
        // The ASA's posted WebVPN logon form arrives in `data`, not `body`.
        let out = scrubbed(
            "cisco-asa-honeypot",
            &json!({"data": format!("username=admin&password={SECRET}&otp={SECRET}&portal=remote")}),
        );
        let data = out["data"].as_str().unwrap();
        assert!(!data.contains(SECRET));
        assert!(data.contains("username=admin"));
        assert!(data.contains("portal=remote"));
    }

    #[test]
    fn a_secret_header_value_is_replaced_but_its_name_is_kept() {
        let out = scrubbed(
            "http-honeypot",
            &json!({"headers": {"Authorization": format!("Basic {SECRET}"), "User-Agent": "curl/8.5.0"}}),
        );
        assert_eq!(out["headers"]["Authorization"], json!(REDACT_MARKER));
        assert_eq!(out["headers"]["User-Agent"], json!("curl/8.5.0"));
    }

    #[test]
    fn the_axis_fields_survive_their_own_key_list() {
        // The bug this pair of tests exists for. "credential" and "auth" are
        // both in REDACT_KEYS, and every axis field's NAME contains one of
        // them, so the scrubber was replacing the values of the fields that
        // report the redaction. An API that answers "was there a credential"
        // with "[redacted]" has been silenced by its own safety check.
        let out = scrubbed(
            "http-honeypot",
            &json!({
                "credential_status": "extracted",
                "credential_present": true,
                "credential_indicator_match": true,
                "credential_indicator": "nexusai-ops/bait-operator",
                "auth_type": "form",
                "auth_outcome": "simulated",
                "decoy_session_present": true,
                "username": "admin"
            }),
        );
        assert_eq!(out["credential_status"], json!("extracted"));
        assert_eq!(out["credential_present"], json!(true));
        assert_eq!(out["credential_indicator_match"], json!(true));
        assert_eq!(out["credential_indicator"], json!("nexusai-ops/bait-operator"));
        assert_eq!(out["auth_type"], json!("form"));
        assert_eq!(out["auth_outcome"], json!("simulated"));
        assert_eq!(out["decoy_session_present"], json!(true));
        assert_eq!(out["username"], json!("admin"));
    }

    #[test]
    fn the_envelope_allowlist_is_not_a_bypass() {
        // The other half of the pair, and the more important one: the
        // allowlist is honoured at the envelope ONLY. If it matched at any
        // depth, an attacker would smuggle a secret past the whole boundary
        // by naming their form field `auth_type` -- and the value would come
        // back out of the API verbatim.
        let out = scrubbed(
            "http-honeypot",
            &json!({
                "auth_type": "form",
                "post_data": {
                    "auth_type": SECRET,
                    "credential_status": SECRET,
                    "username": "admin"
                }
            }),
        );
        assert_eq!(out["auth_type"], json!("form"), "the envelope's own axis field is preserved");
        assert_eq!(out["post_data"]["auth_type"], json!(REDACT_MARKER), "a nested field name is a bypass");
        assert_eq!(out["post_data"]["credential_status"], json!(REDACT_MARKER), "a nested field name is a bypass");
        assert_eq!(out["post_data"]["username"], json!("admin"), "the account still survives where it is data");
    }

    #[test]
    fn the_envelope_allowlist_does_not_extend_to_the_headers_map() {
        // `headers` is one level down from the envelope in spirit but is
        // keyed by attacker-chosen names, so nothing in it is exempt. A
        // header literally called `auth_type` is a header, not an axis.
        let out = scrubbed(
            "http-honeypot",
            &json!({"headers": {"auth_type": SECRET, "username": "admin"}}),
        );
        assert_eq!(out["headers"]["auth_type"], json!(REDACT_MARKER));
        assert_eq!(out["headers"]["username"], json!("admin"));
    }

    #[test]
    fn a_historical_document_with_no_credential_status_is_still_scrubbed() {
        // This is the whole reason the sensor-name list exists: documents
        // indexed before the sensor fix carry a password and no
        // credential_status, and they are the ones an analyst opens.
        let historical = json!({"password": SECRET, "body": format!("password={SECRET}")});
        assert!(historical.get("credential_status").is_none());
        let out = scrubbed("http-honeypot", &historical);
        assert!(out.get("password").is_none());
        assert!(!out["body"].as_str().unwrap().contains(SECRET));
    }

    #[test]
    fn a_document_declaring_credential_status_is_scrubbed_whatever_its_sensor() {
        // The forward-looking half: a sensor added to the fleet later, or a
        // sensor label rewritten in between, is covered by the schema
        // declaration rather than by a list someone has to remember to
        // extend.
        let out = scrubbed(
            "some-future-decoy",
            &json!({"credential_status": "extracted", "password": SECRET}),
        );
        assert!(out.get("password").is_none());
    }

    #[test]
    fn scrub_source_covers_the_raw_record_passthrough() {
        let src = json!({
            "@timestamp": "2026-09-27T00:00:00Z",
            "honeypot": {"sensor": "http-honeypot", "password": SECRET, "body": format!("password={SECRET}")},
            "suricata": {"eve": {"alert": {"signature": "x"}}},
        });
        let out = scrub_source("http-honeypot", &src).expect("a boundary sensor must always be scrubbed");
        assert!(out["honeypot"].get("password").is_none());
        assert!(!out["honeypot"]["body"].as_str().unwrap().contains(SECRET));
        assert_eq!(out["suricata"]["eve"]["alert"]["signature"], json!("x"), "unrelated branches must survive untouched");
        assert_eq!(out["@timestamp"], src["@timestamp"]);
    }

    #[test]
    fn scrub_source_leaves_an_out_of_scope_sensor_alone() {
        let src = json!({"honeypot": {"sensor": "cowrie", "password": "toor"}});
        // None, and therefore the original borrow at every call site -- the
        // explorer builds a row per hit and cloning every cowrie event to
        // hand back the same bytes is a cost this issue does not need to pay.
        assert!(scrub_source("cowrie", &src).is_none(), "cowrie is out of #3213's scope and must not change behaviour here");
    }

    #[test]
    fn a_secret_with_spaces_is_fully_redacted() {
        let out = redact_values("password=hunter2 with spaces inside\nnext=/admin");
        assert!(!out.contains("hunter2"), "the scrubber stopped at the first space: {out}");
        assert!(!out.contains("spaces inside"), "the scrubber left the tail of the secret: {out}");
        assert!(out.contains("next=/admin"), "the line after the credential was eaten: {out}");
    }

    #[test]
    fn a_field_name_inside_another_word_is_not_a_field_name() {
        // The false-positive guard. The scrubber over-redacts on purpose,
        // but if "compass" lost its value the scrubbed bodies would be
        // useless and the redaction would be quietly disabling the payload
        // signal the fleet depends on.
        let out = redact_values("compass=1&user=admin");
        assert!(out.contains("=1"), "'compass' lost its value to the 'pass' inside it: {out}");
        assert!(out.contains("user=admin"));
    }

    #[test]
    fn a_quoted_value_is_bounded_by_its_own_quote() {
        // The JSON case, and the one that leaked: the value after ':' is a
        // quoted string, and the ':' rule (scan to , } ]) runs straight
        // past the closing quote. A JSON body stored under these decoys
        // predates the sensors' own redaction, so the boundary is the only
        // thing standing between a stored secret and a browser.
        for body in [
            format!(r#"{{"password":"{SECRET}"}}"#),
            format!(r#"{{"user":"admin","password":"{SECRET}","next":"/wp-admin"}}"#),
            format!(r#"{{"loginPassword":"{SECRET}"}}"#),
            format!(r#"{{'password': '{SECRET}'}}"#),
            format!(r#"{{"credentials":{{"apiKey":"{SECRET}"}}}}"#),
        ] {
            let out = redact_values(&body);
            assert!(!out.contains(SECRET), "the secret survived redaction of {body:?}: {out:?}");
            assert!(out.contains(REDACT_MARKER), "nothing was redacted in {body:?}: {out:?}");
        }
    }

    #[test]
    fn a_camel_case_field_name_is_recognised() {
        // A match mid-word needs an uppercase letter to start it, which is
        // what separates a real camelCase field name from the "pass" inside
        // "compass". Both halves have to hold.
        for name in ["loginPassword", "userPassword", "apiKey", "APIKEY", "authToken", "sessionId"] {
            let out = redact_values(&format!("{name}={SECRET}"));
            assert!(!out.contains(SECRET), "a camelCase field name was missed: {out:?}");
            assert!(out.contains(&format!("{name}=")), "the field name was mangled: {out:?}");
        }
        for word in ["compass", "mypass", "bypassed", "bypasscode"] {
            let out = redact_values(&format!("{word}=1"));
            assert!(out.contains("=1"), "a word containing 'pass' lost its value: {out:?}");
        }
    }

    #[test]
    fn the_marker_is_recognisable_rather_than_guessed_at() {
        assert_eq!(redact_values("password=x"), format!("password={REDACT_MARKER}"));
    }
}
