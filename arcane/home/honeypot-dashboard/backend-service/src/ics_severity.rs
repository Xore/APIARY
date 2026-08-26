//! DNP3 control-function severity banding, ported from the Go dashboard's
//! `dnp3_severity.go` (#1290).
//!
//! `detail.rs`'s dnp3 branch already reads `app_function` off every real
//! protocol frame, but renders every value as identical plain text — no
//! distinction between a benign link-status read and DIRECT_OPERATE,
//! DNP3's function code for commanding a physical device (trip a breaker,
//! open/close a valve) *without* the protocol's normal
//! select-before-operate confirmation step. Live sensor data showed 81% of
//! real frame traffic against the ElbeGrid Distribution persona carrying
//! exactly that function code.
//!
//! Banding it here lets the events explorer badge the frame the same way
//! ml-anomalies and agent-campaigns already badge their own
//! critical/high/medium severity strings. The Go tier carried this on
//! `storedEvent.ICSSeverity`; the port dropped the field entirely, so the
//! badge could not render at any cost on the frontend.

/// Function codes that change equipment state with no prior select/arm
/// step — the highest-consequence traffic this sensor can see, since a
/// real RTU would act on these immediately.
const CONTROL_FUNCTIONS: &[&str] = &["direct_operate", "direct_operate_no_ack"];

/// Codes that still change device state/behaviour (a restart, a
/// configuration write, a select-then-operate sequence) but either require
/// a follow-up step or affect the RTU itself rather than field equipment
/// directly — real, but a rung below an unconfirmed direct operate.
///
/// Every name here must be spelled exactly as the dnp3 honeypot's IEEE
/// 1815 decoder emits it (`honeypot-dnp3/dnp3-honeypot/main.go`,
/// `applicationFunctionCodes`) — the lookup is an exact string compare
/// against `app_function`, and #2114 was exactly such a drift: this table
/// said `save_config`, the sensor says `save_configuration`, so a
/// configuration write rendered unbadged for the module's whole life.
const RESTART_OR_CONFIG_FUNCTIONS: &[&str] = &[
    "select",
    "operate",
    "cold_restart",
    "warm_restart",
    "initialize_application",
    "activate_config",
    "save_configuration",
    "delete_file",
];

/// Bands an `app_function` value for badge styling. Everything else
/// (read, request_link_status, reset_link_states, confirm, response,
/// assign_class, and so on) is reconnaissance or protocol housekeeping and
/// stays unbadged.
pub fn dnp3_function_severity(app_function: &str) -> &'static str {
    if CONTROL_FUNCTIONS.contains(&app_function) {
        "critical"
    } else if RESTART_OR_CONFIG_FUNCTIONS.contains(&app_function) {
        "high"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::{dnp3_function_severity, CONTROL_FUNCTIONS, RESTART_OR_CONFIG_FUNCTIONS};
    use std::collections::HashSet;

    #[test]
    fn unconfirmed_control_is_critical() {
        assert_eq!(dnp3_function_severity("direct_operate"), "critical");
        assert_eq!(dnp3_function_severity("direct_operate_no_ack"), "critical");
    }

    #[test]
    fn restart_and_config_are_high() {
        assert_eq!(dnp3_function_severity("cold_restart"), "high");
        assert_eq!(dnp3_function_severity("select"), "high");
        // #2114: the wire spelling, not the banding table's — this
        // assertion previously pinned the drifted name `save_config`
        // against the table that contained it, proving nothing.
        assert_eq!(dnp3_function_severity("save_configuration"), "high");
    }

    /// The vocabulary the sensor can possibly emit, lifted straight from
    /// the dnp3 honeypot's decoder map at compile time. Map literal lines
    /// look like `0x13: "save_configuration",`.
    fn decoder_vocabulary() -> HashSet<&'static str> {
        let go = include_str!("../../../honeypot-dnp3/dnp3-honeypot/main.go");
        let map_entry =
            regex::Regex::new(r#"0x[0-9a-fA-F]+:\s*"([a-z0-9_]+)""#).unwrap();
        map_entry
            .captures_iter(go)
            .map(|c| c.get(1).unwrap().as_str())
            .collect()
    }

    #[test]
    fn every_banded_name_is_one_the_sensor_emits() {
        // The parity anchor #2114 lacked: a rename on either side of the
        // producer/bander seam now fails here instead of silently
        // unbadging real configuration writes in production.
        let decoded = decoder_vocabulary();
        assert!(
            decoded.contains("save_configuration"),
            "decoder extraction broke — save_configuration missing"
        );
        for name in CONTROL_FUNCTIONS.iter().chain(RESTART_OR_CONFIG_FUNCTIONS.iter()) {
            assert!(
                decoded.contains(name),
                "{name} is banded but applicationFunctionCodes never emits it"
            );
        }
    }

    #[test]
    fn reconnaissance_and_housekeeping_stay_unbadged() {
        assert_eq!(dnp3_function_severity("read"), "");
        assert_eq!(dnp3_function_severity("request_link_status"), "");
        assert_eq!(dnp3_function_severity("confirm"), "");
        assert_eq!(dnp3_function_severity(""), "");
    }
}
