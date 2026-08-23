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
const RESTART_OR_CONFIG_FUNCTIONS: &[&str] = &[
    "select",
    "operate",
    "cold_restart",
    "warm_restart",
    "initialize_application",
    "activate_config",
    "save_config",
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
    use super::dnp3_function_severity;

    #[test]
    fn unconfirmed_control_is_critical() {
        assert_eq!(dnp3_function_severity("direct_operate"), "critical");
        assert_eq!(dnp3_function_severity("direct_operate_no_ack"), "critical");
    }

    #[test]
    fn restart_and_config_are_high() {
        assert_eq!(dnp3_function_severity("cold_restart"), "high");
        assert_eq!(dnp3_function_severity("select"), "high");
        assert_eq!(dnp3_function_severity("save_config"), "high");
    }

    #[test]
    fn reconnaissance_and_housekeeping_stay_unbadged() {
        assert_eq!(dnp3_function_severity("read"), "");
        assert_eq!(dnp3_function_severity("request_link_status"), "");
        assert_eq!(dnp3_function_severity("confirm"), "");
        assert_eq!(dnp3_function_severity(""), "");
    }
}
