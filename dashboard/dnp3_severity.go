package main

// dnp3_severity.go (#1290): classify.go's dnp3 branch already reads
// app_function off every real protocol frame, but rendered every value as
// identical plain text -- no distinction between a benign link-status read
// and DIRECT_OPERATE, DNP3's function code for commanding a physical device
// (trip a breaker, open/close a valve) WITHOUT the protocol's normal
// select-before-operate confirmation step. Live sensor data showed 81% of
// real frame traffic against the ElbeGrid Distribution persona carrying
// exactly that function code. This assigns a severity band so
// events.html can badge it the same way ml_anomalies.html/
// agent_campaigns.html already badge their own critical/high/medium/muted
// severity strings.

// dnp3ControlFunctions are function codes that change equipment state
// without any prior select/arm step -- the highest-consequence traffic this
// sensor can see, since a real RTU would act on these immediately.
var dnp3ControlFunctions = map[string]bool{
	"direct_operate":        true,
	"direct_operate_no_ack": true,
}

// dnp3RestartOrConfigFunctions still change device state/behavior (a
// restart, a configuration write, a select-then-operate control sequence)
// but either require a follow-up step or affect the RTU itself rather than
// field equipment directly -- real, but a rung below an unconfirmed direct
// operate.
var dnp3RestartOrConfigFunctions = map[string]bool{
	"select":                 true,
	"operate":                true,
	"cold_restart":           true,
	"warm_restart":           true,
	"initialize_application": true,
	"activate_config":        true,
	"save_config":            true,
	"delete_file":            true,
}

// dnp3FunctionSeverity bands an app_function value for badge styling.
// Everything else (read, request_link_status, reset_link_states, confirm,
// response, assign_class, and so on) is reconnaissance or protocol
// housekeeping and stays unbadged ("").
func dnp3FunctionSeverity(appFunction string) string {
	switch {
	case dnp3ControlFunctions[appFunction]:
		return "critical"
	case dnp3RestartOrConfigFunctions[appFunction]:
		return "high"
	default:
		return ""
	}
}

// icsSeverityBadgeClass maps storedEvent.ICSSeverity to the same badge
// modifier vocabulary ml_anomalies.html/agent_campaigns.html already use for
// their own critical/high/medium/muted severity strings.
func icsSeverityBadgeClass(sev string) string {
	switch sev {
	case "critical":
		return "badge--danger"
	case "high":
		return "badge--warning"
	default:
		return "badge--muted"
	}
}
