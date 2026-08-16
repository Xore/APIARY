package main

import "testing"

func TestDnp3FunctionSeverity(t *testing.T) {
	cases := []struct {
		appFunction string
		want        string
	}{
		{"direct_operate", "critical"},
		{"direct_operate_no_ack", "critical"},
		{"select", "high"},
		{"operate", "high"},
		{"cold_restart", "high"},
		{"warm_restart", "high"},
		{"initialize_application", "high"},
		{"activate_config", "high"},
		{"save_config", "high"},
		{"delete_file", "high"},
		{"read", ""},
		{"write", ""},
		{"confirm", ""},
		{"response", ""},
		{"request_link_status", ""},
		{"reset_link_states", ""},
		{"assign_class", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := dnp3FunctionSeverity(c.appFunction); got != c.want {
			t.Errorf("dnp3FunctionSeverity(%q) = %q, want %q", c.appFunction, got, c.want)
		}
	}
}

func TestICSSeverityBadgeClass(t *testing.T) {
	cases := []struct {
		sev  string
		want string
	}{
		{"critical", "badge--danger"},
		{"high", "badge--warning"},
		{"", "badge--muted"},
		{"unknown", "badge--muted"},
	}
	for _, c := range cases {
		if got := icsSeverityBadgeClass(c.sev); got != c.want {
			t.Errorf("icsSeverityBadgeClass(%q) = %q, want %q", c.sev, got, c.want)
		}
	}
}

// #1290: a DIRECT OPERATE frame -- an unconfirmed physical-control command
// (trip a breaker, open/close a valve) -- must be classified critical so
// events.html can badge it distinctly from a benign read/status frame,
// which classify() already surfaces identically in ev.detail otherwise.
func TestClassifyDNP3DirectOperateIsCriticalSeverity(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "dnp3", "event": "frame", "port": float64(20000),
		"function": "unconfirmed_user_data", "app_function": "direct_operate",
		"dnp3_source": float64(4), "dnp3_destination": float64(1),
	}, "dnp3")
	if ev.icsSeverity != "critical" {
		t.Fatalf("icsSeverity = %q, want %q for direct_operate", ev.icsSeverity, "critical")
	}
}

func TestClassifyDNP3StatusReadHasNoSeverity(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "dnp3", "event": "frame", "port": float64(20000),
		"function": "unconfirmed_user_data", "app_function": "read",
		"dnp3_source": float64(4), "dnp3_destination": float64(1),
	}, "dnp3")
	if ev.icsSeverity != "" {
		t.Fatalf("icsSeverity = %q, want empty for a benign read", ev.icsSeverity)
	}
}

func TestClassifyDNP3LinkOnlyFrameHasNoSeverity(t *testing.T) {
	ev := classify(map[string]any{
		"sensor": "dnp3", "event": "frame", "port": float64(20000),
		"function":    "confirmed_user_data",
		"dnp3_source": float64(4), "dnp3_destination": float64(1),
	}, "dnp3")
	if ev.icsSeverity != "" {
		t.Fatalf("icsSeverity = %q, want empty when no app_function is present", ev.icsSeverity)
	}
}
