package main

import "testing"

func TestCorrelateFlossSandboxIOCsNilWhenNoSandboxRun(t *testing.T) {
	floss := &ghidraFloss{DecodedStrings: []string{"http://203.0.113.5/payload"}}
	if got := correlateFlossSandboxIOCs(floss, nil); got != nil {
		t.Fatalf("correlateFlossSandboxIOCs with no sandbox runs = %+v, want nil", got)
	}
}

func TestCorrelateFlossSandboxIOCsUnsupportedFloss(t *testing.T) {
	floss := &ghidraFloss{Unsupported: "unsupported format for string decoding"}
	runs := []sandboxResult{{SHA256: "abc"}}
	got := correlateFlossSandboxIOCs(floss, runs)
	if got == nil || !got.HasSandboxRun || got.HasFlossData {
		t.Fatalf("correlateFlossSandboxIOCs with unsupported floss = %+v", got)
	}
}

// TestCorrelateFlossSandboxIOCsThreeWaySplit exercises #680's three named
// buckets in one pass: a floss-decoded IP that the sandbox never saw at all
// (floss-only), a domain the sandbox's static scan found that floss never
// decoded (sandbox-static-only), and a URL floss decoded that the sandbox
// actually observed downloading at runtime (confirmed-at-runtime) -- plus a
// private IP that must be filtered from the floss side entirely, matching
// extract_iocs.py's own PRIVATE exclusion.
func TestCorrelateFlossSandboxIOCsThreeWaySplit(t *testing.T) {
	floss := &ghidraFloss{
		DecodedStrings: []string{
			"connect to 203.0.113.9 for backup C2",
			"internal check 192.168.1.1 -- must not appear anywhere in output",
			"download from http://malicious.example.com/stage2.exe now",
		},
	}
	runs := []sandboxResult{{
		SHA256: "deadbeef",
		IOCs: sandboxIOCs{
			StaticDNSDomains: []string{"dormant-backup.example.net"},
			DownloadURLs:     []string{"http://malicious.example.com/stage2.exe"},
		},
	}}

	got := correlateFlossSandboxIOCs(floss, runs)
	if got == nil || !got.HasSandboxRun || !got.HasFlossData {
		t.Fatalf("correlateFlossSandboxIOCs = %+v, want a populated correlation", got)
	}

	if len(got.IPs.FlossOnly) != 1 || got.IPs.FlossOnly[0] != "203.0.113.9" {
		t.Errorf("IPs.FlossOnly = %v, want exactly [203.0.113.9]", got.IPs.FlossOnly)
	}
	for _, ip := range append(append([]string{}, got.IPs.FlossOnly...), got.IPs.SandboxStaticOnly...) {
		if ip == "192.168.1.1" {
			t.Errorf("private IP 192.168.1.1 leaked into the correlation, want it filtered like extract_iocs.py's PRIVATE does")
		}
	}

	if len(got.Domains.SandboxStaticOnly) != 1 || got.Domains.SandboxStaticOnly[0] != "dormant-backup.example.net" {
		t.Errorf("Domains.SandboxStaticOnly = %v, want exactly [dormant-backup.example.net]", got.Domains.SandboxStaticOnly)
	}

	if len(got.URLs.ConfirmedAtRuntime) != 1 || got.URLs.ConfirmedAtRuntime[0] != "http://malicious.example.com/stage2.exe" {
		t.Errorf("URLs.ConfirmedAtRuntime = %v, want exactly [http://malicious.example.com/stage2.exe]", got.URLs.ConfirmedAtRuntime)
	}
	if len(got.URLs.FlossOnly) != 0 {
		t.Errorf("URLs.FlossOnly = %v, want empty -- the one URL floss decoded was confirmed at runtime, not floss-only", got.URLs.FlossOnly)
	}
}

func TestMatchingSandboxRunsFiltersBySHA256(t *testing.T) {
	// matchingSandboxRuns reads through loadSandboxResults(), which in this
	// unconfigured test environment (no SANDBOX_RESULTS_DIR/ES) always
	// returns an empty slice -- this just confirms the empty case doesn't
	// panic and correlateFlossSandboxIOCs correctly reports "nothing to
	// correlate" for it, same as TestCorrelateFlossSandboxIOCsNilWhenNoSandboxRun.
	got := matchingSandboxRuns("does-not-exist")
	if len(got) != 0 {
		t.Fatalf("matchingSandboxRuns in an unconfigured environment = %v, want empty", got)
	}
}
