package main

import "testing"

// TestDetectRedisSSHKeyInjectionMatchesLiveSample (#1291) uses the exact
// four-command sequence the issue's own live investigation found: redirect
// the RDB save path into ~/.ssh, rename the save file authorized_keys,
// write the attacker's own public key as a value, force a save.
func TestDetectRedisSSHKeyInjectionMatchesLiveSample(t *testing.T) {
	cmds := []string{
		"CONFIG SET dir /root/.ssh",
		"CONFIG SET dbfilename authorized_keys",
		"SET k \"\n\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINyNe/Z73WAjJGIquLvTPIRuqJ6MuBBYAt8TlGHmHssr pen\n\n\"",
		"BGSAVE",
	}
	if !detectRedisSSHKeyInjection(cmds) {
		t.Fatal("expected the live-sample sequence to match")
	}
}

// TestDetectRedisSSHKeyInjectionAllowsInterleaving covers the issue's own
// "reasonable reordering/interleaving" allowance -- unrelated commands
// between the four real steps must not break the match.
func TestDetectRedisSSHKeyInjectionAllowsInterleaving(t *testing.T) {
	cmds := []string{
		"INFO server",
		"CONFIG SET dir /root/.ssh",
		"PING",
		"CONFIG SET dbfilename authorized_keys",
		"SET k \"ssh-rsa AAAAB3NzaC1yc2E pwned\"",
		"CLIENT LIST",
		"BGSAVE",
	}
	if !detectRedisSSHKeyInjection(cmds) {
		t.Fatal("expected the sequence to match with unrelated commands interleaved")
	}
}

func TestDetectRedisSSHKeyInjectionRejectsWrongOrder(t *testing.T) {
	// BGSAVE before the key is ever written -- not the attack, must not match.
	cmds := []string{
		"BGSAVE",
		"CONFIG SET dir /root/.ssh",
		"CONFIG SET dbfilename authorized_keys",
		"SET k \"ssh-ed25519 AAAA pwned\"",
	}
	if detectRedisSSHKeyInjection(cmds) {
		t.Fatal("out-of-order steps must not match")
	}
}

func TestDetectRedisSSHKeyInjectionRejectsPartialSequence(t *testing.T) {
	// Only the two CONFIG SET calls, no key write or save -- a real but
	// separate, lower-severity probe, not the full RCE technique.
	cmds := []string{"CONFIG SET dir /root/.ssh", "CONFIG SET dbfilename authorized_keys"}
	if detectRedisSSHKeyInjection(cmds) {
		t.Fatal("a partial sequence must not match the full technique")
	}
}

func TestDetectRedisSSHKeyInjectionEmptyInput(t *testing.T) {
	if detectRedisSSHKeyInjection(nil) {
		t.Fatal("no commands must never match")
	}
}

// TestDetectADBReconFingerprintMatchesLiveSample uses the issue's own live
// sample: architecture, CPU count, memory, privilege level, device model
// chained in one shell invocation.
func TestDetectADBReconFingerprintMatchesLiveSample(t *testing.T) {
	cmds := []string{"shell:uname -m; nproc; cat /proc/meminfo | grep MemTotal; id -u; getprop ro.product.model;"}
	if !detectADBReconFingerprint(cmds) {
		t.Fatal("expected the live-sample recon chain to match")
	}
}

// TestDetectADBReconFingerprintRejectsSingleBenignCommand guards against a
// single legitimate-looking uname probe alone counting as a full recon
// fingerprint (the whole point of the 3-of-5 threshold).
func TestDetectADBReconFingerprintRejectsSingleBenignCommand(t *testing.T) {
	if detectADBReconFingerprint([]string{"shell:uname -a"}) {
		t.Fatal("a single indicator must not count as a recon fingerprint")
	}
}

func TestDetectADBReconFingerprintRejectsTwoIndicators(t *testing.T) {
	if detectADBReconFingerprint([]string{"shell:uname -m; nproc"}) {
		t.Fatal("two indicators is below the 3-of-5 threshold, must not match")
	}
}

// TestDetectAttackSequencesFiltersBySensorAndProto (#1291) pins that only
// multipot commands on the exact matching proto feed each pattern -- a
// redis-shaped command sequence on a different sensor/protocol must not
// false-positive.
func TestDetectAttackSequencesFiltersBySensorAndProto(t *testing.T) {
	events := []storedEvent{
		{Sensor: "cowrie", Proto: "ssh", Command: "CONFIG SET dir /root/.ssh"},
		{Sensor: "multipot", Proto: "postgres", Command: "CONFIG SET dir /root/.ssh"},
	}
	if got := detectAttackSequences(events); len(got) != 0 {
		t.Fatalf("expected no matches for wrong sensor/proto, got %+v", got)
	}
}

func TestDetectAttackSequencesFindsRedisAndADBTogether(t *testing.T) {
	events := []storedEvent{
		{Sensor: "multipot", Proto: "redis", Command: "CONFIG SET dir /root/.ssh"},
		{Sensor: "multipot", Proto: "redis", Command: "CONFIG SET dbfilename authorized_keys"},
		{Sensor: "multipot", Proto: "redis", Command: "SET k \"ssh-ed25519 AAAA pwned\""},
		{Sensor: "multipot", Proto: "redis", Command: "BGSAVE"},
		{Sensor: "multipot", Proto: "adb", Command: "shell:uname -m; nproc; getprop ro.product.model;"},
	}
	got := detectAttackSequences(events)
	if len(got) != 2 {
		t.Fatalf("expected 2 sequence matches, got %+v", got)
	}
	if got[0].Severity != "critical" {
		t.Fatalf("redis sequence severity = %q, want critical", got[0].Severity)
	}
	if got[1].Severity != "high" {
		t.Fatalf("adb sequence severity = %q, want high", got[1].Severity)
	}
}

func TestDetectAttackSequencesEmptySession(t *testing.T) {
	if got := detectAttackSequences(nil); len(got) != 0 {
		t.Fatalf("expected no matches on an empty session, got %+v", got)
	}
}

// TestSessionDataPopulatesSequences (#1291) confirms the end-to-end wiring:
// sessionData must run detection against its own already-chronological
// p.Events, not require a caller to do it separately.
func TestSessionDataPopulatesSequences(t *testing.T) {
	s := &store{events: []storedEvent{
		{Session: "sess-redis", Sensor: "multipot", Proto: "redis", Command: "BGSAVE", Time: "2026-08-01 12:03"},
		{Session: "sess-redis", Sensor: "multipot", Proto: "redis", Command: "SET k \"ssh-ed25519 AAAA pwned\"", Time: "2026-08-01 12:02"},
		{Session: "sess-redis", Sensor: "multipot", Proto: "redis", Command: "CONFIG SET dbfilename authorized_keys", Time: "2026-08-01 12:01"},
		{Session: "sess-redis", Sensor: "multipot", Proto: "redis", Command: "CONFIG SET dir /root/.ssh", Time: "2026-08-01 12:00"},
	}}
	page, ok := s.sessionData("sess-redis")
	if !ok {
		t.Fatal("sessionData: no page")
	}
	if len(page.Sequences) != 1 || page.Sequences[0].Severity != "critical" {
		t.Fatalf("expected one critical sequence match, got %+v", page.Sequences)
	}
}

func TestSessionDataNoSequencesWhenNoPatternMatches(t *testing.T) {
	s := &store{events: []storedEvent{
		{Session: "sess-plain", Sensor: "cowrie", Command: "ls -la", Time: "2026-08-01 12:00"},
	}}
	page, ok := s.sessionData("sess-plain")
	if !ok {
		t.Fatal("sessionData: no page")
	}
	if len(page.Sequences) != 0 {
		t.Fatalf("expected no sequences, got %+v", page.Sequences)
	}
}
