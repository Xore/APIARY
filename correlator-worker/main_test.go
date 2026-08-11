package main

import "testing"

func TestClusterDocIDIsStableAndDistinct(t *testing.T) {
	a := clusterDocID("fingerprint", "abc")
	b := clusterDocID("fingerprint", "abc")
	c := clusterDocID("payload", "abc")
	if a != b {
		t.Fatal("expected the same (kind, value) to hash to the same ID")
	}
	if a == c {
		t.Fatal("expected different kinds to hash to different IDs even with the same value")
	}
	if len(a) != 64 { // sha256 hex
		t.Fatalf("expected a 64-char hex ID, got %d chars: %q", len(a), a)
	}
}
