package main

import (
	"testing"
	"time"
)

func TestEveBoxInvestigationURL(t *testing.T) {
	got := investigationURL("https://evebox.honeypot.example/", "evebox", "203.0.113.42", time.Time{})
	want := "https://evebox.honeypot.example/#/inbox?q=203.0.113.42"
	if got != want {
		t.Fatalf("investigationURL() = %q, want %q", got, want)
	}
}
