package main

import "testing"

// #530: extractASCII/extractUTF16LE's byte-range scan (any printable ASCII
// 0x20-0x7e, no character-class filtering) let punctuation-only runs through
// as if they were meaningful extracted strings -- reported live as `//////`
// (path-separator padding) and `''''''''http://...` (quote padding glued
// directly onto a real URL). uniqueStrings' new cleanExtractedString step
// fixes both: reject pure-noise runs entirely, trim boundary noise off
// otherwise-real strings without touching the middle.

func TestCleanExtractedStringRejectsPureNoiseRuns(t *testing.T) {
	for _, s := range []string{"//////", "''''", "--------", "\\\\\\\\", "||||", "````"} {
		if _, ok := cleanExtractedString(s); ok {
			t.Fatalf("pure punctuation run %q must be rejected, has no information content", s)
		}
	}
}

func TestCleanExtractedStringTrimsBoundaryNoiseWithoutTouchingTheMiddle(t *testing.T) {
	cases := []struct{ in, want string }{
		{"''''''''http://evil.example/a", "http://evil.example/a"},
		{"\\\\\\C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\svchost.exe"},
		{"\"quoted argument\"", "quoted argument"},
		{"///usr/bin/curl///", "usr/bin/curl"},
	}
	for _, c := range cases {
		got, ok := cleanExtractedString(c.in)
		if !ok {
			t.Fatalf("cleanExtractedString(%q): unexpectedly rejected, wanted %q", c.in, c.want)
		}
		if got != c.want {
			t.Fatalf("cleanExtractedString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanExtractedStringKeepsLowAlnumButInformativeStrings(t *testing.T) {
	// Format strings are punctuation-heavy but genuinely informative --
	// must survive since they contain at least one letter, unlike the pure
	// separator runs above. A density threshold would have risked dropping
	// these; the "at least one alnum character" rule doesn't.
	for _, s := range []string{"%s: %s (%d)", "a=1&b=2", "1.2.3.4"} {
		if _, ok := cleanExtractedString(s); !ok {
			t.Fatalf("informative low-alnum string %q must survive", s)
		}
	}
}

func TestCleanExtractedStringRejectsEmptyAfterTrim(t *testing.T) {
	if _, ok := cleanExtractedString("   "); ok {
		t.Fatal("whitespace-only input must be rejected")
	}
	if _, ok := cleanExtractedString(""); ok {
		t.Fatal("empty input must be rejected")
	}
	if _, ok := cleanExtractedString("''''''''"); ok {
		t.Fatal("input that is entirely boundary-noise characters must be rejected once nothing is left after trimming")
	}
}

// End-to-end: the actual extractors, not just the helper, against synthetic
// bytes shaped like the real packer/resource-section padding that produced
// this bug report.
func TestExtractASCIIDropsPunctuationFragmentsFromRealisticPadding(t *testing.T) {
	data := []byte("////// " + "C:\\Windows\\System32\\svchost.exe" + " \x00\x00 " + "''''''''http://evil.example/a" + " \x00 " + "----")
	got := extractASCII(data, 4, 160)
	for _, s := range got {
		if s == "//////" || s == "----" || s == "''''''''http://evil.example/a" {
			t.Fatalf("extractASCII still emits a punctuation fragment or unclean glued string: %q in %v", s, got)
		}
	}
	found := false
	for _, s := range got {
		if s == "http://evil.example/a" {
			found = true
		}
	}
	if !found {
		t.Fatalf("extractASCII must still surface the clean URL after trimming boundary noise: %v", got)
	}
}

func TestUniqueStringsDedupesAfterCleaning(t *testing.T) {
	// Two raw inputs that clean to the same string must collapse to one.
	got := uniqueStrings([]string{"'''http://x.example/a'''", "http://x.example/a", "//////"}, 10)
	if len(got) != 1 || got[0] != "http://x.example/a" {
		t.Fatalf("uniqueStrings = %v, want exactly [\"http://x.example/a\"]", got)
	}
}
