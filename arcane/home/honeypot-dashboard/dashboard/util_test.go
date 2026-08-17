package main

import (
	"strings"
	"testing"
)

// TestPluralS (#1566) covers the grammar fix for /clusters' "1 sensors:"
// summary text (intelligence.go's clusterRow.Summary).
func TestPluralS(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "s"},
		{1, ""},
		{2, "s"},
	}
	for _, c := range cases {
		if got := pluralS(c.n); got != c.want {
			t.Errorf("pluralS(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestBoundedFamily(t *testing.T) {
	short := "Mirai"
	if got := boundedFamily(short); got != short {
		t.Errorf("boundedFamily(%q) = %q, want unchanged", short, got)
	}

	exact := strings.Repeat("a", familyDisplayCap)
	if got := boundedFamily(exact); got != exact {
		t.Errorf("a value at exactly the cap must not be truncated, got %q", got)
	}

	long := strings.Repeat("a", familyDisplayCap+40)
	got := boundedFamily(long)
	if got != strings.Repeat("a", familyDisplayCap)+"…" {
		t.Errorf("boundedFamily did not truncate at the cap: %q", got)
	}
	if len([]rune(got)) != familyDisplayCap+1 { // +1 for the ellipsis rune
		t.Errorf("truncated length = %d runes, want %d", len([]rune(got)), familyDisplayCap+1)
	}

	// Multi-byte runes must be cut on a rune boundary, not a byte offset --
	// slicing a []byte mid-character would corrupt the string.
	multiByte := strings.Repeat("界", familyDisplayCap+5)
	got = boundedFamily(multiByte)
	if !strings.HasSuffix(got, "…") || len([]rune(got)) != familyDisplayCap+1 {
		t.Errorf("multi-byte family label was not cleanly truncated: %q", got)
	}
}
