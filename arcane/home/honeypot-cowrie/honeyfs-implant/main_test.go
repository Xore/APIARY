package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestResolveHoneyfsPathRejectsEscapes throws a battery of path-traversal
// shapes at resolveHoneyfsPath -- CodeQL's go/path-injection query flagged
// the sink this function guards (main.go's MkdirAll/WriteFile calls) since
// it doesn't model a custom containment check as a sanitizer. This proves
// the containment actually holds rather than asserting it by inspection.
func TestResolveHoneyfsPathRejectsEscapes(t *testing.T) {
	s := &server{honeyfsDir: t.TempDir()}
	root, err := filepath.Abs(s.honeyfsDir)
	if err != nil {
		t.Fatal(err)
	}

	malicious := []string{
		"../etc/passwd",
		"../../etc/passwd",
		"../../../../../../etc/passwd",
		"..",
		"foo/../../etc/passwd",
		"foo/../../../etc/passwd",
		"a/b/../../../../etc/passwd",
		"/etc/passwd",
		"/etc/../etc/passwd",
		"",
		".",
		"./..",
		"foo/./../../bar",
		"....//....//etc/passwd", // not a real ".." shape, but exercise it anyway
	}
	for _, raw := range malicious {
		t.Run(raw, func(t *testing.T) {
			resolved, err := s.resolveHoneyfsPath(raw)
			if err == nil {
				t.Fatalf("path %q was accepted, resolved to %q -- should have been rejected", raw, resolved)
			}
		})
	}

	// Sanity check the positive case isn't accidentally broken too.
	for _, raw := range []string{"home/mwagner/.aws/credentials", "a/b/c.txt", "file.txt"} {
		t.Run("valid/"+raw, func(t *testing.T) {
			resolved, err := s.resolveHoneyfsPath(raw)
			if err != nil {
				t.Fatalf("legitimate path %q was rejected: %v", raw, err)
			}
			if !strings.HasPrefix(resolved, root+string(filepath.Separator)) {
				t.Fatalf("resolved path %q escaped root %q", resolved, root)
			}
		})
	}
}
