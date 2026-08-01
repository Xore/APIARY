package main

import "testing"

// TestWhenNormalizesDisplayToUTC (#198): different sensors' timestamp
// formats parse into different time.Location values -- a Z-suffixed string
// parses as UTC, suricata's eve.json "...+0200" parses into a fixed +0200
// offset, and an unlabeled string with no zone in the reference layout also
// defaults to UTC per time.Parse's own documented behavior. The unix-epoch
// path (time.Unix) returns the server process's local zone. None of that
// may leak into the displayed string: two events at the exact same real
// instant, logged by different sensors in different formats, must produce
// the exact same wall-clock display.
func TestWhenNormalizesDisplayToUTC(t *testing.T) {
	cases := []struct {
		name string
		e    map[string]any
	}{
		{"Z-suffixed UTC (cowrie-shaped)", map[string]any{"timestamp": "2026-08-01T13:52:10.013146Z"}},
		{"suricata eve.json +0200 offset", map[string]any{"timestamp": "2026-08-01T15:52:10.013146+0200"}},
		{"unlabeled, no zone in the layout (dionaea-shaped)", map[string]any{"timestamp": "2026-08-01T13:52:10.013146"}},
		{"unix epoch seconds", map[string]any{"timestamp": float64(1785592330)}}, // 2026-08-01T13:52:10Z
	}

	const want = "2026-08-01 13:52:10"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, whenStr := when(tc.e)
			if whenStr != want {
				t.Fatalf("whenStr = %q, want %q (all four represent the same real instant and must display identically)", whenStr, want)
			}
		})
	}
}

// TestWhenAgeMathIsLocationIndependent guards the other half of #198's fix:
// normalizing the *display* string must not change the returned time.Time
// itself -- age/sort comparisons elsewhere (aggregate.go) are correct
// regardless of Location, and there is no reason to touch that value.
func TestWhenAgeMathIsLocationIndependent(t *testing.T) {
	utc, _ := when(map[string]any{"timestamp": "2026-08-01T13:52:10Z"})
	offset, _ := when(map[string]any{"timestamp": "2026-08-01T15:52:10+0200"})
	if !utc.Equal(offset) {
		t.Fatalf("the same real instant in two formats must compare equal: %v vs %v", utc, offset)
	}
}
