package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// hashName matches a dionaea capture filename: a bare md5/sha1/sha256 hex hash.
// Enforced on the download path so a request can never escape the binaries dir.
var hashName = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)

var processStarted = time.Now()

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func topN(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// logFiles walks the log volume and returns every JSON-lines file, wherever a
// sensor put it (each sensor writes to its own subdirectory).
func logFiles(dir string) []string {
	var files []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// match foo.json and rotated foo.json.2026-07-18 / foo.json.1
		if strings.Contains(d.Name(), ".json") {
			files = append(files, p)
		}
		return nil
	})
	return files
}

// readTail returns up to tailCap bytes from the end of the file, aligned to
// the next full line when truncated.
func readTail(fn string) []byte {
	f, err := os.Open(fn)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	if st.Size() > tailCap {
		if _, err := f.Seek(st.Size()-tailCap, io.SeekStart); err != nil {
			return nil
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	if st.Size() > tailCap {
		if i := strings.IndexByte(string(data), '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	return data
}

// tunnelPeerIP is the WireGuard peer address cowrie logs for every session:
// portbridge terminates the attacker's TCP on the VPS and re-dials over the
// tunnel, and cowrie's haproxy endpoint is disabled (Twisted incompat), so the
// only real-IP source for cowrie is the portbridge conn-log (see buildViaMap).
const tunnelPeerIP = "10.8.0.1"

// ago renders a last-seen time as a rough relative age.
func ago(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func feedState(last, now time.Time) string {
	if last.IsZero() {
		return "waiting"
	}
	age := now.Sub(last)
	if age < 20*time.Minute {
		return "active"
	}
	if age < 24*time.Hour {
		return "quiet"
	}
	return "stale"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// shortHash trims a sha-256 to its first 12 hex chars for compact display.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// familyDisplayCap bounds how much of a scanner-reported malware family label
// (analysis/github/collect-results.py's family_for(), or a ?family= query
// value echoed back in a filter chip) is ever rendered. This is external
// pipeline text, not something validated at write time the way
// settings_domain.go's presentationTextLimits are -- html/template already
// escapes it, so this only keeps a pathological value from blowing out a
// badge or table cell. See #149.
const familyDisplayCap = 80

// boundedFamily truncates a family label for display. Matching logic must
// always compare the untruncated value -- truncating first would let two
// different long names collide at the cut point.
func boundedFamily(family string) string {
	if utf8.RuneCountInString(family) <= familyDisplayCap {
		return family
	}
	runes := []rune(family)
	return string(runes[:familyDisplayCap]) + "…"
}

func numFloat(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func num(v any) string {
	if f, ok := v.(float64); ok {
		return fmt.Sprintf("%.0f", f)
	}
	return ""
}
