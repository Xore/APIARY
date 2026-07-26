package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const inlineScriptCap = 1 << 20

var inlineScriptSignals = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"powershell", regexp.MustCompile(`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*(?:-e(?:nc(?:odedcommand)?)?\b|-command\b)|invoke-(?:expression|webrequest)|new-object\s+net\.webclient|\.ps1\b`)},
	{"vbscript", regexp.MustCompile(`(?i)\b(?:cscript|wscript)(?:\.exe)?\b|createobject\s*\(|\.vbs\b`)},
	{"shell", regexp.MustCompile(`(?i)\b(?:ba|da|z|k)?sh\s+-c\b|base64\s+(?:--decode|-d)\s*\|\s*(?:ba)?sh\b|<<-?\s*['"]?[A-Za-z_][A-Za-z0-9_]*|\.(?:sh|bash)\b`)},
	{"python", regexp.MustCompile(`(?i)\bpython[23]?(?:\.exe)?\s+-c\b|\.py\b`)},
	{"javascript", regexp.MustCompile(`(?i)\bnode(?:\.exe)?\s+-e\b|\.(?:js|mjs)\b`)},
	{"perl", regexp.MustCompile(`(?i)\bperl\s+-e\b|\.pl\b`)},
	{"php", regexp.MustCompile(`(?i)\bphp\s+-r\b|<\?php|\.php\b`)},
}

func inlineScriptKind(command string) string {
	for _, signal := range inlineScriptSignals {
		if signal.re.MatchString(command) {
			return signal.kind
		}
	}
	return ""
}

// captureScriptPayload stores attacker-supplied script commands as inert text
// under a content hash. It never interprets or executes any captured content.
func (s *store) captureScriptPayload(ev *event) {
	if s.scriptDir == "" || ev.command == "" || ev.shasum != "" || len(ev.command) > inlineScriptCap {
		return
	}
	kind := inlineScriptKind(ev.command)
	if kind == "" {
		return
	}
	content := []byte(ev.command + "\n")
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	path := filepath.Join(s.scriptDir, hash)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_ = os.WriteFile(path, content, 0600)
	}
	ev.shasum = hash
	ev.download = "inline:" + kind
	if !strings.Contains(ev.detail, "script artifact") {
		ev.detail += " [script artifact " + shortHash(hash) + "]"
	}
}
