package main

import (
	"html/template"
	"os"
	"strings"
	"testing"
)

func TestTTYAndVNCViewersRenderShapeMatchedLoadingFrames(t *testing.T) {
	tmpl := template.Must(template.New("dashboard").Funcs(templateFuncs(nil, "")).Parse(pageTemplate))
	var tty strings.Builder
	if err := tmpl.ExecuteTemplate(&tty, "tty-replay", &ttyReplayPageData{Shasum: strings.Repeat("a", 64)}); err != nil {
		t.Fatalf("render TTY: %v", err)
	}
	if !strings.Contains(tty.String(), "data-tty-loading") || !strings.Contains(tty.String(), `id="tty-screen" aria-busy="true"`) {
		t.Fatal("TTY shell is missing its terminal-line loading surface")
	}
	var vnc strings.Builder
	if err := tmpl.ExecuteTemplate(&vnc, "sandbox-vnc", &sandboxVNCPageData{SHA256: strings.Repeat("b", 64), BridgeWS: "wss://example.invalid/vnc"}); err != nil {
		t.Fatalf("render VNC: %v", err)
	}
	if !strings.Contains(vnc.String(), "data-vnc-loading") || !strings.Contains(vnc.String(), `data-vnc-target aria-busy="true"`) {
		t.Fatal("VNC shell is missing its frame-shaped loading surface")
	}
	for _, file := range []string{"static/hp-tty-replay.js", "static/hp-sandbox-vnc.js"} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		if !strings.Contains(text, `aria-busy`) || (!strings.Contains(text, "Could not load recording") && !strings.Contains(text, `"error"`)) {
			t.Fatalf("%s does not settle its loading frame into accessible terminal states", file)
		}
	}
}
