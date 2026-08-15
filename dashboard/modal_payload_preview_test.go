package main

import (
	"encoding/hex"
	"html/template"
	"strings"
	"testing"
	"time"
)

// TestPayloadPreviewCardContract is #1452's inline payload preview. The
// preview is a hex dump computed once, elsewhere -- #1223:
// payload-inventory-worker now owns that computation (its own scan.go,
// ported from this file's original scanPayloads, removed here) and writes
// it onto the shared payloadInventoryIndex document; this only needs to
// verify the dashboard's own remaining responsibility, safely rendering
// whatever Preview value it's handed -- so this seeds s.payloadCache
// directly with a hostile Preview value instead of computing one via a
// real scan.
func TestPayloadPreviewCardContract(t *testing.T) {
	hash := strings.Repeat("a", 64)
	// Content includes markup-shaped bytes that are also printable ASCII, so
	// they land in hex.Dump's own ASCII sidebar column -- exactly the case
	// the guide's "never inject raw payload bytes as HTML" rule is about.
	content := []byte("<script>alert(1)</script>" + strings.Repeat("\x00", 32))
	wantDump := hex.Dump(content)

	s := &store{payloadDirs: []string{t.TempDir()}, es: newESClient("http://127.0.0.1:1", "")}
	s.payloadCache = payloadsPage{UniqueTotal: 1, Files: []capturedFile{
		{Hash: hash, Preview: wantDump, Sources: []string{"cowrie"}},
	}}
	s.payloadCacheAt = time.Now()

	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	page := s.payloadsData(payloadsFilter{})
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "payloads", &page); err != nil {
		t.Fatalf("payloads page does not render: %v", err)
	}
	html := out.String()

	triggerKey := "pf-" + hash
	if strings.Contains(html, "Preview bytes") || strings.Contains(html, `data-hp-evidence="`+triggerKey+`"`) || strings.Contains(html, `data-hp-evidence-body="`+triggerKey+`"`) {
		t.Fatal("payload preview is still hidden behind an action or evidence modal")
	}
	bodyStart := strings.Index(html, `aria-label="Byte preview"`)
	if bodyStart < 0 {
		t.Fatalf("no inline byte-preview card for hash %s", hash)
	}
	bodyEnd := bodyStart + strings.Index(html[bodyStart:], "</section>")
	previewBlock := html[bodyStart:bodyEnd]

	if strings.Contains(previewBlock, "<script>alert(1)") || strings.Contains(previewBlock, "</script>") {
		t.Fatal("hostile payload bytes reached the rendered page unescaped")
	}
	// hex.Dump wraps at 16 bytes/line, so the two escaped fragments land on
	// separate lines of the ASCII sidebar -- checked independently.
	if !strings.Contains(previewBlock, "&lt;script&gt;alert(1)") || !strings.Contains(previewBlock, "&lt;/script&gt;") {
		t.Fatal("expected the hex dump's ASCII sidebar to render the hostile bytes escaped, not stripped")
	}
}
