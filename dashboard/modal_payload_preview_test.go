package main

import (
	"bytes"
	"encoding/hex"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPayloadPreviewModalContract is #59's payload-preview modal, reviewed
// as its own data-attribute contract: the /payloads list "preview" trigger
// pairs with exactly one hidden body per row, keyed by the payload's own
// hash (already globally unique -- no derived key needed, unlike event
// detail). The preview is a hex dump of a small, capped read of the file
// head computed once during the existing background scan (scanPayloads
// already reads a head chunk for MIME sniffing), not a fetch triggered by
// opening the modal.
func TestPayloadPreviewModalContract(t *testing.T) {
	dir := t.TempDir()
	hash := strings.Repeat("a", 64)
	// Content includes markup-shaped bytes that are also printable ASCII, so
	// they land in hex.Dump's own ASCII sidebar column -- exactly the case
	// the guide's "never inject raw payload bytes as HTML" rule is about.
	content := []byte("<script>alert(1)</script>" + strings.Repeat("\x00", 32))
	if err := os.WriteFile(filepath.Join(dir, hash), content, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{payloadDirs: []string{dir}}
	s.payloadCache = s.scanPayloads()
	s.payloadCacheAt = time.Now()

	if len(s.payloadCache.Files) != 1 || s.payloadCache.Files[0].Preview == "" {
		t.Fatalf("scanPayloads did not populate a preview: %+v", s.payloadCache.Files)
	}
	wantDump := hex.Dump(content) // content is well under payloadPreviewCap, so no truncation
	if s.payloadCache.Files[0].Preview != wantDump {
		t.Fatalf("preview does not match hex.Dump of the file head:\ngot:  %q\nwant: %q", s.payloadCache.Files[0].Preview, wantDump)
	}
	if s.payloadCache.Files[0].PreviewTruncated {
		t.Fatal("a file smaller than payloadPreviewCap must not be marked truncated")
	}

	funcs := templateFuncs(s, "")
	tmpl := template.Must(template.New("t").Funcs(funcs).Parse(pageTemplate))
	page := s.payloadsData(payloadsFilter{})
	var out strings.Builder
	if err := tmpl.ExecuteTemplate(&out, "payloads", &page); err != nil {
		t.Fatalf("payloads page does not render: %v", err)
	}
	html := out.String()

	triggerKey := "pf-" + hash
	if !strings.Contains(html, `data-hp-evidence="`+triggerKey+`"`) {
		t.Fatalf("no preview trigger for hash %s", hash)
	}
	if !strings.Contains(html, `data-hp-evidence-body="`+triggerKey+`"`) {
		t.Fatalf("no matching preview body for hash %s", hash)
	}
	bodyStart := strings.Index(html, `data-hp-evidence-body="`+triggerKey+`"`)
	if bodyStart < 0 {
		t.Fatal("preview body not found")
	}
	bodyEnd := bodyStart + strings.Index(html[bodyStart:], "</div>")
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

// TestPayloadPreviewCapsAtPayloadPreviewCap proves the guide's "size-capped"
// requirement holds even when the file itself is large -- the preview must
// never grow with the file, and PreviewTruncated must say so.
func TestPayloadPreviewCapsAtPayloadPreviewCap(t *testing.T) {
	dir := t.TempDir()
	hash := strings.Repeat("b", 64)
	big := bytes.Repeat([]byte{'A'}, payloadPreviewCap*4)
	if err := os.WriteFile(filepath.Join(dir, hash), big, 0o600); err != nil {
		t.Fatal(err)
	}

	s := &store{payloadDirs: []string{dir}}
	s.payloadCache = s.scanPayloads()
	file := s.payloadCache.Files[0]
	if !file.PreviewTruncated {
		t.Fatal("a file larger than payloadPreviewCap must be marked truncated")
	}
	wantDump := hex.Dump(big[:payloadPreviewCap])
	if file.Preview != wantDump {
		t.Fatalf("preview was not capped at payloadPreviewCap bytes: got %d dump chars, want %d", len(file.Preview), len(wantDump))
	}
}
