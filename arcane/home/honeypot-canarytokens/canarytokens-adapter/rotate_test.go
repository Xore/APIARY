package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteEvent_RotatesWithoutLosingLines covers #2216: this writer opened
// its log file once at startup and never rotated. Proves rotateLog() (ported
// from multipot's logger.rotate(), see that package's rotate_test.go) closes,
// renames and reopens without dropping any written line.
func TestWriteEvent_RotatesWithoutLosingLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "canarytokens.json")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	logFile = f
	logPath = path
	logSize = 0
	logMax = 1
	t.Cleanup(func() {
		if logFile != nil {
			logFile.Close()
		}
		logFile, logPath, logSize, logMax = nil, "", 0, 0
	})

	const n = 20
	for i := 0; i < n; i++ {
		body := `{"channel":"HTTP","token_type":"web","src_ip":"198.51.100.9","token":"tok1","memo":"` +
			strings.Repeat("x", 20) + `"}`
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		rec := httptest.NewRecorder()
		writeEvent(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("write %d: status = %d, body = %s", i, rec.Code, rec.Body.String())
		}
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 2 {
		t.Fatalf("want more than one file after %d writes with max=1, got %v", n, files)
	}
	total := 0
	for _, fi := range files {
		data, err := os.ReadFile(filepath.Join(dir, fi.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line != "" {
				total++
			}
		}
	}
	if total != n {
		t.Fatalf("want all %d lines preserved across rotation, got %d (files: %v)", n, total, files)
	}
}
