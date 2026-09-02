package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dicom "github.com/grailbio/go-dicom"
	"github.com/grailbio/go-dicom/dicomtag"
)

func TestGetenvFallsBackToDefault(t *testing.T) {
	if got := getenv("DICOMPOT_TEST_UNSET", "fallback"); got != "fallback" {
		t.Fatalf("getenv default = %q, want fallback", got)
	}
	t.Setenv("DICOMPOT_TEST_SET", "explicit")
	if got := getenv("DICOMPOT_TEST_SET", "fallback"); got != "explicit" {
		t.Fatalf("getenv set = %q, want explicit", got)
	}
}

func TestSrcIPStripsPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			defer c.Close()
		}
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if ip := srcIP(conn); ip != "127.0.0.1" {
		t.Fatalf("srcIP = %q, want 127.0.0.1", ip)
	}
}

func TestLoggerEmitStampsFixedFieldsAndWritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dicompot.json")
	l := newLogger(path)
	l.emit(event{Port: 11112, SrcIP: "203.0.113.9", Event: "c_echo"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var got event
	if err := json.Unmarshal(data[:len(data)-1], &got); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
	if got.Sensor != "dicompot" || got.Proto != "dicom" || got.Org != "NexusAI Research GmbH" {
		t.Fatalf("event missing stamped fields: %+v", got)
	}
	if got.SrcIP != "203.0.113.9" || got.Event != "c_echo" || got.Port != 11112 {
		t.Fatalf("event lost caller-provided fields: %+v", got)
	}
	if got.Time == "" {
		t.Fatal("event.Time not stamped")
	}
}

func TestDecodeProxyRewritesRemoteAddrFromV1Header(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		c.Write([]byte("PROXY TCP4 203.0.113.9 10.8.0.2 51234 11112\r\n"))
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	wrapped := decodeProxy(conn, true)
	if ip := srcIP(wrapped); ip != "203.0.113.9" {
		t.Fatalf("srcIP after decodeProxy = %q, want 203.0.113.9", ip)
	}
}

func TestFormatQueryFilterSurfacesPatientNameSearch(t *testing.T) {
	elements := []*dicom.Element{
		{Tag: dicomtag.PatientName, VR: "PN", Value: []interface{}{"DOE^JOHN"}},
		{Tag: dicomtag.PatientID, VR: "LO", Value: []interface{}{"12345"}},
		{Tag: dicomtag.Tag{Group: 0x0010, Element: 0x0020}, VR: "LO", Value: nil}, // empty value, must be skipped
	}
	got := formatQueryFilter(elements)
	if !strings.Contains(got, "PatientName") || !strings.Contains(got, "DOE^JOHN") {
		t.Fatalf("expected PatientName search term surfaced, got %q", got)
	}
	if !strings.Contains(got, "PatientID") || !strings.Contains(got, "12345") {
		t.Fatalf("expected PatientID surfaced, got %q", got)
	}
}

func TestJoinNonEmptySkipsMissingSide(t *testing.T) {
	if got := joinNonEmpty("1.2.840", ""); got != "1.2.840" {
		t.Fatalf("joinNonEmpty with empty filter = %q, want sopClassUID only", got)
	}
	if got := joinNonEmpty("", "PatientName=X"); got != "PatientName=X" {
		t.Fatalf("joinNonEmpty with empty sopClassUID = %q, want filter only", got)
	}
	if got := joinNonEmpty("1.2.840", "PatientName=X"); got != "1.2.840 | PatientName=X" {
		t.Fatalf("joinNonEmpty = %q, want both joined", got)
	}
}

func TestWaitForMarkerReturnsOnceFileExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log-init.done")
	done := make(chan struct{})
	go func() {
		waitForMarker(path)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("waitForMarker returned before marker file existed")
	default:
	}

	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("waitForMarker did not return within timeout after marker appeared")
	}
}

// TestNextAcceptBackoffDoublesAndCaps covers #2328: repeated Accept()
// errors must back off instead of retrying unconditionally (which spins a
// CPU core at 100% under persistent fd exhaustion), and the backoff must
// not grow unbounded. Ported from endlessh-honeypot/main_test.go.
func TestNextAcceptBackoffDoublesAndCaps(t *testing.T) {
	d := time.Duration(0)
	d = nextAcceptBackoff(d)
	if d != 5*time.Millisecond {
		t.Fatalf("first backoff = %s, want 5ms", d)
	}
	d = nextAcceptBackoff(d)
	if d != 10*time.Millisecond {
		t.Fatalf("second backoff = %s, want 10ms", d)
	}
	for i := 0; i < 20; i++ {
		d = nextAcceptBackoff(d)
	}
	if d != maxAcceptBackoff {
		t.Fatalf("backoff after many failures = %s, want it capped at %s", d, maxAcceptBackoff)
	}
}
