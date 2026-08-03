package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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
