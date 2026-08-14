package main

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// startFakeModelStatusAdapter serves a valid model-status response over a
// real AF_UNIX socket and points MODEL_STATUS_SOCKET at it, mirroring
// services_control_test.go's startFakeServicesAdapter helper.
func startFakeModelStatusAdapter(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	socket := filepath.Join(dir, "model-status.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(workbenchModelStatus{
			SchemaVersion: 1, Overall: "approved", AdvisoryOnly: true,
			Runtime: workbenchModelComponent{Status: "approved"},
			Host:    workbenchModelComponent{Status: "approved"},
		})
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	t.Setenv("MODEL_STATUS_SOCKET", socket)
}

// Regression test for #1339: loadWorkbenchModelStatus used to build a fresh
// *http.Transport per call and never close its idle connection -- Body.Close()
// alone only returns the connection to that (immediately discarded)
// transport's own idle pool, leaking one goroutine (the pooled connection's
// readLoop) and one open Unix-socket fd per call, indefinitely. Calling it
// repeatedly must not leave the process's goroutine count elevated.
func TestLoadWorkbenchModelStatusDoesNotLeakConnections(t *testing.T) {
	startFakeModelStatusAdapter(t)

	// Warm up first -- the very first calls can start unrelated background
	// runtime goroutines (e.g. the DNS resolver) that would otherwise be
	// mistaken for a leak.
	for i := 0; i < 3; i++ {
		if status := loadWorkbenchModelStatus(); !status.Available {
			t.Fatalf("warm-up call: expected Available=true, got %+v", status)
		}
	}
	runtime.GC()
	before := runtime.NumGoroutine()

	const calls = 50
	for i := 0; i < calls; i++ {
		if status := loadWorkbenchModelStatus(); !status.Available {
			t.Fatalf("call %d: expected Available=true, got %+v", i, status)
		}
	}

	// A leaked readLoop goroutine per call would grow the count by ~calls;
	// give cleanup a moment (goroutine exit after conn.Close() isn't
	// synchronous) and allow a small constant slack for unrelated runtime
	// goroutines, but not anywhere close to `calls`.
	var after int
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		after = runtime.NumGoroutine()
		if after <= before+5 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if after > before+5 {
		t.Fatalf("goroutine count grew from %d to %d after %d calls to loadWorkbenchModelStatus -- suggests a leaked connection per call", before, after, calls)
	}
}
