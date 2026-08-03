package main

import (
	"testing"
	"time"
)

func TestPendingQueueResolvesOnceViaMapCatchesUp(t *testing.T) {
	var q pendingQueue
	now := time.Now()
	q.add([]byte(`{"src_ip":"10.8.0.1","src_port":1}`), 5*time.Second, now)

	// Still empty: the portbridge entry hasn't landed yet.
	ready := q.drain(viaMap{}, now.Add(1*time.Second))
	if len(ready) != 0 {
		t.Fatalf("expected nothing ready before resolution or timeout, got %d", len(ready))
	}

	ready = q.drain(viaMap{1: "203.0.113.9"}, now.Add(2*time.Second))
	if len(ready) != 1 {
		t.Fatalf("expected the line to resolve and flush, got %d", len(ready))
	}
	if string(ready[0]) != `{"src_ip":"203.0.113.9","src_port":1}` {
		t.Fatalf("unexpected resolved line: %s", ready[0])
	}
}

func TestPendingQueueFlushesUnenrichedAfterTimeout(t *testing.T) {
	var q pendingQueue
	now := time.Now()
	line := []byte(`{"src_ip":"10.8.0.1","src_port":1}`)
	q.add(line, 5*time.Second, now)

	ready := q.drain(viaMap{}, now.Add(6*time.Second))
	if len(ready) != 1 {
		t.Fatalf("expected the line to flush unenriched after its deadline, got %d", len(ready))
	}
	if string(ready[0]) != string(line) {
		t.Fatalf("expected the original, unenriched line, got %s", ready[0])
	}

	// It must not be retried again after flushing.
	again := q.drain(viaMap{1: "203.0.113.9"}, now.Add(7*time.Second))
	if len(again) != 0 {
		t.Fatalf("expected an already-flushed line not to reappear, got %d", len(again))
	}
}
