package main

import (
	"net"
	"testing"
	"time"
)

// TestPipeTCPClosesIdleConnection verifies that a forwarded connection with
// no data flowing in either direction is closed once it exceeds the idle
// timeout, instead of being held open (and its goroutines/fds pinned)
// forever.
func TestPipeTCPClosesIdleConnection(t *testing.T) {
	// Upstream "target" that accepts and then goes silent, like a
	// legitimate service that just hasn't sent anything yet.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamLn.Close()
	go func() {
		c, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(2 * time.Second)
	}()

	// Front listener that stands in for the honeypot's public accept
	// loop, so we can obtain a real net.Conn pair to hand to pipeTCP.
	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen front: %v", err)
	}
	defer frontLn.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := frontLn.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	attacker, err := net.Dial("tcp", frontLn.Addr().String())
	if err != nil {
		t.Fatalf("dial front: %v", err)
	}
	defer attacker.Close()

	var serverSide net.Conn
	select {
	case serverSide = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for front accept")
	}

	done := make(chan struct{})
	go func() {
		pipeTCP(serverSide, upstreamLn.Addr().String(), 100*time.Millisecond)
		close(done)
	}()

	// The attacker sends nothing and reads nothing. Once the idle
	// timeout trips, pipeTCP must close its side, which the attacker
	// observes as EOF.
	attacker.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = attacker.Read(buf)
	if err == nil {
		t.Fatal("expected idle connection to be closed, got no error")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeTCP did not return after idle timeout")
	}
}
