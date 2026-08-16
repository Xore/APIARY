package main

import (
	"bufio"
	"bytes"
	"net"
	"testing"
	"time"
)

// TestPeekJA3KnownVector feeds a hand-built ClientHello record (constructed
// independently in Python, see the commit that added this test) encoding
// version=771 (0x0303), ciphers 4865/4866/4867/49195/49199, extensions
// 0/23/65281/10/11/16, supported_groups 29/23/24, ec_point_formats [0] --
// i.e. the JA3 string "771,4865-4866-4867-49195-49199,0-23-65281-10-11-16,
// 29-23-24,0", whose MD5 was computed independently via Python's hashlib,
// not derived from this Go code -- and confirms peekJA3 reproduces the
// exact same hash.
func TestPeekJA3KnownVector(t *testing.T) {
	record := []byte{
		0x16, 0x03, 0x01, 0x00, 0x64, 0x01, 0x00, 0x00, 0x60, 0x03, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0,
		0x2f, 0x01, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17,
		0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x10, 0x00,
		0x05, 0x00, 0x03, 0x02, 0x68, 0x32,
	}
	const want = "12f6df346b234f53494467df7a4e5f44"

	got := peekJA3(bufio.NewReader(bytes.NewReader(record)))
	if got != want {
		t.Fatalf("peekJA3 = %q, want %q", got, want)
	}
}

// TestJA3ListenerAcceptDoesNotBlockOnSlowPeer covers #1347: Accept() must
// return as soon as the underlying listener accepts a connection, even if
// the peer then sends nothing at all -- the ClientHello peek (and its
// 5-second deadline) must not run synchronously inside Accept(), or one
// slow/silent connection stalls admission of every other connection on the
// shared accept loop net/http.Server.Serve() drives.
func TestJA3ListenerAcceptDoesNotBlockOnSlowPeer(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer raw.Close()
	ln := &ja3Listener{raw}

	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	// Deliberately send nothing -- a real ClientHello peek would otherwise
	// block here for up to its own 5s deadline.

	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Accept() returned an error: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Accept() blocked on a silent peer instead of returning immediately")
	}
}

// TestJA3ConnPeeksLazilyOnFirstRead proves the peek that Accept() no longer
// performs still happens -- deferred to the first Read, as the real TLS
// handshake would trigger -- and that JA3()/JA4() see the result even
// though the same bytes remain readable afterward (Peek never consumes).
func TestJA3ConnPeeksLazilyOnFirstRead(t *testing.T) {
	record := []byte{
		0x16, 0x03, 0x01, 0x00, 0x64, 0x01, 0x00, 0x00, 0x60, 0x03, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0,
		0x2f, 0x01, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x05, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17,
		0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x10, 0x00,
		0x05, 0x00, 0x03, 0x02, 0x68, 0x32,
	}
	const wantJA3 = "12f6df346b234f53494467df7a4e5f44"

	server, client := net.Pipe()
	defer client.Close()
	go func() {
		client.Write(record)
	}()

	jc := &ja3Conn{Conn: server, r: bufio.NewReaderSize(server, maxClientHelloBytes)}
	if jc.fp != "" || jc.fp4 != "" {
		t.Fatal("fingerprints must be empty before any Read/JA3/JA4 call")
	}

	buf := make([]byte, len(record))
	n, err := jc.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], record[:n]) {
		t.Fatal("Read must still deliver the peeked bytes to the caller (Peek never consumes)")
	}
	if jc.JA3() != wantJA3 {
		t.Fatalf("JA3() = %q, want %q", jc.JA3(), wantJA3)
	}
}

func TestIsGREASEMatchesRFC8701Table(t *testing.T) {
	greaseValues := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
		0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, v := range greaseValues {
		if !isGREASE(v) {
			t.Errorf("isGREASE(0x%04x) = false, want true", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x0a1a, 0xc02b, 0x0000, 0xffff} {
		if isGREASE(v) {
			t.Errorf("isGREASE(0x%04x) = true, want false", v)
		}
	}
}
