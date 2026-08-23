package main

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
)

// fakeP0f starts a minimal stand-in for p0f's API socket (api.c/api.h): read
// one p0fQuery, write back a canned p0fResponse, close. Real p0f serves
// exactly one query per accepted connection the same way (confirmed against
// vendored tools/p0f-client.c, the reference client this wire format is
// copied from), so this is a faithful enough double for queryP0f's client
// side without needing the real C binary in a Go test.
func fakeP0f(t *testing.T, respond func(q p0fQuery) p0fResponse) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "p0f.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var q p0fQuery
				if binary.Read(conn, binary.LittleEndian, &q) != nil {
					return
				}
				r := respond(q)
				binary.Write(conn, binary.LittleEndian, &r)
			}()
		}
	}()
	return sock
}

func putStr(dst *[32]byte, s string) {
	copy(dst[:], s)
}

func TestQueryP0fReturnsOSGuessOnMatch(t *testing.T) {
	sock := fakeP0f(t, func(q p0fQuery) p0fResponse {
		if q.Magic != p0fQueryMagic {
			t.Errorf("query magic = %#x, want %#x", q.Magic, p0fQueryMagic)
		}
		if q.AddrType != p0fAddrIPv4 {
			t.Errorf("addr_type = %#x, want IPv4", q.AddrType)
		}
		if got := net.IP(q.Addr[:4]).String(); got != "198.51.100.7" {
			t.Errorf("query addr = %s, want 198.51.100.7", got)
		}
		r := p0fResponse{Magic: p0fRespMagic, Status: p0fStatusOK}
		putStr(&r.OSName, "Linux")
		putStr(&r.OSFlavor, "3.11 and newer")
		return r
	})

	got := queryP0f(sock, "198.51.100.7")
	if want := "Linux 3.11 and newer"; got != want {
		t.Errorf("queryP0f() = %q, want %q", got, want)
	}
}

func TestQueryP0fNoFlavorOmitsTrailingSpace(t *testing.T) {
	sock := fakeP0f(t, func(q p0fQuery) p0fResponse {
		r := p0fResponse{Magic: p0fRespMagic, Status: p0fStatusOK}
		putStr(&r.OSName, "Linux")
		return r
	})
	if got := queryP0f(sock, "198.51.100.7"); got != "Linux" {
		t.Errorf("queryP0f() = %q, want %q", got, "Linux")
	}
}

func TestQueryP0fNoMatchReturnsEmpty(t *testing.T) {
	sock := fakeP0f(t, func(q p0fQuery) p0fResponse {
		return p0fResponse{Magic: p0fRespMagic, Status: p0fStatusNoMatch}
	})
	if got := queryP0f(sock, "198.51.100.7"); got != "" {
		t.Errorf("queryP0f() = %q, want empty on P0F_STATUS_NOMATCH", got)
	}
}

func TestQueryP0fBadMagicReturnsEmpty(t *testing.T) {
	sock := fakeP0f(t, func(q p0fQuery) p0fResponse {
		return p0fResponse{Magic: 0xdeadbeef, Status: p0fStatusOK}
	})
	if got := queryP0f(sock, "198.51.100.7"); got != "" {
		t.Errorf("queryP0f() = %q, want empty on bad response magic", got)
	}
}

func TestQueryP0fEmptySockNeverDials(t *testing.T) {
	// No listener anywhere -- if this dials at all, it can only fail slowly
	// (timeout), not return quickly. This must return immediately.
	if got := queryP0f("", "198.51.100.7"); got != "" {
		t.Errorf("queryP0f() = %q, want empty with no socket configured", got)
	}
}

func TestQueryP0fUnreachableSockReturnsEmpty(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "nonexistent.sock")
	if got := queryP0f(sock, "198.51.100.7"); got != "" {
		t.Errorf("queryP0f() = %q, want empty when nothing is listening", got)
	}
}

func TestQueryP0fMalformedIPReturnsEmpty(t *testing.T) {
	sock := fakeP0f(t, func(q p0fQuery) p0fResponse {
		t.Fatal("must not query p0f with an unparsable address")
		return p0fResponse{}
	})
	if got := queryP0f(sock, "not-an-ip"); got != "" {
		t.Errorf("queryP0f() = %q, want empty for a malformed IP", got)
	}
}

// IPv6 addresses go in the full 16-byte form, addr_type IPv6 -- distinct from
// the IPv4 path, which left-aligns 4 bytes per api.h's "IP address (big
// endian left align)" comment.
func TestQueryP0fIPv6UsesFullAddress(t *testing.T) {
	sock := fakeP0f(t, func(q p0fQuery) p0fResponse {
		if q.AddrType != p0fAddrIPv6 {
			t.Errorf("addr_type = %#x, want IPv6", q.AddrType)
		}
		want := net.ParseIP("2001:db8::1").To16()
		if net.IP(q.Addr[:]).String() != net.IP(want).String() {
			t.Errorf("query addr = %v, want %v", q.Addr, want)
		}
		r := p0fResponse{Magic: p0fRespMagic, Status: p0fStatusOK}
		putStr(&r.OSName, "Linux")
		return r
	})
	if got := queryP0f(sock, "2001:db8::1"); got != "Linux" {
		t.Errorf("queryP0f() = %q, want %q", got, "Linux")
	}
}

// End-to-end through connLogger.log: the "os" field only appears when a p0f
// socket is configured and it actually matches, and never blocks or breaks
// logging when it isn't.
func TestConnLoggerEmbedsP0fOSGuess(t *testing.T) {
	sock := fakeP0f(t, func(q p0fQuery) p0fResponse {
		r := p0fResponse{Magic: p0fRespMagic, Status: p0fStatusOK}
		putStr(&r.OSName, "Windows")
		putStr(&r.OSFlavor, "7 or 8")
		return r
	})

	logPath := filepath.Join(t.TempDir(), "portbridge.json")
	cl := newConnLogger(logPath)
	cl.p0fSock = sock
	t.Cleanup(func() { cl.f.Close() })

	r := rule{proto: "tcp", listenPort: "22", target: "10.8.0.2:19022"}
	src := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 40000}
	cl.log(r, src, nil, nil)

	rec := lastConnLogRecord(t, logPath)
	if got := rec["os"]; got != "Windows 7 or 8" {
		t.Errorf(`rec["os"] = %v, want "Windows 7 or 8"`, got)
	}
}

func TestConnLoggerWithoutP0fSockOmitsOSField(t *testing.T) {
	t.Setenv("P0F_API_SOCK", "")
	logPath := filepath.Join(t.TempDir(), "portbridge.json")
	cl := newConnLogger(logPath)
	t.Cleanup(func() { cl.f.Close() })

	r := rule{proto: "tcp", listenPort: "22", target: "10.8.0.2:19022"}
	src := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 7), Port: 40000}
	cl.log(r, src, nil, nil)

	rec := lastConnLogRecord(t, logPath)
	if _, ok := rec["os"]; ok {
		t.Errorf(`rec["os"] = %v, want the field absent entirely`, rec["os"])
	}
}
