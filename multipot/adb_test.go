package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

// #238: ADB, ported from ADBHoney's CNXN handshake + OPEN/WRTE/CLSE stream
// lifecycle -- moderate effort per that issue's research, but multipot's
// exact shape (accept, read, pattern-match, canned response, log).

func encodeADB(command, arg0, arg1 uint32, data []byte) []byte {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], command)
	binary.LittleEndian.PutUint32(header[4:8], arg0)
	binary.LittleEndian.PutUint32(header[8:12], arg1)
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(data)))
	binary.LittleEndian.PutUint32(header[16:20], adbChecksum(data))
	binary.LittleEndian.PutUint32(header[20:24], command^0xffffffff)
	return append(header, data...)
}

func decodeADBHeader(t *testing.T, r *bufio.Reader) adbMessage {
	t.Helper()
	msg, err := readADBMessage(r)
	if err != nil {
		t.Fatalf("failed to read ADB message: %v", err)
	}
	return msg
}

func TestADBHandshakeLogsIdentityAndRepliesCNXN(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handleADB(server, &logger{out: &output}, 5555) }()

	identity := []byte("host::pixel_6:features=cmd,shell_v2")
	client.Write(encodeADB(adbCNXN, 0x01000000, 4096, identity))

	r := bufio.NewReader(client)
	reply := decodeADBHeader(t, r)
	if reply.Command != adbCNXN {
		t.Fatalf("expected a CNXN reply, got %#x", reply.Command)
	}
	client.Close()
	<-done

	var ev event
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if err := json.Unmarshal([]byte(line), &ev); err == nil && ev.Event == "handshake" {
			break
		}
	}
	if ev.Proto != "adb" || ev.Client != string(identity) {
		t.Fatalf("identity banner not captured: %+v", ev)
	}
}

func TestADBOpenLogsDestinationAndClosesTheStream(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handleADB(server, &logger{out: &output}, 5555) }()

	client.Write(encodeADB(adbCNXN, 0x01000000, 4096, []byte("host::")))
	r := bufio.NewReader(client)
	decodeADBHeader(t, r) // CNXN reply

	client.Write(encodeADB(adbOPEN, 42, 0, []byte("shell:cat /proc/cpuinfo")))
	okay := decodeADBHeader(t, r)
	if okay.Command != adbOKAY {
		t.Fatalf("expected OKAY after OPEN, got %#x", okay.Command)
	}
	clse := decodeADBHeader(t, r)
	if clse.Command != adbCLSE {
		t.Fatalf("expected the stream closed after OPEN, got %#x", clse.Command)
	}
	client.Close()
	<-done

	var ev event
	found := false
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if err := json.Unmarshal([]byte(line), &ev); err == nil && ev.Event == "open" {
			found = true
			break
		}
	}
	if !found || ev.Command != "shell:cat /proc/cpuinfo" {
		t.Fatalf("attempted command not captured: %+v (found=%v)", ev, found)
	}
}

func TestADBRejectsOversizedPayload(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handleADB(server, &logger{out: &output}, 5555) }()

	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], adbCNXN)
	binary.LittleEndian.PutUint32(header[12:16], 1<<20) // claims a 1MiB payload
	client.Write(header)
	client.Close()
	<-done

	if output.Len() != 0 {
		t.Fatalf("a bogus oversized length must not be allocated/logged: %s", output.String())
	}
}
