package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
)

// #238: RDP, ADB, POP3, IMAP, SOCKS5, HL7 -- T-Pot protocol coverage gaps.
// These cover POP3/IMAP/SOCKS5/HL7, ported directly into multipot per that
// issue's research (heralding's pop3/imap/socks5 handlers, medpot's HL7
// substring check -- all multipot's exact shape).

func TestPOP3CapturesCredentialsAndAlwaysFails(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handlePOP3(server, &logger{out: &output}, 110) }()

	r := bufio.NewReader(client)
	greeting, _ := r.ReadString('\n')
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("unexpected greeting: %q", greeting)
	}
	io.WriteString(client, "USER attacker\r\n")
	r.ReadString('\n')
	io.WriteString(client, "PASS hunter2\r\n")
	resp, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("PASS must always fail, got %q", resp)
	}
	io.WriteString(client, "QUIT\r\n")
	client.Close()
	<-done

	var ev event
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if err := json.Unmarshal([]byte(line), &ev); err == nil && ev.Event == "login" {
			break
		}
	}
	if ev.Username != "attacker" || ev.Password != "hunter2" || ev.Proto != "pop3" {
		t.Fatalf("credentials not captured: %+v", ev)
	}
}

func TestIMAPLoginFailsAndEchoesTag(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handleIMAP(server, &logger{out: &output}, 143) }()

	r := bufio.NewReader(client)
	r.ReadString('\n') // greeting
	io.WriteString(client, "a1 LOGIN attacker hunter2\r\n")
	resp, _ := r.ReadString('\n')
	if !strings.HasPrefix(resp, "a1 NO") {
		t.Fatalf("expected tagged NO response, got %q", resp)
	}
	io.WriteString(client, "a2 LOGOUT\r\n")
	client.Close()
	<-done

	var ev event
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if err := json.Unmarshal([]byte(line), &ev); err == nil && ev.Event == "login" {
			break
		}
	}
	if ev.Username != "attacker" || ev.Password != "hunter2" || ev.Proto != "imap" {
		t.Fatalf("credentials not captured: %+v", ev)
	}
}

func TestSOCKS5LogsConnectTargetAndRefuses(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handleSOCKS5(server, &logger{out: &output}, 1080) }()

	// Version 5, 1 method, method 0x00 (no auth).
	client.Write([]byte{0x05, 0x01, 0x00})
	r := bufio.NewReader(client)
	methodResp := make([]byte, 2)
	io.ReadFull(r, methodResp)
	if methodResp[0] != 0x05 || methodResp[1] != 0x00 {
		t.Fatalf("unexpected method selection response: %v", methodResp)
	}
	// CONNECT to example.com:443 via domain-name addressing (atyp 0x03).
	req := []byte{0x05, 0x01, 0x00, 0x03, 11}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x01, 0xbb) // port 443
	client.Write(req)
	reply := make([]byte, 10)
	io.ReadFull(r, reply)
	if reply[1] != 0x05 {
		t.Fatalf("expected reply code 5 (connection refused), got %v", reply)
	}
	client.Close()
	<-done

	var ev event
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		if err := json.Unmarshal([]byte(line), &ev); err == nil && ev.Event == "connect_request" {
			break
		}
	}
	if ev.Proto != "socks5" || ev.Data != "example.com:443" {
		t.Fatalf("connect target not captured: %+v", ev)
	}
}

func TestHL7LogsMessageAndSendsMLLPFramedACK(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handleHL7(server, &logger{out: &output}, 2575) }()

	msg := "\x0bMSH|^~\\&|SENDER|FAC|RECV|FAC|20260101000000||ADT^A01|1|P|2.3\x1c\r"
	io.WriteString(client, msg)
	resp := make([]byte, 256)
	n, _ := client.Read(resp)
	client.Close()
	<-done

	if !strings.Contains(string(resp[:n]), "MSA|AA") {
		t.Fatalf("expected an MLLP-framed ACK, got %q", resp[:n])
	}
	if !strings.Contains(output.String(), `"proto":"hl7"`) {
		t.Fatalf("HL7 message not logged: %s", output.String())
	}
}

func TestHL7IgnoresNonHL7Traffic(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handleHL7(server, &logger{out: &output}, 2575) }()

	io.WriteString(client, "GET / HTTP/1.1\r\n\r\n")
	client.Close()
	<-done

	if output.Len() != 0 {
		t.Fatalf("non-HL7 traffic must not be logged as an HL7 message: %s", output.String())
	}
}
