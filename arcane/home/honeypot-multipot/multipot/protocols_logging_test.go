package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
)

// Covers logging gaps found while auditing every sensor's data completeness
// against Elasticsearch (#33): commands that were answered but never
// emitted as events at all (Redis DBSIZE/SELECT/KEYS/TYPE/TTL/GET), a
// parsed-but-discarded field (Postgres startup "database" param), and two
// handlers that never read a request body in the first place
// (Elasticsearch/Docker HTTP POST payloads).

func decodeEvents(t *testing.T, raw string) []event {
	t.Helper()
	var out []event
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		var ev event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

func TestRedisLogsPreviouslySilentCommands(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handleRedis(server, &sessionLogger{logger: &logger{out: &output}}, 6379)
	}()

	r := bufio.NewReader(client)
	for _, cmd := range []string{"DBSIZE", "SELECT 1", "KEYS *", "TYPE foo", "TTL foo", "GET foo", "PING"} {
		client.Write([]byte(cmd + "\r\n"))
		line, _ := r.ReadString('\n')
		switch {
		case strings.HasPrefix(line, "$") && !strings.HasPrefix(line, "$-1"):
			r.ReadString('\n') // bulk payload
		case strings.HasPrefix(line, "*"):
			n, _ := strconv.Atoi(strings.TrimSpace(line[1:]))
			for i := 0; i < n*2; i++ {
				r.ReadString('\n')
			}
		}
	}
	client.Write([]byte("QUIT\r\n"))
	client.Close()
	<-done

	events := decodeEvents(t, output.String())
	seen := map[string]bool{}
	for _, ev := range events {
		seen[strings.Fields(ev.Command)[0]] = true
	}
	for _, want := range []string{"DBSIZE", "SELECT", "KEYS", "TYPE", "TTL", "GET"} {
		if !seen[want] {
			t.Errorf("expected %s to be logged, got events: %+v", want, events)
		}
	}
	if seen["PING"] {
		t.Errorf("PING should remain unlogged (high-volume, no signal), got events: %+v", events)
	}
}

func TestPostgresLogsDatabaseParam(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handlePostgres(server, &sessionLogger{logger: &logger{out: &output}}, 5432)
	}()

	params := "user\x00attacker\x00database\x00accounting\x00\x00"
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body, 196608) // protocol version 3.0
	copy(body[4:], params)

	msg := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(msg, uint32(4+len(body)))
	copy(msg[4:], body)
	client.Write(msg)

	r := bufio.NewReader(client)
	authTag := make([]byte, 8)
	io.ReadFull(r, authTag) // AuthenticationCleartextPassword

	pw := "hunter2"
	pwMsg := make([]byte, 1+4+len(pw)+1)
	pwMsg[0] = 'p'
	binary.BigEndian.PutUint32(pwMsg[1:], uint32(4+len(pw)+1))
	copy(pwMsg[5:], pw)
	client.Write(pwMsg)
	client.Close()
	<-done

	events := decodeEvents(t, output.String())
	if len(events) != 1 {
		t.Fatalf("expected 1 login event, got %+v", events)
	}
	ev := events[0]
	if ev.Username != "attacker" || ev.Password != "hunter2" {
		t.Fatalf("credentials not captured: %+v", ev)
	}
	if ev.Data != "database=accounting" {
		t.Fatalf("expected database param surfaced in Data, got %+v", ev)
	}
}

func TestElasticLogsRequestBody(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handleElastic(server, &sessionLogger{logger: &logger{out: &output}}, 9200)
	}()

	payload := `{"query":{"script":{"source":"malicious"}}}`
	req := fmt.Sprintf("POST /_search HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)
	client.Write([]byte(req))

	go io.Copy(io.Discard, client)
	client.Close()
	<-done

	events := decodeEvents(t, output.String())
	if len(events) != 1 {
		t.Fatalf("expected 1 http_request event, got %+v", events)
	}
	if events[0].Data != payload {
		t.Fatalf("expected request body captured, got Data=%q", events[0].Data)
	}
}

func TestDockerLogsRequestBody(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		handleDocker(server, &sessionLogger{logger: &logger{out: &output}}, 2375)
	}()

	payload := `{"Image":"evil/backdoor:latest","Privileged":true}`
	req := fmt.Sprintf("POST /containers/create HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload)
	client.Write([]byte(req))

	go io.Copy(io.Discard, client)
	client.Close()
	<-done

	events := decodeEvents(t, output.String())
	if len(events) != 1 {
		t.Fatalf("expected 1 http_request event, got %+v", events)
	}
	if events[0].Data != payload {
		t.Fatalf("expected request body captured, got Data=%q", events[0].Data)
	}
}
