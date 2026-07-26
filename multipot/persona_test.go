package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
)

func TestPersonaMetadataAndProtocolAssets(t *testing.T) {
	var output bytes.Buffer
	log := &logger{out: &output}
	log.emit(event{Proto: "redis", Event: "connect"})
	var got event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Persona != "nexusai-core" || got.Site != "nexusai-berlin-core" || got.Asset != "cache01" {
		t.Fatalf("unexpected persona metadata: %+v", got)
	}
}

func TestDockerPersonaResponse(t *testing.T) {
	client, server := net.Pipe()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); handleDocker(server, &logger{out: &output}, 2375) }()
	if _, err := io.WriteString(client, "GET /version HTTP/1.1\r\nHost: build01\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !strings.Contains(string(response), `"Name":"build01"`) || !strings.Contains(string(response), `"Version":"25.0.5"`) {
		t.Fatalf("unexpected Docker response: %s", response)
	}
	if !strings.Contains(output.String(), `"asset_id":"build01"`) {
		t.Fatalf("Docker event missing persona asset: %s", output.String())
	}
}
